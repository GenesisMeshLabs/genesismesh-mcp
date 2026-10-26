"""OAuth 2.1 authorization server for the HTTP transport.

Clients register themselves (RFC 7591) and use the authorization code flow with
PKCE. A grant needs an approval code: someone with access to the server host
issues it (``genesismesh-mcp-admin issue-code``) and types it into the consent
page. The code is single use, expires, and names the scopes it allows.
Autonomous agents get a scoped access token from ``create-agent`` instead.

Codes and tokens are stored as SHA-256 digests only. Revoking a client revokes
every token issued to it.
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

from .settings import PROFILES

SCOPE_PREFIX = "gm:"
ADMIN_SCOPE = "gm:admin"
ALL_SCOPES = [ADMIN_SCOPE, *sorted(SCOPE_PREFIX + profile for profile in PROFILES)]
CONSENT_PATH = "/consent"
MCP_PATH = "/mcp"
MAX_CONSENT_FAILURES = 5
PENDING_SECONDS = 600
CODE_SECONDS = 300

_SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    client_id TEXT PRIMARY KEY, info TEXT NOT NULL, created REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS approvals (
    digest TEXT PRIMARY KEY, scopes TEXT NOT NULL, label TEXT NOT NULL, expires REAL NOT NULL, used REAL);
CREATE TABLE IF NOT EXISTS pending (
    request_id TEXT PRIMARY KEY, client_id TEXT NOT NULL, params TEXT NOT NULL, expires REAL NOT NULL,
    failures INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS codes (
    digest TEXT PRIMARY KEY, client_id TEXT NOT NULL, record TEXT NOT NULL, expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS tokens (
    digest TEXT PRIMARY KEY, kind TEXT NOT NULL, client_id TEXT NOT NULL, scopes TEXT NOT NULL,
    expires REAL, resource TEXT, family TEXT NOT NULL, label TEXT NOT NULL, created REAL NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0);
"""


def digest(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def scope_profiles(scopes: Iterable[str]) -> frozenset[str]:
    """The MCP profiles a set of scopes grants: ``gm:<profile>`` each, ``gm:admin`` all."""
    granted: set[str] = set()
    for scope in scopes:
        if scope == ADMIN_SCOPE:
            granted |= PROFILES
        elif scope.startswith(SCOPE_PREFIX) and scope[len(SCOPE_PREFIX):] in PROFILES:
            granted.add(scope[len(SCOPE_PREFIX):])
    return frozenset(granted)


def profile_scopes(profiles: frozenset[str]) -> list[str]:
    """The canonical scopes for a set of profiles."""
    if profiles == PROFILES:
        return [ADMIN_SCOPE]
    return sorted(SCOPE_PREFIX + profile for profile in profiles)


def parse_scopes(text: str) -> list[str]:
    """Scopes from a comma- or space-separated list; unknown scopes are refused."""
    scopes = [scope for scope in text.replace(",", " ").split() if scope]
    if not scopes or any(scope not in ALL_SCOPES for scope in scopes):
        raise ValueError("Use one or more of: " + ", ".join(ALL_SCOPES))
    return profile_scopes(scope_profiles(scopes))


class OAuthStore:
    """The authorization server's state, in one SQLite file.

    Provider methods are called from the event loop; each statement is short,
    and a lock serializes access to the shared connection.
    """

    def __init__(self, path: Path, issuer_url: str, *, access_seconds: int = 3600,
                 refresh_seconds: int = 30 * 86400, approval_seconds: int = 900,
                 clock: Callable[[], float] = time.time):
        self.issuer_url = issuer_url.rstrip("/")
        # Every token is bound to this server's MCP endpoint (RFC 8707), and the transport
        # refuses a token bound to another resource.
        self.resource_url = self.issuer_url + MCP_PATH
        self.access_seconds = access_seconds
        self.refresh_seconds = refresh_seconds
        self.approval_seconds = approval_seconds
        self.clock = clock
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        if os.name != "nt":
            os.chmod(path, 0o600)
        self._lock = threading.Lock()
        with self._lock:
            self._db.executescript(_SCHEMA)

    def close(self) -> None:
        self._db.close()

    def _run(self, sql: str, args: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._db.execute(sql, args)

    # -- Operator administration -------------------------------------------------------------

    def issue_approval(self, scopes: list[str], label: str, seconds: int | None = None) -> str:
        """A single-use approval code for the consent page, allowing ``scopes``."""
        code = "-".join(secrets.token_hex(3).upper() for _ in range(4))
        expires = self.clock() + (seconds or self.approval_seconds)
        self._run("INSERT INTO approvals (digest, scopes, label, expires) VALUES (?, ?, ?, ?)",
                  (digest(code), json.dumps(scopes), label, expires))
        return code

    def create_agent(self, label: str, scopes: list[str], days: int) -> tuple[str, str]:
        """A client id and an access token for an autonomous agent; the token is shown once."""
        client_id = "agent-" + secrets.token_hex(6)
        token = "gma_" + secrets.token_urlsafe(32)
        now = self.clock()
        self._run("INSERT INTO tokens (digest, kind, client_id, scopes, expires, resource, family, label, created) "
                  "VALUES (?, 'agent', ?, ?, ?, ?, ?, ?, ?)",
                  (digest(token), client_id, json.dumps(scopes), now + days * 86400, self.resource_url, client_id,
                   label, now))
        return client_id, token

    def revoke_client(self, client_id: str) -> int:
        """Revoke a client and every token issued to it; the number of tokens revoked."""
        self._run("UPDATE clients SET revoked = 1 WHERE client_id = ?", (client_id,))
        return self._run("UPDATE tokens SET revoked = 1 WHERE client_id = ? AND revoked = 0", (client_id,)).rowcount

    def clients(self) -> list[dict[str, Any]]:
        """Registered clients and agents, with their live tokens; no secrets."""
        now = self.clock()
        rows: dict[str, dict[str, Any]] = {}
        for client_id, info, created, revoked in self._run(
                "SELECT client_id, info, created, revoked FROM clients ORDER BY created"):
            name = json.loads(info).get("client_name")
            rows[client_id] = {"client_id": client_id, "kind": "oauth", "name": name, "created": created,
                               "revoked": bool(revoked), "live_tokens": 0, "scopes": []}
        for client_id, kind, scopes, label, created in self._run(
                "SELECT client_id, kind, scopes, label, created FROM tokens "
                "WHERE revoked = 0 AND (expires IS NULL OR expires > ?) ORDER BY created", (now,)):
            row = rows.setdefault(client_id, {"client_id": client_id, "kind": kind, "name": label,
                                              "created": created, "revoked": False, "live_tokens": 0, "scopes": []})
            row["live_tokens"] += 1
            row["scopes"] = sorted(set(row["scopes"]) | set(json.loads(scopes)))
        return list(rows.values())

    # -- OAuthAuthorizationServerProvider ----------------------------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        row = self._run("SELECT info FROM clients WHERE client_id = ? AND revoked = 0", (client_id,)).fetchone()
        return OAuthClientInformationFull.model_validate_json(row[0]) if row else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self._run("INSERT INTO clients (client_id, info, created) VALUES (?, ?, ?)",
                  (client_info.client_id, client_info.model_dump_json(), self.clock()))

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        request_id = secrets.token_urlsafe(24)
        self._run("INSERT INTO pending (request_id, client_id, params, expires) VALUES (?, ?, ?, ?)",
                  (request_id, client.client_id, params.model_dump_json(), self.clock() + PENDING_SECONDS))
        return f"{self.issuer_url}{CONSENT_PATH}?request={request_id}"

    async def load_authorization_code(self, client: OAuthClientInformationFull,
                                      authorization_code: str) -> AuthorizationCode | None:
        row = self._run("SELECT record FROM codes WHERE digest = ? AND client_id = ? AND expires > ?",
                        (digest(authorization_code), client.client_id, self.clock())).fetchone()
        return AuthorizationCode.model_validate_json(row[0]).model_copy(update={"code": authorization_code}) \
            if row else None

    async def exchange_authorization_code(self, client: OAuthClientInformationFull,
                                          authorization_code: AuthorizationCode) -> OAuthToken:
        removed = self._run("DELETE FROM codes WHERE digest = ? AND client_id = ?",
                            (digest(authorization_code.code), client.client_id)).rowcount
        if removed != 1:
            raise TokenError(error="invalid_grant", error_description="The authorization code was already used.")
        return self._issue(client.client_id, authorization_code.scopes, authorization_code.resource)

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        row = self._live(refresh_token, "refresh")
        if row is None or row["client_id"] != client.client_id:
            return None
        return RefreshToken(token=refresh_token, client_id=row["client_id"], scopes=row["scopes"],
                            expires_at=int(row["expires"]), resource=row["resource"])

    async def exchange_refresh_token(self, client: OAuthClientInformationFull, refresh_token: RefreshToken,
                                     scopes: list[str]) -> OAuthToken:
        family = self._run("SELECT family FROM tokens WHERE digest = ? AND revoked = 0",
                           (digest(refresh_token.token),)).fetchone()
        if family is None:
            raise TokenError(error="invalid_grant", error_description="The refresh token was revoked.")
        # Rotation: the old pair stops working when the new one is issued.
        self._run("UPDATE tokens SET revoked = 1 WHERE family = ?", (family[0],))
        # The token endpoint already checked that requested scopes are a subset of the grant.
        return self._issue(client.client_id, scopes or refresh_token.scopes, refresh_token.resource)

    async def load_access_token(self, token: str) -> AccessToken | None:
        row = self._live(token, "access") or self._live(token, "agent")
        if row is None:
            return None
        if row["kind"] == "access" and await self.get_client(row["client_id"]) is None:
            return None
        return AccessToken(token=token, client_id=row["client_id"], scopes=row["scopes"],
                           expires_at=int(row["expires"]) if row["expires"] else None, resource=row["resource"],
                           claims={"iss": self.issuer_url})

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        family = self._run("SELECT family FROM tokens WHERE digest = ?", (digest(token.token),)).fetchone()
        if family is not None:
            self._run("UPDATE tokens SET revoked = 1 WHERE family = ?", (family[0],))

    # -- Internals ---------------------------------------------------------------------------

    def _live(self, token: str, kind: str) -> dict[str, Any] | None:
        row = self._run("SELECT client_id, scopes, expires, resource, kind FROM tokens "
                        "WHERE digest = ? AND kind = ? AND revoked = 0", (digest(token), kind)).fetchone()
        if row is None or (row[2] is not None and row[2] <= self.clock()):
            return None
        return {"client_id": row[0], "scopes": json.loads(row[1]), "expires": row[2], "resource": row[3],
                "kind": row[4]}

    def _issue(self, client_id: str, scopes: list[str], resource: str | None) -> OAuthToken:
        access, refresh, family = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_hex(12)
        now = self.clock()
        for token, kind, seconds in ((access, "access", self.access_seconds), (refresh, "refresh", self.refresh_seconds)):
            self._run("INSERT INTO tokens (digest, kind, client_id, scopes, expires, resource, family, label, created) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, '', ?)",
                      (digest(token), kind, client_id, json.dumps(scopes), now + seconds,
                       resource or self.resource_url, family, now))
        return OAuthToken(access_token=access, expires_in=self.access_seconds, scope=" ".join(scopes),
                          refresh_token=refresh)

    # -- Consent page ------------------------------------------------------------------------

    def consent_routes(self) -> list[Route]:
        return [Route(CONSENT_PATH, self._consent, methods=["GET", "POST"])]

    async def _consent(self, request: Request) -> Response:
        if request.method == "GET":
            pending = self._pending(request.query_params.get("request", ""))
            if pending is None:
                return _page("This request has expired. Start the connection again from your client.", status=400)
            return _consent_page(pending, error=None)
        origin = request.headers.get("origin")
        if origin is not None and origin != self.issuer_url:
            return _page("This form must be submitted from the server's own page.", status=403)
        form = await request.form()
        pending = self._pending(str(form.get("request", "")))
        if pending is None:
            return _page("This request has expired. Start the connection again from your client.", status=400)
        params = AuthorizationParams.model_validate_json(pending["params"])
        if form.get("action") == "deny":
            self._run("DELETE FROM pending WHERE request_id = ?", (pending["request_id"],))
            return RedirectResponse(construct_redirect_uri(str(params.redirect_uri), error="access_denied",
                                                           state=params.state), status_code=302)
        granted = self._approve(str(form.get("code", "")).strip().upper(), params.scopes)
        if granted is None:
            failures = pending["failures"] + 1
            if failures >= MAX_CONSENT_FAILURES:
                self._run("DELETE FROM pending WHERE request_id = ?", (pending["request_id"],))
                return _page("Too many invalid approval codes. Start the connection again from your client.",
                             status=403)
            self._run("UPDATE pending SET failures = ? WHERE request_id = ?", (failures, pending["request_id"]))
            return _consent_page({**pending, "failures": failures},
                                 error="That approval code is not valid for this request.", status=400)
        self._run("DELETE FROM pending WHERE request_id = ?", (pending["request_id"],))
        code = secrets.token_urlsafe(32)
        record = AuthorizationCode(code="", scopes=granted, expires_at=self.clock() + CODE_SECONDS,
                                   client_id=pending["client_id"], code_challenge=params.code_challenge,
                                   redirect_uri=params.redirect_uri,
                                   redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
                                   resource=params.resource)
        self._run("INSERT INTO codes (digest, client_id, record, expires) VALUES (?, ?, ?, ?)",
                  (digest(code), pending["client_id"], record.model_dump_json(), record.expires_at))
        return RedirectResponse(construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state),
                                status_code=302)

    def _pending(self, request_id: str) -> dict[str, Any] | None:
        row = self._run("SELECT request_id, client_id, params, failures FROM pending "
                        "WHERE request_id = ? AND expires > ?", (request_id, self.clock())).fetchone()
        if row is None:
            return None
        info = self._run("SELECT info FROM clients WHERE client_id = ?", (row[1],)).fetchone()
        name = json.loads(info[0]).get("client_name") if info else None
        return {"request_id": row[0], "client_id": row[1], "params": row[2], "failures": row[3],
                "client_name": name or row[1]}

    def _approve(self, code: str, requested: list[str] | None) -> list[str] | None:
        """The scopes granted by a valid unused approval code, which is then spent."""
        row = self._run("SELECT scopes FROM approvals WHERE digest = ? AND used IS NULL AND expires > ?",
                        (digest(code), self.clock())).fetchone()
        if row is None:
            return None
        allowed = scope_profiles(json.loads(row[0]))
        profiles = allowed & scope_profiles(requested) if requested else allowed
        if not profiles:
            return None
        spent = self._run("UPDATE approvals SET used = ? WHERE digest = ? AND used IS NULL",
                          (self.clock(), digest(code))).rowcount
        return profile_scopes(profiles) if spent == 1 else None


_STYLE = ("body{font-family:system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem;color:#1f2933}"
          "code{background:#eef2f6;padding:.1rem .3rem;border-radius:4px}input{font:inherit;padding:.5rem;width:100%;"
          "box-sizing:border-box;margin:.5rem 0}button{font:inherit;padding:.5rem 1rem;margin-right:.5rem}"
          ".error{color:#b42318}")
_HEADERS = {"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
                                       "frame-ancestors 'none'",
            "X-Frame-Options": "DENY", "Cache-Control": "no-store",
            # same-origin, not no-referrer: under no-referrer a browser posts the consent form with
            # Origin: null, which the same-origin check must refuse.
            "Referrer-Policy": "same-origin"}


_ORIGIN = re.compile(r"^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?$")


def _consent_headers(redirect_uri: str) -> dict[str, str]:
    """The page headers, with the client's redirect origin allowed as a form target: browsers apply
    form-action to the redirect that follows the form post, so 'self' alone blocks the hand-back."""
    parts = urlsplit(redirect_uri)
    origin = f"{parts.scheme}://{parts.netloc}"
    target = f" {origin}" if _ORIGIN.match(origin) else ""
    return {**_HEADERS, "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                                                   f"form-action 'self'{target}; frame-ancestors 'none'"}


def _page(body: str, *, status: int = 200) -> HTMLResponse:
    return HTMLResponse(f"<!doctype html><meta charset=utf-8><title>Genesis Mesh MCP</title><style>{_STYLE}</style>"
                        f"<h1>Genesis Mesh MCP</h1><p>{html.escape(body)}</p>", status_code=status, headers=_HEADERS)


def _consent_page(pending: dict[str, Any], *, error: str | None, status: int = 200) -> HTMLResponse:
    params = AuthorizationParams.model_validate_json(pending["params"])
    requested = ", ".join(params.scopes) if params.scopes else "whatever the approval code allows"
    message = f'<p class="error">{html.escape(error)}</p>' if error else ""
    return HTMLResponse(
        f"<!doctype html><meta charset=utf-8><title>Approve a client</title><style>{_STYLE}</style>"
        f"<h1>Approve a client</h1><p><strong>{html.escape(pending['client_name'])}</strong> asks to use this "
        f"Genesis Mesh MCP server and will be sent back to <code>{html.escape(str(params.redirect_uri))}</code>.</p>"
        f"<p>Requested access: <code>{html.escape(requested)}</code></p>{message}"
        f'<form method="post"><input type="hidden" name="request" value="{html.escape(pending["request_id"])}">'
        '<label>Approval code<input name="code" autocomplete="off" autofocus required></label>'
        '<button name="action" value="approve">Approve</button>'
        '<button name="action" value="deny" formnovalidate>Deny</button></form>'
        "<p>Ask the server's operator for a code: <code>genesismesh-mcp-admin issue-code</code>.</p>",
        status_code=status, headers=_consent_headers(str(params.redirect_uri)))
