"""Serve the MCP server over Streamable HTTP, with a built-in OAuth authorization server.

stdio (``genesismesh-mcp``) stays the default. ``genesismesh-mcp-http`` serves the same
tools at ``<issuer>/mcp``. Every request needs an access token, and its scopes
(``gm:<profile>``, or ``gm:admin``) narrow the configured profiles for that request:
a client lists and calls only the tools its grant covers. ``genesismesh-mcp-admin``
issues approval codes and agent tokens, lists clients and revokes them.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
from dataclasses import dataclass, fields
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import uvicorn
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import ProviderTokenVerifier
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from .remote_auth import ALL_SCOPES, MCP_PATH, OAuthStore, parse_scopes, scope_profiles
from .server import create_server
from .settings import Settings


@dataclass(frozen=True)
class RemoteConfig:
    """Where and how the HTTP transport listens; separate from the tool ``Settings``."""

    issuer_url: str
    state_db: Path
    host: str = "127.0.0.1"
    port: int = 8765
    allowed_hosts: tuple[str, ...] = ()
    access_token_seconds: int = 3600
    refresh_token_seconds: int = 2_592_000
    approval_code_seconds: int = 900

    def __post_init__(self) -> None:
        parsed = urlsplit(self.issuer_url)
        if not parsed.hostname or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError("issuer_url must be an origin such as https://mcp.example.org")
        try:
            loopback = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            loopback = parsed.hostname == "localhost"
        if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
            raise ValueError("issuer_url must use HTTPS, except on a loopback development host")
        object.__setattr__(self, "issuer_url", f"{parsed.scheme}://{parsed.netloc}")
        if not 0 < self.port < 65536:
            raise ValueError("port must be between 1 and 65535")
        for name in ("access_token_seconds", "refresh_token_seconds", "approval_code_seconds"):
            if not isinstance(getattr(self, name), int) or getattr(self, name) <= 0:
                raise ValueError(f"{name} must be a positive integer")
        object.__setattr__(self, "allowed_hosts", tuple(self.allowed_hosts) or (parsed.netloc,))

    @classmethod
    def from_file(cls, path: Path) -> RemoteConfig:
        path = path.resolve()
        if path.stat().st_size > 65_536:
            raise ValueError("Remote configuration file is too large")
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or set(data) - {f.name for f in fields(cls)} or "state_db" not in data:
            raise ValueError("Remote configuration must contain issuer_url, state_db and only documented settings")
        data["state_db"] = path.parent / data["state_db"]
        if "allowed_hosts" in data:
            data["allowed_hosts"] = tuple(data["allowed_hosts"])
        return cls(**data)

    def store(self) -> OAuthStore:
        return OAuthStore(self.state_db, self.issuer_url, access_seconds=self.access_token_seconds,
                          refresh_seconds=self.refresh_token_seconds, approval_seconds=self.approval_code_seconds)


def granted_profiles() -> frozenset[str]:
    """The profiles the current request's access token grants; none without a token."""
    token = get_access_token()
    return scope_profiles(token.scopes) if token is not None else frozenset()


async def _health(_request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


def build_app(settings: Settings, config: RemoteConfig, store: OAuthStore) -> Starlette:
    """The ASGI application: OAuth endpoints, the consent page and the protected MCP endpoint."""
    server = create_server(settings, granted_profiles=granted_profiles)
    auth = AuthSettings(
        issuer_url=config.issuer_url, resource_server_url=config.issuer_url + MCP_PATH,
        client_registration_options=ClientRegistrationOptions(enabled=True, valid_scopes=ALL_SCOPES,
                                                              default_scopes=ALL_SCOPES),
        revocation_options=RevocationOptions(enabled=True), validate_token_resource=True)
    security = TransportSecuritySettings(enable_dns_rebinding_protection=True,
                                         allowed_hosts=list(config.allowed_hosts),
                                         allowed_origins=[config.issuer_url])
    return server.streamable_http_app(
        streamable_http_path=MCP_PATH, json_response=True, stateless_http=True, transport_security=security,
        host=config.host, auth=auth, token_verifier=ProviderTokenVerifier(store), auth_server_provider=store,
        custom_starlette_routes=[*store.consent_routes(), Route("/health", _health)])


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Genesis Mesh MCP server over Streamable HTTP with OAuth")
    parser.add_argument("--config", type=Path, help="Tool settings file, as for the stdio server")
    parser.add_argument("--remote", type=Path, required=True, help="Remote transport settings file")
    args = parser.parse_args(argv)
    try:
        settings = Settings.from_file(args.config) if args.config else Settings()
        config = RemoteConfig.from_file(args.remote)
        app = build_app(settings, config, config.store())
    except (ValueError, TypeError, KeyError, OSError):
        parser.error("Invalid configuration or incompatible installation; check the documented settings.")
    uvicorn.run(app, host=config.host, port=config.port, proxy_headers=False, server_header=False,
                log_level="info")


def admin_main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Administer the OAuth clients of a Genesis Mesh MCP HTTP server")
    parser.add_argument("--remote", type=Path, required=True, help="Remote transport settings file")
    commands = parser.add_subparsers(dest="command", required=True)
    issue = commands.add_parser("issue-code", help="Issue a single-use approval code for the consent page")
    issue.add_argument("--scopes", required=True, help="Comma-separated scopes: " + ", ".join(ALL_SCOPES))
    issue.add_argument("--label", default="approval")
    issue.add_argument("--minutes", type=int, default=15)
    agent = commands.add_parser("create-agent", help="Create an access token for an autonomous agent")
    agent.add_argument("--label", required=True)
    agent.add_argument("--scopes", required=True, help="Comma-separated scopes: " + ", ".join(ALL_SCOPES))
    agent.add_argument("--days", type=int, default=30)
    commands.add_parser("list", help="List clients and agents with live tokens")
    revoke = commands.add_parser("revoke", help="Revoke a client or agent and all its tokens")
    revoke.add_argument("client_id")
    args = parser.parse_args(argv)
    try:
        store = RemoteConfig.from_file(args.remote).store()
        if args.command in ("issue-code", "create-agent"):
            scopes = parse_scopes(args.scopes)
            if (args.minutes if args.command == "issue-code" else args.days) < 1:
                raise ValueError("The lifetime must be positive")
    except (ValueError, TypeError, KeyError, OSError) as exc:
        parser.error(str(exc) or "Invalid remote configuration.")
    if args.command == "issue-code":
        code = store.issue_approval(scopes, args.label, args.minutes * 60)
        print(json.dumps({"approval_code": code, "scopes": scopes, "expires_in_minutes": args.minutes}))
    elif args.command == "create-agent":
        client_id, token = store.create_agent(args.label, scopes, args.days)
        print(json.dumps({"client_id": client_id, "access_token": token, "scopes": scopes, "expires_in_days": args.days}))
    elif args.command == "list":
        rows = store.clients()
        for row in rows:
            row["created"] = datetime.fromtimestamp(row["created"], timezone.utc).isoformat(timespec="seconds")
        print(json.dumps(rows, indent=2))
    else:
        print(json.dumps({"client_id": args.client_id, "tokens_revoked": store.revoke_client(args.client_id)}))
    store.close()
