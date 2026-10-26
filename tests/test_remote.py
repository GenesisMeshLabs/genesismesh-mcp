"""The HTTP transport end to end: dynamic registration, PKCE, approval codes, scoped tokens,
refresh rotation, revocation, agent tokens and the admin command."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from starlette.testclient import TestClient

from genesismesh_mcp import remote
from genesismesh_mcp.remote import RemoteConfig, admin_main, build_app, granted_profiles
from genesismesh_mcp.remote_auth import (
    ADMIN_SCOPE,
    ALL_SCOPES,
    MAX_CONSENT_FAILURES,
    OAuthStore,
    parse_scopes,
    profile_scopes,
    scope_profiles,
)
from genesismesh_mcp.server import build_tools
from genesismesh_mcp.settings import PROFILES, Settings

ISSUER = "http://127.0.0.1:8765"
REDIRECT = "http://127.0.0.1:9999/callback"
ACCEPT = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


class Clock:
    def __init__(self):
        self.now = 1_800_000_000.0

    def __call__(self):
        return self.now


@pytest.fixture
def harness(tmp_path):
    clock = Clock()
    config = RemoteConfig(issuer_url=ISSUER, state_db=tmp_path / "state/oauth.db")
    store = OAuthStore(config.state_db, config.issuer_url, clock=clock)
    app = build_app(Settings(), config, store)
    with TestClient(app, base_url=ISSUER) as client:
        yield client, store, clock
    store.close()


def register(client, name="Test client"):
    response = client.post("/register", json={"redirect_uris": [REDIRECT], "client_name": name,
                                              "token_endpoint_auth_method": "none",
                                              "grant_types": ["authorization_code", "refresh_token"],
                                              "response_types": ["code"]})
    assert response.status_code == 201, response.text
    return response.json()["client_id"]


def start(client, client_id, scope=None):
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    query = {"response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT, "state": "s-1",
             "code_challenge": challenge, "code_challenge_method": "S256"}
    if scope:
        query["scope"] = scope
    response = client.get("/authorize", params=query, follow_redirects=False)
    assert response.status_code == 302, response.text
    consent = urlsplit(response.headers["location"])
    assert f"{consent.scheme}://{consent.netloc}" == ISSUER and consent.path == "/consent"
    return parse_qs(consent.query)["request"][0], verifier


def approve(client, request_id, code):
    # As a browser posts the consent form from the server's own page.
    return client.post("/consent", data={"request": request_id, "code": code, "action": "approve"},
                       headers={"Origin": ISSUER}, follow_redirects=False)


def redeem(client, client_id, location, verifier):
    query = parse_qs(urlsplit(location).query)
    assert query["state"] == ["s-1"]
    response = client.post("/token", data={"grant_type": "authorization_code", "code": query["code"][0],
                                           "redirect_uri": REDIRECT, "client_id": client_id,
                                           "code_verifier": verifier})
    assert response.status_code == 200, response.text
    return response.json()


def connect(client, store, scopes, requested=None):
    client_id = register(client)
    request_id, verifier = start(client, client_id, requested)
    location = approve(client, request_id, store.issue_approval(scopes, "test")).headers["location"]
    return client_id, redeem(client, client_id, location, verifier)


def rpc(client, token, method, params=None, ident=1):
    headers = {**ACCEPT, **({"Authorization": f"Bearer {token}"} if token else {})}
    return client.post("/mcp", headers=headers,
                       json={"jsonrpc": "2.0", "id": ident, "method": method, "params": params or {}})


def initialize(client, token):
    return rpc(client, token, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                             "clientInfo": {"name": "test", "version": "1"}})


def tool_names(client, token):
    response = rpc(client, token, "tools/list", ident=2)
    assert response.status_code == 200, response.text
    return {tool["name"] for tool in response.json()["result"]["tools"]}


def test_scopes_map_to_profiles():
    assert scope_profiles([ADMIN_SCOPE]) == PROFILES
    assert scope_profiles(["gm:read", "gm:unknown", "other"]) == {"read"}
    assert profile_scopes(PROFILES) == [ADMIN_SCOPE]
    assert profile_scopes(frozenset({"verify", "read"})) == ["gm:read", "gm:verify"]
    assert parse_scopes("gm:verify, gm:read") == ["gm:read", "gm:verify"]
    assert parse_scopes("gm:admin gm:read") == [ADMIN_SCOPE]
    assert set(ALL_SCOPES) == {ADMIN_SCOPE, *(f"gm:{p}" for p in PROFILES)}
    for text in ("", "gm:everything", "read"):
        with pytest.raises(ValueError):
            parse_scopes(text)
    assert granted_profiles() == frozenset()


def test_remote_config_validation(tmp_path):
    config = RemoteConfig(issuer_url="https://mcp.example.org/", state_db=tmp_path / "s.db")
    assert config.issuer_url == "https://mcp.example.org" and config.allowed_hosts == ("mcp.example.org",)
    assert RemoteConfig(issuer_url="http://localhost:9", state_db=tmp_path / "s.db").issuer_url == "http://localhost:9"
    for issuer in ("http://mcp.example.org", "https://mcp.example.org/mcp", "https://mcp.example.org?x=1",
                   "https://mcp.example.org#f", "mcp.example.org", "ftp://127.0.0.1"):
        with pytest.raises(ValueError):
            RemoteConfig(issuer_url=issuer, state_db=tmp_path / "s.db")
    with pytest.raises(ValueError, match="port"):
        RemoteConfig(issuer_url=ISSUER, state_db=tmp_path / "s.db", port=0)
    for name in ("access_token_seconds", "refresh_token_seconds", "approval_code_seconds"):
        with pytest.raises(ValueError, match=name):
            RemoteConfig(issuer_url=ISSUER, state_db=tmp_path / "s.db", **{name: 0})
    path = tmp_path / "remote.json"
    path.write_text(json.dumps({"issuer_url": ISSUER, "state_db": "state/oauth.db", "allowed_hosts": ["a", "b"],
                                "port": 9000}))
    loaded = RemoteConfig.from_file(path)
    assert loaded.state_db == tmp_path / "state/oauth.db" and loaded.allowed_hosts == ("a", "b")
    assert loaded.port == 9000
    for data in ({"issuer_url": ISSUER}, {"issuer_url": ISSUER, "state_db": "s.db", "secret": 1}, ["list"]):
        path.write_text(json.dumps(data))
        with pytest.raises(ValueError):
            RemoteConfig.from_file(path)
    path.write_text(" " * 70_000)
    with pytest.raises(ValueError, match="too large"):
        RemoteConfig.from_file(path)


def test_metadata_health_and_unauthenticated_requests(harness):
    client, _, _ = harness
    metadata = client.get("/.well-known/oauth-authorization-server").json()
    assert metadata["issuer"] == ISSUER and set(metadata["scopes_supported"]) == set(ALL_SCOPES)
    assert "S256" in metadata["code_challenge_methods_supported"]
    resource = client.get("/.well-known/oauth-protected-resource/mcp").json()
    assert resource["resource"] == ISSUER + "/mcp" and resource["authorization_servers"] == [ISSUER]
    assert client.get("/health").json() == {"status": "ok"}
    denied = initialize(client, None)
    assert denied.status_code == 401 and "resource_metadata" in denied.headers["www-authenticate"]
    assert initialize(client, "not-a-token").status_code == 401
    rebinding = client.post("/mcp", headers={**ACCEPT, "Host": "evil.example"}, json={})
    assert rebinding.status_code in (400, 401, 403, 421)


def test_full_oauth_flow_scopes_the_tools_a_client_sees_and_calls(harness):
    client, store, _ = harness
    client_id, tokens = connect(client, store, ["gm:verify"])
    assert tokens["scope"] == "gm:verify" and tokens["token_type"] == "Bearer"
    access = tokens["access_token"]
    assert initialize(client, access).status_code == 200
    names = tool_names(client, access)
    expected = {tool.name for tool in build_tools(Settings()) if tool.profiles <= {"verify"}}
    assert names == expected
    everything = tool_names(client, connect(client, store, [ADMIN_SCOPE])[1]["access_token"])
    configured = Settings().profiles
    assert everything == {tool.name for tool in build_tools(Settings()) if tool.profiles <= configured}
    assert everything > names
    read_tool = sorted(everything - names)[0]
    called = rpc(client, access, "tools/call", {"name": read_tool, "arguments": {}}, ident=3).json()["result"]
    assert called["isError"] and called["structuredContent"]["error"]["code"] == "scope_required"


def test_approval_code_narrows_requested_scopes_and_is_single_use(harness):
    client, store, _ = harness
    client_id = register(client)
    request_id, verifier = start(client, client_id, "gm:read gm:verify")
    code = store.issue_approval(["gm:verify", "gm:sign"], "narrow")
    location = approve(client, request_id, code.lower()).headers["location"]
    assert redeem(client, client_id, location, verifier)["scope"] == "gm:verify"
    again, _ = start(client, client_id)
    assert approve(client, again, code).status_code == 400
    # A code whose scopes do not meet the request grants nothing.
    disjoint, _ = start(client, client_id, "gm:read")
    assert approve(client, disjoint, store.issue_approval(["gm:sign"], "disjoint")).status_code == 400


def test_consent_page_denial_failures_expiry_and_origin(harness):
    client, store, clock = harness
    client_id = register(client, name="<script>alert(1)</script>")
    request_id, _ = start(client, client_id, "gm:read")
    page = client.get("/consent", params={"request": request_id})
    assert page.status_code == 200 and "<script>alert" not in page.text and "&lt;script&gt;" in page.text
    assert "default-src 'none'" in page.headers["content-security-policy"]
    # Under no-referrer a browser would post the form with Origin: null, which is refused.
    assert page.headers["referrer-policy"] == "same-origin"
    assert client.get("/consent", params={"request": "unknown"}).status_code == 400
    cross = client.post("/consent", data={"request": request_id, "code": "x", "action": "approve"},
                        headers={"Origin": "https://evil.example"})
    assert cross.status_code == 403
    opaque = client.post("/consent", data={"request": request_id, "code": "x", "action": "approve"},
                         headers={"Origin": "null"})
    assert opaque.status_code == 403
    assert client.post("/consent", data={"request": "unknown", "action": "approve"}).status_code == 400
    for attempt in range(1, MAX_CONSENT_FAILURES):
        failed = approve(client, request_id, "WRONG-CODE")
        assert failed.status_code == 400 and "not valid" in failed.text
    assert approve(client, request_id, "WRONG-CODE").status_code == 403
    assert client.get("/consent", params={"request": request_id}).status_code == 400
    denied_id, _ = start(client, client_id)
    denied = client.post("/consent", data={"request": denied_id, "action": "deny"}, follow_redirects=False)
    assert parse_qs(urlsplit(denied.headers["location"]).query) == {"error": ["access_denied"], "state": ["s-1"]}
    expired_id, _ = start(client, client_id)
    code = store.issue_approval(["gm:read"], "late")
    clock.now += 3600
    assert approve(client, expired_id, code).status_code == 400
    fresh_id, _ = start(client, client_id)
    assert approve(client, fresh_id, code).status_code == 400  # the code expired too


def test_codes_refresh_rotation_revocation_and_client_revocation(harness):
    client, store, clock = harness
    client_id = register(client)
    request_id, verifier = start(client, client_id)
    approval = store.issue_approval(["gm:read", "gm:verify"], "pair")
    location = approve(client, request_id, approval).headers["location"]
    code = parse_qs(urlsplit(location).query)["code"][0]
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT, "client_id": client_id,
            "code_verifier": verifier}
    tokens = client.post("/token", data=form).json()
    assert tokens["scope"] == "gm:read gm:verify"
    assert client.post("/token", data=form).status_code == 400  # single use
    widened = client.post("/token", data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"],
                                          "client_id": client_id, "scope": "gm:admin"})
    assert widened.status_code == 400  # a refresh never widens the grant
    refreshed = client.post("/token", data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"],
                                            "client_id": client_id, "scope": "gm:verify"})
    assert refreshed.status_code == 200 and refreshed.json()["scope"] == "gm:verify"
    assert initialize(client, tokens["access_token"]).status_code == 401  # rotated away
    assert client.post("/token", data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"],
                                       "client_id": client_id}).status_code == 400
    current = refreshed.json()
    kept = client.post("/token", data={"grant_type": "refresh_token", "refresh_token": current["refresh_token"],
                                       "client_id": client_id}).json()
    assert kept["scope"] == "gm:verify"
    revoked = client.post("/revoke", data={"token": kept["access_token"], "client_id": client_id, "client_secret": ""})
    assert revoked.status_code == 200
    assert initialize(client, kept["access_token"]).status_code == 401
    _, other = connect(client, store, ["gm:read"])
    clock.now += 7200  # past the access token lifetime
    assert initialize(client, other["access_token"]).status_code == 401
    clock.now -= 7200
    other_client = store.clients()[-1]["client_id"]
    assert store.revoke_client(other_client) >= 1
    assert initialize(client, other["access_token"]).status_code == 401


async def test_store_edge_cases(tmp_path):
    clock = Clock()
    store = OAuthStore(tmp_path / "oauth.db", ISSUER + "/", clock=clock)
    if os.name != "nt":
        assert (tmp_path / "oauth.db").stat().st_mode & 0o077 == 0
    client_id, token = store.create_agent("worker", ["gm:read"], 1)
    loaded = await store.load_access_token(token)
    assert loaded.client_id == client_id and loaded.scopes == ["gm:read"] and loaded.claims == {"iss": ISSUER}
    assert loaded.resource == ISSUER + "/mcp"
    assert await store.load_access_token("missing") is None
    assert await store.get_client(client_id) is None
    listed = store.clients()
    assert listed[0]["kind"] == "agent" and listed[0]["name"] == "worker" and listed[0]["live_tokens"] == 1
    clock.now += 2 * 86400
    assert await store.load_access_token(token) is None
    await store.revoke_token(type("T", (), {"token": "unknown"})())
    store.close()


def test_agent_tokens_and_admin_command(tmp_path, capsys):
    remote_file = tmp_path / "remote.json"
    remote_file.write_text(json.dumps({"issuer_url": ISSUER, "state_db": "oauth.db"}))
    admin_main(["--remote", str(remote_file), "create-agent", "--label", "ops", "--scopes", "gm:admin", "--days", "7"])
    agent = json.loads(capsys.readouterr().out)
    assert agent["scopes"] == [ADMIN_SCOPE] and agent["access_token"].startswith("gma_")
    admin_main(["--remote", str(remote_file), "issue-code", "--scopes", "gm:read,gm:verify", "--minutes", "5"])
    issued = json.loads(capsys.readouterr().out)
    assert issued["scopes"] == ["gm:read", "gm:verify"] and len(issued["approval_code"]) == 27
    admin_main(["--remote", str(remote_file), "list"])
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["client_id"] == agent["client_id"] and rows[0]["created"].endswith("+00:00")
    config = RemoteConfig.from_file(remote_file)
    store = config.store()
    app = build_app(Settings(), config, store)
    with TestClient(app, base_url=ISSUER) as client:
        assert initialize(client, agent["access_token"]).status_code == 200
        assert any(name.startswith("na_") for name in tool_names(client, agent["access_token"]))
        admin_main(["--remote", str(remote_file), "revoke", agent["client_id"]])
        assert json.loads(capsys.readouterr().out)["tokens_revoked"] == 1
        assert initialize(client, agent["access_token"]).status_code == 401
    store.close()
    for argv in (["issue-code", "--scopes", "gm:everything"], ["issue-code", "--scopes", "gm:read", "--minutes", "0"],
                 ["create-agent", "--label", "x", "--scopes", "gm:read", "--days", "0"]):
        with pytest.raises(SystemExit):
            admin_main(["--remote", str(remote_file), *argv])
    with pytest.raises(SystemExit):
        admin_main(["--remote", str(tmp_path / "missing.json"), "list"])


def test_http_entry_point_runs_uvicorn_with_the_configured_listener(tmp_path, monkeypatch):
    remote_file = tmp_path / "remote.json"
    remote_file.write_text(json.dumps({"issuer_url": ISSUER, "state_db": "oauth.db", "host": "0.0.0.0",
                                       "port": 8123}))
    settings_file = tmp_path / "settings.json"
    settings_file.write_text(json.dumps({"profiles": ["verify"]}))
    calls = []
    monkeypatch.setattr(remote.uvicorn, "run", lambda app, **kwargs: calls.append((app, kwargs)))
    remote.main(["--config", str(settings_file), "--remote", str(remote_file)])
    remote.main(["--remote", str(remote_file)])
    assert [call[1]["port"] for call in calls] == [8123, 8123] and calls[0][1]["host"] == "0.0.0.0"
    assert calls[0][1]["proxy_headers"] is False
    with pytest.raises(SystemExit):
        remote.main(["--remote", str(Path(tmp_path / "missing.json"))])


async def test_store_refuses_replayed_codes_revoked_refresh_tokens_and_revoked_clients(tmp_path):
    from mcp.server.auth.provider import AuthorizationCode, TokenError
    from mcp.shared.auth import OAuthClientInformationFull

    store = OAuthStore(tmp_path / "oauth.db", ISSUER, clock=Clock())
    client = OAuthClientInformationFull(client_id="c-1", redirect_uris=[REDIRECT], client_name="c")
    await store.register_client(client)
    record = AuthorizationCode(code="spent", scopes=["gm:read"], expires_at=2e9, client_id="c-1", code_challenge="x",
                               redirect_uri=REDIRECT, redirect_uri_provided_explicitly=True)
    with pytest.raises(TokenError):  # never stored, or already exchanged by a concurrent request
        await store.exchange_authorization_code(client, record)
    tokens = store._issue("c-1", ["gm:read"], None)
    refresh = await store.load_refresh_token(client, tokens.refresh_token)
    assert await store.load_refresh_token(OAuthClientInformationFull(client_id="other", redirect_uris=[REDIRECT]),
                                          tokens.refresh_token) is None
    store.revoke_client("c-1")
    with pytest.raises(TokenError):
        await store.exchange_refresh_token(client, refresh, [])
    fresh = store._issue("c-1", ["gm:read"], None)
    store._run("UPDATE clients SET revoked = 1 WHERE client_id = ?", ("c-1",))
    assert await store.load_access_token(fresh.access_token) is None  # its client is gone
    store.close()
