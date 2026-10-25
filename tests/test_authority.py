"""Wire-level coverage for every registered authority operation and refusal paths."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote, urlsplit

import pytest
import requests
from genesis_mesh.crypto import generate_keypair, save_keypair, verify_model_signature, verify_signature
from genesis_mesh.crypto.admin_auth import admin_signing_payload
from genesis_mesh.crypto.node_auth import executor_proof_payload, node_signing_payload
from genesis_mesh.models import AgentDescriptor
from jsonschema import Draft202012Validator

from genesismesh_mcp.authority import _request_parts, build_tools, input_schema, invoke, operations
from genesismesh_mcp.settings import Settings
from genesismesh_mcp.types import ToolError


@pytest.fixture
def identities(tmp_path):
    keys = {name: generate_keypair() for name in ("operator", "node", "executor", "authority")}
    paths = {name: save_keypair(pair, str(tmp_path / name))[0] for name, pair in keys.items()}
    settings = Settings(authority_url="http://127.0.0.1:9443", allow_http_loopback=True,
                        profiles=frozenset({"read", "verify", "operator", "node", "write"}),
                        operator_key_file=paths["operator"], operator_key_id="test-operator",
                        node_key_file=paths["node"], executor_key_file=paths["executor"],
                        authority_public_key=keys["authority"].public_key_b64,
                        invite_token="test-ephemeral-enrollment-token")
    return settings, keys


class Response:
    def __init__(self, result=None, *, status=200, raw=None, headers=None):
        self.status_code = status
        self.headers = headers or {}
        self.raw = raw if raw is not None else json.dumps(result if result is not None else {"authorized": False}).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def iter_content(self, chunk_size):
        for offset in range(0, len(self.raw), chunk_size):
            yield self.raw[offset:offset + chunk_size]


@pytest.fixture
def transport(monkeypatch):
    calls = []
    response = [Response()]

    class Session:
        trust_env = True

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def mount(self, prefix, adapter):
            assert adapter.max_retries.total == 0

        def request(self, method, url, **kwargs):
            assert self.trust_env is False
            assert kwargs["allow_redirects"] is False
            assert kwargs["stream"] is True
            calls.append((method, url, kwargs))
            if isinstance(response[0], Exception):
                raise response[0]
            return response[0]

    monkeypatch.setattr(requests, "Session", Session)
    return calls, response


def example(schema):
    if "const" in schema:
        return schema["const"]
    if "enum" in schema:
        return schema["enum"][0]
    if "anyOf" in schema:
        return example(schema["anyOf"][0])
    kind = schema.get("type")
    if kind == "object" or "properties" in schema:
        fields = set(schema.get("required", []))
        if "oneOf" in schema:
            # The attestation basis is smaller than an agreement; acceptance's
            # first branch contains an offer rather than counter plus offer.
            branch = schema["oneOf"][-1] if "attestation_id" in schema.get("properties", {}) else schema["oneOf"][0]
            fields.update(branch.get("required", []))
        value = {name: example(schema["properties"][name]) for name in fields}
        if "allOf" in schema and "from" in schema.get("properties", {}):
            value.update({"from": "one", "to": "two"})
        return value
    if kind == "array":
        return [example(schema.get("items", {})) for _ in range(schema.get("minItems", 0))]
    if kind in {"integer", "number"}:
        return max(schema.get("minimum", 0), schema.get("exclusiveMinimum", -1) + 1)
    if kind == "boolean":
        return False
    if kind == "null":
        return None
    if kind == "string":
        if schema.get("format") == "date-time":
            return (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        return "a" * max(schema.get("minLength", 1), 1)
    return None


def by_path(path, method="POST"):
    return next(op for op in operations() if op["path"] == path and op["method"] == method)


def test_registry_has_every_public_operation_and_private_roster():
    registered = operations()
    assert len(registered) == 118
    assert len({(op["method"], op["path"]) for op in registered}) == 116
    assert len({op["name"] for op in registered}) == 118
    for op in registered:
        Draft202012Validator.check_schema(input_schema(op))
        assert op["source"].startswith("genesis_mesh/na_service/routes/")
        assert op["auth"] in {"public", "operator", "node", "agent_descriptor", "agent_delete", "signed_record"}


@pytest.mark.parametrize("operation", operations(), ids=lambda op: op["name"])
def test_every_operation_dispatches_once_with_its_declared_auth(operation, identities, transport):
    settings, keys = identities
    calls, response = transport
    args = example(input_schema(operation))
    # Agent descriptors perform additional model validation while being signed.
    if operation["auth"] == "agent_descriptor":
        args["body"]["endpoint"] = {"host": "127.0.0.1", "port": 443, "scheme": "wss"}
    result = invoke(settings, operation, args)
    assert result["http_status"] == 200
    assert len(calls) == 1
    method, url, kwargs = calls[0]
    assert method == operation["method"]
    assert url.startswith(settings.authority_url + "/")
    headers = kwargs["headers"]
    body = json.loads(kwargs["data"]) if kwargs["data"] else {}
    if operation["auth"] == "operator":
        payload = admin_signing_payload(method=method, path=unquote(urlsplit(url).path),
                                        audience=settings.authority_public_key, body=body,
                                        query=args.get("query", {}), key_id=settings.operator_key_id,
                                        timestamp=headers["X-Admin-Timestamp"], nonce=headers["X-Admin-Nonce"])
        assert verify_signature(payload, headers["X-Admin-Signature"], keys["operator"].public_key_b64)
    else:
        assert not any(key.startswith("X-Admin-") for key in headers)
    if operation["auth"] == "node":
        assert verify_signature(node_signing_payload(body), body["signature"], keys["node"].public_key_b64)
        assert body["node_public_key"] == keys["node"].public_key_b64
    if operation["response"] == "json":
        assert result["result"] == {"authorized": False}


def test_unsigned_count_and_signed_roster_are_separate(identities, transport):
    settings, _ = identities
    calls, _ = transport
    tools = {tool.name: tool for tool in build_tools(settings)}
    tools["na_health_list_nodes"].handler({})
    tools["na_nodes_roster"].handler({})
    assert "X-Admin-Signature" not in calls[0][2]["headers"]
    assert "X-Admin-Signature" in calls[1][2]["headers"]
    default_tools = {tool.name: tool for tool in build_tools(Settings())}
    with pytest.raises(ToolError, match="not enabled"):
        default_tools["na_nodes_roster"].handler({})


def test_query_unicode_and_resource_path_sign_exact_decoded_request(identities, transport):
    settings, keys = identities
    calls, _ = transport
    operation = by_path("/admin/evidence/changes/<path:resource_id>", "GET")
    invoke(settings, operation, {"path": {"resource_id": "kv:vault/café?version#1"}, "query": {"after_sequence": 2, "limit": 3}})
    _, url, kwargs = calls[0]
    assert "/kv%3Avault%2Fcaf%C3%A9%3Fversion%231?after_sequence=2&limit=3" in url
    headers = kwargs["headers"]
    payload = admin_signing_payload(method="GET", path="/admin/evidence/changes/kv:vault/café?version#1",
                                    query={"after_sequence": 2, "limit": 3}, body={}, audience=settings.authority_public_key,
                                    key_id=settings.operator_key_id, timestamp=headers["X-Admin-Timestamp"], nonce=headers["X-Admin-Nonce"])
    assert verify_signature(payload, headers["X-Admin-Signature"], keys["operator"].public_key_b64)


@pytest.mark.parametrize("identifier", ["..", "a/../b", "%2e%2e", "a\\b", "a\x00b"])
def test_ambiguous_paths_are_refused_before_network(identifier, identities, transport):
    settings, _ = identities
    calls, _ = transport
    with pytest.raises(ToolError):
        invoke(settings, by_path("/admin/evidence/changes/<path:resource_id>", "GET"), {"path": {"resource_id": identifier}})
    assert calls == []


def test_node_scoped_audience_nonce_and_edge_cosignature(identities, transport):
    settings, keys = identities
    calls, _ = transport
    invoke(settings, by_path("/node/state"), {"body": {"cert_id": "cert"}})
    invoke(settings, by_path("/node/state"), {"body": {"cert_id": "cert"}})
    first, second = (json.loads(call[2]["data"]) for call in calls)
    assert first["audience"] == settings.authority_public_key
    assert first["purpose"] == "node_state"
    assert first["nonce"] != second["nonce"]
    invoke(settings, by_path("/join"), {"body": {"edge": True, "agent_version": "test"}})
    joined = json.loads(calls[-1][2]["data"])
    assert joined["invite_token"] == settings.invite_token
    assert "edge" not in joined
    assert verify_signature(executor_proof_payload(joined), joined["executor_signature"], keys["executor"].public_key_b64)
    assert verify_signature(node_signing_payload(joined), joined["signature"], keys["node"].public_key_b64)


def test_agent_descriptor_and_delete_have_distinct_signatures(identities, transport):
    settings, keys = identities
    calls, _ = transport
    invoke(settings, by_path("/agents"), {"body": {"agent_id": "example", "network_name": "demo", "capabilities": ["read"],
                                                  "endpoint": {"host": "127.0.0.1", "port": 443},
                                                  "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()}})
    descriptor = AgentDescriptor.model_validate_json(calls[0][2]["data"])
    assert verify_model_signature(descriptor, descriptor.signatures[0], keys["node"].public_key_b64)
    invoke(settings, by_path("/agents/<path:node_public_key>", "DELETE"), {})
    body = json.loads(calls[1][2]["data"])
    payload = f"delete-agent|v1|{keys['node'].public_key_b64}|{body['signed_at']}".encode()
    assert verify_signature(payload, body["signature"], keys["node"].public_key_b64)
    assert unquote(urlsplit(calls[1][1]).path) == "/agents/" + keys["node"].public_key_b64


@pytest.mark.parametrize("operation", operations(), ids=lambda op: op["name"])
def test_direct_handler_enforces_every_required_profile(operation, identities, transport):
    settings, _ = identities
    calls, _ = transport
    with pytest.raises(ToolError) as error:
        invoke(replace(settings, profiles=frozenset()), operation, {})
    assert error.value.code == "profile_required"
    assert calls == []


@pytest.mark.parametrize("response,error_code", [
    (Response(status=302), "authority_redirect_refused"),
    (Response(raw=b"x" * 1200), "output_too_large"),
    (Response(headers={"Content-Length": "999999"}), "output_too_large"),
    (Response(raw=b'{"a":1,"a":2}'), "invalid_authority_response"),
    (Response(raw=b"not-json"), "invalid_authority_response"),
    (Response(result={"echo": "test-ephemeral-enrollment-token"}), "sensitive_authority_response"),
])
def test_bounded_and_private_responses(response, error_code, identities, transport):
    settings, _ = identities
    _, response_slot = transport
    response_slot[0] = response
    with pytest.raises(ToolError) as error:
        invoke(replace(settings, max_output_bytes=1024), by_path("/health", "GET"), {})
    assert error.value.code == error_code


def test_error_and_denial_bodies_preserved_without_retry(identities, transport):
    settings, _ = identities
    calls, response_slot = transport
    expected = {"error": {"code": "evidence_store_unavailable", "message": "Unavailable", "details": {}}}
    response_slot[0] = Response(expected, status=503)
    result = invoke(settings, by_path("/admin/na/reissue"), {})
    assert result == {"http_status": 503, "http_ok": False, "response_format": "json", "result": expected}
    assert len(calls) == 1
    response_slot[0] = requests.ConnectionError("Sensitive transport internals")
    with pytest.raises(ToolError) as error:
        invoke(settings, by_path("/admin/na/reissue"), {})
    assert error.value.code == "authority_unavailable"
    assert "Sensitive" not in str(error.value)
    assert len(calls) == 2


def test_schema_and_identity_override_rejected(identities, transport):
    settings, _ = identities
    calls, _ = transport
    for arguments in ({"authority_url": "https://elsewhere.invalid"}, {"headers": {"X-Admin-Key-Id": "other"}},
                      {"body": {"cert_id": "cert", "node_public_key": "other"}}):
        with pytest.raises(ToolError):
            invoke(settings, by_path("/node/state"), arguments)
    with pytest.raises(ToolError) as error:
        invoke(replace(settings, node_key_file=None), by_path("/node/state"), {"body": {"cert_id": "cert"}})
    assert error.value.code == "identity_not_configured"
    assert calls == []


def test_streamed_elapsed_deadline_refuses_slow_trickle(monkeypatch, identities, transport):
    import genesismesh_mcp.authority as adapter
    settings, _ = identities
    calls, response_slot = transport
    class SlowResponse(Response):
        def iter_content(self, chunk_size):
            yield b'{"value":'
            yield b'1}'
    response_slot[0] = SlowResponse()
    elapsed = iter([0.0, 0.0, 1.0, settings.timeout_seconds + 1])
    monkeypatch.setattr(adapter, "monotonic", lambda: next(elapsed))
    with pytest.raises(ToolError) as error:
        invoke(settings, by_path("/health", "GET"), {})
    assert error.value.code == "authority_response_deadline"
    assert len(calls) == 1


def test_signed_payload_not_normalized(identities, transport):
    settings, _ = identities
    # Serialization preserves exactly the caller's record shape; no Pydantic
    # model_dump adds defaults or changes numeric/time representations.
    operation = by_path("/admin/agreements/accept")
    body = {"offer": {"deliberately": "invalid signed record", "optional_omitted": None}}
    _, _, raw = _request_parts(settings, operation, {"body": body})
    assert json.loads(raw) == body
