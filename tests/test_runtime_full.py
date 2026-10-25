"""Adversarial configured runtime inputs and persisted node/guard state."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from datetime import datetime, timezone

import pytest
from genesis_mesh.crypto import generate_keypair
from genesis_mesh.models.mediation import MediationRejection
from test_authority_integration import authority as authority
from test_authority_integration import operation
from test_runtime_workflows import call, node_settings
from test_runtime_workflows import guard as guard

from genesismesh_mcp import runtime_workflows as runtime
from genesismesh_mcp.authority import invoke
from genesismesh_mcp.runtime_config import GuardAction, NodeConfig, PeerConfig, parse_runtime_config
from genesismesh_mcp.runtime_workflows import GUARD, JOIN, SEND, STATUS
from genesismesh_mcp.settings import Settings
from genesismesh_mcp.types import ToolError


@pytest.mark.parametrize("pin", ["!", "AA==", 0])
def test_runtime_pins_require_exact_ed25519_public_keys(tmp_path, pin):
    with pytest.raises(ValueError, match="Ed25519"):
        NodeConfig("authority", tmp_path, root_public_key=pin)


@pytest.mark.parametrize("invite", ["", 7, "x" * 4097])
def test_node_invites_are_bounded_and_not_represented(tmp_path, invite):
    with pytest.raises(ValueError, match="invite_token"):
        NodeConfig("authority", tmp_path, invite_token=invite)
    assert "secret" not in repr(NodeConfig("authority", tmp_path, invite_token="secret"))


@pytest.mark.parametrize("url", ["ws://localhost:70000", "ws://localhost:notaport", "https://localhost",
                                  "ws://localhost/?x=y", "ws://localhost/#fragment", "ws://localhost/ white"])
def test_peer_destinations_refuse_ambiguous_or_non_websocket_urls(url):
    with pytest.raises(ValueError):
        PeerConfig("node", url, generate_keypair().public_key_b64)


@pytest.mark.parametrize("changes", [
    {"host": "localhost"}, {"port": True}, {"guard_sovereign_id": ""}, {"agent_sovereign_id": "a\n"},
    {"capability": 3}, {"command": "shell command"}, {"command": ()}, {"command": ("bad\0arg",)},
    {"allowed_env": "PATH"}, {"allowed_env": ("BAD=VALUE",)}, {"signer": "../key"},
])
def test_guard_configuration_refuses_unbounded_or_ambiguous_actions(changes):
    values = {"port": 9000, "guard_public_key": generate_keypair().public_key_b64,
              "guard_sovereign_id": "guard", "agent_sovereign_id": "agent", "signer": "signer",
              "capability": "capability", "command": ("fixed-command",)}
    with pytest.raises(ValueError):
        GuardAction(**{**values, **changes})


@pytest.mark.parametrize("value", [[], {str(i): {} for i in range(65)}, {"node": None},
                                    {"node": {"unexpected": 1}}, {"node": {"authority": "test"}}])
def test_runtime_registry_refuses_missing_unknown_and_excess_entries(value):
    with pytest.raises(ValueError):
        parse_runtime_config("node_runtimes", value)


def test_runtime_registries_accept_named_peer_guard_and_pathless_node_identity(tmp_path):
    key = generate_keypair().public_key_b64
    peers = parse_runtime_config("peers", {"peer": {"node": "client", "endpoint": "wss://peer.example",
                                                    "peer_public_key": key, "recipient_public_key": key}})
    assert peers["peer"].recipient_public_key == key
    guards = parse_runtime_config("guard_actions", {"action": {"port": 1, "guard_public_key": key,
        "guard_sovereign_id": "guard", "agent_sovereign_id": "agent", "signer": "signer", "capability": "read",
        "command": ["fixed"], "allowed_env": ["PATH"]}})
    assert guards["action"].command == ("fixed",)
    nodes = parse_runtime_config("node_runtimes", {"node": {"authority": "a", "state_dir": "state"}}, tmp_path)
    assert nodes["node"].node_key_file is None
    assert parse_runtime_config("peers", peers)["peer"] is peers["peer"]


@pytest.mark.parametrize("name,args,code", [
    (JOIN, {"node": "absent", "operation_id": "unknown"}, "node_not_configured"),
    (STATUS, {"node": "absent"}, "node_not_configured"),
    (SEND, {"peer": "absent", "operation_id": "unknown", "message": "test"}, "peer_not_configured"),
])
def test_runtime_handlers_refuse_unknown_named_resources(name, args, code):
    settings = Settings(profiles={"read", "node", "local", "write", "execute"})
    with pytest.raises(ToolError) as exc:
        call(settings, name, args)
    assert exc.value.code == code


def test_guard_handler_refuses_unknown_action_before_using_token(guard):
    settings, args, _, _ = guard
    with pytest.raises(ToolError) as exc:
        call(settings, GUARD, {**args, "action": "absent"})
    assert exc.value.code == "guard_action_not_configured"


def test_status_before_join_and_without_held_certificate(authority, tmp_path):
    settings = node_settings(authority, tmp_path)
    before = call(settings, STATUS, {"node": "client"})
    assert not before["local_state_available"] and before["error"] == "node_not_joined"
    assert call(settings, JOIN, {"node": "client", "operation_id": "join"})["complete"]
    state = settings.node_runtimes["client"].state_dir
    (state / "certificate.json").unlink()
    (state / "policy.json").unlink()
    without = call(settings, STATUS, {"node": "client"})
    assert without["local_state_available"]
    assert without["status"]["certificate_revoked"] is None
    assert without["status"]["revocation_checked"] is False


@pytest.mark.parametrize("fault,expected", [("too_large", "node_state_too_large"),
    ("policy", "invalid_node_policy"), ("history", "invalid_node_key_history"), ("json", "invalid_node_state")])
def test_status_refuses_corrupted_held_material(authority, tmp_path, fault, expected):
    settings = node_settings(authority, tmp_path)
    assert call(settings, JOIN, {"node": "client", "operation_id": "join"})["complete"]
    state = settings.node_runtimes["client"].state_dir
    if fault == "too_large":
        (state / "genesis.json").write_bytes(b"x" * (settings.max_output_bytes + 1))
    elif fault == "json":
        (state / "genesis.json").write_text("{not-json}")
    elif fault == "history":
        (state / "key-history.json").write_text(json.dumps({"successions": [{}]}))
    else:
        policy = json.loads((state / "policy.json").read_text())
        policy["signatures"] = []
        (state / "policy.json").write_text(json.dumps(policy))
    result = call(settings, STATUS, {"node": "client"})
    assert not result["local_state_available"] and result["error"] == expected, result


def test_status_preserves_probe_failures_without_masking_local_identity(authority, tmp_path, monkeypatch):
    settings = node_settings(authority, tmp_path)
    call(settings, JOIN, {"node": "client", "operation_id": "join"})
    original = runtime._http
    def refused(selected, path, *args, **kwargs):
        if path == "/readyz":
            raise ToolError("maintenance", "Authority not ready")
        return original(selected, path, *args, **kwargs)
    monkeypatch.setattr(runtime, "_http", refused)
    result = call(settings, STATUS, {"node": "client"})
    assert result["local_state_available"] and result["probes"]["readyz"]["error"] == "maintenance"


@pytest.mark.parametrize("fault,expected", [("missing", "node_identity_missing"), ("invalid", "node_identity_unavailable"),
                                             ("unmanaged", "node_storage_unmanaged")])
def test_join_refuses_unavailable_or_unmanaged_identity(authority, tmp_path, fault, expected):
    settings = node_settings(authority, tmp_path, generate=fault == "unmanaged")
    config = settings.node_runtimes["client"]
    if fault == "unmanaged":
        config.state_dir.mkdir()
    else:
        key = tmp_path / "bad.key"
        if fault == "invalid":
            key.write_text("invalid key")
        settings = replace(settings, node_runtimes={"client": replace(config, node_key_file=key)})
    with pytest.raises(ToolError) as exc:
        call(settings, JOIN, {"node": "client", "operation_id": "refuse"})
    assert exc.value.code == expected


def test_join_invalid_held_certificate_requires_a_fresh_invite(authority, tmp_path):
    settings = node_settings(authority, tmp_path)
    call(settings, JOIN, {"node": "client", "operation_id": "join"})
    config = settings.node_runtimes["client"]
    path = config.state_dir / "certificate.json"
    cert = json.loads(path.read_text())
    cert["signatures"] = []
    path.write_text(json.dumps(cert))
    settings = replace(settings, node_runtimes={"client": replace(config, invite_token=None)})
    with pytest.raises(ToolError) as exc:
        call(settings, JOIN, {"node": "client", "operation_id": "rejoin"})
    assert exc.value.code == "invite_required"


@pytest.mark.parametrize("fault,expected", [("history", "invalid_authority_history"),
    ("policy", "invalid_node_policy"), ("heartbeat", "heartbeat_refused")])
def test_join_refuses_unverified_or_unacknowledged_authority_material(authority, tmp_path, monkeypatch, fault, expected):
    settings = node_settings(authority, tmp_path)
    original = runtime._http
    def altered(selected, path, *args, **kwargs):
        data = original(selected, path, *args, **kwargs)
        if fault == "history" and path == "/na/key-history":
            return {"successions": "invalid"}
        if fault == "policy" and path == "/policy":
            data["signatures"] = []
        if fault == "heartbeat" and path == "/heartbeat":
            data["ack"] = False
        return data
    monkeypatch.setattr(runtime, "_http", altered)
    if fault == "history":
        with pytest.raises(ToolError) as exc:
            call(settings, JOIN, {"node": "client", "operation_id": "join"})
        assert exc.value.code == expected
    else:
        result = call(settings, JOIN, {"node": "client", "operation_id": "join"})
        assert result["enrolled"] and not result["complete"] and result["error"] == expected


def test_node_lock_rejects_concurrent_mutation_and_releases_after_failure(authority, tmp_path):
    settings = node_settings(authority, tmp_path)
    config = settings.node_runtimes["client"]
    with runtime._locked_node(config):
        with pytest.raises(ToolError) as exc:
            call(settings, JOIN, {"node": "client", "operation_id": "busy"})
        assert exc.value.code == "node_busy"
    assert call(settings, JOIN, {"node": "client", "operation_id": "busy"})["complete"]


def test_peer_refuses_oversized_message_before_network(authority, tmp_path):
    settings = node_settings(authority, tmp_path)
    settings = replace(settings, max_input_bytes=1024, peers={"peer": PeerConfig(
        "client", "ws://127.0.0.1:1", generate_keypair().public_key_b64)})
    with pytest.raises(ToolError) as exc:
        call(settings, SEND, {"peer": "peer", "operation_id": "large", "message": "é" * 513})
    assert exc.value.code == "message_too_large"


@pytest.mark.parametrize("fault,expected", [("missing", "node_not_joined"), ("revoked", "node_revoked"),
                                             ("crl", "invalid_crl"), ("transport", "peer_send_failed")])
def test_peer_send_refuses_missing_revoked_or_unverifiable_node(authority, tmp_path, monkeypatch, fault, expected):
    settings = node_settings(authority, tmp_path)
    joined = call(settings, JOIN, {"node": "client", "operation_id": "join"})
    settings = replace(settings, peers={"peer": PeerConfig("client", "ws://127.0.0.1:1", generate_keypair().public_key_b64)})
    if fault == "missing":
        (settings.node_runtimes["client"].state_dir / "certificate.json").unlink()
    elif fault == "revoked":
        assert invoke(authority[0], operation("/admin/revoke"), {
            "body": {"cert_id": joined["status"]["certificate_id"]}})["http_ok"]
    elif fault == "crl":
        original = runtime._http
        def unsigned(selected, path, *args, **kwargs):
            result = original(selected, path, *args, **kwargs)
            if path == "/crl":
                result["signatures"] = []
            return result
        monkeypatch.setattr(runtime, "_http", unsigned)
    with pytest.raises(ToolError) as exc:
        call(settings, SEND, {"peer": "peer", "operation_id": "send", "message": "never delivered"})
    assert exc.value.code == expected
    with pytest.raises(ToolError) as exc:
        call(settings, SEND, {"peer": "peer", "operation_id": "send", "message": "never delivered"})
    assert exc.value.code == "outcome_unknown"


def test_guard_refuses_request_over_protocol_limit_before_connecting(guard):
    settings, args, daemon, _ = guard
    action = settings.guard_actions["version"]
    settings = replace(settings, max_input_bytes=1024, guard_actions={
        "version": replace(action, command=(*action.command, "x" * 2048))})
    with pytest.raises(ToolError) as exc:
        call(settings, GUARD, args)
    assert exc.value.code == "guard_request_too_large"
    assert daemon._token_use_counts == {}


def test_guard_refuses_a_rejection_for_another_request(guard, monkeypatch):
    settings, args, daemon, _ = guard
    def mismatch(_request):
        return MediationRejection(request_id="another-request", agent_sovereign_id="agent",
                                  rejected_at=datetime.now(timezone.utc), reason="denied")
    monkeypatch.setattr(daemon, "handle_request", mismatch)
    with pytest.raises(ToolError) as exc:
        call(settings, GUARD, args)
    assert exc.value.code == "guard_response_mismatch"


def test_guard_read_deadline_retains_unknown_outcome(guard, monkeypatch):
    settings, args, _, _ = guard
    clock = iter([0, settings.timeout_seconds + 1])
    monkeypatch.setattr(runtime, "monotonic", lambda: next(clock))
    with pytest.raises(ToolError) as exc:
        call(settings, GUARD, args)
    assert exc.value.code == "guard_unavailable"
    record = next(settings.workflow_state_dir.glob("*.json"))
    assert json.loads(record.read_text())["steps"]["guard_request"]["status"] == "unknown"


def test_noop_broadcast_completes_without_side_effects():
    assert asyncio.run(runtime._noop_broadcast("unused")) is None
