"""Real local authorities, Noise peers and guard daemons exercise runtime adapters."""

from __future__ import annotations

import asyncio
import json
import shlex
import socket
import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from genesis_mesh.crypto import generate_keypair, save_keypair, sign_model
from genesis_mesh.guard.daemon import GenesisGuardDaemon
from genesis_mesh.models import JoinCertificate
from genesis_mesh.models.context import BoundaryDecision
from genesis_mesh.models.invocation_token import InvocationToken
from genesis_mesh.models.mediation import MediatedExecutionReceipt
from genesis_mesh.transport.noise_handshake import NoiseHandshake
from genesis_mesh.transport.protocol import MeshMessage
from genesis_mesh.transport.websocket_transport import accept_websocket_with_noise
from test_authority_integration import authority as authority
from test_authority_integration import operation
from websockets.asyncio.server import serve

from genesismesh_mcp.authority import invoke
from genesismesh_mcp.runtime_config import GuardAction, NodeConfig, PeerConfig, parse_runtime_config
from genesismesh_mcp.runtime_workflows import GUARD, JOIN, SEND, STATUS, build_tools
from genesismesh_mcp.settings import Settings
from genesismesh_mcp.types import ToolError
from genesismesh_mcp.workflow_config import AuthorityConfig


def call(settings, name, arguments):
    return next(tool for tool in build_tools(settings) if tool.name == name).handler(arguments)


def node_settings(authority, tmp_path, *, generate=False):
    base, keys, paths = authority
    invite = invoke(base, operation("/admin/invite"), {"body": {"roles": ["role:client"]}})
    assert invite["http_ok"], invite
    selected = AuthorityConfig(url=base.authority_url, public_key=base.authority_public_key,
                               root_public_key=keys["root"].public_key_b64,
                               allowed_tools=frozenset({JOIN, STATUS, SEND}))
    config = NodeConfig(authority="test", state_dir=tmp_path / "state",
                        node_key_file=None if generate else paths["node"],
                        invite_token=invite["result"]["token_id"])
    return replace(base, profiles=base.profiles | {"local", "provision", "execute"},
                   authorities={"test": selected}, node_runtimes={"client": config},
                   workflow_state_dir=tmp_path / "workflows")


def test_join_persists_reuses_identity_and_reports_local_status(authority, tmp_path):
    settings = node_settings(authority, tmp_path, generate=True)
    joined = call(settings, JOIN, {"node": "client", "operation_id": "initial"})
    assert joined["complete"] and joined["enrolled"]
    assert joined["invite_consumed"] and joined["heartbeat_acknowledged"]
    assert joined["runtime_started"] is False
    state = settings.node_runtimes["client"].state_dir
    assert (state / "node.key").is_file()
    assert {"genesis.json", "key-history.json", "certificate.json", "policy.json", "node.json"} <= {
        p.name for p in state.iterdir()
    }
    # An unavailable/revoked invite is irrelevant while the held cert is valid.
    settings = replace(settings, node_runtimes={"client": replace(settings.node_runtimes["client"], invite_token=None)})
    reused = call(settings, JOIN, {"node": "client", "operation_id": "reuse"})
    assert reused["reused_certificate"] and not reused["invite_consumed"]
    assert reused["status"]["certificate_id"] == joined["status"]["certificate_id"]
    assert call(settings, JOIN, {"node": "client", "operation_id": "reuse"}) == reused
    status = call(settings, STATUS, {"node": "client"})
    assert status["local_state_available"] and status["status"]["certificate_valid"]
    assert status["probes"]["nodes"]["count"] == 1
    private_seed = (state / "node.key").read_text().splitlines()[-1]
    assert private_seed not in json.dumps(joined)
    assert private_seed not in "".join(p.read_text() for p in settings.workflow_state_dir.glob("*.json"))
    assert settings.node_runtimes["client"].invite_token is None


def test_join_requires_provision_for_new_key_and_authority_permission(authority, tmp_path):
    settings = node_settings(authority, tmp_path, generate=True)
    with pytest.raises(ToolError, match="not enabled"):
        call(replace(settings, profiles=settings.profiles - {"provision"}), JOIN,
             {"node": "client", "operation_id": "missing-permission"})
    assert not (tmp_path / "state/node.key").exists()
    config = replace(settings.authorities["test"], allowed_tools=frozenset({STATUS}))
    with pytest.raises(ToolError) as caught:
        call(replace(settings, authorities={"test": config}), JOIN, {"node": "client", "operation_id": "denied"})
    assert caught.value.code == "authority_not_authorized"


def test_join_policy_failure_keeps_certificate_and_recovers_without_invite(authority, tmp_path, monkeypatch):
    from genesismesh_mcp import runtime_workflows

    settings = node_settings(authority, tmp_path)
    original = runtime_workflows._http

    def fail_policy(selected, path, *args, **kwargs):
        if path == "/policy":
            raise ToolError("policy_offline", "Test policy failure")
        return original(selected, path, *args, **kwargs)

    monkeypatch.setattr(runtime_workflows, "_http", fail_policy)
    partial = call(settings, JOIN, {"node": "client", "operation_id": "partial"})
    assert partial["enrolled"] and not partial["complete"] and partial["certificate_persisted"]
    assert partial["error"] == "policy_offline"
    monkeypatch.setattr(runtime_workflows, "_http", original)
    settings = replace(settings, node_runtimes={"client": replace(settings.node_runtimes["client"], invite_token=None)})
    recovered = call(settings, JOIN, {"node": "client", "operation_id": "recover"})
    assert recovered["complete"] and recovered["reused_certificate"]
    assert recovered["status"]["certificate_id"] == partial["certificate_id"]


def test_wrong_root_and_wrong_local_certificate_refused(authority, tmp_path):
    settings = node_settings(authority, tmp_path)
    bad_config = replace(settings.node_runtimes["client"], root_public_key=generate_keypair().public_key_b64)
    with pytest.raises(ToolError) as caught:
        call(replace(settings, node_runtimes={"client": bad_config}), JOIN,
             {"node": "client", "operation_id": "wrong-root"})
    assert caught.value.code == "root_pin_mismatch"
    call(settings, JOIN, {"node": "client", "operation_id": "valid"})
    path = tmp_path / "state/certificate.json"
    cert = json.loads(path.read_text())
    cert["node_public_key"] = generate_keypair().public_key_b64
    path.write_text(json.dumps(cert))
    status = call(settings, STATUS, {"node": "client"})
    assert not status["local_state_available"] and status["error"] == "invalid_node_certificate"


@pytest.mark.asyncio
async def test_real_noise_send_verifies_peer_identity_and_reports_transport_only(authority, tmp_path):
    settings = node_settings(authority, tmp_path)
    await asyncio.to_thread(call, settings, JOIN, {"node": "client", "operation_id": "enroll"})
    _, keys, _ = authority
    peer_key = generate_keypair()
    now = datetime.now(timezone.utc)
    cert = JoinCertificate(cert_id="peer-cert", node_public_key=peer_key.public_key_b64, network_name="mcp-test",
                           roles=["role:client"], issued_at=now, expires_at=now + timedelta(hours=1), issued_by="test-na")
    cert.signatures.append(sign_model(cert, keys["root"].private_key, "test-na"))
    import base64
    encoded = base64.b64encode(cert.model_dump_json().encode()).decode()
    delivered = asyncio.get_running_loop().create_future()

    async def receive(websocket):
        transport, _, _ = await accept_websocket_with_noise(
            websocket, NoiseHandshake.keypair_from_join_cert_key(peer_key.private_key), encoded)
        frame = await transport.receive()
        if frame and not delivered.done():
            delivered.set_result(MeshMessage.from_bytes(frame))
        await transport.close()

    async with serve(receive, "127.0.0.1", 0) as server:
        endpoint = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        settings = replace(settings, peers={"target": PeerConfig("client", endpoint, peer_key.public_key_b64)})
        result = await asyncio.to_thread(call, settings, SEND,
                                         {"peer": "target", "operation_id": "message", "message": "hello mesh"})
        message = await asyncio.wait_for(delivered, 5)
        assert result["transport_sent"] and result["peer_identity_verified"]
        assert result["recipient_delivery_confirmed"] is False
        assert message.message_id == result["message_id"]
        assert message.recipient_id == peer_key.public_key_b64
        wrong = replace(settings, peers={"target": PeerConfig("client", endpoint, keys["node"].public_key_b64)})
        with pytest.raises(ToolError) as caught:
            await asyncio.to_thread(call, wrong, SEND,
                                    {"peer": "target", "operation_id": "wrong-peer", "message": "must not send"})
        assert caught.value.code == "peer_identity_mismatch"


@pytest.fixture
def guard(tmp_path):
    guard_key, agent_key, operator_key = (generate_keypair() for _ in range(3))
    now = datetime.now(timezone.utc)
    decision = BoundaryDecision(context_id="context", agreement_id="agreement", authorized=True,
                                decision_valid_until=now + timedelta(hours=1), operator_sovereign_id="operator")
    decision.signature = sign_model(decision, operator_key.private_key, "operator")
    token = InvocationToken(issued_at=now, expires_at=now + timedelta(hours=1), issuer_sovereign_id="operator",
                            bearer_sovereign_id="agent", agreement_id="agreement", capabilities=["python-version"],
                            max_invocations=1)
    token.signature = sign_model(token, operator_key.private_key, "operator")
    daemon = GenesisGuardDaemon("guard", guard_key.private_key, {decision.decision_id: decision},
                                {"agent": [agent_key.public_key_b64]},
                                operator_public_keys={"operator": [operator_key.public_key_b64]},
                                token_issuer_public_keys={"operator": [operator_key.public_key_b64]},
                                command_allowlist=[f"{shlex.quote(sys.executable)} --version"])
    daemon.start()
    key_path = save_keypair(agent_key, str(tmp_path / "agent"))[0]
    action = GuardAction(daemon.port, guard_key.public_key_b64, "guard", "agent", "agent", "python-version",
                         (sys.executable, "--version"), allowed_env=("SYSTEMROOT",))
    settings = Settings(profiles=frozenset({"local", "write", "execute", "sign"}),
                        workflow_state_dir=tmp_path / "operations", signer_files={"agent": key_path},
                        signer_permissions={"agent": frozenset({GUARD})}, guard_actions={"version": action})
    args = {"action": "version", "operation_id": "first", "token": token.model_dump(mode="json"),
            "decision": decision.model_dump(mode="json")}
    try:
        yield settings, args, daemon, guard_key
    finally:
        daemon.stop()


def test_real_guard_execution_receipt_and_no_repeat_on_same_operation(guard):
    settings, args, daemon, _ = guard
    result = call(settings, GUARD, args)
    assert result["accepted"] and result["execution_confirmed"] and result["receipt_signature_verified"]
    assert result["process_exit_success"] and result["receipt"]["subprocess_pid"] > 0
    assert call(settings, GUARD, args) == result
    assert daemon._token_use_counts[args["token"]["token_id"]] == 1
    denied = call(settings, GUARD, {**args, "operation_id": "second"})
    assert not denied["accepted"] and not denied["execution_confirmed"]
    assert denied["response_authenticated"] is False
    assert denied["rejection"]["reason"]


def test_guard_rejects_token_binding_and_missing_signer_permission(guard):
    settings, args, _, _ = guard
    with pytest.raises(ToolError) as caught:
        call(settings, GUARD, {**args, "token": {**args["token"], "bearer_sovereign_id": "someone-else"}})
    assert caught.value.code == "guard_binding_mismatch"
    with pytest.raises(ToolError) as caught:
        call(replace(settings, signer_permissions={}), GUARD, args)
    assert caught.value.code == "signer_not_authorized"


def test_guard_refuses_wrong_signed_receipt_binding_and_preserves_uncertainty(guard, monkeypatch):
    settings, args, daemon, key = guard
    original = daemon.handle_request

    def altered(request):
        result = original(request)
        assert isinstance(result, MediatedExecutionReceipt)
        result.request_id = "unrelated"
        result.signature = sign_model(result, key.private_key, "guard")
        return result

    monkeypatch.setattr(daemon, "handle_request", altered)
    with pytest.raises(ToolError) as caught:
        call(settings, GUARD, args)
    assert caught.value.code == "invalid_guard_receipt"
    with pytest.raises(ToolError) as caught:
        call(settings, GUARD, args)
    assert caught.value.code == "outcome_unknown"
    assert daemon._token_use_counts[args["token"]["token_id"]] == 1


def test_guard_connection_loss_does_not_retry(guard, monkeypatch):
    settings, args, _, _ = guard
    calls = []

    def fail(*_, **__):
        calls.append(True)
        raise socket.timeout

    monkeypatch.setattr(socket, "create_connection", fail)
    with pytest.raises(ToolError) as caught:
        call(settings, GUARD, args)
    assert caught.value.code == "guard_unavailable"
    with pytest.raises(ToolError) as caught:
        call(settings, GUARD, args)
    assert caught.value.code == "outcome_unknown" and len(calls) == 1


def test_guard_response_size_is_bounded_and_unknown_outcome_is_recorded(guard, monkeypatch):
    settings, args, _, _ = guard

    class OversizedResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def sendall(self, data):
            pass

        def settimeout(self, _):
            pass

        def recv(self, count):
            return b"x" * count

    monkeypatch.setattr(socket, "create_connection", lambda *_, **__: OversizedResponse())
    with pytest.raises(ToolError) as caught:
        call(replace(settings, max_output_bytes=1024), GUARD, args)
    assert caught.value.code == "guard_output_too_large"
    record = next(settings.workflow_state_dir.glob("*.json"))
    assert json.loads(record.read_text())["steps"]["guard_request"]["status"] == "unknown"


def test_runtime_tools_reject_caller_selected_network_and_command_overrides():
    from jsonschema import Draft202012Validator

    tools = {tool.name: tool for tool in build_tools(Settings())}
    assert list(Draft202012Validator(tools[SEND].input_schema).iter_errors({
        "peer": "target", "operation_id": "send", "message": "hello", "endpoint": "ws://elsewhere/",
    }))
    assert "command" not in tools[GUARD].input_schema["properties"]
    assert "signer" not in tools[GUARD].input_schema["properties"]
    assert list(Draft202012Validator(tools[JOIN].input_schema).iter_errors({
        "node": "client", "operation_id": "join", "invite_token": "caller-token",
    }))


@pytest.mark.asyncio
async def test_peer_websocket_redirect_is_refused():
    from websockets.datastructures import Headers
    from websockets.exceptions import InvalidStatus
    from websockets.http11 import Response

    from genesismesh_mcp.runtime_workflows import _NoRedirectConnect

    visits = []

    async def destination(connection):
        visits.append(True)

    async with serve(destination, "127.0.0.1", 0) as target:
        endpoint = f"ws://127.0.0.1:{target.sockets[0].getsockname()[1]}"

        def redirect(*_):
            return Response(307, "Temporary Redirect", Headers({"Location": endpoint}), b"")

        async with serve(destination, "127.0.0.1", 0, process_request=redirect) as source:
            origin = f"ws://127.0.0.1:{source.sockets[0].getsockname()[1]}"
            with pytest.raises(InvalidStatus):
                async with _NoRedirectConnect(origin, proxy=None):
                    pytest.fail("Redirect was followed")
    assert visits == []


def test_configuration_limits_and_relative_paths(tmp_path):
    key = generate_keypair().public_key_b64
    parsed = parse_runtime_config("node_runtimes", {"client": {"authority": "test", "state_dir": "node",
                                                               "node_key_file": "keys/client.key"}}, tmp_path)
    assert parsed["client"].state_dir == tmp_path / "node"
    assert parsed["client"].node_key_file == tmp_path / "keys/client.key"
    with pytest.raises(TypeError):
        parsed["other"] = parsed["client"]
    with pytest.raises(ValueError):
        GuardAction(9999, key, "guard", "agent", "agent", "read", ("command",), host="192.0.2.1")
    with pytest.raises(ValueError):
        PeerConfig("client", "ws://user:password@localhost:1234", key)
    with pytest.raises(ValueError):
        parse_runtime_config("node_runtimes", {"../escape": {"authority": "test", "state_dir": "node"}})


def test_node_state_symlink_refused(authority, tmp_path):
    settings = node_settings(authority, tmp_path)
    call(settings, JOIN, {"node": "client", "operation_id": "first"})
    target = tmp_path / "outside.json"
    target.write_text("{}")
    path = tmp_path / "state/certificate.json"
    original = path.read_bytes()
    path.unlink()
    try:
        path.symlink_to(target)
    except OSError:
        path.write_bytes(original)
        pytest.skip("Creating symlinks requires platform permission")
    with pytest.raises(ToolError) as caught:
        call(settings, JOIN, {"node": "client", "operation_id": "unsafe"})
    assert caught.value.code == "unsafe_node_state"
