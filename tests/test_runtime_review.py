"""Independent runtime review regressions against real authorities and daemons."""

from __future__ import annotations

import asyncio
import base64
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from genesis_mesh.crypto import generate_keypair, sign_model
from genesis_mesh.models import JoinCertificate
from genesis_mesh.transport.noise_handshake import NoiseHandshake
from genesis_mesh.transport.websocket_transport import accept_websocket_with_noise
from test_authority_integration import authority as authority
from test_authority_integration import operation
from test_runtime_workflows import call, node_settings
from test_runtime_workflows import guard as guard
from websockets.asyncio.server import serve

from genesismesh_mcp.authority import invoke
from genesismesh_mcp.runtime_config import PeerConfig
from genesismesh_mcp.runtime_workflows import GUARD, JOIN, SEND, STATUS
from genesismesh_mcp.types import ToolError


def test_status_reports_current_revocation_and_held_policy(authority, tmp_path):
    settings = node_settings(authority, tmp_path)
    joined = call(settings, JOIN, {"node": "client", "operation_id": "join"})
    status = call(settings, STATUS, {"node": "client"})
    initial_policy_id = status["status"]["policy_id"]
    base, _, _ = authority
    revoked = invoke(base, operation("/admin/revoke"), {
        "body": {"cert_id": joined["status"]["certificate_id"]}})
    assert revoked["http_ok"], revoked
    status = call(settings, STATUS, {"node": "client"})
    assert status["local_state_available"]
    assert status["status"]["certificate_valid"] is False
    assert status["status"]["certificate_revoked"] is True
    assert status["status"]["revocation_checked"] is True
    assert initial_policy_id == joined["status"]["policy_id"]


def test_status_refuses_an_expired_held_certificate(authority, tmp_path):
    settings = node_settings(authority, tmp_path)
    call(settings, JOIN, {"node": "client", "operation_id": "join"})
    _, keys, _ = authority
    path = tmp_path / "state/certificate.json"
    cert = JoinCertificate.model_validate_json(path.read_text())
    now = datetime.now(timezone.utc)
    cert.issued_at = now - timedelta(hours=2)
    cert.expires_at = now - timedelta(hours=1)
    cert.signatures = [sign_model(cert, keys["root"].private_key, "test-na")]
    path.write_text(cert.model_dump_json())
    status = call(settings, STATUS, {"node": "client"})
    assert status["local_state_available"] is False
    assert status["error"] == "invalid_node_certificate"


def test_enrollment_response_survives_certificate_file_failure(authority, tmp_path, monkeypatch):
    from genesismesh_mcp import runtime_workflows

    settings = node_settings(authority, tmp_path)
    original_write, original_http = runtime_workflows._write_state, runtime_workflows._http
    join_calls = []
    failed = []

    def counting_http(selected, path, *args, **kwargs):
        if path == "/join":
            join_calls.append(path)
        return original_http(selected, path, *args, **kwargs)

    def fail_once(selected, config, name, value):
        if name == "certificate.json" and not failed:
            failed.append(True)
            raise OSError("simulated disk failure")
        return original_write(selected, config, name, value)

    monkeypatch.setattr(runtime_workflows, "_http", counting_http)
    monkeypatch.setattr(runtime_workflows, "_write_state", fail_once)
    args = {"node": "client", "operation_id": "disk-recovery"}
    partial = call(settings, JOIN, args)
    assert partial["enrolled"] and not partial["complete"] and not partial["certificate_persisted"]
    recovered = call(settings, JOIN, args)
    assert recovered["complete"] and recovered["state_persisted"]
    assert recovered["status"]["certificate_id"] == partial["certificate_id"]
    assert len(join_calls) == 1


def test_status_will_not_report_validity_from_an_expired_crl(authority, tmp_path, monkeypatch):
    from genesis_mesh.models.revocation import CertificateRevocationList

    from genesismesh_mcp import runtime_workflows

    settings = node_settings(authority, tmp_path)
    call(settings, JOIN, {"node": "client", "operation_id": "join"})
    _, keys, _ = authority
    original = runtime_workflows._http

    def old_crl(selected, path, *args, **kwargs):
        value = original(selected, path, *args, **kwargs)
        if path == "/crl":
            crl = CertificateRevocationList.model_validate(value)
            now = datetime.now(timezone.utc)
            crl.issued_at = now - timedelta(hours=2)
            crl.next_update = now - timedelta(hours=1)
            crl.signatures = [sign_model(crl, keys["root"].private_key, "test-na")]
            return crl.model_dump(mode="json")
        return value

    monkeypatch.setattr(runtime_workflows, "_http", old_crl)
    result = call(settings, STATUS, {"node": "client"})
    assert result["local_state_available"] is False and result["error"] == "invalid_crl"


def test_send_holds_verified_key_history_and_refuses_later_rollback(authority, tmp_path, monkeypatch):
    from genesis_mesh.models.key_succession import KeySuccessionRecord
    from genesis_mesh.trust.key_succession import sign_succession

    from genesismesh_mcp import runtime_workflows

    settings = node_settings(authority, tmp_path)
    call(settings, JOIN, {"node": "client", "operation_id": "join"})
    _, keys, _ = authority
    new_key = generate_keypair()
    now = datetime.now(timezone.utc)
    succession = KeySuccessionRecord(sovereign_id="mcp-test", key_sequence=2, previous_key_id="test-na",
        previous_public_key=keys["root"].public_key_b64, new_key_id="next-na", new_public_key=new_key.public_key_b64,
        issued_at=now, effective_at=now + timedelta(minutes=10), new_valid_to=now + timedelta(days=1))
    succession = sign_succession(succession, keys["root"].private_key, "root")
    succession = sign_succession(succession, new_key.private_key, "next-na")
    offered = [succession.to_wire()]
    original = runtime_workflows._http

    def history_view(selected, path, *args, **kwargs):
        value = original(selected, path, *args, **kwargs)
        if path == "/na/key-history":
            value["successions"] = offered[:]
        return value

    def unavailable_peer(*_args, **_kwargs):
        raise OSError("test transport unavailable after history verification")

    monkeypatch.setattr(runtime_workflows, "_http", history_view)
    monkeypatch.setattr(runtime_workflows, "_NoRedirectConnect", unavailable_peer)
    settings = replace(settings, peers={"target": PeerConfig("client", "ws://127.0.0.1:9999", keys["node"].public_key_b64)})
    with pytest.raises(ToolError) as caught:
        call(settings, SEND, {"peer": "target", "operation_id": "send", "message": "message"})
    assert caught.value.code == "peer_send_failed"
    cached = json.loads((tmp_path / "state/key-history.json").read_text())
    assert len(cached["successions"]) == 1
    offered.clear()
    status = call(settings, STATUS, {"node": "client"})
    assert status["local_state_available"] is False and status["error"] == "invalid_authority_history"


@pytest.mark.parametrize("mutation", ["signature", "capability", "missing_decision"])
def test_guard_rejects_unauthorized_material_without_execution(guard, mutation):
    settings, args, daemon, _ = guard
    args = json.loads(json.dumps(args))
    if mutation == "signature":
        args["token"]["signature"]["sig"] = "invalid"
    elif mutation == "capability":
        args["token"]["capabilities"] = ["not-the-configured-action"]
    else:
        args["decision"]["decision_id"] = "decision-not-present-at-guard"
    result = call(settings, GUARD, args)
    assert result["accepted"] is False and result["execution_confirmed"] is False
    assert daemon._token_use_counts.get(args["token"]["token_id"], 0) == 0


@pytest.mark.asyncio
async def test_peer_certificate_must_bind_noise_static_identity(authority, tmp_path):
    settings = node_settings(authority, tmp_path)
    await asyncio.to_thread(call, settings, JOIN, {"node": "client", "operation_id": "join"})
    _, keys, _ = authority
    certified_key, handshake_key = generate_keypair(), generate_keypair()
    now = datetime.now(timezone.utc)
    cert = JoinCertificate(cert_id="peer-cert", node_public_key=certified_key.public_key_b64,
                           network_name="mcp-test", roles=["role:client"], issued_at=now,
                           expires_at=now + timedelta(hours=1), issued_by="test-na")
    cert.signatures.append(sign_model(cert, keys["root"].private_key, "test-na"))
    encoded = base64.b64encode(cert.model_dump_json().encode()).decode()
    frames = []

    async def receive(websocket):
        transport, _, _ = await accept_websocket_with_noise(websocket,
            NoiseHandshake.keypair_from_join_cert_key(handshake_key.private_key), encoded)
        try:
            frame = await transport.receive()
            if frame:
                frames.append(frame)
        finally:
            await transport.close()

    async with serve(receive, "127.0.0.1", 0) as server:
        endpoint = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        settings = replace(settings, peers={"target": PeerConfig("client", endpoint, certified_key.public_key_b64)})
        with pytest.raises(ToolError) as caught:
            await asyncio.to_thread(call, settings, SEND, {"peer": "target", "operation_id": "bad-static", "message": "must not send"})
        assert caught.value.code == "peer_send_failed"
        assert not frames
