"""Disposable real HTTP authority tests; no production endpoint or credentials."""

from __future__ import annotations

import threading
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from genesis_mesh.audit import logger as audit_logger
from genesis_mesh.crypto import generate_keypair, save_keypair, sign_model
from genesis_mesh.models import GenesisBlock, NetworkAuthority, PolicyManifestRef
from genesis_mesh.na_service.server import NetworkAuthorityService
from werkzeug.serving import make_server

from genesismesh_mcp.authority import invoke, operations
from genesismesh_mcp.settings import Settings


def operation(path, method="POST", name=None):
    return next(op for op in operations() if op["path"] == path and op["method"] == method
                and (name is None or op["name"] == name))


@pytest.fixture
def authority(tmp_path, monkeypatch):
    monkeypatch.setattr(audit_logger, "DEFAULT_AUDIT_DIR", tmp_path / "audit")
    keys = {name: generate_keypair() for name in ("root", "operator", "reader", "node", "executor")}
    paths = {name: save_keypair(pair, str(tmp_path / name))[0] for name, pair in keys.items()}
    now = datetime.now(timezone.utc)
    genesis = GenesisBlock(network_name="mcp-test", network_version="1.8.1", root_public_key=keys["root"].public_key_b64,
                           network_authority=NetworkAuthority(public_key=keys["root"].public_key_b64,
                                                              valid_from=now, valid_to=now + timedelta(days=1)),
                           policy_manifest=PolicyManifestRef(hash="sha256:test", url=None))
    genesis.signatures.append(sign_model(genesis, keys["root"].private_key, "root"))
    service = NetworkAuthorityService(genesis_block=genesis, na_private_key=keys["root"].private_key, key_id="test-na",
                                      db_path=str(tmp_path / "authority.db"),
                                      operator_public_keys={"operator": keys["operator"].public_key_b64,
                                                            "reader": keys["reader"].public_key_b64},
                                      operator_key_tiers={"operator": "privileged", "reader": "read"},
                                      boundary_policy_enforcement="required", evidence_store="on",
                                      evidence_out_of_band="on", evidence_remediation="on", evidence_grants="on")
    server = make_server("127.0.0.1", 0, service.app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    settings = Settings(authority_url=f"http://127.0.0.1:{server.server_port}", allow_http_loopback=True,
                        profiles=frozenset({"read", "verify", "operator", "node", "write"}),
                        authority_public_key=keys["root"].public_key_b64,
                        operator_key_file=paths["operator"], operator_key_id="operator",
                        node_key_file=paths["node"], executor_key_file=paths["executor"])
    try:
        yield settings, keys, paths
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        service.db.close()


def test_operator_tiers_signed_reads_and_attestation_lifecycle(authority):
    settings, _, paths = authority
    reader = replace(settings, operator_key_file=paths["reader"], operator_key_id="reader")
    roster = invoke(reader, operation("/nodes", "GET", "na_nodes_roster"), {})
    assert roster["http_status"] == 200
    assert roster["result"] == {"count": 0, "nodes": {}}
    refused = invoke(reader, operation("/admin/attestations"), {"body": {"subject_id": "client", "roles": ["role:client"]}})
    assert refused["http_status"] in {401, 403}
    assert refused["http_ok"] is False
    issued = invoke(settings, operation("/admin/attestations"), {"body": {"subject_id": "client", "roles": ["role:client"], "claims": {"apps": ["example"]}}})
    assert issued["http_status"] == 201, issued
    attestation = issued["result"]
    fetched = invoke(settings, operation("/attestations/<attestation_id>", "GET"), {"path": {"attestation_id": attestation["attestation_id"]}})
    assert fetched["http_status"] == 200
    assert fetched["result"]["attestation"]["attestation_id"] == attestation["attestation_id"]
    public_count = invoke(reader, operation("/attestations", "GET", "na_attestations_list_attestations"), {})
    assert public_count["result"] == {"count": 1}
    signed_list = invoke(reader, operation("/attestations", "GET", "na_attestations_roster"), {"query": {"subject_id": "client"}})
    assert signed_list["http_status"] == 200, signed_list
    assert signed_list["result"]["attestations"][0]["attestation"]["attestation_id"] == attestation["attestation_id"]
    revoked = invoke(settings, operation("/admin/attestations/<attestation_id>/revoke"), {"path": {"attestation_id": attestation["attestation_id"]}, "body": {"reason": "integration test"}})
    assert revoked["http_status"] == 200, revoked
    assert revoked["result"]["status"] == "revoked"


def test_signed_policy_denial_and_evidence_store_are_preserved(authority):
    settings, keys, _ = authority
    issued = invoke(settings, operation("/admin/attestations"), {"body": {"subject_id": "client", "roles": ["role:client"]}})
    assert issued["http_status"] == 201
    response = invoke(settings, operation("/admin/boundary/evaluate"), {"body": {"attestation_id": issued["result"]["attestation_id"], "requested_capability": "secret.manage", "context": {"request_parameters": {"resource_id": "kv:test/secret"}}}})
    assert response["http_status"] == 201, response
    decision = response["result"]["decision"]
    assert decision["authorized"] is False
    assert decision["signature"]
    checked = invoke(settings, operation("/boundary/verify"), {"body": {"decision": decision, "operator_public_keys": [keys["root"].public_key_b64]}})
    assert checked["http_status"] == 200, checked
    assert checked["result"]["accepted"] is True
    records = invoke(settings, operation("/admin/evidence", "GET"), {"query": {"decision_id": decision["decision_id"], "limit": 10}})
    assert records["http_status"] == 200, records
    assert records["result"]["entries"]
    justification = response["result"]["justification_proof"]
    vote = invoke(settings, operation("/admin/consensus/vote"), {"body": {"justification_proof": justification, "vote": True}})
    assert vote["http_status"] == 201, vote
    proof = invoke(settings, operation("/admin/consensus/proof"), {"body": {"justification_proof": justification,
                    "votes": [vote["result"]], "required_threshold": 1, "validator_sovereign_ids": ["mcp-test"]}})
    assert proof["http_status"] == 201, proof
    verified = invoke(settings, operation("/consensus/verify"), {"body": {"proof": proof["result"],
                      "validator_public_keys": {"mcp-test": keys["root"].public_key_b64},
                      "assembler_public_keys": [keys["root"].public_key_b64]}})
    assert verified["http_status"] == 200, verified
    assert verified["result"]["valid"] is True


def test_enrollment_heartbeat_discovery_and_node_bound_purpose(authority):
    settings, keys, _ = authority
    invite = invoke(settings, operation("/admin/invite"), {"body": {"roles": ["role:client"], "node_sovereign_id": "edge-test", "executor_resource_prefix": "kv:edge-test/"}})
    assert invite["http_status"] == 201, invite
    enrolled_settings = replace(settings, invite_token=invite["result"]["token_id"])
    joined = invoke(enrolled_settings, operation("/join"), {"body": {"edge": True, "agent_version": "mcp-test"}})
    assert joined["http_status"] == 201, joined
    cert_id = joined["result"]["cert_id"]
    heartbeat = invoke(settings, operation("/heartbeat"), {"body": {"cert_id": cert_id, "status": "active"}})
    assert heartbeat["http_status"] == 200, heartbeat
    assert heartbeat["result"]["ack"] is True
    state = invoke(settings, operation("/node/state"), {"body": {"cert_id": cert_id}})
    assert state["http_status"] == 200, state
    wrong_audience = replace(settings, authority_public_key=keys["operator"].public_key_b64)
    refused = invoke(wrong_audience, operation("/node/state"), {"body": {"cert_id": cert_id}})
    assert refused["http_status"] in {401, 403}, refused
    registration = invoke(settings, operation("/agents"), {"body": {"agent_id": "mcp-edge", "network_name": "mcp-test", "capabilities": ["read:test"], "endpoint": {"host": "127.0.0.1", "port": 8443}, "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()}})
    assert registration["http_status"] == 200, registration
    count = invoke(settings, operation("/agents", "GET"), {})
    assert "agents" not in count["result"]
    lookup = invoke(settings, operation("/agents", "GET"), {"query": {"capability": "read:test"}})
    assert len(lookup["result"]["agents"]) == 1
    removed = invoke(settings, operation("/agents/<path:node_public_key>", "DELETE"), {})
    assert removed["http_status"] == 200, removed
    assert removed["result"]["status"] == "deregistered"
