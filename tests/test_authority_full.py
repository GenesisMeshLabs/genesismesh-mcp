"""Domain scenarios through registered handlers and disposable HTTP authorities."""

from __future__ import annotations

import copy
import threading
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from genesis_mesh.crypto import generate_keypair, save_keypair, sign_model, verify_model_signature
from genesis_mesh.models import GenesisBlock, MembershipAttestation, NetworkAuthority, PolicyManifest, PolicyManifestRef
from genesis_mesh.models.context import BoundaryDecision
from genesis_mesh.models.data_usage import DataAccessIntent, DataLicensePolicy
from genesis_mesh.models.evidence import TrustEvidence
from genesis_mesh.trust.evidence import graph_digest_from_export, verify_trust_evidence
from genesis_mesh.trust.execution import record_execution
from genesis_mesh.trust.key_succession import verify_key_history
from test_authority_integration import authority as authority
from test_multi_workflows import pair as pair

from genesismesh_mcp.authority import build_tools, operations
from genesismesh_mcp.offline import build_tools as build_offline_tools
from genesismesh_mcp.settings import Settings
from genesismesh_mcp.types import ToolError


def request(settings, route, method="POST", *, status=200, name=None, **arguments):
    operation = next(op for op in operations() if op["method"] == method and op["path"] == route
                     and (name is None or op["name"] == name))
    tool = next(tool for tool in build_tools(settings) if tool.name == operation["name"])
    result = tool.handler(arguments)
    assert result["http_status"] == status, result
    assert result["http_ok"] == (200 <= status < 300)
    return result["result"]


def active_policy(settings, policy_id="limits", maximum=90):
    now = datetime.now(timezone.utc)
    body = {"policy_id": policy_id, "valid_from": (now - timedelta(hours=1)).isoformat(),
            "valid_until": (now + timedelta(hours=3)).isoformat(),
            "selector": {"capabilities": ["secret.manage"]},
            "gates": [{"gate_id": "limit", "gate_type": "max_value.v1", "order": 0,
                       "config": {"path": "request_parameters.lifetime_days", "max": maximum}}]}
    policy = request(settings, "/admin/boundary-policies", status=201, body=body)
    request(settings, "/admin/boundary-policies/<policy_id>/activate", path={"policy_id": policy_id},
            body={"version": policy["version"]})
    return body, policy


def test_public_metadata_policy_versions_and_signed_wire(authority):
    settings, keys, _ = authority
    genesis = request(settings, "/genesis", "GET")
    model = GenesisBlock.model_validate(genesis)
    assert verify_model_signature(model, model.signatures[0], keys["root"].public_key_b64)
    history = request(settings, "/na/key-history", "GET")
    assert verify_key_history(history["genesis"], history["successions"], keys["root"].public_key_b64).verified
    assert request(settings, "/health", "GET")["status"] == "healthy"
    assert request(settings, "/healthz", "GET")["status"] == "ok"
    assert request(settings, "/readyz", "GET")["status"] == "ready"
    assert request(settings, "/sovereign.json", "GET")["root_public_key"] == keys["root"].public_key_b64
    assert "genesis_mesh_na_issued_certs_total 0" in request(settings, "/metrics", "GET")
    first = request(settings, "/admin/policy", status=201, body={"policy_id": "first", "allowed_ports": [443]})
    second = request(settings, "/admin/policy", status=201, body={"policy_id": "second", "allowed_ports": [8443]})
    for raw in (first, second):
        policy = PolicyManifest.model_validate(raw)
        assert verify_model_signature(policy, policy.signatures[0], keys["root"].public_key_b64)
    versions = request(settings, "/admin/policy/history", "GET")["versions"]
    assert [row["policy_id"] for row in versions if row["active"]] == ["second"]
    assert request(settings, "/policy", "GET")["allowed_ports"] == [8443]
    restored = request(settings, "/admin/policy/rollback", body={"policy_id": "first"})
    assert restored == first
    assert request(settings, "/policy", "GET") == first
    refused = request(settings, "/admin/policy/rollback", status=404, body={"policy_id": "absent"})
    assert refused["error"]["code"] == "policy_not_found"


def test_boundary_policy_and_recognition_lifecycles(authority):
    settings, keys, _ = authority
    body, policy = active_policy(settings)
    validation = request(settings, "/admin/boundary-policies/validate", body=body)
    assert validation["valid"] is True
    rows = request(settings, "/admin/boundary-policies", "GET")
    assert [(row["policy_id"], row["version"]) for row in rows["policies"]] == [("limits", policy["version"])]
    history = request(settings, "/admin/boundary-policies/<policy_id>/history", "GET", path={"policy_id": "limits"})
    assert history["versions"][0]["policy"] == policy
    assert request(settings, "/admin/boundary-policies/active", "GET")["active"][0]["policy"] == policy
    assert request(settings, "/boundary-policies/verify", body={"policy": policy})["valid"] is True
    changed = {**policy, "description": "changed after signature"}
    assert request(settings, "/boundary-policies/verify", body={"policy": changed})["valid"] is False
    attestation = request(settings, "/admin/attestations", status=201,
                          body={"subject_id": "vendor", "roles": ["role:client"],
                                "claims": {"capabilities": ["secret.manage"]}})
    assert request(settings, "/attestations/<attestation_id>", "GET",
                   path={"attestation_id": attestation["attestation_id"]})["attestation"] == attestation
    recognition = {"local_sovereign_id": "mcp-test", "recognized_issuers": [{
        "sovereign_id": "mcp-test", "public_keys": [keys["root"].public_key_b64],
        "allowed_roles": ["role:client"], "accepted_statuses": ["active"]}], "revoked_attestation_ids": []}
    request(settings, "/admin/recognition-policy", body={"recognition_policy": recognition})
    assert request(settings, "/recognition-policy", "GET")["local_sovereign_id"] == "mcp-test"
    assert request(settings, "/attestations/verify", body={"attestation": attestation})["accepted"] is True
    changed = copy.deepcopy(attestation)
    changed["subject_id"] = "forged-subject"
    assert request(settings, "/attestations/verify", body={"attestation": changed})["accepted"] is False
    assert request(settings, "/attestations", "GET")["count"] == 1
    roster = request(settings, "/attestations", "GET", name="na_attestations_roster", query={"subject_id": "vendor"})
    assert roster["attestations"][0]["attestation"]["attestation_id"] == attestation["attestation_id"]
    request(settings, "/admin/attestations/<attestation_id>/revoke", path={"attestation_id": attestation["attestation_id"]})
    feed = request(settings, "/sovereign-revocation-feed", "GET")
    assert attestation["attestation_id"] in feed["revoked_attestation_ids"]
    request(settings, "/admin/boundary-policies/<policy_id>/deactivate", path={"policy_id": "limits"},
            body={"version": policy["version"]})
    assert request(settings, "/admin/boundary-policies/active", "GET")["active"] == []


def test_data_license_intent_signatures_and_policy_denial(authority):
    settings, keys, _ = authority
    now = datetime.now(timezone.utc)
    policy = request(settings, "/admin/data-usage/policy", status=201, body={
        "licensee_sovereign_id": "mcp-test", "allowed_source_ids": ["dataset"], "allowed_access_types": ["read"],
        "max_volume_bytes_per_session": 100,
        "valid_from": (now - timedelta(minutes=1)).isoformat(), "valid_until": (now + timedelta(hours=1)).isoformat()})
    intent_args = {"sources": [{"source_id": "dataset", "source_type": "proprietary", "owner_sovereign_id": "owner"}],
                   "access_types": ["read"], "estimated_volume_bytes": 50}
    intent = request(settings, "/admin/data-usage/intent", status=201, body=intent_args)
    for raw, cls in ((policy, DataLicensePolicy), (intent, DataAccessIntent)):
        model = cls.model_validate(raw)
        assert verify_model_signature(model, model.signature, keys["root"].public_key_b64)
    assert request(settings, "/data-usage/policy", "GET") == policy
    assert request(settings, "/data-usage/verify", body={"intent": intent, "policy": policy})["valid"] is True
    oversized = request(settings, "/admin/data-usage/intent", status=201,
                        body={**intent_args, "estimated_volume_bytes": 101})
    refusal = request(settings, "/data-usage/verify", body={"intent": oversized, "policy": policy})
    assert refusal["valid"] is False and refusal["violation_count"] > 0
    forged = {**intent, "decision_id": "different"}
    assert request(settings, "/data-usage/verify", body={"intent": forged, "policy": policy})["valid"] is False


def test_trust_evidence_uses_trust_decision_and_verifies_binding(authority):
    settings, keys, _ = authority
    graph = request(settings, "/atlas.json", "GET")
    decision = {"source_sovereign_id": "mcp-test", "target_sovereign_id": "other", "verdict": "block",
                "reason": "No recognition path", "requested_roles": ["role:client"], "trusted": False,
                "trust_path": [], "hop_count": 0, "signals": [{"code": "no_path", "severity": "error", "detail": "missing"}],
                "evaluated_at": datetime.now(timezone.utc).isoformat()}
    evidence = request(settings, "/admin/trust-evidence", status=201,
                       body={"decision": decision, "graph_digest": graph["graph_digest"]})
    record = TrustEvidence.model_validate(evidence)
    assert verify_model_signature(record, record.signatures[0], keys["root"].public_key_b64)
    checked = request(settings, "/trust-evidence/verify", body={"evidence": evidence,
                      "expected_graph_digest": graph["graph_digest"]})
    assert checked["accepted"] is True and checked["verdict"] == "block"
    assert request(settings, "/trust-evidence/verify", body={"evidence": evidence,
                   "expected_graph_digest": "0" * 64})["accepted"] is False
    assert request(settings, "/trust-evidence/verify", body={"evidence": {**evidence, "verdict": "allow"}})["accepted"] is False


def test_offline_nonempty_trust_path_round_trips_through_authority_evidence(authority):
    settings, keys, _ = authority
    treaty = request(settings, "/admin/recognition-treaties", status=201, body={
        "subject_sovereign_id": "other", "subject_public_keys": [keys["node"].public_key_b64],
        "scope": {"allowed_roles": ["role:client"]}})
    graph = request(settings, "/recognition-graph", "GET")
    evaluate = next(tool for tool in build_offline_tools(settings)
                    if tool.name == "gm_offline_decision_evaluate_trust_decision")
    decision = evaluate.handler({"graph": graph, "source_sovereign_id": "mcp-test",
                                 "target_sovereign_id": "other", "requested_roles": ["role:client"]})
    original = copy.deepcopy(decision)
    assert decision["trusted"] is True and decision["hop_count"] == 1
    assert decision["trust_path"][0]["treaty_id"] == treaty["treaty_id"]
    assert decision["trust_path"][0]["from"] == "mcp-test"
    assert decision["trust_path"][0]["to"] == "other"
    digest = graph_digest_from_export(graph)
    evidence = request(settings, "/admin/trust-evidence", status=201,
                       body={"decision": decision, "graph_digest": digest})
    assert decision == original
    record = TrustEvidence.model_validate(evidence)
    assert verify_trust_evidence(record, [keys["root"].public_key_b64], expected_graph_digest=digest).accepted
    for field in ("source_sovereign_id", "target_sovereign_id", "verdict", "reason", "requested_roles",
                  "trusted", "hop_count", "signals", "evaluated_at"):
        assert evidence[field] == decision[field]
    assert request(settings, "/trust-evidence/verify", body={"evidence": evidence,
                   "expected_graph_digest": digest})["accepted"] is True
    assert request(settings, "/trust-evidence/verify", body={"evidence": evidence,
                   "expected_graph_digest": "0" * 64})["accepted"] is False
    with pytest.raises(ToolError) as caught:
        request(settings, "/admin/trust-evidence", body={"decision": {**decision, "trust_path": ["other"]}})
    assert caught.value.code == "invalid_arguments"


def test_edge_enrollment_renew_discovery_and_revoke(authority):
    settings, keys, _ = authority
    invitation = request(settings, "/admin/invite", status=201, body={"roles": ["role:client"],
        "recipient_public_key": keys["node"].public_key_b64, "node_sovereign_id": "edge-test",
        "executor_resource_prefix": "kv:edge-test/"})
    node = replace(settings, invite_token=invitation["token_id"])
    joined = request(node, "/join", status=201, body={"edge": True})
    cert_id = joined["cert_id"]
    request(node, "/heartbeat", body={"cert_id": cert_id, "status": "online"})
    assert request(settings, "/nodes", "GET")["count"] == 1
    assert request(settings, "/nodes", "GET", name="na_nodes_roster")["nodes"]
    assert request(settings, "/admin/edge-nodes", "GET", query={"node_sovereign_id": "edge-test"})["edge_nodes"]
    state = request(node, "/node/state", body={"cert_id": cert_id})
    assert state["node"]["node_sovereign_id"] == "edge-test"
    missing = request(node, "/node/evidence/resource-head", status=404,
                      body={"cert_id": cert_id, "resource_id": "kv:edge-test/item"})
    assert missing["error"]["code"] == "resource_not_found"
    refused = request(node, "/node/evidence/resource-head", status=403,
                      body={"cert_id": cert_id, "resource_id": "kv:other/item"})
    assert refused["error"]["code"]
    active_policy(settings)
    attestation = request(settings, "/admin/attestations", status=201, body={"subject_id": "edge-test",
        "subject_public_key": keys["node"].public_key_b64, "roles": ["role:client"], "claims": {"capabilities": ["secret.manage"]}})
    evaluated = request(node, "/node/boundary/evaluate", status=201, body={"cert_id": cert_id,
        "attestation_id": attestation["attestation_id"], "requested_capability": "secret.manage",
        "context": {"request_parameters": {"lifetime_days": 30}}})
    assert evaluated["decision"]["authorized"] is True
    evidence = record_execution(BoundaryDecision.model_validate(evaluated["decision"]), "edge-test", "secret.manage",
        "success", keys["executor"].private_key, issued_by=state["executor_key"]["key_id"],
        resource_id="kv:edge-test/item", resource_action="create")
    stored = request(node, "/evidence/execution", status=201, body={"evidence": evidence.model_dump(mode="json")})
    assert stored["status"] == "recorded"
    assert request(node, "/node/evidence/resource-head", body={"cert_id": cert_id,
                   "resource_id": "kv:edge-test/item"})["record_digest"] == evidence.digest()
    descriptor = request(node, "/agents", body={"agent_id": "edge", "network_name": "mcp-test",
        "capabilities": ["secret.manage"], "endpoint": {"host": "127.0.0.1", "port": 9944},
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()})
    assert descriptor
    assert request(settings, "/agents/<path:node_public_key>", "GET",
                   path={"node_public_key": keys["node"].public_key_b64})["agent_id"] == "edge"
    assert request(settings, "/agents", "GET", query={"capability": "secret.manage"})["agents"]
    assert request(node, "/agents/<path:node_public_key>", "DELETE")["status"] == "deregistered"
    renewed = request(node, "/renew", status=201, body={"cert_id": cert_id})
    new_id = renewed["cert_id"]
    request(settings, "/admin/revoke", body={"cert_id": new_id, "reason": "key_compromise"})
    assert new_id in str(request(settings, "/crl", "GET"))
    revoked = request(node, "/node/state", status=403, body={"cert_id": new_id})
    assert revoked["error"]["code"]


def test_consensus_denial_and_evidence_through_registered_handlers(authority, monkeypatch):
    # Reuse the established real-core scenario, replacing only its direct invoke
    # shortcut with the registered wrapper that MCP dispatches.
    import test_authority_integration as scenarios

    def through_handler(settings, operation, arguments):
        tool = next(tool for tool in build_tools(settings) if tool.name == operation["name"])
        return tool.handler(arguments)

    monkeypatch.setattr(scenarios, "invoke", through_handler)
    scenarios.test_signed_policy_denial_and_evidence_store_are_preserved(authority)


def selected(pair, alias):
    base, credentials = pair
    config = base.authorities[alias]
    return replace(base, authority_url=config.url, authority_public_key=config.public_key,
                   operator_key_file=config.operator_key_file, operator_key_id=config.operator_key_id), credentials[alias][0]


def test_treaties_agreement_disclosure_and_revocation_between_real_authorities(pair):
    from genesis_mesh.models import AgreementRecord, CapabilityCommitment
    from genesis_mesh.models.selective_disclosure import CapabilityNullifier
    from genesis_mesh.trust.agreement import verify_agreement

    alpha, akeys = selected(pair, "alpha")
    beta, bkeys = selected(pair, "beta")
    alpha_treaty = request(alpha, "/admin/recognition-treaties", status=201, body={
        "subject_sovereign_id": "beta", "subject_public_keys": [bkeys["na"].public_key_b64],
        "scope": {"allowed_roles": ["role:client"]}})
    request(beta, "/admin/recognition-treaties", status=201, body={
        "subject_sovereign_id": "alpha", "subject_public_keys": [akeys["na"].public_key_b64],
        "scope": {"allowed_roles": ["role:client"]}})
    path = {"treaty_id": alpha_treaty["treaty_id"]}
    fetched = request(alpha, "/recognition-treaties/<treaty_id>", "GET", path=path)
    assert fetched["treaty"]["treaty_id"] == alpha_treaty["treaty_id"]
    assert request(alpha, "/recognition-treaties", "GET", query={"subject_sovereign_id": "beta"})["count"] == 1
    assert request(alpha, "/recognition-treaties/verify", body={"treaty": alpha_treaty})["accepted"] is True
    assert request(alpha, "/recognition-treaties/verify", body={"treaty": {**alpha_treaty, "subject_sovereign_id": "other"}})["accepted"] is False
    graph = request(alpha, "/recognition-graph", "GET")
    assert graph["recognition_edges"]
    assert request(alpha, "/connectome.json", "GET")
    trusted = request(alpha, "/connectome/trust-path", "GET", query={"from": "alpha", "to": "beta"})
    assert trusted["trusted"] is True
    assert request(alpha, "/connectome/trust-path", "GET", query={"from": "alpha", "to": "missing"})["trusted"] is False
    now = datetime.now(timezone.utc)
    terms = {"capabilities": ["secret.manage"], "valid_from": (now - timedelta(minutes=1)).isoformat(),
             "valid_until": (now + timedelta(hours=1)).isoformat()}
    offer = request(alpha, "/admin/agreements/offer", status=201, body={**terms,
        "responder_sovereign_id": "beta", "expires_at": (now + timedelta(minutes=30)).isoformat()})
    counter = request(beta, "/admin/agreements/counter", status=201, body={**terms, "offer": offer})
    agreement = request(alpha, "/admin/agreements/accept", status=201, body={"counter": counter, "original_offer": offer})
    a_pub, b_pub = akeys["na"].public_key_b64, bkeys["na"].public_key_b64
    assert verify_agreement(AgreementRecord.model_validate(agreement), offerer_public_keys=[a_pub], responder_public_keys=[b_pub]).accepted
    assert request(alpha, "/agreements/verify", body={"agreement": agreement,
        "offerer_public_keys": [a_pub], "responder_public_keys": [b_pub]})["accepted"] is True
    forged = copy.deepcopy(agreement)
    forged["agreed_terms"]["capabilities"].append("secret.delete")
    assert request(alpha, "/agreements/verify", body={"agreement": forged,
        "offerer_public_keys": [a_pub], "responder_public_keys": [b_pub]})["accepted"] is False
    decision = request(alpha, "/admin/boundary/decide", status=201,
                       body={"agreement": agreement, "requested_capability": "secret.manage"})
    assert decision["authorized"] is True
    denied = request(alpha, "/admin/boundary/decide", status=201,
                     body={"agreement": agreement, "requested_capability": "secret.delete"})
    assert denied["authorized"] is False
    commitment = request(alpha, "/admin/disclosure/commit", status=201,
                         body={"agreement": agreement, "capabilities": ["secret.manage"]})
    record = CapabilityCommitment.model_validate(commitment)
    assert verify_model_signature(record, record.signature, a_pub)
    proof_args = {"capability": "secret.manage", "capabilities": ["secret.manage"],
                  "commitment": commitment, "prover_sovereign_id": "beta"}
    proof = request(alpha, "/disclosure/prove", body=proof_args)
    assert request(alpha, "/disclosure/verify", body={"proof": proof, "commitment": commitment})["valid"] is True
    assert request(alpha, "/disclosure/verify", body={"proof": {**proof, "revealed_capability": "secret.delete"},
        "commitment": commitment})["valid"] is False
    nullifier = request(alpha, "/admin/disclosure/nullifier", status=201, body={"proof": proof})
    nullifier_record = CapabilityNullifier.model_validate(nullifier)
    assert verify_model_signature(nullifier_record, nullifier_record.signature, a_pub)
    attestation = request(beta, "/admin/attestations", status=201,
                          body={"subject_id": "vendor", "roles": ["role:client"]})
    assertion = {"attestation": attestation, "treaty": alpha_treaty}
    assert request(alpha, "/attestations/verify-with-treaty", body=assertion)["accepted"] is True
    request(beta, "/admin/attestations/<attestation_id>/revoke", path={"attestation_id": attestation["attestation_id"]})
    feed = request(beta, "/sovereign-revocation-feed", "GET")
    imported = request(alpha, "/admin/sovereign-revocation-feeds/import", body={"feed": feed})
    assert imported["accepted"] is True
    assert request(alpha, "/attestations/verify-with-treaty", body=assertion)["accepted"] is False
    request(alpha, "/admin/recognition-treaties/<treaty_id>/revoke", path=path)
    assert request(alpha, "/recognition-treaties/verify", body={"treaty": alpha_treaty})["accepted"] is False


def test_evidence_observations_remediation_and_verified_archive(authority):
    from genesis_mesh.models.audit_pack import AuditPackManifest
    from genesis_mesh.models.out_of_band import BreakGlassRecord, ObservationRecord
    from genesis_mesh.models.remediation import RemediationRecord
    from genesis_mesh.trust.evidence_store import ExecutorKey, parse_export_lines, verify_evidence_events
    from genesis_mesh.workflows.audit_pack import verify_audit_pack

    settings, keys, _ = authority
    active_policy(settings)
    for name, role in (("executor", "executor"), ("node", "observer")):
        request(settings, "/admin/evidence/executor-keys", status=201, body={"key_id": name,
            "public_key": keys[name].public_key_b64, "executor_sovereign_id": "vendor" if role == "executor" else "observer",
            "role": role, "resource_prefix": "kv:test/"})
    registry = request(settings, "/admin/evidence/executor-keys", "GET")["executor_keys"]
    assert {row["key_id"] for row in registry} == {"executor", "node"}
    attestation = request(settings, "/admin/attestations", status=201, body={"subject_id": "vendor",
        "roles": ["role:client"], "claims": {"capabilities": ["secret.manage"]}})
    decision = request(settings, "/admin/boundary/evaluate", status=201, body={
        "attestation_id": attestation["attestation_id"], "requested_capability": "secret.manage",
        "context": {"request_parameters": {"lifetime_days": 30, "resource_id": "kv:test/secret"}}})["decision"]
    assert decision["authorized"] is True
    execution = record_execution(BoundaryDecision.model_validate(decision), "vendor", "secret.manage", "success",
        keys["executor"].private_key, issued_by="executor", resource_id="kv:test/secret", resource_action="rotate")
    wire = execution.model_dump(mode="json")
    changed = {**wire, "outcome": "failure"}
    refused = request(settings, "/evidence/execution", status=422, body={"evidence": changed})
    assert refused["error"]["code"] == "evidence_invalid_signature"
    assert request(settings, "/evidence/execution", status=201, body={"evidence": wire})["status"] == "recorded"
    assert request(settings, "/evidence/execution", body={"evidence": wire})["status"] == "duplicate"
    resource = {"resource_id": "kv:test/secret"}
    assert request(settings, "/admin/evidence/resource-heads/<path:resource_id>", "GET", path=resource)["record_digest"] == execution.digest()
    assert request(settings, "/admin/evidence/resources/<path:resource_id>", "GET", path=resource)["verification"]["verified"]
    assert request(settings, "/admin/evidence/vendors/<vendor_id>", "GET", path={"vendor_id": "vendor"})["verification"]["verified"]
    assert request(settings, "/admin/evidence/status", "GET")["entries"] > 0

    def observed(event):
        now = datetime.now(timezone.utc)
        value = ObservationRecord(observer_sovereign_id="observer", resource_id="kv:test/outside", action="rotate",
            capability="secret.manage", changed_at=now, observed_at=now, actor="outside-actor", source="activity-log",
            source_event_id=event, version_id=event, metadata={"lifetime_days": 400})
        return value.model_copy(update={"signature": sign_model(value, keys["node"].private_key, "node")})

    observation = observed("first")
    recorded = request(settings, "/evidence/observations", status=201, body={"observation": observation.to_wire()})
    judgement = recorded["judgement"]["payload"]
    assert judgement["verdict"] == "deny"
    assert request(settings, "/admin/evidence/observations/<observation_id>/judge",
        path={"observation_id": observation.observation_id})["payload"]["judgement_id"] == judgement["judgement_id"]
    batch = request(settings, "/evidence/observations/batch", body={"observations": [observed("second").to_wire()]})
    assert batch["results"][0]["status"] == "recorded"
    changes = request(settings, "/admin/evidence/changes/<path:resource_id>", "GET", path={"resource_id": "kv:test/outside"})
    assert len(changes["changes"]) == 2
    subject = {"subject_id": judgement["judgement_id"]}
    item = request(settings, "/admin/evidence/remediations/<subject_id>", "GET", path=subject)
    assert item["state"] == "remediation_due"
    notified = request(settings, "/admin/evidence/remediations/<subject_id>/notified", path=subject, body={"channel": "test-console"})
    assert notified["notified_at"] and notified["notified_by"] == "operator"
    remediation = RemediationRecord(executor_sovereign_id="vendor", subject_kind="judgement",
        subject_id=judgement["judgement_id"], change_kind="observation", change_id=observation.observation_id,
        resource_id="kv:test/outside", outcome="alerted", steps="none", remediated_at=datetime.now(timezone.utc))
    remediation = remediation.model_copy(update={"signature": sign_model(remediation, keys["executor"].private_key, "executor")})
    remediated = request(settings, "/evidence/remediations", status=201, body={"record": remediation.to_wire()})
    assert remediated["status"] == "recorded"
    assert request(settings, "/evidence/remediations", body={"record": remediation.to_wire()})["status"] == "duplicate"
    emergency = BreakGlassRecord(executor_sovereign_id="vendor", resource_id="kv:test/emergency", resource_action="rotate",
        capability="secret.manage", attestation_id=attestation["attestation_id"], request_parameters={"lifetime_days": 30},
        justification="Authority unavailable during declared action", evaluation_request_digest="0" * 64,
        evaluation_failure="network_error", executed_at=datetime.now(timezone.utc), outcome="success")
    emergency = emergency.model_copy(update={"signature": sign_model(emergency, keys["executor"].private_key, "executor")})
    admitted = request(settings, "/evidence/break-glass", status=201, body={"record": emergency.to_wire()})
    assert admitted["judgement"]["payload"]["verdict"] == "allow"
    assert request(settings, "/admin/evidence/break-glass/<break_glass_id>/judge",
        path={"break_glass_id": emergency.break_glass_id})["status"] == "existing"
    assert request(settings, "/admin/evidence/verify", "GET")["verified"] is True
    exported = request(settings, "/admin/evidence/export", "GET")
    executor_keys = {"executor": ExecutorKey("executor", keys["executor"].public_key_b64, "vendor", resource_prefix="kv:test/"),
                     "node": ExecutorKey("node", keys["node"].public_key_b64, "observer", role="observer", resource_prefix="kv:test/")}
    verified = verify_evidence_events(parse_export_lines(exported.splitlines()), na_public_keys=[keys["root"].public_key_b64], executor_keys=executor_keys)
    assert verified.verified, verified.to_dict()
    anchored = request(settings, "/admin/evidence/anchors", status=201)
    assert anchored["anchor"]["store_sequence"] > 1
    held = request(settings, "/admin/evidence/anchors", "GET")["anchors"]
    pack = request(settings, "/admin/evidence/audit-pack")
    manifest = AuditPackManifest.model_validate(pack["manifest"])
    files = {name: value.encode() for name, value in pack["files"].items()}
    files["manifest.json"] = manifest.file_bytes()
    checked = verify_audit_pack(files, root_public_key=keys["root"].public_key_b64, held_anchors=None)
    assert checked.verified, checked.to_dict()
    assert held[-1]["store_sequence"] == manifest.through_sequence
    archived = request(settings, "/admin/evidence/archives", status=201,
        body={"manifest": pack["manifest"], "location": "test://immutable/disposable-pack"})
    assert archived["archive"]["pack_id"] == manifest.pack_id
    assert request(settings, "/admin/evidence/archives", "GET")["archived_through_sequence"] == manifest.through_sequence
    retained = request(settings, "/admin/evidence/retention/apply", body={"older_than_days": 365})
    assert retained["removed_count"] == 0
    retired = request(settings, "/admin/evidence/executor-keys/<key_id>/retire", path={"key_id": "node"})
    assert retired == {"key_id": "node", "active": False}


def test_holder_change_requires_second_holder_and_revoked_operator_is_refused(authority):
    settings, _, paths = authority
    holders = request(settings, "/admin/evidence/operator-holders", "GET")["holders"]
    assert {row["holder"] for row in holders} == {"Actor", "Reader", "Reviewer", "Approver"}
    proposed = request(settings, "/admin/operator-keys/<key_id>/holder", status=201,
                       path={"key_id": "reader"}, body={"holder": "New auditor"})
    path = {"proposal_id": proposed["proposal_id"]}
    refused = request(settings, "/admin/operator-keys/holder-changes/<proposal_id>/approve", status=409, path=path)
    assert refused["error"]["code"] == "holder_change_needs_second_holder"
    approver = replace(settings, operator_key_id="decider", operator_key_file=paths["decider"])
    assert request(approver, "/admin/operator-keys/holder-changes/<proposal_id>/approve", path=path)["approved"] is True
    assert any(row["holder"] == "New auditor" for row in request(settings, "/admin/evidence/operator-holders", "GET")["holders"])
    revoked = request(settings, "/admin/operator-keys/<key_id>/revoke", path={"key_id": "requester"}, body={"reason": "retired"})
    assert revoked
    former = replace(settings, operator_key_id="requester", operator_key_file=paths["requester"])
    refused = request(former, "/admin/evidence/operator-holders", "GET", status=401)
    assert refused["error"]["code"] == "admin_auth_failed"


def test_review_read_returns_the_signed_decision_and_distinct_holders(authority):
    from genesis_mesh.models.remediation import ReviewRecord
    from genesis_mesh.trust.remediation import review_approval_problem

    settings, keys, paths = authority
    active_policy(settings)
    attestation = request(settings, "/admin/attestations", status=201, body={"subject_id": "vendor",
        "roles": ["role:client"], "claims": {"capabilities": ["secret.manage"]}})
    decision = request(settings, "/admin/boundary/evaluate", status=201, body={
        "attestation_id": attestation["attestation_id"], "requested_capability": "secret.manage",
        "context": {"request_parameters": {"lifetime_days": 30}}})["decision"]
    requester = replace(settings, operator_key_id="requester", operator_key_file=paths["requester"])
    decider = replace(settings, operator_key_id="decider", operator_key_file=paths["decider"])
    opened = request(requester, "/admin/evidence/reviews", status=201,
        body={"subject_kind": "decision", "subject_id": decision["decision_id"], "justification": "Review declared change"})
    path = {"review_id": opened["review_id"]}
    pending = request(settings, "/admin/evidence/reviews/<review_id>", "GET", path=path)
    assert pending["review_id"] == opened["review_id"]
    queue = request(settings, "/admin/evidence/remediations", "GET", query={"state": "review_pending"})
    assert any(row["subject_id"] == decision["decision_id"] for row in queue["remediations"])
    decided = request(decider, "/admin/evidence/reviews/<review_id>/decide", path=path, body={"verdict": "deny"})
    review = ReviewRecord.model_validate(decided["review"]["payload"])
    assert review_approval_problem(review, [keys["root"].public_key_b64]) is None
    assert verify_model_signature(review, review.signature, keys["root"].public_key_b64)
    fetched = request(settings, "/admin/evidence/reviews/<review_id>", "GET", path=path)
    assert fetched["record"]["payload"] == review.to_wire()


def test_root_and_new_key_succession_restart_reissues_long_lived_records(tmp_path, monkeypatch):
    from genesis_mesh.audit import logger as audit_logger
    from genesis_mesh.models.key_succession import KeySuccessionRecord
    from genesis_mesh.na_service.server import NetworkAuthorityService
    from genesis_mesh.na_service.services.key_history import KeyHistoryService
    from genesis_mesh.na_service.services.reissue import ReissueService
    from werkzeug.serving import make_server

    monkeypatch.setattr(audit_logger, "DEFAULT_AUDIT_DIR", tmp_path / "audit")
    keys = {name: generate_keypair() for name in ("root", "old", "new", "operator", "stranger")}
    path = save_keypair(keys["operator"], str(tmp_path / "operator"))[0]
    now = datetime.now(timezone.utc)
    effective = now + timedelta(minutes=2)
    genesis = GenesisBlock(network_name="succession", network_version="1.8.1", root_public_key=keys["root"].public_key_b64,
        network_authority=NetworkAuthority(public_key=keys["old"].public_key_b64,
            valid_from=now - timedelta(hours=1), valid_to=now + timedelta(days=30)),
        policy_manifest=PolicyManifestRef(hash="sha256:test"))
    genesis.signatures = [sign_model(genesis, keys["root"].private_key, "root")]

    @contextmanager
    def running(who):
        service = NetworkAuthorityService(genesis_block=genesis, na_private_key=keys[who].private_key,
            key_id=who, db_path=str(tmp_path / "same-authority.db"), evidence_store="on",
            operator_public_keys={"operator": keys["operator"].public_key_b64},
            operator_key_tiers={"operator": "privileged"})
        server = make_server("127.0.0.1", 0, service.app)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        settings = Settings(authority_url=f"http://127.0.0.1:{server.server_port}", allow_http_loopback=True,
            authority_public_key=keys["old"].public_key_b64, operator_key_file=path, operator_key_id="operator",
            profiles=frozenset({"read", "write", "operator", "verify"}))
        try:
            yield settings
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            service.db.close()

    with running("old") as settings:
        original = request(settings, "/admin/attestations", status=201,
                           body={"subject_id": "vendor", "roles": ["role:client"], "validity_hours": 168})
        request(settings, "/admin/policy", status=201, body={"policy_id": "before"})
        record = KeySuccessionRecord(sovereign_id="succession", key_sequence=2,
            previous_key_id="old", previous_public_key=keys["old"].public_key_b64,
            new_key_id="new", new_public_key=keys["new"].public_key_b64,
            issued_at=now, effective_at=effective, new_valid_to=now + timedelta(days=365))
        wrong = record.model_copy(update={"signatures": [sign_model(record, keys["stranger"].private_key, "root"),
                                                         sign_model(record, keys["new"].private_key, "new")]})
        refused = request(settings, "/admin/na/succession", status=422, body={"succession": wrong.to_wire()})
        assert refused["error"]["code"] == "succession_invalid_root_signature"
        signed = record.model_copy(update={"signatures": [sign_model(record, keys["root"].private_key, "root"),
                                                          sign_model(record, keys["new"].private_key, "new")]})
        result = request(settings, "/admin/na/succession", status=201, body={"succession": signed.to_wire()})
        assert result["status"] == "recorded" and len(result["succession"]["signatures"]) == 3
        history = result["key_history"]
        assert verify_key_history(history["genesis"], history["successions"], keys["root"].public_key_b64).verified

    # Advance the two injected service clocks, keeping real signatures, DB,
    # HTTP transport and verification. No wall-clock sleep or domain verifier stub.
    future = effective + timedelta(seconds=1)
    monkeypatch.setattr(KeyHistoryService, "_now", staticmethod(lambda: future))
    monkeypatch.setattr(ReissueService, "_now", staticmethod(lambda: future))
    with running("new") as restarted:
        result = request(restarted, "/admin/na/reissue")
        assert result["reissue_pending"] == 0
        roster = request(restarted, "/attestations", "GET", name="na_attestations_roster")
        replacements = [row["attestation"] for row in roster["attestations"] if row["attestation"]["issued_by"] == "new"]
        assert len(replacements) == 1
        replacement = MembershipAttestation.model_validate(replacements[0])
        assert replacement.subject_id == original["subject_id"]
        assert verify_model_signature(replacement, replacement.signatures[0], keys["new"].public_key_b64)
        assert not verify_model_signature(replacement, replacement.signatures[0], keys["old"].public_key_b64)
