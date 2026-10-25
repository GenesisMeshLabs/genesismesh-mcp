"""Disposable real HTTP authority tests; no production endpoint or credentials."""

from __future__ import annotations

import copy
import threading
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from genesis_mesh.audit import logger as audit_logger
from genesis_mesh.crypto import generate_keypair, save_keypair, sign_model, verify_model_signature
from genesis_mesh.models import GenesisBlock, NetworkAuthority, PolicyManifestRef
from genesis_mesh.models.grants import (
    CapabilityGrant,
    GrantExecutionEvidence,
    GrantRevocationRecord,
    TimeToken,
    TimeTokenRequest,
)
from genesis_mesh.models.remediation import ReviewRecord
from genesis_mesh.na_service.server import NetworkAuthorityService
from genesis_mesh.trust.evidence_store import ExecutorKey, parse_export_lines, verify_evidence_events
from genesis_mesh.trust.grants import grant_horizon, use_problem
from genesis_mesh.trust.remediation import review_approval_problem
from mcp import Client
from werkzeug.serving import make_server

from genesismesh_mcp.authority import invoke, operations
from genesismesh_mcp.offline.adapter import json_value
from genesismesh_mcp.server import create_server
from genesismesh_mcp.settings import Settings


def operation(path, method="POST", name=None):
    return next(op for op in operations() if op["path"] == path and op["method"] == method
                and (name is None or op["name"] == name))


@pytest.fixture
def authority(tmp_path, monkeypatch):
    monkeypatch.setattr(audit_logger, "DEFAULT_AUDIT_DIR", tmp_path / "audit")
    keys = {name: generate_keypair() for name in ("root", "operator", "reader", "node", "executor", "requester", "decider")}
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
                                                            "requester": keys["requester"].public_key_b64,
                                                            "decider": keys["decider"].public_key_b64,
                                                            "reader": keys["reader"].public_key_b64},
                                      operator_key_tiers={"operator": "privileged", "reader": "read",
                                                          "requester": "privileged", "decider": "privileged"},
                                      operator_key_holders={"operator": "Actor", "reader": "Reader",
                                                            "requester": "Reviewer", "decider": "Approver"},
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


async def test_mcp_grant_lifecycle_matches_core_and_verifies_export(authority):
    """Real HTTP through MCP, independently checked by the pinned core's offline verifiers."""
    settings, keys, paths = authority
    root_key = keys["root"].public_key_b64
    now = datetime.now(timezone.utc)

    async with Client(create_server(settings)) as client:
        async def request(template, method="POST", expected=200, **arguments):
            result = await client.call_tool(operation(template, method)["name"], arguments)
            body = result.structured_content
            assert body["http_status"] == expected, body
            assert result.is_error == (expected >= 400), body
            return body["result"]

        registered = await request("/admin/evidence/executor-keys", expected=201, body={
            "key_id": "executor", "public_key": keys["executor"].public_key_b64,
            "executor_sovereign_id": "edge-test"})
        assert registered["key_id"] == "executor"
        attestation = await request("/admin/attestations", expected=201, body={
            "subject_id": "client", "roles": ["role:client"], "claims": {"capabilities": ["secret.manage"]}})
        policy = await request("/admin/boundary-policies", expected=201, body={
            "policy_id": "lifetime", "valid_from": (now - timedelta(minutes=1)).isoformat(),
            "valid_until": (now + timedelta(hours=3)).isoformat(), "selector": {"capabilities": ["secret.manage"]},
            "gates": [{"gate_id": "max-lifetime", "gate_type": "max_value.v1", "order": 0,
                       "config": {"path": "request_parameters.lifetime_days", "max": 90}}]})
        await request("/admin/boundary-policies/<policy_id>/activate", path={"policy_id": "lifetime"},
                      body={"version": policy["version"]})
        envelope = {"lifetime_days": {"number_range": {"number_type": "integer", "minimum": 1, "maximum": 60}}}
        grant_args = {"bearer_key_id": "executor", "capabilities": ["secret.manage"],
                      "attestation_id": attestation["attestation_id"], "valid_until": (now + timedelta(hours=1)).isoformat(),
                      "max_uses": 5, "max_uses_per_time_token": 2, "parameter_envelope": envelope}
        refused = await request("/admin/grants", expected=422, body={**grant_args, "parameter_envelope": {
            "lifetime_days": {"number_range": {"number_type": "integer", "minimum": 1, "maximum": 400}}}})
        assert refused["error"]["code"] == "grant_gate_may_deny"
        issued = await request("/admin/grants", expected=201, body=grant_args)
        grant = CapabilityGrant.model_validate(issued["grant"])
        token = TimeToken.model_validate(issued["time_token"])
        assert grant.to_wire() == issued["grant"]
        assert token.to_wire() == issued["time_token"]
        for record in (grant, token):
            assert verify_model_signature(record, record.signature, root_key)
            assert not verify_model_signature(record, record.signature, keys["reader"].public_key_b64)
        assert "use_head_digest" not in issued["time_token"]
        assert [(p.policy_id, p.version) for p in grant.policy_binding.policies] == [("lifetime", policy["version"])]
        horizon = await client.call_tool("gm_offline_grants_grant_horizon", {"grant": grant.to_wire()})
        assert not horizon.is_error
        assert horizon.structured_content == {"result": json_value(grant_horizon(grant))}

        def signed_use(sequence, previous=None, days=30, time_token=None):
            record = GrantExecutionEvidence(grant_id=grant.grant_id, grant_digest=grant.digest(),
                use_sequence=sequence, prev_use_digest=previous.digest() if previous else None,
                executor_sovereign_id="edge-test", capability="secret.manage",
                request_parameters={"lifetime_days": days}, resource_id="kv:edge-test/secret", resource_action="rotate",
                executed_at=datetime.now(timezone.utc), time_token=time_token or token, outcome="success")
            return record.model_copy(update={"signature": sign_model(record, keys["executor"].private_key, "executor")})

        first = signed_use(1)
        comparison = dict(grant=grant, previous=None, admitted=0, token_head=None, token_keys=[root_key],
                          raw_token=token.to_wire(), revoked_at=None, recorded_at=first.executed_at)
        for use, options, expected_code in (
            (first, comparison, None),
            (first.model_copy(update={"request_parameters": {"lifetime_days": True}}), comparison, "grant_envelope_mismatch"),
            (first.model_copy(update={"request_parameters": {}}), comparison, "grant_envelope_mismatch"),
            (first.model_copy(update={"capability": "secret.delete"}), comparison, "grant_capability_mismatch"),
            (first, {**comparison, "admitted": grant.max_uses}, "grant_budget_exhausted"),
            (first, {**comparison, "token_keys": [keys["reader"].public_key_b64]}, "grant_time_token_invalid"),
        ):
            expected_problem = use_problem(use, **options)
            assert (expected_problem[0] if expected_problem else None) == expected_code
            compared = await client.call_tool("gm_offline_grants_use_problem", json_value({"use": use, **options}))
            assert not compared.is_error
            assert compared.structured_content == {"result": json_value(expected_problem)}
        admitted = await request("/evidence/grant-executions", expected=201, body={"evidence": first.to_wire()})
        assert admitted["status"] == "recorded" and admitted["resource_sequence"] == 1
        duplicate = await request("/evidence/grant-executions", body={"evidence": first.to_wire()})
        assert duplicate["status"] == "duplicate"
        assert duplicate["entry_digest"] == admitted["entry_digest"]
        tampered = copy.deepcopy(first.to_wire())
        tampered["outcome"] = "failure"
        refused = await request("/evidence/grant-executions", expected=422, body={"evidence": tampered})
        assert refused["error"]["code"] == "grant_use_invalid_signature"
        outside = signed_use(2, first, days=400)
        comparison_args = dict(grant=grant, previous=None, admitted=1, token_head=None, token_keys=[root_key],
                               raw_token=token.to_wire(), revoked_at=None, recorded_at=outside.executed_at)
        problem = use_problem(outside, **comparison_args)
        compared = await client.call_tool("gm_offline_grants_use_problem", json_value({"use": outside, **comparison_args}))
        assert not compared.is_error
        assert compared.structured_content == {"result": json_value(problem)}
        refused = await request("/evidence/grant-executions", expected=422, body={"evidence": outside.to_wire()})
        assert refused["error"]["code"] == problem[0] == "grant_envelope_mismatch"
        assert refused["error"]["details"]["quarantine_id"]

        refresh = TimeTokenRequest(grant_id=grant.grant_id, use_sequence=2, use_head_digest=outside.digest(),
                                   requested_at=datetime.now(timezone.utc))
        signed_request = refresh.model_copy(update={"signature": sign_model(refresh, keys["executor"].private_key, "executor")})
        forged_request = refresh.model_copy(update={"signature": sign_model(refresh, keys["reader"].private_key, "executor")})
        refused = await request("/grants/time-tokens", expected=422, body={"request": forged_request.to_wire()})
        assert refused["error"]["code"] == "time_token_request_invalid_signature"
        refreshed = await request("/grants/time-tokens", expected=201, body={"request": signed_request.to_wire()})
        next_token = TimeToken.model_validate(refreshed["time_token"])
        assert verify_model_signature(next_token, next_token.signature, root_key)
        assert next_token.use_sequence == 2 and next_token.use_head_digest == outside.digest()
        third = signed_use(3, outside, time_token=next_token)
        await request("/evidence/grant-executions", expected=201, body={"evidence": third.to_wire()})
        state = await request("/admin/grants/<grant_id>", "GET", path={"grant_id": grant.grant_id})
        assert (state["uses"], state["chain_length"], state["remaining_uses"]) == (2, 3, 3)
        uses = await request("/admin/grants/<grant_id>/uses", "GET", path={"grant_id": grant.grant_id})
        assert [u["use_sequence"] for u in uses["uses"]] == [3, 2, 1]
        listed = await request("/admin/grants", "GET", query={"status": "active", "bearer_key_id": "executor"})
        assert [g["grant_id"] for g in listed["grants"]] == [grant.grant_id]
        revoked = await request("/admin/grants/<grant_id>/revoke", path={"grant_id": grant.grant_id}, body={"reason": "test"})
        revocation = GrantRevocationRecord.model_validate(revoked["revocation"])
        assert revoked["status"] == "revoked"
        assert verify_model_signature(revocation, revocation.signature, root_key)
        fourth = signed_use(4, third, time_token=next_token)
        refused = await request("/evidence/grant-executions", expected=422, body={"evidence": fourth.to_wire()})
        assert refused["error"]["code"] == "grant_revoked"
        exported = await request("/admin/evidence/export", "GET")
        events = parse_export_lines(exported.splitlines())
        executor_keys = {"executor": ExecutorKey(key_id="executor", public_key=keys["executor"].public_key_b64,
                                                  executor_sovereign_id="edge-test")}
        verified = verify_evidence_events(events, na_public_keys=[root_key], executor_keys=executor_keys)
        assert verified.verified, verified.to_dict()
        changed = copy.deepcopy(events)
        event = next(e for e in changed if e.entry.entry_kind == "grant_execution")
        event.payload["outcome"] = "failure"
        assert not verify_evidence_events(changed, na_public_keys=[root_key], executor_keys=executor_keys).verified

    reader = replace(settings, operator_key_file=paths["reader"], operator_key_id="reader")
    async with Client(create_server(reader)) as client:
        denied = await client.call_tool(operation("/admin/grants/<grant_id>/revoke")["name"],
                                        {"path": {"grant_id": grant.grant_id}, "body": {"reason": "reader"}})
        assert denied.is_error
        assert denied.structured_content["http_status"] == 403
        assert denied.structured_content["result"]["error"]["code"] == "insufficient_operator_tier"


async def test_mcp_review_requires_independent_holders_and_core_verifies_approval(authority):
    settings, keys, paths = authority
    requester = replace(settings, operator_key_file=paths["requester"], operator_key_id="requester")
    decider = replace(settings, operator_key_file=paths["decider"], operator_key_id="decider")
    async with (Client(create_server(settings)) as actor_client,
                Client(create_server(requester)) as requester_client,
                Client(create_server(decider)) as decider_client):
        async def request(client, template, method="POST", expected=200, **arguments):
            response = await client.call_tool(operation(template, method)["name"], arguments)
            body = response.structured_content
            assert body["http_status"] == expected, body
            assert response.is_error == (expected >= 400), body
            return body["result"]

        attestation = await request(actor_client, "/admin/attestations", expected=201,
            body={"subject_id": "client", "roles": ["role:client"], "claims": {"capabilities": ["secret.manage"]}})
        now = datetime.now(timezone.utc)
        policy = await request(actor_client, "/admin/boundary-policies", expected=201, body={
            "policy_id": "review-lifetime", "valid_from": (now - timedelta(minutes=1)).isoformat(),
            "valid_until": (now + timedelta(hours=3)).isoformat(), "selector": {"capabilities": ["secret.manage"]},
            "gates": [{"gate_id": "max-lifetime", "gate_type": "max_value.v1", "order": 0,
                       "config": {"path": "request_parameters.lifetime_days", "max": 90}}]})
        await request(actor_client, "/admin/boundary-policies/<policy_id>/activate",
                      path={"policy_id": "review-lifetime"}, body={"version": policy["version"]})
        evaluated = await request(actor_client, "/admin/boundary/evaluate", expected=201,
            body={"attestation_id": attestation["attestation_id"], "requested_capability": "secret.manage",
                  "context": {"request_parameters": {"lifetime_days": 30}}})
        assert evaluated["decision"]["authorized"] is True
        subject_id = evaluated["decision"]["decision_id"]
        review_body = {"subject_kind": "decision", "subject_id": subject_id, "justification": "Independent review"}
        denied = await request(actor_client, "/admin/evidence/reviews", expected=409, body=review_body)
        assert denied["error"]["code"] == "review_requested_by_actor"
        opened = await request(requester_client, "/admin/evidence/reviews", expected=201, body=review_body)
        review_path = {"review_id": opened["review_id"]}
        queue = await request(requester_client, "/admin/evidence/remediations", "GET", query={"state": "review_pending"})
        assert [r["subject_id"] for r in queue["remediations"]] == [subject_id]
        for client, code in ((requester_client, "review_same_holder_as_requester"),
                             (actor_client, "review_same_holder_as_actor")):
            refused = await request(client, "/admin/evidence/reviews/<review_id>/decide", expected=409,
                                    path=review_path, body={"verdict": "deny"})
            assert refused["error"]["code"] == code
        decided = await request(decider_client, "/admin/evidence/reviews/<review_id>/decide",
                                path=review_path, body={"verdict": "deny", "note": "Reviewed"})
        assert decided["review_pending"] is False
        review = ReviewRecord.model_validate(decided["review"]["payload"])
        assert (review.requester_holder, review.decider_holder, review.actor_holder) == ("Reviewer", "Approver", "Actor")
        assert verify_model_signature(review, review.signature, keys["root"].public_key_b64)
        audiences = [keys["root"].public_key_b64]
        assert review_approval_problem(review, audiences) is None
        for record, pins, valid in ((review, audiences, True),
                                    (review.model_copy(update={"verdict": "uphold"}), audiences, False),
                                    (review, [keys["reader"].public_key_b64], False)):
            expected_problem = review_approval_problem(record, pins)
            assert (expected_problem is None) == valid
            compared = await decider_client.call_tool("gm_offline_remediation_review_approval_problem",
                                                     {"review": record.to_wire(), "audiences": pins})
            assert not compared.is_error, compared.structured_content
            assert compared.structured_content == {"result": json_value(expected_problem)}
        duplicate = await request(decider_client, "/admin/evidence/reviews/<review_id>/decide", expected=409,
                                  path=review_path, body={"verdict": "uphold"})
        assert duplicate["error"]["code"] == "review_already_decided"
        exported = await request(decider_client, "/admin/evidence/export", "GET")
        verified = verify_evidence_events(parse_export_lines(exported.splitlines()), na_public_keys=audiences, executor_keys={})
        assert verified.verified and verified.to_dict()["reviews"] == 1, verified.to_dict()
