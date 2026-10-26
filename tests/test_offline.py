"""Exercise the JSON boundary with real core records, not mocked verifiers."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone

import nacl.signing
import pytest
from jsonschema import Draft202012Validator

from genesismesh_mcp.offline import build_tools
from genesismesh_mcp.offline.adapter import json_value
from genesismesh_mcp.settings import Settings
from genesismesh_mcp.types import ToolError

NOW = datetime(2026, 10, 25, 12, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def environment(tmp_path_factory):
    root = tmp_path_factory.mktemp("offline-signers")
    keys = {name: nacl.signing.SigningKey.generate() for name in ("alpha", "beta", "gamma", "human")}
    files = {}
    for name, key in keys.items():
        path = root / (name + ".key")
        path.write_text(base64.b64encode(bytes(key)).decode(), encoding="utf-8")
        os.chmod(path, 0o600)
        files[name] = path
    signing_operations = frozenset(t.name for t in build_tools(Settings()) if "sign" in t.profiles)
    settings = Settings(profiles=frozenset({"read", "verify", "sign"}), signer_files=files,
                        signer_permissions={name: signing_operations for name in files})
    return settings, keys, {t.name: t for t in build_tools(settings)}


def public(environment, name="alpha"):
    return base64.b64encode(bytes(environment[1][name].verify_key)).decode()


def call(environment, name, **kwargs):
    tool = environment[2]["gm_offline_" + name]
    args = json.loads(json.dumps(json_value(kwargs)))
    return tool.handler(args)


def graph():
    pairs = [(a, b) for a in ("alpha", "beta", "gamma") for b in ("alpha", "beta", "gamma") if a != b]
    return {
        "sovereigns": [{"sovereign_id": a} for a in ("alpha", "beta", "gamma")],
        "recognition_edges": [{"from": a, "to": b, "treaty_id": a + b, "status": "active",
                               "lifecycle_state": "active", "expiry_risk": "low",
                               "valid_from": (NOW - timedelta(days=1)).isoformat(),
                               "expires_at": (NOW + timedelta(days=10)).isoformat()} for a, b in pairs],
        "active_treaties": [{"treaty_id": a + b, "issuer_sovereign_id": a, "subject_sovereign_id": b,
                             "scope": {"allowed_roles": ["read", "write"]}} for a, b in pairs],
        "revoked_trust_material": [],
    }


@pytest.fixture(scope="module")
def agreement(environment):
    terms = {"capabilities": ["read", "write"], "scope": {},
             "valid_from": NOW - timedelta(minutes=1), "valid_until": NOW + timedelta(days=1)}
    offer = call(environment, "agreement_build_offer", offerer_sovereign_id="alpha", responder_sovereign_id="beta",
                 requested_terms=terms, graph=graph(), signer_ref="alpha", issued_by="alpha",
                 expires_at=NOW + timedelta(hours=1), now=NOW)
    record = call(environment, "agreement_accept_offer", offer=offer, graph=graph(), signer_ref="beta",
                  issued_by="beta", now=NOW)
    return call(environment, "agreement_cosign_agreement", record=record, signer_ref="alpha", issued_by="alpha")


def test_every_registered_schema_is_valid_and_has_no_key_input(environment):
    for tool in environment[2].values():
        Draft202012Validator.check_schema(tool.input_schema)
        props = tool.input_schema["properties"]
        assert not {"signing_key", "private_key", "agent_signing_key", "human_signing_key", "module", "function"} & props.keys()
    assert len(environment[2]) >= 120


def test_signer_profile_cannot_be_bypassed_by_direct_invocation():
    tools = {t.name: t for t in build_tools(Settings())}
    with pytest.raises(ToolError, match="not enabled"):
        tools["gm_offline_freshness_issue_freshness_proof"].handler({})


def test_unknown_signer_and_unknown_input_rejected(environment):
    args = dict(feed_sovereign_id="alpha", feed_sequence=2, feed_digest="a" * 64,
                issued_by="alpha", issuer_sovereign_id="alpha", now=NOW)
    with pytest.raises(ToolError, match="not configured"):
        call(environment, "freshness_issue_freshness_proof", **args, signer_ref="../../key")
    with pytest.raises(ValueError, match="schema"):
        call(environment, "freshness_issue_freshness_proof", **args, signer_ref="alpha", private_key="SECRET")


def test_freshness_round_trip_stale_and_tampered(environment):
    proof = call(environment, "freshness_issue_freshness_proof", feed_sovereign_id="alpha", feed_sequence=2,
                 feed_digest="a" * 64, issued_by="alpha", issuer_sovereign_id="alpha", signer_ref="alpha", now=NOW)
    args = dict(proof=proof, issuer_public_keys=[public(environment)], required_sequence=2, at_time=NOW)
    assert call(environment, "freshness_verify_freshness_proof", **args)["valid"]
    assert not call(environment, "freshness_verify_freshness_proof", **{**args, "required_sequence": 3})["valid"]
    changed = copy.deepcopy(proof)
    changed["feed_digest"] = "b" * 64
    assert not call(environment, "freshness_verify_freshness_proof", **{**args, "proof": changed})["valid"]
    assert not call(environment, "freshness_verify_freshness_proof", **{**args, "at_time": NOW + timedelta(hours=1)})["valid"]
    changed["unrecognized_signed_field"] = "cannot silently drop"
    with pytest.raises(ValueError, match="schema"):
        call(environment, "freshness_verify_freshness_proof", **{**args, "proof": changed})


def test_agreement_and_delegation_roundtrip_and_widening_refused(environment, agreement):
    verified = call(environment, "agreement_verify_agreement", record=agreement,
                    offerer_public_keys=[public(environment)], responder_public_keys=[public(environment, "beta")])
    assert verified["accepted"]
    terms = {**agreement["agreed_terms"], "capabilities": ["read"]}
    delegated = call(environment, "delegation_build_delegation", parent=agreement, delegated_terms=terms,
                     graph=graph(), signer_ref="beta", delegator_sovereign_id="beta", delegate_sovereign_id="gamma",
                     issued_by="beta", now=NOW)
    delegated = call(environment, "delegation_cosign_delegation", record=delegated, graph=graph(), signer_ref="gamma",
                     issued_by="gamma", now=NOW)
    chain = {"root": agreement, "hops": [delegated]}
    result = call(environment, "delegation_verify_delegation_chain", chain=chain,
                  root_offerer_public_keys=[public(environment)], root_responder_public_keys=[public(environment, "beta")],
                  per_hop_keys={"beta": [public(environment, "beta")], "gamma": [public(environment, "gamma")]})
    assert result["accepted"]
    with pytest.raises(ValueError):
        call(environment, "delegation_build_delegation", parent=agreement,
             delegated_terms={**terms, "capabilities": ["admin"]}, graph=graph(), signer_ref="beta",
             delegator_sovereign_id="beta", delegate_sovereign_id="gamma", issued_by="beta", now=NOW)


def test_invocation_token_capability_bearer_and_usage(environment, agreement):
    token = call(environment, "invocation_token_issue_invocation_token", agreement=agreement, bearer_sovereign_id="beta",
                 capabilities=["read"], signer_ref="alpha", issued_by="alpha", max_invocations=1, now=NOW)
    args = dict(token=token, issuer_public_keys=[public(environment)], requested_capability="read",
                bearer_sovereign_id="beta", at_time=NOW)
    assert call(environment, "invocation_token_verify_invocation_token", **args)["valid"]
    assert not call(environment, "invocation_token_verify_invocation_token", **{**args, "requested_capability": "write"})["valid"]
    use = call(environment, "invocation_token_record_invocation_use", token=token, action_tag="test", outcome="success",
               signer_ref="beta", used_by="beta", now=NOW)
    assert not call(environment, "invocation_token_verify_invocation_token", **{**args, "use_records": [use]})["valid"]


def test_disclosure_merkle_proof_detects_tampering(environment, agreement):
    commitment = call(environment, "selective_disclosure_commit_capabilities", capabilities=["read", "write"],
                      agreement=agreement, signer_ref="alpha", issued_by="alpha", now=NOW)
    proof = call(environment, "selective_disclosure_prove_capability_membership", capability="read",
                 capabilities=["read", "write"], commitment=commitment, prover_sovereign_id="beta", now=NOW)
    args = dict(proof=proof, commitment=commitment, issuer_public_keys=[public(environment)], now=NOW)
    assert call(environment, "selective_disclosure_verify_capability_proof", **args)["valid"]
    proof["revealed_capability"] = "admin"
    assert not call(environment, "selective_disclosure_verify_capability_proof", **args)["valid"]


def test_privacy_base64_roundtrip_and_allocation_bound(environment):
    profile = call(environment, "privacy_create_privacy_profile", profile={"sovereign_id": "alpha", "message_length_block_bytes": 8},
                   signer_ref="alpha")
    result = call(environment, "privacy_apply_privacy_profile", payload=base64.b64encode(b"abc").decode(),
                  headers={"X-Secret": "hidden"}, dispatch_time=NOW, sender_sovereign_id="alpha", profile=profile,
                  signer_ref="alpha", now=NOW)
    assert base64.b64decode(result[1]).startswith(b"abc")
    assert len(base64.b64decode(result[1])) == 8
    assert "X-Secret" not in result[0]["retained_headers"]
    with pytest.raises(ValueError, match="base64"):
        call(environment, "privacy_normalize_payload_length", payload="%%%", block_bytes=8)
    with pytest.raises(ValueError, match="bound"):
        call(environment, "privacy_normalize_payload_length", payload="YQ==", block_bytes=10**10)


def test_discovery_roundtrip_replay_and_expiry(environment):
    record = call(environment, "overlay_discovery_create_discovery_record", sovereign_id="alpha",
                  na_public_key_b64=public(environment), endpoints=["https://example.invalid"], capabilities_hash="a" * 64,
                  signer_ref="alpha", now=NOW)
    assert call(environment, "overlay_discovery_verify_discovery_record", record=record, at_time=NOW)[0]
    assert not call(environment, "overlay_discovery_verify_discovery_record", record=record, at_time=NOW,
                    known_sequence_no=record["sequence_no"] + 1)[0]
    assert not call(environment, "overlay_discovery_verify_discovery_record", record=record, at_time=NOW + timedelta(days=2))[0]


def test_risk_signal_signature_and_decay(environment):
    signal = call(environment, "risk_signal_create_risk_signal", from_sovereign_id="alpha", to_sovereign_id="beta",
                  signer_ref="alpha", now=NOW)
    assert call(environment, "risk_signal_check_risk_signal_gate", signal=signal, minimum_signal=0.1,
                issuer_public_keys=[public(environment)], at_time=NOW)[0]
    assert not call(environment, "risk_signal_check_risk_signal_gate", signal=signal, minimum_signal=0.1,
                    issuer_public_keys=[public(environment, "beta")], at_time=NOW)[0]
    decayed = call(environment, "risk_signal_decay_risk_signal", signal=signal, signer_ref="alpha", now=NOW + timedelta(hours=1))
    assert decayed["signature"]


def test_human_oversight_dual_signature_and_expiry(environment):
    policy = {"policy_id": "policy-one", "agreement_id": "a", "human_sovereign_id": "human", "allowed_capabilities": ["write"],
              "value_threshold": 10, "created_at": NOW}
    request, evaluation = call(environment, "oversight_propose_commitment", policy=policy,
                               proposed_action={"capability": "write", "value": 100}, requesting_sovereign_id="alpha",
                               agent_signer_ref="alpha", issued_by="alpha", now=NOW)
    assert evaluation["result"] == "human_approve"
    response, commitment = call(environment, "oversight_approve_commitment", request=request, policy=policy,
                                human_signer_ref="human", issued_by="human", now=NOW)
    assert response["approved"]
    args = dict(commitment=commitment, agent_public_keys=[public(environment)], human_public_keys=[public(environment, "human")],
                request=request, at_time=NOW)
    assert call(environment, "oversight_verify_dual_signed_commitment", **args)["valid"]
    assert not call(environment, "oversight_verify_dual_signed_commitment", **{**args, "at_time": NOW + timedelta(days=1)})["valid"]


def test_context_integrity_detects_changed_system_prompt(environment):
    tree = {"system_prompt_hash": hashlib.sha256(b"system").hexdigest(), "turn_count": 0,
            "message_hashes": [], "tool_result_hashes": [], "total_token_estimate": 100}
    record = call(environment, "context_integrity_create_context_integrity_record", agent_sovereign_id="alpha",
                  decision_id="decision", base_context_tree=tree, declared_segments=[], signer_ref="alpha", now=NOW)
    args = dict(record=record, final_context_tree=tree, observed_segments=[], agent_public_keys=[public(environment)], at_time=NOW)
    assert call(environment, "context_integrity_verify_context_integrity", **args)[0]
    assert not call(environment, "context_integrity_verify_context_integrity",
                    **{**args, "final_context_tree": {**tree, "system_prompt_hash": "f" * 64}})[0]


def test_purge_receipt_merkle_proof_and_wrong_key(environment):
    identity = {"consensus_id": "c", "decision_id": "d", "bearer_sovereign_id": "beta",
                "issued_at": NOW - timedelta(hours=2), "expires_at": NOW - timedelta(hours=1), "allowed_capabilities": ["read"]}
    receipt = call(environment, "purge_create_nullification_receipt", identity=identity,
                   purging_sovereign_id="alpha", signer_ref="alpha", now=NOW)
    root, levels = call(environment, "purge_build_nullification_registry", receipts=[receipt], operator_sovereign_id="alpha",
                        signer_ref="alpha", now=NOW)
    proof = call(environment, "purge_prove_nullification_inclusion", receipt_id=receipt["receipt_id"], receipts=[receipt],
                 levels=levels, registry_root=root)
    args = dict(proof=proof, registry_root=root, expected_receipt=receipt, issuer_public_keys=[public(environment)])
    assert call(environment, "purge_verify_nullification_inclusion", **args)[0]
    assert not call(environment, "purge_verify_nullification_inclusion", **{**args, "issuer_public_keys": [public(environment, "beta")]})[0]


def test_remediation_holder_separation_and_illegal_transition(environment):
    from genesis_mesh.trust.remediation import TransitionRefused

    result = call(environment, "remediation_review_holder_problem", decided_by="alpha", decider_holder="person-one",
                  requested_by="beta", requester_holder="person-two", actor="gamma", actor_holder="person-one")
    assert result and result[0] == "review_same_holder_as_actor"
    with pytest.raises(TransitionRefused):
        call(environment, "remediation_next_state", state="nonsense", event="nonsense")


def test_malformed_audit_pack_returns_negative_result(environment):
    result = call(environment, "audit_pack_verify_audit_pack", files={}, root_public_key=public(environment), held_anchors=[])
    assert result["verified"] is False
    assert result["failures"]


def test_bundle_validation_reports_errors_without_fetch(environment):
    result = call(environment, "trust_bundle_validate_trust_bundle", bundle={})
    assert result["errors"]


@pytest.fixture(scope="module")
def decision(environment, agreement):
    context = {"agreement_id": agreement["agreement_id"], "requester_sovereign_id": "alpha",
               "provider_sovereign_id": "beta", "requested_capability": "read", "requested_at": NOW}
    return call(environment, "context_evaluate_context", context=context, agreement=agreement,
                operator_sovereign_id="alpha", signer_ref="alpha", issued_by="alpha", now=NOW)


def test_boundary_decision_denial_and_justification_are_preserved(environment, agreement, decision):
    assert decision["decision"]["authorized"] is True
    assert decision["executed"] is False
    verified = call(environment, "context_verify_boundary_decision", decision=decision["decision"],
                    operator_public_keys=[public(environment)], now=NOW)
    assert verified["accepted"] and verified["authorized"]
    proof = call(environment, "justification_verify_justification_proof", proof=decision["justification"],
                 issuer_public_keys=[public(environment)], decision=decision["decision"])
    assert proof["valid"]
    denied = call(environment, "context_evaluate_context", context={"agreement_id": agreement["agreement_id"],
                  "requester_sovereign_id": "alpha", "provider_sovereign_id": "beta", "requested_capability": "admin",
                  "requested_at": NOW}, agreement=agreement, operator_sovereign_id="alpha", signer_ref="alpha",
                  issued_by="alpha", now=NOW)
    assert denied["decision"]["authorized"] is False
    assert denied["decision"]["denial_reason"]
    verified_denial = call(environment, "context_verify_boundary_decision", decision=denied["decision"],
                           operator_public_keys=[public(environment)], now=NOW)
    assert verified_denial["accepted"] and verified_denial["authorized"] is False


def test_consensus_vote_proof_identity_and_threshold(environment, decision):
    proof = decision["justification"]
    vote = call(environment, "consensus_cast_validator_vote", justification_proof=proof, validator_sovereign_id="beta",
                vote=True, signer_ref="beta", now=NOW)
    consensus = call(environment, "consensus_assemble_consensus_proof", justification_proof=proof, votes=[vote],
                     required_threshold=1, validator_sovereign_ids=["beta"], assembler_signer_ref="alpha",
                     issued_by="alpha", cascade_threshold=0, now=NOW)
    result = call(environment, "consensus_verify_consensus_proof", proof=consensus,
                  validator_public_keys={"beta": public(environment, "beta")}, assembler_public_keys=[public(environment)],
                  justification_proof=proof, cascade_threshold=0, at_time=NOW)
    assert result["valid"]
    with pytest.raises(ValueError, match="threshold"):
        call(environment, "consensus_assemble_consensus_proof", justification_proof=proof, votes=[vote],
             required_threshold=2, validator_sovereign_ids=["beta", "gamma"], assembler_signer_ref="alpha",
             issued_by="alpha", cascade_threshold=0, now=NOW)
    identity = call(environment, "consensus_issue_ephemeral_identity", consensus_proof=consensus,
                    bearer_sovereign_id="beta", allowed_capabilities=["read"], signer_ref="alpha", issued_by="alpha", now=NOW)
    args = dict(identity=identity, issuer_public_keys=[public(environment)], requested_capability="read",
                bearer_sovereign_id="beta", consensus_proof=consensus, at_time=NOW)
    assert call(environment, "consensus_verify_ephemeral_identity", **args)["valid"]
    assert not call(environment, "consensus_verify_ephemeral_identity", **{**args, "bearer_sovereign_id": "gamma"})["valid"]


def test_data_policy_intent_record_and_unauthorized_source(environment):
    policy = call(environment, "data_usage_create_data_policy", policy={"licensor_sovereign_id": "alpha",
                   "licensee_sovereign_id": "beta", "allowed_source_ids": ["dataset"], "allowed_access_types": ["read"],
                   "valid_from": NOW - timedelta(minutes=1), "valid_until": NOW + timedelta(days=1)},
                   signer_ref="alpha", issued_by="alpha")
    source = {"source_id": "dataset", "source_type": "synthetic", "owner_sovereign_id": "alpha"}
    intent = call(environment, "data_usage_create_data_access_intent", agent_sovereign_id="beta", decision_id="d",
                  sources=[source], access_types=["read"], signer_ref="beta", now=NOW)
    args = dict(intent=intent, policy=policy, agent_public_keys=[public(environment, "beta")], at_time=NOW)
    assert call(environment, "data_usage_verify_data_access_intent", **args)[0]
    record = call(environment, "data_usage_create_data_record", record={"intent_id": intent["intent_id"],
                   "agent_sovereign_id": "beta", "decision_id": "d", "accessed_sources": [source],
                   "access_types_used": ["read"], "accessed_at": NOW}, signer_ref="beta", issued_by="beta")
    assert call(environment, "data_usage_verify_data_access_record", record=record, **args)[0]
    denied_intent = call(environment, "data_usage_create_data_access_intent", agent_sovereign_id="beta", decision_id="d",
                         sources=[{**source, "source_id": "not-licensed"}], access_types=["read"], signer_ref="beta", now=NOW)
    assert not call(environment, "data_usage_verify_data_access_intent", **{**args, "intent": denied_intent})[0]


def test_jwt_interop_checks_signature(environment, decision):
    token = call(environment, "jose_decision_to_jwt", decision=decision["decision"], signer_ref="alpha")
    assert call(environment, "jose_jwt_to_decision_claims", token=token, verify_key_b64=public(environment))
    assert call(environment, "jose_jwt_to_decision_claims", token=token, verify_key_b64=public(environment, "beta")) is None


def test_execution_evidence_chain_checks_tampering(environment, decision):
    first = call(environment, "execution_record_execution", decision=decision["decision"], executor_sovereign_id="beta",
                 executed_capability="read", outcome="success", signer_ref="beta", issued_by="beta", now=NOW)
    args = dict(chain={"decision_id": decision["decision"]["decision_id"], "records": [first]},
                executor_public_keys_by_sovereign={"beta": [public(environment, "beta")]}, decision=decision["decision"])
    assert call(environment, "execution_verify_evidence_chain", **args)["verified"]
    changed = copy.deepcopy(first)
    changed["outcome"] = "failure"
    assert not call(environment, "execution_verify_evidence_chain", **{**args, "chain": {**args["chain"], "records": [changed]}})["verified"]


def test_direct_adapter_enforces_input_and_output_limits(environment):
    settings = Settings(max_input_bytes=1024, max_output_bytes=1024)
    tools = {t.name: t for t in build_tools(settings)}
    with pytest.raises(ValueError, match="input limit"):
        tools["gm_offline_context_integrity_scan_for_injection_markers"].handler({"content": "a" * 2000})
    with pytest.raises(ValueError, match="output limit"):
        tools["gm_offline_privacy_normalize_payload_length"].handler({"payload": "YQ==", "block_bytes": 1024})


def test_signer_permission_is_specific_to_operation(environment):
    settings = Settings(profiles=frozenset({"sign"}), signer_files={"alpha": environment[0].signer_files["alpha"]},
                        signer_permissions={"alpha": frozenset({"gm_offline_freshness_issue_freshness_proof"})})
    tools = {tool.name: tool for tool in build_tools(settings)}
    with pytest.raises(ToolError, match="not authorized"):
        tools["gm_offline_risk_signal_create_risk_signal"].handler(
            {"from_sovereign_id": "alpha", "to_sovereign_id": "beta", "signer_ref": "alpha"})


def test_verified_key_history_output_can_be_supplied_to_evidence_verifier(environment):
    from genesis_mesh.crypto import sign_model
    from genesis_mesh.models import GenesisBlock, NetworkAuthority, PolicyManifestRef

    block = GenesisBlock(network_name="alpha", network_version="1.8.1", root_public_key=public(environment),
                         network_authority=NetworkAuthority(public_key=public(environment, "beta"),
                                                            valid_from=NOW - timedelta(days=1), valid_to=NOW + timedelta(days=1)),
                         policy_manifest=PolicyManifestRef(hash="sha256:" + "a" * 64))
    block.signatures.append(sign_model(block, environment[1]["alpha"], "alpha"))
    assert call(environment, "genesis_verify_genesis", block=json_value(block), root_public_key=public(environment))["valid"]
    assert not call(environment, "genesis_verify_genesis", block=json_value(block), root_public_key=public(environment, "gamma"))["valid"]
    assert not call(environment, "genesis_verify_genesis", block={**json_value(block), "signatures": []}, root_public_key=public(environment))["valid"]
    result = call(environment, "key_succession_verify_key_history", genesis=json_value(block), successions=[],
                  root_public_key=public(environment))
    assert result["verified"]
    assert result["history"]["vouching_grace"] == "P1D"
    evidence = call(environment, "evidence_store_verify_evidence_events", events=[], executor_keys={},
                    na_public_keys=result["history"])
    assert evidence["verified"]
    refused = call(environment, "key_succession_verify_key_history", genesis=json_value(block), successions=[],
                   root_public_key=public(environment, "gamma"))
    assert not refused["verified"]


def test_signed_model_serializer_honors_wire_omissions(environment):
    from genesis_mesh.models.key_succession import KeySuccessionRecord

    succession = KeySuccessionRecord(sovereign_id="alpha", key_sequence=2,
                                    previous_key_id="alpha", previous_public_key=public(environment),
                                    new_key_id="beta", new_public_key=public(environment, "beta"),
                                    effective_at=NOW, new_valid_to=NOW + timedelta(days=1), issued_at=NOW)
    assert "previous_succession_digest" not in json_value(succession)
    from genesis_mesh.models.boundary_policy import BoundaryPolicy
    policy = BoundaryPolicy(policy_id="policy", version=1, issuer_sovereign_id="alpha", issued_by="alpha",
                            issued_at=NOW, valid_from=NOW, valid_until=NOW + timedelta(days=1))
    assert "remediation" not in policy.model_dump(mode="json")
    assert "remediation" not in json_value(policy)


def test_detached_and_typed_artifact_signature_verifiers(environment):
    signature = environment[1]["alpha"].sign(b"test payload").signature
    args = dict(data=base64.b64encode(b"test payload").decode(), signature_b64=base64.b64encode(signature).decode(),
                public_key=public(environment))
    assert call(environment, "crypto_verify_detached_signature", **args)["valid"]
    assert not call(environment, "crypto_verify_detached_signature", **{**args, "data": "eA=="})["valid"]
    proof = call(environment, "freshness_issue_freshness_proof", feed_sovereign_id="alpha", feed_sequence=2,
                 feed_digest="a" * 64, issued_by="alpha", issuer_sovereign_id="alpha", signer_ref="alpha", now=NOW)
    result = call(environment, "crypto_verify_artifact", artifact_type="genesis_mesh.models.freshness:FreshnessProof",
                  artifact=proof, signature=proof["signature"], public_key=public(environment))
    assert result == {"valid": True, "verification_scope": "signature_only", "artifact_type": "genesis_mesh.models.freshness:FreshnessProof"}
    with pytest.raises(ValueError, match="schema"):
        call(environment, "crypto_verify_artifact", artifact_type="os:system", artifact={},
             signature=proof["signature"], public_key=public(environment))


def test_guard_receipt_verification_cannot_launch_a_process(environment):
    from genesis_mesh.crypto import sign_model
    from genesis_mesh.models.mediation import MediatedExecutionReceipt

    receipt = MediatedExecutionReceipt(request_id="r", agent_sovereign_id="beta", capability="read", decision_id="d",
                                       subprocess_pid=123, mediated_at=NOW, guard_sovereign_id="alpha")
    missing = call(environment, "mediation_verify_guard_receipt", receipt=json_value(receipt), guard_public_key=public(environment))
    assert missing == {"valid": False, "reason": "missing_signature"}
    receipt.signature = sign_model(receipt, environment[1]["alpha"], "alpha")
    assert call(environment, "mediation_verify_guard_receipt", receipt=json_value(receipt), guard_public_key=public(environment))["valid"]
    assert not call(environment, "mediation_verify_guard_receipt", receipt=json_value(receipt), guard_public_key=public(environment, "beta"))["valid"]


def test_audit_and_atlas_refuse_excessive_work_before_core_processing(environment):
    changes = [{"index": i, "resource_id": "resource", "action": "update", "changed_at": NOW} for i in range(201)]
    with pytest.raises(ValueError, match="comparison budget"):
        call(environment, "audit_pack_verify_audit_pack", files={"entries.jsonl": base64.b64encode(b"{}\n" * 501).decode()},
             root_public_key=public(environment), held_anchors=[], changes=changes)
    with pytest.raises(ValueError, match="graph-work budget"):
        call(environment, "atlas_build_trust_path_cache", pairs=[["alpha", "beta"]] * 201,
             graph={"sovereigns": [{"sovereign_id": str(i)} for i in range(501)]},
             operator_sovereign_id="alpha", signer_ref="alpha", now=NOW)


def test_public_node_key_helpers_validate_key_length(environment):
    key = public(environment)
    assert call(environment, "node_auth_decode_ed25519_public_key", public_key_b64=key) == key
    expected = "edge-" + hashlib.sha256(base64.b64decode(key)).hexdigest()[:32]
    assert call(environment, "node_auth_executor_key_id", public_key_b64=key) == expected
    with pytest.raises(ValueError, match="32 bytes"):
        call(environment, "node_auth_decode_ed25519_public_key", public_key_b64="YQ==")


def test_succession_proof_is_bound_to_named_new_key(environment):
    from genesis_mesh.crypto import verify_model_signature
    from genesis_mesh.models.key_succession import KeySuccessionRecord

    record = KeySuccessionRecord(sovereign_id="alpha", key_sequence=2,
                                previous_key_id="alpha", previous_public_key=public(environment),
                                new_key_id="beta", new_public_key=public(environment, "beta"),
                                effective_at=NOW, new_valid_to=NOW + timedelta(days=1), issued_at=NOW)
    result = call(environment, "key_succession_prove_succession", record=record, signer_ref="beta")
    assert "previous_succession_digest" not in result
    signed = KeySuccessionRecord.model_validate(result)
    assert len(signed.signatures) == 1
    assert signed.signatures[0].key_id == "beta"
    assert verify_model_signature(signed, signed.signatures[0], public(environment, "beta"))
    assert not verify_model_signature(signed, signed.signatures[0], public(environment))
    changed = signed.model_copy(update={"new_valid_to": NOW + timedelta(days=2)})
    assert not verify_model_signature(changed, signed.signatures[0], public(environment, "beta"))
    with pytest.raises(ValueError, match="not the new key"):
        call(environment, "key_succession_prove_succession", record=record, signer_ref="alpha")


def test_proof_inspection_distinguishes_summary_from_cryptographic_proof(environment):
    bundle = {"proof": "remote-sovereign-recognition-revocation", "attestation_id": "a", "treaty_id": "t", "feed_id": "f",
              "acceptor": {"network_name": "alpha"}, "issuer": {"network_name": "beta"},
              "pre_revocation": {"accepted": True, "reason": "accepted"},
              "post_revocation": {"accepted": False, "reason": "attestation_locally_revoked"},
              "trust_path": {"trusted": True, "from": "alpha", "to": "beta", "hop_count": 1},
              "connectome_summary": {"sovereign_count": 2, "active_edge_count": 1,
                                     "imported_revocation_count": 1, "revoked_trust_material_count": 1}}
    result = call(environment, "proof_inspect_proof_bundle", bundle=bundle)
    assert result["valid"] and result["signatures_verified"] is False
    assert result["verification_scope"] == "summary_consistency_only"
    tampered = copy.deepcopy(bundle)
    tampered["post_revocation"]["accepted"] = True
    assert not call(environment, "proof_inspect_proof_bundle", bundle=tampered)["valid"]
