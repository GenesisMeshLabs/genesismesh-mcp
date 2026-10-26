"""Nonempty real-core scenarios for the remaining offline protocol families."""

from __future__ import annotations

import base64
import copy
from datetime import timedelta

import pytest
from genesis_mesh.crypto import verify_model_signature
from genesis_mesh.models.atlas import PrunedAtlasExport, TrustPathEntry
from genesis_mesh.models.attestation import AttestationPolicy, ModelAttestation
from genesis_mesh.models.overlay_discovery import DiscoveryFeed
from genesis_mesh.models.oversight import HumanApprovalResponse
from genesis_mesh.models.risk_signal import PeerRiskSignal, RiskSignalUpdate
from test_offline import NOW, call, graph, public
from test_offline import agreement as agreement
from test_offline import decision as decision
from test_offline import environment as environment


def test_counter_negotiation_narrows_scope_and_preserves_signatures(environment):
    terms = {"capabilities": ["read", "write"], "scope": {},
             "valid_from": NOW - timedelta(minutes=1), "valid_until": NOW + timedelta(days=1)}
    offer = call(environment, "agreement_build_offer", offerer_sovereign_id="alpha", responder_sovereign_id="beta",
                 requested_terms=terms, graph=graph(), signer_ref="alpha", issued_by="alpha",
                 expires_at=NOW + timedelta(hours=1), now=NOW)
    counter = call(environment, "agreement_build_counter", offer=offer, offered_terms={**terms, "capabilities": ["read"]},
                   graph=graph(), signer_ref="beta", issued_by="beta", now=NOW)
    record = call(environment, "agreement_accept_counter", counter=counter, original_offer=offer,
                  signer_ref="alpha", issued_by="alpha", now=NOW)
    checked = call(environment, "agreement_verify_agreement", record=record,
                   offerer_public_keys=[public(environment)], responder_public_keys=[public(environment, "beta")])
    assert checked["accepted"]
    assert record["agreed_terms"]["capabilities"] == ["read"]
    with pytest.raises(ValueError, match="exceed|subset|widen"):
        call(environment, "agreement_build_counter", offer=offer, offered_terms={**terms, "capabilities": ["admin"]},
             graph=graph(), signer_ref="beta", issued_by="beta", now=NOW)


@pytest.fixture
def trust_evidence(environment):
    exported = graph()
    decision = call(environment, "decision_evaluate_trust_decision", graph=exported,
                    source_sovereign_id="alpha", target_sovereign_id="beta", requested_roles=["read"], now=NOW)
    assert decision["trusted"] and decision["verdict"] == "warn"
    assert decision["signals"]
    digest = call(environment, "evidence_graph_digest_from_export", graph=exported)
    evidence = call(environment, "evidence_build_trust_evidence", decision=decision, issuer_sovereign_id="alpha",
                    graph_digest=digest, issued_by="alpha", signer_ref="alpha", now=NOW)
    return exported, digest, evidence


def test_graph_decisions_and_portable_evidence_detect_wrong_graph_and_key(environment, trust_evidence):
    exported, digest, evidence = trust_evidence
    checked = call(environment, "evidence_verify_trust_evidence", evidence=evidence,
                   issuer_public_keys=[public(environment)], expected_graph_digest=digest)
    assert checked["accepted"] and checked["verdict"] == "warn"
    for pins, expected_digest in (([public(environment, "beta")], digest), ([public(environment)], "0" * 64)):
        assert not call(environment, "evidence_verify_trust_evidence", evidence=evidence,
                        issuer_public_keys=pins, expected_graph_digest=expected_digest)["accepted"]
    denied = call(environment, "decision_evaluate_trust_decision", graph={**exported, "recognition_edges": []},
                  source_sovereign_id="alpha", target_sovereign_id="beta", now=NOW)
    assert denied["trusted"] is False and denied["verdict"] == "block"
    view = call(environment, "connectome_build_connectome_view", graph=exported)
    assert view["sovereigns"] == exported["sovereigns"]
    assert view["recognition_edges"] == exported["recognition_edges"]
    assert view["summary"]["sovereign_count"] == 3
    assert view["summary"]["active_edge_count"] == 6
    explanation = call(environment, "connectome_explain_trust_path", graph=exported,
                       source_sovereign_id="alpha", target_sovereign_id="beta")
    assert explanation["trusted"] is True


def test_atlas_cache_roundtrip_staleness_and_signed_pruning(environment):
    exported = graph()
    entry = call(environment, "atlas_cache_trust_path", source="alpha", target="beta", graph=exported,
                 operator_sovereign_id="alpha", signer_ref="alpha", now=NOW)
    entry_model = TrustPathEntry.model_validate(entry)
    assert verify_model_signature(entry_model, entry_model.signature, public(environment))
    cache = call(environment, "atlas_build_trust_path_cache", pairs=[["alpha", "beta"]], graph=exported,
                 operator_sovereign_id="alpha", signer_ref="alpha", now=NOW)
    found = call(environment, "atlas_lookup_trust_path", cache=cache, source="alpha", target="beta", at_time=NOW)
    assert found is not None and found["source_sovereign_id"] == "alpha"
    assert call(environment, "atlas_lookup_trust_path", cache=cache, source="alpha", target="beta",
                at_time=NOW + timedelta(hours=1)) is None
    pruned, audit = call(environment, "atlas_prune_graph", graph=exported,
                         policy={"operator_sovereign_id": "alpha"}, operator_sovereign_id="alpha",
                         signer_ref="alpha", now=NOW)
    assert pruned["sovereigns"] == exported["sovereigns"]
    audit_model = PrunedAtlasExport.model_validate(audit)
    assert verify_model_signature(audit_model, audit_model.signature, public(environment))
    assert audit["removed_edge_count"] == 0
    with pytest.raises(ValueError, match="old"):
        call(environment, "atlas_prune_graph", graph={**exported, "exported_at": (NOW - timedelta(days=2)).isoformat()},
             policy={"operator_sovereign_id": "alpha"}, operator_sovereign_id="alpha", signer_ref="alpha", now=NOW)


def test_spiffe_and_vc_bridges_keep_evidence_and_reject_foreign_metadata(environment, agreement, trust_evidence):
    svid = call(environment, "spiffe_agreement_to_svid", record=agreement)
    fields = call(environment, "spiffe_svid_to_agreement_fields", svid=svid)
    assert fields["agreement_id"] == agreement["agreement_id"]
    assert fields["gm_signatures"] == agreement["signatures"]
    assert call(environment, "spiffe_svid_to_agreement_fields", svid={"spiffe_id": "spiffe://foreign/workload"}) is None
    agreement_vc = call(environment, "w3c_vc_agreement_to_vc", record=agreement)
    assert agreement_vc["id"] == "urn:gm:agreement:" + agreement["agreement_id"]
    assert agreement_vc["issuer"] == "did:gm:" + agreement["offerer_sovereign_id"]
    assert agreement_vc["credentialSubject"]["id"] == "did:gm:" + agreement["responder_sovereign_id"]
    assert agreement_vc["credentialSubject"]["capabilities"] == agreement["agreed_terms"]["capabilities"]
    assert agreement_vc["proof"]["_gm_signatures"] == agreement["signatures"]
    evidence = trust_evidence[2]
    vc = call(environment, "w3c_vc_trust_evidence_to_vc", evidence=evidence)
    recovered = call(environment, "w3c_vc_vc_to_trust_evidence_fields", vc=vc)
    assert recovered["evidence_id"] == evidence["evidence_id"]
    assert recovered["gm_signatures"] == evidence["signatures"]
    assert call(environment, "w3c_vc_vc_to_trust_evidence_fields", vc={}) is None


def test_logic_attestation_policy_binds_model_prompt_tools_and_token(environment):
    attestation = call(environment, "logic_attestation_create_model_attestation", agent_sovereign_id="alpha",
                       model_id="model-one", model_version_tag="pinned", system_prompt="bounded instructions",
                       tool_ids=["read", "verify"], token_id="token", signer_ref="alpha", now=NOW)
    policy = call(environment, "attestation_create_attestation_policy", policy={"operator_sovereign_id": "beta",
                  "valid_from": NOW, "valid_until": NOW + timedelta(hours=1), "allowed_model_ids": ["model-one"],
                  "allowed_system_prompt_hashes": [attestation["system_prompt_hash"]],
                  "allowed_tool_manifest_hashes": [attestation["tool_manifest_hash"]], "require_bound_token": True},
                  signer_ref="beta", issued_by="beta")
    assert verify_model_signature(AttestationPolicy.model_validate(policy),
                                  AttestationPolicy.model_validate(policy).signature, public(environment, "beta"))
    verified = call(environment, "logic_attestation_verify_model_attestation", attestation=attestation,
                    policy=policy, agent_public_keys=[public(environment)], at_time=NOW)
    assert verified == [True, "valid"]
    assert verify_model_signature(ModelAttestation.model_validate(attestation),
                                  ModelAttestation.model_validate(attestation).signature, public(environment))
    for changed in ({**attestation, "model_id": "other"}, {**attestation, "token_id": None}):
        assert not call(environment, "logic_attestation_verify_model_attestation", attestation=changed,
                        policy=policy, agent_public_keys=[public(environment)], at_time=NOW)[0]
    assert not call(environment, "logic_attestation_verify_model_attestation", attestation=attestation,
                    policy=policy, agent_public_keys=[public(environment)], at_time=NOW + timedelta(days=1))[0]


def test_oversight_evaluation_and_signed_rejection_do_not_claim_approval(environment):
    policy = {"policy_id": "policy", "agreement_id": "a", "human_sovereign_id": "human",
              "allowed_capabilities": ["write"], "value_threshold": 10, "created_at": NOW}
    args = dict(policy=policy, proposed_action={"capability": "write", "value": 100}, requesting_sovereign_id="alpha", now=NOW)
    assert call(environment, "oversight_evaluate_oversight_policy", **args)["result"] == "human_approve"
    request, _ = call(environment, "oversight_propose_commitment", **args, agent_signer_ref="alpha", issued_by="alpha")
    refused = call(environment, "oversight_reject_commitment", request=request, policy=policy,
                   human_signer_ref="human", issued_by="human", note="Refused", now=NOW)
    assert refused["approved"] is False and refused["human_signature"]
    response_model = HumanApprovalResponse.model_validate(refused)
    assert verify_model_signature(response_model, response_model.human_signature, public(environment, "human"))
    assert call(environment, "oversight_evaluate_oversight_policy", **{**args, "proposed_action": {"capability": "admin"}})["result"] == "block"


def test_discovery_cache_feed_and_metadata_scan(environment):
    record = call(environment, "overlay_discovery_create_discovery_record", sovereign_id="alpha",
                  na_public_key_b64=public(environment), endpoints=["https://alpha.invalid"], capabilities_hash="a" * 64,
                  signer_ref="alpha", now=NOW)
    cache, changed = call(environment, "overlay_discovery_merge_discovery_records", existing=[], incoming=[record], now=NOW)
    assert changed == ["alpha"] and cache[0]["verified"]
    cache_again, changed_again = call(environment, "overlay_discovery_merge_discovery_records", existing=cache,
                                    incoming=[record], now=NOW)
    assert cache_again == cache and changed_again == []
    feed = call(environment, "overlay_discovery_build_discovery_feed", records=[record], operator_sovereign_id="alpha",
                signer_ref="alpha", now=NOW)
    assert feed["signature"] and feed["entries"] == [record]
    feed_model = DiscoveryFeed.model_validate(feed)
    assert verify_model_signature(feed_model, feed_model.signature, public(environment))
    normalized = call(environment, "privacy_normalize_payload_length", payload="YQ==", block_bytes=16)
    padded = base64.b64decode(normalized)
    assert len(padded) == 16 and padded.startswith(b"a")


def test_risk_updates_inspection_and_seed_assessment_use_signed_history(environment, decision):
    signal = call(environment, "risk_signal_create_risk_signal", from_sovereign_id="alpha", to_sovereign_id="beta",
                  signer_ref="alpha", now=NOW)
    evidence = call(environment, "execution_record_execution", decision=decision["decision"], executor_sovereign_id="beta",
                    executed_capability="read", outcome="success", signer_ref="beta", issued_by="beta", now=NOW)
    updated, change, _ = call(environment, "risk_signal_update_risk_signal", signal=signal, evidence=evidence,
                              signer_ref="alpha", now=NOW)
    assert updated["signal"] > signal["signal"] and updated["update_count"] == 1
    for model, record in ((PeerRiskSignal, updated), (RiskSignalUpdate, change)):
        value = model.model_validate(record)
        assert verify_model_signature(value, value.signature, public(environment))
    inspected = call(environment, "risk_signal_inspect_risk", signal=updated)
    assert inspected == updated
    report = call(environment, "risk_signal_assess_seed_isolation", signal=updated, history=[change], now=NOW)
    assert report["history_length"] == 1 and report["isolated"] is False
    wrong_key = copy.deepcopy(updated)
    wrong_key["signal"] = 0.01
    assert not call(environment, "risk_signal_check_risk_signal_gate", signal=wrong_key, minimum_signal=0.1,
                    issuer_public_keys=[public(environment)], at_time=NOW)[0]


def test_nullifier_binds_membership_and_reuse_is_refused(environment, agreement):
    committed = call(environment, "selective_disclosure_commit_capabilities", capabilities=["read", "write"],
                     agreement=agreement, signer_ref="alpha", issued_by="alpha", now=NOW)
    proof = call(environment, "selective_disclosure_prove_capability_membership", capability="read", capabilities=["read", "write"],
                 commitment=committed, prover_sovereign_id="beta", now=NOW)
    nullifier = call(environment, "selective_disclosure_issue_nullifier", proof=proof, signer_ref="beta", issued_by="beta", now=NOW)
    assert nullifier["signature"]
    verified = call(environment, "selective_disclosure_verify_capability_proof", proof=proof, commitment=committed,
                    issuer_public_keys=[public(environment)], nullifier=nullifier, used_nullifiers=[], now=NOW)
    assert verified["valid"]
    reused = call(environment, "selective_disclosure_verify_capability_proof", proof=proof, commitment=committed,
                  issuer_public_keys=[public(environment)], nullifier=nullifier, used_nullifiers=[nullifier["nullifier_id"]], now=NOW)
    assert not reused["valid"]
