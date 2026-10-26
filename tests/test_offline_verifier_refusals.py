"""Direct cryptographic refusals for each remaining offline domain verifier."""

from __future__ import annotations

import copy
from datetime import timedelta

from test_offline import NOW, call, graph, public
from test_offline import agreement as agreement
from test_offline import decision as decision
from test_offline import environment as environment


def test_agreement_verifier_rejects_wrong_party_pin_and_changed_terms(environment, agreement):
    args = dict(record=agreement, offerer_public_keys=[public(environment)],
                responder_public_keys=[public(environment, "beta")])
    assert call(environment, "agreement_verify_agreement", **args)["accepted"]
    wrong_pin = call(environment, "agreement_verify_agreement",
                     **{**args, "offerer_public_keys": [public(environment, "gamma")]})
    assert wrong_pin["accepted"] is False and wrong_pin["reason"] == "invalid_offerer_signature"
    changed = copy.deepcopy(agreement)
    changed["agreed_terms"]["capabilities"] = ["read"]
    tampered = call(environment, "agreement_verify_agreement", **{**args, "record": changed})
    assert tampered["accepted"] is False and tampered["reason"] == "invalid_offerer_signature"


def test_consensus_verifier_rejects_wrong_assembler_pin_and_changed_vote(environment, decision):
    justification = decision["justification"]
    vote = call(environment, "consensus_cast_validator_vote", justification_proof=justification,
                validator_sovereign_id="beta", vote=True, signer_ref="beta", now=NOW)
    proof = call(environment, "consensus_assemble_consensus_proof", justification_proof=justification,
                 votes=[vote], required_threshold=1, validator_sovereign_ids=["beta"],
                 assembler_signer_ref="alpha", issued_by="alpha", cascade_threshold=0, now=NOW)
    args = dict(proof=proof, validator_public_keys={"beta": public(environment, "beta")},
                assembler_public_keys=[public(environment)], justification_proof=justification,
                cascade_threshold=0, at_time=NOW)
    assert call(environment, "consensus_verify_consensus_proof", **args)["valid"]
    wrong_pin = call(environment, "consensus_verify_consensus_proof",
                     **{**args, "assembler_public_keys": [public(environment, "gamma")]})
    assert wrong_pin["valid"] is False and wrong_pin["reason"] == "invalid_assembler_signature"
    changed = copy.deepcopy(proof)
    changed["votes"][0]["vote"] = False
    tampered = call(environment, "consensus_verify_consensus_proof", **{**args, "proof": changed})
    assert tampered["valid"] is False and tampered["reason"] == "invalid_assembler_signature"


def test_delegation_verifier_rejects_wrong_hop_pin_and_changed_terms(environment, agreement):
    terms = {**agreement["agreed_terms"], "capabilities": ["read"]}
    delegated = call(environment, "delegation_build_delegation", parent=agreement, delegated_terms=terms,
                     graph=graph(), signer_ref="beta", delegator_sovereign_id="beta",
                     delegate_sovereign_id="gamma", issued_by="beta", now=NOW)
    delegated = call(environment, "delegation_cosign_delegation", record=delegated, graph=graph(),
                     signer_ref="gamma", issued_by="gamma", now=NOW)
    chain = {"root": agreement, "hops": [delegated]}
    args = dict(chain=chain, root_offerer_public_keys=[public(environment)],
                root_responder_public_keys=[public(environment, "beta")],
                per_hop_keys={"beta": [public(environment, "beta")], "gamma": [public(environment, "gamma")]})
    assert call(environment, "delegation_verify_delegation_chain", **args)["accepted"]
    wrong_pin = call(environment, "delegation_verify_delegation_chain", **{**args, "per_hop_keys": {
        "beta": [public(environment, "human")], "gamma": [public(environment, "gamma")]}})
    assert wrong_pin["accepted"] is False and wrong_pin["reason"] == "invalid_delegator_signature"
    assert wrong_pin["failed_at_hop"] == 1
    changed = copy.deepcopy(chain)
    changed["hops"][0]["delegated_terms"]["capabilities"] = ["write"]
    tampered = call(environment, "delegation_verify_delegation_chain", **{**args, "chain": changed})
    assert tampered["accepted"] is False and tampered["reason"] == "invalid_delegator_signature"
    assert tampered["failed_at_hop"] == 1


def test_data_record_verifier_rejects_wrong_agent_pin_and_changed_volume(environment):
    policy = call(environment, "data_usage_create_data_policy", policy={"licensor_sovereign_id": "alpha",
        "licensee_sovereign_id": "beta", "allowed_source_ids": ["dataset"], "allowed_access_types": ["read"],
        "valid_from": NOW - timedelta(minutes=1), "valid_until": NOW + timedelta(days=1)},
        signer_ref="alpha", issued_by="alpha")
    source = {"source_id": "dataset", "source_type": "synthetic", "owner_sovereign_id": "alpha"}
    intent = call(environment, "data_usage_create_data_access_intent", agent_sovereign_id="beta",
                  decision_id="decision", sources=[source], access_types=["read"], signer_ref="beta", now=NOW)
    record = call(environment, "data_usage_create_data_record", record={"intent_id": intent["intent_id"],
        "agent_sovereign_id": "beta", "decision_id": "decision", "accessed_sources": [source],
        "access_types_used": ["read"], "accessed_at": NOW, "actual_volume_bytes": 10},
        signer_ref="beta", issued_by="beta")
    args = dict(record=record, intent=intent, policy=policy, agent_public_keys=[public(environment, "beta")], at_time=NOW)
    assert call(environment, "data_usage_verify_data_access_record", **args) == [True, None, []]
    wrong_pin = call(environment, "data_usage_verify_data_access_record",
                     **{**args, "agent_public_keys": [public(environment, "gamma")]})
    assert wrong_pin[0] is False and wrong_pin[2][0]["detail"] == "Invalid record signature"
    changed = {**record, "actual_volume_bytes": 11}
    tampered = call(environment, "data_usage_verify_data_access_record", **{**args, "record": changed})
    assert tampered[0] is False and tampered[2][0]["detail"] == "Invalid record signature"
