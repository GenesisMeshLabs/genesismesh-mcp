"""Reviewed pure/core operations. This is an allowlist, never user-selected imports.

The final tuple lists CLI value workflows represented by the operation. Local file
reading/writing is replaced by structured MCP arguments/results.
"""

OPERATIONS = {
    "crypto.node_auth": {"executor_key_id": (), "decode_ed25519_public_key": ()},
    "trust.agreement": {
        "build_offer": ("trust agree offer",),
        "build_counter": ("trust agree counter",),
        "accept_offer": ("trust agree accept",),
        "accept_counter": (),
        "cosign_agreement": ("trust agree cosign",),
        "verify_agreement": ("trust agree verify",),
    },
    "trust.attestation": {"verify_membership_attestation": ()},
    "trust.treaty": {
        "verify_recognition_treaty": (),
        "verify_attestation_with_treaty": (),
        "verify_sovereign_revocation_feed": (),
    },
    "trust.decision": {"evaluate_trust_decision": ("trust decide",)},
    "trust.connectome": {"build_connectome_view": (), "explain_trust_path": ()},
    "trust.atlas": {
        "cache_trust_path": (), "lookup_trust_path": ("atlas lookup",),
        "build_trust_path_cache": ("atlas cache",), "prune_graph": ("atlas prune",),
    },
    "trust.delegation": {
        "build_delegation": ("trust delegate create",),
        "cosign_delegation": ("trust delegate cosign",),
        "verify_delegation_chain": ("trust delegate verify",),
    },
    "trust.invocation_token": {
        "issue_invocation_token": ("trust token issue",),
        "verify_invocation_token": ("trust token verify",),
        "record_invocation_use": ("trust token record-use",),
    },
    "trust.freshness": {
        "issue_freshness_proof": ("trust freshness issue",),
        "verify_freshness_proof": ("trust freshness verify",),
    },
    "trust.justification": {
        "sign_justification_proof": ("trust justify sign",),
        "verify_justification_proof": ("trust justify verify",),
    },
    "trust.execution": {
        "record_execution": ("trust execution record",),
        "verify_evidence_chain": ("trust execution verify",),
    },
    "trust.evidence": {
        "build_trust_evidence": ("trust evidence",),
        "verify_trust_evidence": ("trust verify-evidence",),
        "graph_digest_from_export": (),
    },
    "trust.evidence_store": {
        "check_metadata_only": (), "validate_execution": (),
        "verify_retention_checkpoint": (), "verify_evidence_events": (),
        "verify_store_anchors": (), "parse_export_lines": (),
    },
    "trust.selective_disclosure": {
        "commit_capabilities": ("trust disclose commit",),
        "prove_capability_membership": ("trust disclose prove",),
        "verify_capability_proof": ("trust disclose verify",),
        "issue_nullifier": ("trust disclose nullify",),
    },
    "trust.consensus": {
        "cast_validator_vote": ("trust consensus vote",),
        "assemble_consensus_proof": ("trust consensus assemble",),
        "verify_consensus_proof": ("trust consensus verify",),
        "issue_ephemeral_identity": ("trust consensus issue-identity",),
        "verify_ephemeral_identity": ("trust consensus verify-identity",),
        "assess_cascade_risk": ("trust consensus assess-cascade",),
    },
    "trust.data_usage": {
        "create_data_access_intent": ("trust data intent",),
        "verify_data_access_intent": ("trust data verify",),
        "verify_data_access_record": (),
    },
    "trust.oversight": {
        "evaluate_oversight_policy": ("trust oversight evaluate",),
        "propose_commitment": ("trust oversight propose",),
        "approve_commitment": ("trust oversight approve",),
        "reject_commitment": ("trust oversight reject",),
        "verify_dual_signed_commitment": ("trust oversight verify",),
    },
    "trust.risk_signal": {
        "create_risk_signal": ("trust risk create",),
        "update_risk_signal": ("trust risk update",),
        "decay_risk_signal": ("trust risk decay",),
        "check_risk_signal_gate": (),
        "assess_seed_isolation": ("trust risk assess-seed",),
    },
    "trust.context_integrity": {
        "scan_for_injection_markers": (),
        "create_context_integrity_record": ("trust integrity commit",),
        "verify_context_integrity": ("trust integrity verify",),
    },
    "trust.privacy": {
        "bucket_timestamp": (), "normalize_payload_length": (),
        "scan_metadata_fingerprints": ("trust privacy scan",),
        "apply_privacy_profile": ("trust privacy apply",),
    },
    "trust.purge": {
        "create_nullification_receipt": ("trust purge receipt",),
        "build_nullification_registry": ("trust purge register",),
        "prove_nullification_inclusion": ("trust purge prove",),
        "verify_nullification_inclusion": ("trust purge verify",),
    },
    "trust.logic_attestation": {
        "create_model_attestation": ("trust attest create",),
        "verify_model_attestation": ("trust attest verify",),
    },
    "trust.supply_chain": {"verify_supply_chain_maintainer_gate": ("supply-chain verify",)},
    "interop.jose": {"decision_to_jwt": ("trust interop to-jwt",), "jwt_to_decision_claims": ()},
    "interop.spiffe": {"agreement_to_svid": ("trust interop to-spiffe",), "svid_to_agreement_fields": ()},
    "interop.w3c_vc": {
        "trust_evidence_to_vc": ("trust interop to-vc",),
        "agreement_to_vc": (), "vc_to_trust_evidence_fields": (),
    },
    "trust.overlay_discovery": {
        "create_discovery_record": ("trust discover announce",),
        "verify_discovery_record": ("trust discover verify",),
        "merge_discovery_records": ("trust discover merge",),
        "build_discovery_feed": ("trust discover feed",),
    },
    "trust.remediation": {
        "next_state": (), "remediation_plan": (), "decision_plan": (),
        "check_remediation": (), "review_holder_problem": (),
        "review_approval_problem": (), "admin_approval_valid": (),
        "remediation_record_problem": (), "review_request_problem": (),
        "request_approval_problem": (), "rfc3339": (), "emergency_map": (),
        "rotation_problem": (),
    },
    "trust.out_of_band": {"check_observation": (), "check_break_glass": ()},
    "trust.key_succession": {"verify_key_history": (), "genesis_refusal": ()},
    "trust.context": {
        "verify_boundary_decision": ("trust context verify",),
        "sign_boundary_policy": (),
        "validate_boundary_policy": ("trust boundary-policy validate",),
        "verify_boundary_policy": ("trust boundary-policy verify",),
        "resolve_policies": (), "assess_attestation_basis": (),
    },
    "workflows.trust_bundle": {
        "validate_trust_bundle": ("trust-bundle validate",),
        "bundle_summary": ("trust-bundle inspect",),
        "bundle_hash": (), "validate_bundle_against_review": (),
    },
    "workflows.audit_pack": {
        "verify_audit_pack": ("audit verify",),
        "check_completeness": (), "parse_changes": (),
    },
    "trust.mediation": {"validate_mediation_request": ()},
    "trust.grants": {
        "check_grant": (), "use_problem": (), "grant_horizon": (),
        "envelope_secret_problem": (), "use_secret_problem": (),
    },
}
