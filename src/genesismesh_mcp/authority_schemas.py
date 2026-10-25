"""Reviewed HTTP request schemas for Genesis Mesh 1.8.1.

These schemas describe request envelopes, not a new implementation of protocol
validation. Signed nested objects are validated without normalizing their bytes
or inserting defaults. Their schemas come from the pinned core models.
"""

from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
from importlib import import_module
from typing import Any

S = {"type": "string", "maxLength": 16384}
NONNEGATIVE = {"type": "integer", "minimum": 0}
P = {"type": "integer", "minimum": 1}
B = {"type": "boolean"}
T = {"type": "string", "format": "date-time"}
J = {"type": "object", "description": "Protocol-defined extension fields; the authority validates domain rules."}


def obj(properties: dict[str, Any] | None = None, required: tuple[str, ...] = ()) -> dict[str, Any]:
    return {"type": "object", "properties": properties or {}, "required": list(required), "additionalProperties": False}


def arr(item: dict[str, Any]) -> dict[str, Any]:
    return {"type": "array", "items": item, "maxItems": 10000}


MODELS = {
    "AgreementRecord": "genesis_mesh.models", "CapabilityOffer": "genesis_mesh.models",
    "CapabilityCounter": "genesis_mesh.models", "RecognitionPolicy": "genesis_mesh.models",
    "MembershipAttestation": "genesis_mesh.models", "RecognitionTreaty": "genesis_mesh.models",
    "RecognitionTreatyScope": "genesis_mesh.models", "SovereignRevocationFeed": "genesis_mesh.models",
    "BoundaryPolicy": "genesis_mesh.models", "PolicySelector": "genesis_mesh.models",
    "GateSpec": "genesis_mesh.models", "AgentDescriptor": "genesis_mesh.models",
    "BoundaryDecision": "genesis_mesh.models.context", "JustificationProof": "genesis_mesh.models.justification",
    "ExecutionEvidence": "genesis_mesh.models.execution", "AuditPackManifest": "genesis_mesh.models.audit_pack",
    "KeySuccessionRecord": "genesis_mesh.models.key_succession",
    "ValidatorVote": "genesis_mesh.models.consensus", "ConsensusProof": "genesis_mesh.models.consensus",
    "DataSourceDescriptor": "genesis_mesh.trust.data_usage", "DataAccessIntent": "genesis_mesh.trust.data_usage",
    "DataLicensePolicy": "genesis_mesh.trust.data_usage", "TrustEvidence": "genesis_mesh.models.evidence",
    "CapabilityCommitment": "genesis_mesh.models.selective_disclosure",
    "CapabilityMembershipProof": "genesis_mesh.models.selective_disclosure",
    "ObservationRecord": "genesis_mesh.models.out_of_band", "BreakGlassRecord": "genesis_mesh.models.out_of_band",
    "RemediationRecord": "genesis_mesh.models.remediation",
    "TimeTokenRequest": "genesis_mesh.models.grants", "GrantExecutionEvidence": "genesis_mesh.models.grants",
    "EnvelopeParameter": "genesis_mesh.models.grants",
}


@lru_cache(maxsize=None)
def model(name: str) -> dict[str, Any]:
    cls = getattr(import_module(MODELS[name]), name)
    schema = cls.model_json_schema()
    definitions = schema.pop("$defs", {})

    def expand(value: Any) -> Any:
        if isinstance(value, dict):
            if "$ref" in value:
                target = value["$ref"].removeprefix("#/$defs/")
                return expand({**definitions[target], **{k: v for k, v in value.items() if k != "$ref"}})
            return {k: expand(v) for k, v in value.items()}
        if isinstance(value, list):
            return [expand(v) for v in value]
        return value

    return expand(schema)


def _body_schemas() -> dict[str, dict[str, Any]]:
    m = model
    policy = obj({"policy_id": S, "description": S, "valid_from": T, "valid_until": T,
                  "selector": m("PolicySelector"), "gates": arr(m("GateSpec")),
                  "remediation": J, "review_required": B, "emergency": J}, ("policy_id", "valid_from", "valid_until"))
    context = obj({"requester_sovereign_id": S, "provider_sovereign_id": S,
                   "request_parameters": J, "context_freshness_seq": NONNEGATIVE,
                   "context_id": S, "parent_kind": S, "attributes": J})
    evaluation = obj({"agreement": m("AgreementRecord"), "attestation_id": S,
                      "requested_capability": S, "context": context}, ("requested_capability",))
    evaluation["oneOf"] = [{"required": ["agreement"], "not": {"required": ["attestation_id"]}},
                           {"required": ["attestation_id"], "not": {"required": ["agreement"]}}]
    schemas = {
        "/admin/invite": obj({"roles": arr(S), "recipient_public_key": S, "max_validity_hours": P,
                              "token_expiry_hours": P, "node_sovereign_id": S, "executor_resource_prefix": S}),
        "/admin/policy": obj({"min_client_version": S, "allowed_ports": arr(P), "allowed_services": arr(S),
                              "routing": J, "policy_id": S}),
        "/admin/policy/rollback": obj({"policy_id": S}, ("policy_id",)),
        "/admin/revoke": obj({"cert_id": S, "reason": S}, ("cert_id",)),
        "/admin/agreements/offer": obj({"responder_sovereign_id": S, "capabilities": arr(S), "scope": J,
                                        "valid_from": T, "valid_until": T, "expires_at": T},
                                       ("responder_sovereign_id", "capabilities", "valid_from", "valid_until", "expires_at")),
        "/admin/agreements/counter": obj({"offer": m("CapabilityOffer"), "capabilities": arr(S), "scope": J,
                                          "valid_from": T, "valid_until": T}, ("offer", "capabilities", "valid_from", "valid_until")),
        "/admin/agreements/accept": obj({"offer": m("CapabilityOffer"), "counter": m("CapabilityCounter"),
                                         "original_offer": m("CapabilityOffer")}),
        "/agreements/verify": obj({"agreement": m("AgreementRecord"), "offerer_public_keys": arr(S),
                                   "responder_public_keys": arr(S)}, ("agreement",)),
        "/admin/attestations": obj({"subject_id": S, "roles": arr(S), "issuer_sovereign_id": S,
                                    "subject_public_key": S, "claims": J, "validity_hours": P}, ("subject_id", "roles")),
        "/admin/recognition-policy": obj({"policy_id": S, "recognition_policy": m("RecognitionPolicy")}, ("recognition_policy",)),
        "/attestations/verify": obj({"attestation": m("MembershipAttestation"), "recognition_policy": m("RecognitionPolicy")}, ("attestation",)),
        "/admin/boundary/decide": obj({"agreement": m("AgreementRecord"), "requested_capability": S, "context": context}, ("agreement", "requested_capability")),
        "/admin/boundary/evaluate": evaluation,
        "/boundary/verify": obj({"decision": m("BoundaryDecision"), "operator_public_keys": arr(S)}, ("decision",)),
        "/admin/boundary-policies/validate": policy,
        "/admin/boundary-policies": policy,
        "/boundary-policies/verify": obj({"policy": m("BoundaryPolicy"), "issuer_public_keys": arr(S)}, ("policy",)),
        "/admin/consensus/vote": obj({"justification_proof": m("JustificationProof"), "vote": B, "reason": S}, ("justification_proof", "vote")),
        "/admin/consensus/proof": obj({"justification_proof": m("JustificationProof"), "votes": arr(m("ValidatorVote")), "required_threshold": P, "validator_sovereign_ids": arr(S)}, ("justification_proof", "votes", "required_threshold", "validator_sovereign_ids")),
        "/consensus/verify": obj({"proof": m("ConsensusProof"), "validator_public_keys": {"type": "object", "additionalProperties": S}, "assembler_public_keys": arr(S)}, ("proof", "validator_public_keys")),
        "/admin/data-usage/policy": obj({"licensee_sovereign_id": S, "allowed_source_ids": arr(S), "allowed_access_types": arr(S), "valid_from": T, "valid_until": T, "max_volume_bytes_per_session": NONNEGATIVE, "prohibited_classification_tags": arr(S)}, ("licensee_sovereign_id", "allowed_source_ids", "allowed_access_types", "valid_from", "valid_until")),
        "/admin/data-usage/intent": obj({"sources": arr(m("DataSourceDescriptor")), "access_types": arr(S), "estimated_volume_bytes": NONNEGATIVE, "decision_id": S}, ("sources", "access_types")),
        "/data-usage/verify": obj({"intent": m("DataAccessIntent"), "policy": m("DataLicensePolicy"), "agent_public_keys": arr(S)}, ("intent", "policy")),
        "/admin/disclosure/commit": obj({"capabilities": arr(S), "agreement": m("AgreementRecord")}, ("capabilities",)),
        "/admin/disclosure/nullifier": obj({"proof": m("CapabilityMembershipProof")}, ("proof",)),
        "/disclosure/prove": obj({"capability": S, "capabilities": arr(S), "commitment": m("CapabilityCommitment"), "prover_sovereign_id": S}, ("capability", "capabilities", "commitment", "prover_sovereign_id")),
        "/disclosure/verify": obj({"proof": m("CapabilityMembershipProof"), "commitment": m("CapabilityCommitment"), "issuer_public_keys": arr(S)}, ("proof", "commitment")),
        "/agents": obj({"agent_id": S, "network_name": S, "capabilities": arr(S), "endpoint": obj({"host": S, "port": {"type": "integer", "minimum": 1, "maximum": 65535}, "scheme": {"enum": ["ws", "wss"]}}, ("host", "port")), "expires_at": T, "metadata": J}, ("agent_id", "network_name", "endpoint", "expires_at")),
        "/join": obj({"validity_hours": P, "edge": B, "agent_version": S}),
        "/heartbeat": obj({"cert_id": S, "status": S, "agent": J}, ("cert_id",)),
        "/renew": obj({"cert_id": S, "validity_hours": P}, ("cert_id",)),
        "/node/state": obj({"cert_id": S}, ("cert_id",)),
        "/node/boundary/evaluate": obj({"cert_id": S, "attestation_id": S, "requested_capability": S, "context": context}, ("cert_id", "attestation_id", "requested_capability")),
        "/node/evidence/resource-head": obj({"cert_id": S, "resource_id": S}, ("cert_id", "resource_id")),
        "/admin/trust-evidence": obj({"decision": obj({
            "source_sovereign_id": S, "target_sovereign_id": S,
            "verdict": {"enum": ["allow", "warn", "block", "escalate"]}, "reason": S,
            "requested_roles": arr(S), "trusted": B, "trust_path": arr(J),
            "hop_count": NONNEGATIVE,
            "signals": arr(obj({"code": S, "severity": S, "detail": S}, ("code", "severity"))),
            "evaluated_at": S,
        }, ("source_sovereign_id", "target_sovereign_id", "verdict")), "graph_digest": S}, ("decision",)),
        "/trust-evidence/verify": obj({"evidence": m("TrustEvidence"), "expected_graph_digest": S, "issuer_public_keys": arr(S)}, ("evidence",)),
        "/evidence/execution": obj({"evidence": m("ExecutionEvidence")}, ("evidence",)),
        "/admin/evidence/executor-keys": obj({"key_id": S, "public_key": S, "executor_sovereign_id": S, "role": {"enum": ["executor", "observer"]}, "resource_prefix": S}, ("key_id", "public_key", "executor_sovereign_id")),
        "/admin/evidence/anchors": obj(),
        "/admin/evidence/audit-pack": obj({"from_sequence": P, "until_sequence": P, "since": T, "until": T}),
        "/admin/evidence/archives": obj({"manifest": m("AuditPackManifest"), "location": S}, ("manifest", "location")),
        "/admin/evidence/retention/apply": obj({"older_than_days": {"anyOf": [NONNEGATIVE, {"type": "null"}]}, "through_sequence": NONNEGATIVE}),
        "/admin/grants": obj({"bearer_key_id": S, "capabilities": arr(S), "agreement": m("AgreementRecord"), "attestation_id": S, "context_freshness_seq": NONNEGATIVE, "valid_from": T, "valid_until": T, "max_uses": P, "max_uses_per_time_token": P, "parameter_envelope": {"type": "object", "additionalProperties": m("EnvelopeParameter")}}, ("bearer_key_id", "capabilities", "valid_until", "max_uses")),
        "/grants/time-tokens": obj({"request": m("TimeTokenRequest")}, ("request",)),
        "/evidence/grant-executions": obj({"evidence": m("GrantExecutionEvidence")}, ("evidence",)),
        "/admin/na/succession": obj({"succession": m("KeySuccessionRecord")}, ("succession",)),
        "/admin/na/reissue": obj(),
        "/evidence/observations": obj({"observation": m("ObservationRecord")}, ("observation",)),
        "/evidence/observations/batch": obj({"observations": arr(m("ObservationRecord"))}, ("observations",)),
        "/evidence/break-glass": obj({"record": m("BreakGlassRecord")}, ("record",)),
        "/evidence/remediations": obj({"record": m("RemediationRecord")}, ("record",)),
        "/admin/evidence/reviews": obj({"subject_kind": {"enum": ["judgement", "decision"]}, "subject_id": S, "justification": S}, ("subject_kind", "subject_id", "justification")),
        "/admin/recognition-treaties": obj({"subject_sovereign_id": S, "subject_public_keys": arr(S), "issuer_sovereign_id": S, "scope": m("RecognitionTreatyScope"), "metadata": J, "validity_hours": P}, ("subject_sovereign_id", "subject_public_keys")),
        "/recognition-treaties/verify": obj({"treaty": m("RecognitionTreaty"), "issuer_public_keys": arr(S), "expected_issuer_sovereign_id": S, "expected_subject_sovereign_id": S}, ("treaty",)),
        "/attestations/verify-with-treaty": obj({"attestation": m("MembershipAttestation"), "treaty": m("RecognitionTreaty"), "treaty_issuer_public_keys": arr(S)}, ("attestation", "treaty")),
        "/admin/sovereign-revocation-feeds/import": obj({"feed": m("SovereignRevocationFeed"), "issuer_public_keys": arr(S), "expected_issuer_sovereign_id": S}, ("feed",)),
    }
    schemas["/admin/agreements/accept"]["oneOf"] = [
        {"required": ["offer"], "not": {"anyOf": [{"required": ["counter"]}, {"required": ["original_offer"]}]}},
        {"required": ["counter", "original_offer"], "not": {"required": ["offer"]}},
    ]
    return schemas


@lru_cache(maxsize=1)
def bodies() -> dict[str, dict[str, Any]]:
    return _body_schemas()


def body_schema(method: str, path: str) -> dict[str, Any]:
    if method == "GET" or (method == "DELETE" and path == "/agents/<path:node_public_key>"):
        return obj()
    if path in bodies():
        return deepcopy(bodies()[path])
    if path.endswith("/revoke"):
        return obj({"reason": S})
    if path.startswith("/admin/boundary-policies/") and path.endswith(("/activate", "/deactivate")):
        return obj({"version": P}, ("version",))
    if path.endswith(("/retire", "/judge", "/approve")):
        return obj()
    if path.endswith("/holder"):
        return obj({"holder": S}, ("holder",))
    if path.endswith("/notified"):
        return obj({"channel": S})
    if path == "/admin/evidence/reviews/<review_id>/decide":
        return obj({"verdict": {"enum": ["uphold", "deny", "waive_until"]}, "note": S, "waive_until": T}, ("verdict",))
    raise ValueError(f"HTTP body has not been reviewed: {method} {path}")


QUERY_FIELDS = {
    "/attestations": "status subject_id issuer_sovereign_id",
    "/sovereign-revocation-feed": "issuer_sovereign_id",
    "/agents": "capability",
    "/admin/edge-nodes": "status limit before node_sovereign_id",
    "/admin/evidence": "after_sequence attestation_id capability decision_id entry_kind grant_id limit outcome resource_id since until vendor_id",
    "/admin/evidence/export": "since_sequence limit",
    "/admin/evidence/anchors": "after_anchor limit",
    "/admin/grants": "before bearer_key_id limit status",
    "/admin/grants/<grant_id>/uses": "before limit",
    "/admin/evidence/changes/<path:resource_id>": "after_sequence limit",
    "/admin/evidence/remediations": "state limit after",
    "/recognition-treaties": "issuer_sovereign_id subject_sovereign_id status",
    "/connectome/trust-path": "from source to target",
}


def query_schema(method: str, path: str) -> dict[str, Any]:
    names = QUERY_FIELDS.get(path, "").split() if method == "GET" else []
    result = obj({name: (P if name == "limit" else NONNEGATIVE if name in {"after_sequence", "since_sequence", "after_anchor"} else S) for name in names})
    if path == "/connectome/trust-path":
        result["allOf"] = [{"anyOf": [{"required": ["from"]}, {"required": ["source"]}]},
                           {"anyOf": [{"required": ["to"]}, {"required": ["target"]}]}]
    return result
