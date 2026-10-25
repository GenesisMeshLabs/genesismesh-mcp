"""Small explicit compositions matching the core's ordinary CLI workflows."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from genesis_mesh.crypto import sign_model
from genesis_mesh.crypto.signing import SigningKeyLike
from genesis_mesh.models.agreement import AgreementRecord
from genesis_mesh.models.attestation import AttestationPolicy
from genesis_mesh.models.boundary_policy import BoundaryPolicy
from genesis_mesh.models.context import ContextRecord
from genesis_mesh.models.data_usage import DataAccessRecord, DataLicensePolicy
from genesis_mesh.models.freshness import FreshnessProof
from genesis_mesh.models.genesis import GenesisBlock
from genesis_mesh.models.key_succession import KeySuccessionRecord
from genesis_mesh.models.mediation import MediatedExecutionReceipt
from genesis_mesh.models.privacy import CommunicationPrivacyProfile
from genesis_mesh.models.risk_signal import PeerRiskSignal
from genesis_mesh.trust.context import BoundaryEngine, GateRegistry

from .adapter import make_tool


def evaluate_context(context: ContextRecord, agreement: AgreementRecord,
                     operator_sovereign_id: str, signing_key: SigningKeyLike,
                     issued_by: str, *, decision_valid_seconds: int = 300,
                     require_freshness_proof: bool = False,
                     freshness_proof: FreshnessProof | None = None,
                     freshness_proof_issuer_keys: list[str] | None = None,
                     policies: list[BoundaryPolicy] | None = None,
                     policy_public_keys: list[str] | None = None,
                     now: datetime | None = None) -> Any:
    """Evaluate supplied context and agreement, returning signed decision and justification.

    This assesses supplied artifacts offline; it neither executes a capability
    nor establishes that supplied revocation state is the latest authority state.
    """
    engine = BoundaryEngine(operator_sovereign_id,
                            decision_valid_seconds=decision_valid_seconds,
                            require_freshness_proof=require_freshness_proof)
    options = dict(issued_by=issued_by, freshness_proof=freshness_proof,
                   freshness_proof_issuer_keys=freshness_proof_issuer_keys, now=now)
    if policies is not None:
        decision, proof = engine.evaluate_with_policies(
            context, agreement, signing_key, policies=policies,
            registry=GateRegistry.default(), policy_public_keys=policy_public_keys or [], **options)
    else:
        decision, proof = engine.evaluate_with_proof(context, agreement, signing_key, **options)
    return {"decision": decision, "justification": proof, "executed": False}


def create_data_policy(policy: DataLicensePolicy, signing_key: SigningKeyLike,
                       issued_by: str) -> DataLicensePolicy:
    """Sign a supplied, schema-validated data license policy, as the core CLI does."""
    return policy.model_copy(update={"signature": sign_model(policy, signing_key, issued_by)})


def create_data_record(record: DataAccessRecord, signing_key: SigningKeyLike,
                       issued_by: str) -> DataAccessRecord:
    """Sign a declared completed data-access record; this does not perform or attest observation of access."""
    return record.model_copy(update={"signature": sign_model(record, signing_key, issued_by)})


def create_privacy_profile(profile: CommunicationPrivacyProfile,
                           signing_key: SigningKeyLike) -> CommunicationPrivacyProfile:
    """Sign a schema-validated communication privacy profile."""
    return profile.model_copy(update={"signature": sign_model(profile, signing_key, profile.sovereign_id)})


def create_attestation_policy(policy: AttestationPolicy,
                              signing_key: SigningKeyLike, issued_by: str) -> AttestationPolicy:
    """Sign a schema-validated model-attestation acceptance policy."""
    return policy.model_copy(update={"signature": sign_model(policy, signing_key, issued_by)})


def create_context(context: ContextRecord) -> ContextRecord:
    """Construct and validate an offline context request without submitting or executing it."""
    return context


def inspect_risk(signal: PeerRiskSignal) -> PeerRiskSignal:
    """Inspect a risk signal without asserting its signature or freshness is valid."""
    return signal


def gate_types() -> list[dict[str, Any]]:
    """Describe the pinned core's built-in gate types and their configuration."""
    return GateRegistry.default().describe()


def explain_policy(policy: BoundaryPolicy) -> dict[str, Any]:
    """Show a boundary policy and its validation against the core gate registry."""
    from genesis_mesh.trust.context import validate_boundary_policy
    return {"policy": policy, "validation": validate_boundary_policy(policy, GateRegistry.default())}


def verify_detached_signature(data: bytes, signature_b64: str, public_key: str) -> dict[str, Any]:
    """Verify a detached Ed25519 signature over base64 bytes. This does not establish issuer trust or authorization."""
    from genesis_mesh.crypto import verify_signature
    return {"valid": verify_signature(data, signature_b64, public_key), "verification_scope": "signature_only"}


def verify_guard_receipt(receipt: MediatedExecutionReceipt, guard_public_key: str) -> dict[str, Any]:
    """Verify the guard signature on a receipt, following trust guard verify; no process is started."""
    from genesis_mesh.crypto import verify_model_signature
    if receipt.signature is None:
        return {"valid": False, "reason": "missing_signature"}
    valid = verify_model_signature(receipt, receipt.signature, guard_public_key)
    return {"valid": valid, "reason": "valid" if valid else "invalid_signature"}


def verify_genesis(block: GenesisBlock, root_public_key: str) -> dict[str, Any]:
    """Verify every genesis signature against an independently supplied root pin; an unsigned genesis fails."""
    from genesis_mesh.crypto import verify_model_signature
    matches = block.root_public_key == root_public_key
    checks = [{"key_id": sig.key_id, "valid": matches and verify_model_signature(block, sig, root_public_key)}
              for sig in block.signatures]
    return {"valid": matches and bool(checks) and all(row["valid"] for row in checks),
            "root_matched": matches, "signature_count": len(checks), "signatures": checks,
            "network_name": block.network_name}


def inspect_genesis(block: GenesisBlock) -> dict[str, Any]:
    """Inspect genesis metadata; this does not verify signatures or grant trust."""
    return {"genesis": block, "signatures_verified": False,
            "na_validity_note": "The genesis NA key signs until succession; verify current key history."}


def prove_succession(record: KeySuccessionRecord, signing_key: SigningKeyLike) -> KeySuccessionRecord:
    """Prove possession of the new NA key named in a succession; this does not root-authorize, submit, or activate it."""
    import base64

    from genesis_mesh.trust.key_succession import sign_succession

    public = base64.b64encode(bytes(signing_key.verify_key)).decode("ascii")
    if public != record.new_public_key:
        raise ValueError("Configured signer is not the new key named by this succession")
    return sign_succession(record, signing_key, record.new_key_id)


def inspect_proof_bundle(bundle: dict[str, Any], *, connectome_artifact: dict[str, Any] | None = None) -> dict[str, Any]:
    """Check a redacted proof summary and optional Connectome consistency; this does not verify signatures or run a live proof."""
    from genesis_mesh.workflows.proof import inspect_proof_bundle as core_inspect

    return {**core_inspect(bundle, connectome_artifact=connectome_artifact),
            "verification_scope": "summary_consistency_only", "signatures_verified": False}


def artifact_verifier():
    """Build a fixed artifact-model selector; no client-supplied imports are possible."""
    import importlib
    from typing import Literal

    from genesis_mesh.crypto import verify_model_signature
    from genesis_mesh.models.genesis import Signature
    from jsonschema import Draft202012Validator

    from genesismesh_mcp.catalog import load_contract

    from .adapter import close_models

    models = {}
    for item in load_contract()["signed_artifacts"]:
        module, name = item["model"].split(":", 1)
        model = getattr(importlib.import_module(module), name)
        schema = model.model_json_schema()
        close_models(schema)
        models[item["model"]] = (model, Draft202012Validator(schema))

    def verify_artifact(artifact_type, artifact: dict[str, Any], signature, public_key: str) -> dict[str, Any]:
        """Verify cryptographic signature only using a pinned artifact model; this does not establish issuer trust or authorization.

        Signature validity alone does not establish issuer trust, revocation,
        freshness, threshold satisfaction, policy acceptance or authorization.
        Use the domain verifier for those checks.
        """
        model, validator = models[artifact_type]
        if next(validator.iter_errors(artifact), None) is not None:
            raise ValueError("Artifact does not match its pinned model schema")
        record = model.model_validate(artifact)
        return {"valid": verify_model_signature(record, signature, public_key),
                "verification_scope": "signature_only", "artifact_type": artifact_type}

    verify_artifact.__annotations__["artifact_type"] = Literal[tuple(models)]
    verify_artifact.__annotations__["signature"] = Signature
    return verify_artifact


def build_workflow_tools(settings: Any) -> list:
    definitions = [
        (evaluate_context, "context", "evaluate_context", ("trust context evaluate",),
         "python:genesis_mesh.trust.context:BoundaryEngine"),
        (create_context, "context", "create_context", ("trust context request",),
         "python:genesis_mesh.models:ContextRecord"),
        (create_data_policy, "data_usage", "create_data_policy", ("trust data policy",),
         "artifact:genesis_mesh.models.data_usage:DataLicensePolicy"),
        (create_data_record, "data_usage", "create_data_record", ("trust data record",),
         "artifact:genesis_mesh.models.data_usage:DataAccessRecord"),
        (create_privacy_profile, "privacy", "create_privacy_profile", ("trust privacy profile",),
         "artifact:genesis_mesh.models.privacy:CommunicationPrivacyProfile"),
        (create_attestation_policy, "attestation", "create_attestation_policy", ("trust attest policy",),
         "artifact:genesis_mesh.models.attestation:AttestationPolicy"),
        (inspect_risk, "risk_signal", "inspect_risk", ("trust risk show",),
         "artifact:genesis_mesh.models.risk_signal:PeerRiskSignal"),
        (gate_types, "context", "gate_types", ("trust boundary-policy gate-types",),
         "python:genesis_mesh.trust.context:GateRegistry"),
        (explain_policy, "context", "explain_policy", ("trust boundary-policy explain",),
         "python:genesis_mesh.models:BoundaryPolicy"),
        (verify_detached_signature, "crypto", "verify_detached_signature", (),
         "python:genesis_mesh.crypto:verify_signature"),
        (verify_guard_receipt, "mediation", "verify_guard_receipt", ("trust guard verify",),
         "artifact:genesis_mesh.models.mediation:MediatedExecutionReceipt"),
        (artifact_verifier(), "crypto", "verify_artifact", (),
         "python:genesis_mesh.crypto:verify_model_signature"),
        (verify_genesis, "genesis", "verify_genesis", ("genesis verify",),
         "python:genesis_mesh.models:GenesisBlock"),
        (inspect_genesis, "genesis", "inspect_genesis", ("info",),
         "python:genesis_mesh.models:GenesisBlock"),
        (prove_succession, "key_succession", "prove_succession", ("na succession prove",),
         "artifact:genesis_mesh.models.key_succession:KeySuccessionRecord"),
        (inspect_proof_bundle, "proof", "inspect_proof_bundle", ("proof inspect",),
         "python:genesis_mesh.workflows.proof:inspect_proof_bundle"),
    ]
    return [make_tool(settings, fn, module, name, cli, target=target)
            for fn, module, name, cli, target in definitions]
