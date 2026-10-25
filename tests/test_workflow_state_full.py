"""Storage boundaries, proof failure ordering and signed review material."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import replace
from datetime import datetime, timezone

import pytest
from genesis_mesh.crypto import generate_keypair, sign_model
from genesis_mesh.models import RecognitionTreaty
from genesis_mesh.models.evidence import TrustEvidence
from genesis_mesh.trust.evidence import graph_digest_from_export
from test_authority_integration import authority as authority
from test_canary_workflows import canary_store as canary_store
from test_multi_workflows import pair as pair
from test_proof_workflows import proof_store as proof_store
from test_workflow_branches import call

from genesismesh_mcp import authority as http
from genesismesh_mcp import proof_workflows, provision_workflows, workflow_support, workflows
from genesismesh_mcp.proof_workflows import CANARY, CLEANUP, PREVIEW, TABLES
from genesismesh_mcp.settings import Settings
from genesismesh_mcp.types import ToolError


def test_support_dependency_errors_are_specific_and_do_not_create_paths(tmp_path):
    settings = Settings(profiles={"read", "local"})
    for function, args, code in [
        (workflow_support.pinned_root, (settings, "absent"), "root_pin_required"),
        (workflow_support.artifact_root, (settings, "absent"), "artifact_root_not_configured"),
        (workflow_support.WorkflowJournal, (settings, "workflow", "one", {}), "workflow_state_required"),
    ]:
        with pytest.raises(ToolError) as exc:
            function(*args)
        assert exc.value.code == code
    with pytest.raises(ToolError) as exc:
        workflow_support.normalize_roles(["not-a-core-role"])
    assert exc.value.code == "invalid_roles"
    assert list(tmp_path.iterdir()) == []


def test_missing_and_oversized_credentials_bind_distinct_fingerprints(tmp_path):
    missing, oversized = tmp_path / "missing", tmp_path / "oversized"
    oversized.write_bytes(b"x" * 65537)
    settings = Settings(signer_files={"missing": missing, "oversized": oversized})
    value = workflow_support._bound_configuration(settings)
    assert value["credential_fingerprints"] == {str(missing): "unavailable", str(oversized): "oversized"}
    oversized.write_bytes(b"new")
    assert workflow_support._bound_configuration(settings)["credential_fingerprints"][str(oversized)] == hashlib.sha256(b"new").hexdigest()


def test_step_summaries_limit_identifier_count_depth_and_size():
    result = {f"item{i}_id": str(i) for i in range(40)}
    result.update(secret_id="x" * 300, nested={"a": {"b": {"c": {"deep_id": "unreported"}}}}, values=[1, 2])
    summary = workflow_support._step_summaries({"step": {"status": "completed", "result": result}})["step"]
    assert len(summary["result_identifiers"]) == 32
    assert all("deep" not in key and "secret" not in key for key in summary["result_identifiers"])
    assert summary["result_sha256"] == hashlib.sha256(json.dumps(result, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def test_journal_sparse_oversize_record_is_refused_before_parsing(tmp_path):
    settings = Settings(profiles={"local", "read"}, workflow_state_dir=tmp_path / "state")
    with workflow_support.WorkflowJournal(settings, "gm_workflow_fleet_status", "large", {}) as journal:
        path = journal.path
    with path.open("wb") as stream:
        stream.truncate(16_777_217)
    with pytest.raises(ToolError) as exc:
        with workflow_support.WorkflowJournal(settings, "gm_workflow_fleet_status", "large", {}):
            pass
    assert exc.value.code == "workflow_state_too_large"
    with pytest.raises(ToolError) as exc:
        call(settings, "gm_workflow_operation_status", {"workflow": "gm_workflow_fleet_status", "operation_id": "large"})
    assert exc.value.code == "operation_not_found"


def test_operation_status_requires_valid_identifier_and_storage():
    settings = Settings(profiles={"local", "read"})
    for args, code in [({"workflow": "gm_workflow_../unsafe", "operation_id": "one"}, "invalid_operation_id"),
                       ({"workflow": "gm_workflow_fleet_status", "operation_id": "one"}, "workflow_state_required")]:
        with pytest.raises(ToolError) as exc:
            call(settings, "gm_workflow_operation_status", args)
        assert exc.value.code == code


@pytest.mark.parametrize("kind", ["state", "lock", "atomic"])
def test_journal_and_atomic_writes_refuse_symlink_redirects(tmp_path, kind):
    settings = Settings(profiles={"local"}, workflow_state_dir=tmp_path / "state")
    with workflow_support.WorkflowJournal(settings, "tool", "operation", {}) as journal:
        path = journal.lock_path if kind == "lock" else journal.path
    path.unlink()
    victim = tmp_path / "victim"
    victim.write_text("untouched")
    try:
        path.symlink_to(victim)
    except OSError:
        pytest.skip("Platform does not permit symbolic links")
    with pytest.raises(ToolError) as exc:
        if kind == "atomic":
            workflow_support.atomic_json(path, {"write": True})
        else:
            with workflow_support.WorkflowJournal(settings, "tool", "operation", {}):
                pass
    assert exc.value.code == "unsafe_storage" and victim.read_text() == "untouched"


def test_journal_handles_another_process_creating_storage_first(tmp_path, monkeypatch):
    settings = Settings(profiles={"local"}, workflow_state_dir=tmp_path / "state")
    original = workflow_support.private_directory
    def another_process_won(path):
        original(path)
        raise FileExistsError(path)
    monkeypatch.setattr(workflow_support, "private_directory", another_process_won)
    with workflow_support.WorkflowJournal(settings, "tool", "race", {}) as journal:
        assert journal.step("read", lambda: True)
    journal.__exit__(None, None, None)


@pytest.mark.parametrize("days", [0, 3651, True])
def test_fleet_generation_refuses_invalid_validity_before_writes(tmp_path, days):
    settings = Settings(profiles={"local", "write", "provision"}, workflow_state_dir=tmp_path / "state",
                        provisioning={"lab": {"root": tmp_path / "fleet"}})
    with pytest.raises(ToolError) as exc:
        call(settings, provision_workflows.NAME, {"provisioning": "lab", "operation_id": "invalid", "names": ["one"],
                                                 "na_valid_days": days})
    assert exc.value.code == "invalid_validity" and not (tmp_path / "fleet").exists()


@pytest.mark.parametrize("failure", ["exists", "invalid_genesis", "io"])
def test_generation_partial_failures_never_publish_invalid_fleet(tmp_path, monkeypatch, failure):
    settings = Settings(profiles={"local", "write", "provision"}, workflow_state_dir=tmp_path / "state",
                        provisioning={"lab": {"root": tmp_path / "fleet"}})
    destination = tmp_path / "fleet/partial"
    if failure == "exists":
        destination.mkdir(parents=True)
        (destination / "existing").write_text("preserved")
    else:
        original = provision_workflows._scaffold_sovereign
        def corrupt(**kwargs):
            if failure == "io":
                raise OSError("storage lost")
            original(**kwargs)
            path = kwargs["home"] / "genesis.signed.json"
            data = json.loads(path.read_text())
            data["signatures"] = []
            path.write_text(json.dumps(data))
        monkeypatch.setattr(provision_workflows, "_scaffold_sovereign", corrupt)
    result = call(settings, provision_workflows.NAME, {"provisioning": "lab", "operation_id": "partial", "names": ["one"]})
    assert result["status"] == "partial"
    assert result["error"] == {"exists": "provisioning_conflict", "invalid_genesis": "generated_genesis_invalid",
                                "io": "provisioning_failed"}[failure]
    if failure == "exists":
        assert (destination / "existing").read_text() == "preserved"
    else:
        assert not destination.exists()


def test_cleanup_permissions_and_existing_backup_leave_database_unchanged(proof_store):
    settings, path = proof_store
    denied = replace(settings, proof_stores={"lab": replace(settings.proof_stores["lab"], allowed_tools=frozenset())})
    with pytest.raises(ToolError) as exc:
        call(denied, PREVIEW, {"store": "lab"})
    assert exc.value.code == "proof_store_not_authorized"
    preview = call(settings, PREVIEW, {"store": "lab"})
    config = settings.proof_stores["lab"]
    config.backup_dir.mkdir()
    filename = "before-cleanup-" + hashlib.sha256(b"collision").hexdigest()[:32] + ".sqlite3"
    existing = config.backup_dir / filename
    existing.write_bytes(b"preserve backup")
    result = call(settings, CLEANUP, {"store": "lab", "operation_id": "collision", "preview_digest": preview["scope_digest"]})
    assert result["status"] == "partial" and result["error"] == "proof_cleanup_failed"
    assert existing.read_bytes() == b"preserve backup"
    with sqlite3.connect(path) as connection:
        assert connection.execute(f"SELECT COUNT(*) FROM {TABLES[0]}").fetchone() == (2,)


def test_cleanup_empty_database_verifies_backup_without_deleting_other_tables(proof_store):
    settings, path = proof_store
    with sqlite3.connect(path) as connection:
        for table in TABLES:
            connection.execute(f"DROP TABLE {table}")
    preview = call(settings, PREVIEW, {"store": "lab"})
    result = call(settings, CLEANUP, {"store": "lab", "operation_id": "empty", "preview_digest": preview["scope_digest"]})
    assert result["status"] == "completed" and set(result["deleted_rows"].values()) == {0}
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone() == (1,)


def test_canary_prepares_current_schema_and_refuses_schema_drift(canary_store):
    settings, _ = canary_store
    config = settings.proof_stores["canary"]
    assert proof_workflows._prepare_database(config) == {"ready": True, "initialized": True}
    assert proof_workflows._prepare_database(config) == {"ready": True, "initialized": False}
    with sqlite3.connect(config.db_path) as connection:
        connection.execute("DELETE FROM schema_version WHERE version > 0")
    result = call(settings, CANARY, {"store": "canary", "acceptor": "alpha", "issuer": "beta", "operation_id": "schema"})
    assert result["status"] == "partial" and result["error"] == "proof_schema_mismatch"


def test_canary_does_not_sign_receipt_for_a_partial_remote_proof(canary_store):
    settings, _ = canary_store
    # The real workflow rejects the duplicate sovereign pair before mutation.
    result = call(settings, CANARY, {"store": "canary", "acceptor": "alpha", "issuer": "alpha", "operation_id": "same"})
    assert result["status"] == "partial" and result["receipt_signed"] is False
    assert result["remote"]["error"]["code"] == "distinct_authorities_required"
    assert not settings.proof_stores["canary"].receipt_dir.exists()


def test_canary_refuses_preexisting_receipt_without_overwriting_or_recording_audit(canary_store):
    settings, _ = canary_store
    config = settings.proof_stores["canary"]
    config.receipt_dir.mkdir()
    filename = "canary-" + hashlib.sha256(b"collision").hexdigest()[:32] + ".json"
    target = config.receipt_dir / filename
    target.write_text("existing receipt")
    result = call(settings, CANARY, {"store": "canary", "acceptor": "alpha", "issuer": "beta", "operation_id": "collision"})
    assert result["status"] == "partial" and result["error"] == "receipt_exists"
    assert target.read_text() == "existing receipt"
    with sqlite3.connect(config.db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone() == (0,)


def test_canary_detects_receipt_write_corruption_before_audit(canary_store, monkeypatch):
    settings, _ = canary_store
    original = proof_workflows.atomic_json
    def corrupt(path, value, **kwargs):
        original(path, value, **kwargs)
        if path.parent == settings.proof_stores["canary"].receipt_dir:
            path.write_text("{}")
    monkeypatch.setattr(proof_workflows, "atomic_json", corrupt)
    result = call(settings, CANARY, {"store": "canary", "acceptor": "alpha", "issuer": "beta", "operation_id": "corrupt"})
    assert result["status"] == "partial" and result["error"] == "receipt_readback_failed"
    with sqlite3.connect(settings.proof_stores["canary"].db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone() == (0,)


def test_bundle_review_compares_live_authority_and_refuses_missing_configuration(authority):
    settings, _, _ = authority
    handlers = {tool.name: tool.handler for tool in workflows.build_tools(settings)}
    bundle = handlers["gm_workflow_trust_bundle_export"]({})["bundle"]
    review = handlers["gm_workflow_trust_bundle_review"]({"bundle": bundle, "compare_live": True})
    assert review["accepted_for_review"] is True and review["trust_granted"] is False
    no_authority = {tool.name: tool.handler for tool in workflows.build_tools(Settings())}
    with pytest.raises(ToolError) as exc:
        no_authority["gm_workflow_trust_bundle_export"]({})
    assert exc.value.code == "authority_required"
    with pytest.raises(ToolError) as exc:
        no_authority["gm_workflow_trust_bundle_review"]({"bundle": bundle, "compare_live": True})
    assert exc.value.code == "authority_required"


def test_public_session_refuses_duplicate_query_and_exposes_only_response_content():
    session = workflows._PublicSession(Settings(authority_url="https://configured.example"))
    with pytest.raises(ToolError) as exc:
        session.get("https://configured.example/healthz?limit=1&limit=2")
    assert exc.value.code == "invalid_query"
    response = workflows._Response(403, {"error": "denied"})
    assert response.ok is False and json.loads(response.text) == response.json() == {"error": "denied"}


def test_federation_preview_validates_supplied_bundle_endpoint(pair):
    settings, _ = pair
    selected = workflow_support.select_authority(settings, "beta", "gm_workflow_federation_preview")
    bundle = workflows.build_tools(selected)[0].handler({})["bundle"]
    args = {"acceptor": "alpha", "issuer": "beta", "issuer_bundle": bundle}
    result = call(settings, "gm_workflow_federation_preview", args)
    assert result["issuer_bundle_validation"]
    wrong = json.loads(json.dumps(bundle))
    # Core bundles place the reviewed endpoint at their top level.
    wrong["source_endpoint"] = "https://wrong.example"
    with pytest.raises(ToolError) as exc:
        call(settings, "gm_workflow_federation_preview", {**args, "issuer_bundle": wrong})
    assert exc.value.code == "bundle_endpoint_mismatch"


def test_remote_proof_reports_failed_precheck_and_keeps_issued_ids(pair, monkeypatch):
    settings, credentials = pair
    original = http.invoke
    def refuse_precheck(config, operation, args):
        result = original(config, operation, args)
        if operation["path"] == "/attestations/verify-with-treaty":
            result["result"] = {"accepted": False, "reason": "test-inconsistent-state"}
        return result
    monkeypatch.setattr(http, "invoke", refuse_precheck)
    args = {"acceptor": "alpha", "issuer": "beta", "operation_id": "precheck",
            "subject_public_key": credentials["beta"][0]["subject"].public_key_b64}
    result = call(settings, "gm_workflow_proof_remote", args)
    assert result["status"] == "partial" and result["error"]["code"] == "proof_step_rejected"
    assert result["steps"]["steps"]["attestation-issue"]["result_identifiers"]["result.attestation_id"]
    assert "attestation-revoke" not in result["steps"]["steps"]


def test_atlas_checks_signed_evidence_and_marks_tampering():
    graph = {"sovereigns": [], "recognition_edges": []}
    key = generate_keypair()
    evidence = TrustEvidence(issuer_sovereign_id="issuer", source_sovereign_id="issuer", target_sovereign_id="subject",
                             graph_digest=graph_digest_from_export(graph), verdict="block", reason="no_path", trusted=False,
                             hop_count=0, issued_by="issuer", evaluated_at=datetime.now(timezone.utc).isoformat())
    evidence.signatures = [sign_model(evidence, key.private_key, "issuer")]
    tool = workflows.build_tools(Settings())[1]
    result = tool.handler({"graph": graph, "evidence": [evidence.model_dump(mode="json")],
                           "issuer_public_keys": [key.public_key_b64]})
    assert result["evidence_failures"] == 0 and result["atlas"]["evidence"][0]["_atlas_verified"]
    evidence.reason = "tampered"
    refused = tool.handler({"graph": graph, "evidence": [evidence.model_dump(mode="json")],
                            "issuer_public_keys": [key.public_key_b64]})
    assert refused["evidence_failures"] == 1 and not refused["atlas"]["evidence"][0]["_atlas_verified"]


@pytest.mark.parametrize("fault", ["scope", "record_identity"])
def test_federation_checks_signed_scope_and_persisted_identity(pair, monkeypatch, fault):
    settings, credentials = pair
    args = {"acceptor": "alpha", "issuer": "beta"}
    preview = call(settings, "gm_workflow_federation_preview", args)
    original = http.invoke
    def substitute(config, operation, arguments):
        response = original(config, operation, arguments)
        target = "/admin/recognition-treaties" if fault == "scope" else "/recognition-treaties/<treaty_id>"
        if operation["path"] == target:
            wire = response["result"] if fault == "scope" else response["result"]["treaty"]
            treaty = RecognitionTreaty.model_validate(wire)
            if fault == "scope":
                treaty.scope.allowed_roles = ["role:operator"]
            else:
                treaty.treaty_id = "another-validly-signed-record"
            treaty.signatures = [sign_model(treaty, credentials["alpha"][0]["na"].private_key, "na")]
            replacement = treaty.model_dump(mode="json")
            if fault == "scope":
                response["result"] = replacement
            else:
                response["result"]["treaty"] = replacement
        return response
    monkeypatch.setattr(http, "invoke", substitute)
    result = call(settings, "gm_workflow_federation_bootstrap", {
        **args, "operation_id": "substituted", "preview_digest": preview["preview_digest"]})
    assert result["status"] == "partial"
    assert result["error"]["code"] == ("treaty_scope_mismatch" if fault == "scope" else "persisted_treaty_mismatch")


def test_fleet_refuses_aliases_of_one_sovereign_before_mutating(pair):
    settings, _ = pair
    settings = replace(settings, authorities={"alpha": settings.authorities["alpha"], "beta": settings.authorities["alpha"]})
    result = call(settings, "gm_workflow_fleet_mesh", {"fleet": "two", "operation_id": "duplicate"})
    assert result["status"] == "partial" and result["error"]["code"] == "distinct_authorities_required"
    assert result["pairs"] == []
    verified = call(settings, "gm_workflow_fleet_verify", {"fleet": "two"})
    assert verified["untrusted"] == 2
    assert all(row["error"]["code"] == "distinct_authorities_required" for row in verified["pairs"])


def test_fleet_final_observation_cannot_claim_complete_after_path_loss(pair, monkeypatch):
    settings, _ = pair
    original = http.invoke
    observed = 0
    def vanish(config, operation, arguments):
        nonlocal observed
        result = original(config, operation, arguments)
        if operation["path"] == "/connectome/trust-path":
            observed += 1
            if observed > 2:
                result["result"]["trusted"] = False
        return result
    monkeypatch.setattr(http, "invoke", vanish)
    result = call(settings, "gm_workflow_fleet_mesh", {"fleet": "two", "operation_id": "path-loss"})
    assert result["status"] == "partial" and result["failed"] == 2
    assert all(row["error"]["code"] == "trust_path_rejected" for row in result["pairs"])
