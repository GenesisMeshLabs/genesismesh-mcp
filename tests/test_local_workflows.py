"""Real authority lifecycle, durable held evidence, and failure ordering."""

from __future__ import annotations

import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest
from test_authority_integration import authority as authority

from genesismesh_mcp import local_workflows as workflow
from genesismesh_mcp.types import ToolError


@pytest.fixture
def configured(authority, tmp_path):
    base, keys, _ = authority
    names = frozenset(tool.name for tool in workflow.build_tools(base))
    settings = replace(base, profiles=base.profiles | {"local"}, workflow_state_dir=tmp_path / "state",
                       artifact_roots={"audit": tmp_path / "artifacts"},
                       authorities={"test": {"url": base.authority_url, "public_key": keys["root"].public_key_b64,
                                   "root_public_key": keys["root"].public_key_b64,
                                   "operator_key_file": base.operator_key_file, "operator_key_id": "operator",
                                   "allowed_tools": names}})
    return settings, keys


def run(settings, name, **args):
    tool = next(tool for tool in workflow.build_tools(settings) if tool.name == name)
    return tool.handler({"authority": "test", **args})


def issue_treaty(settings, key):
    return workflow._call(settings, "/admin/recognition-treaties", "POST", body={
        "subject_sovereign_id": "other", "subject_public_keys": [key],
        "scope": {"allowed_roles": ["role:service:maintainer"], "accepted_statuses": ["active"], "claims": {"one": "1"}},
        "validity_hours": 24, "metadata": {"purpose": "test"}})


def history(settings):
    issued = workflow._call(settings, "/admin/attestations", "POST",
                            body={"subject_id": "client", "roles": ["role:client"]})
    workflow._call(settings, "/admin/boundary/evaluate", "POST", body={"attestation_id": issued["attestation_id"],
                   "requested_capability": "secret.manage", "context": {"request_parameters": {"resource_id": "kv:test/item"}}})
    workflow._call(settings, "/admin/evidence/anchors", "POST")


def test_treaty_renew_and_replay_create_one_linked_replacement(configured):
    settings, keys = configured
    old = issue_treaty(settings, keys["node"].public_key_b64)
    result = run(settings, "gm_workflow_treaty_renew", treaty_id=old["treaty_id"], operation_id="renew")
    assert result["completed"] is True
    assert result["new_treaty"]["metadata"]["renew_of"] == old["treaty_id"]
    assert result["new_treaty"]["metadata"]["purpose"] == "test"
    assert result["old_treaty_revocation"]["status"] == "revoked"
    again = run(settings, "gm_workflow_treaty_renew", treaty_id=old["treaty_id"], operation_id="renew")
    assert again == result
    rows = workflow._call(settings, "/recognition-treaties")["recognition_treaties"]
    assert len(rows) == 2


def test_treaty_replace_preserves_linkage_and_changes_scope(configured):
    settings, keys = configured
    old = issue_treaty(settings, keys["node"].public_key_b64)
    result = run(settings, "gm_workflow_treaty_replace", treaty_id=old["treaty_id"], operation_id="replace",
                 roles=["role:service:observer"], claims={"two": "2"}, validity_hours=12)
    assert result["completed"] is True, result
    assert result["new_treaty"]["scope"]["allowed_roles"] == ["role:service:observer"]
    assert result["new_treaty"]["scope"]["claims"] == {"two": "2"}
    assert result["new_treaty"]["metadata"]["replace_of"] == old["treaty_id"]


def test_revoke_timeout_preserves_new_treaty_and_refuses_blind_reissue(configured, monkeypatch):
    settings, keys = configured
    old = issue_treaty(settings, keys["node"].public_key_b64)
    original = workflow.invoke

    def uncertain(selected, op, args):
        if op["path"] == "/admin/recognition-treaties/<treaty_id>/revoke":
            raise ToolError("authority_unavailable", "Mutation outcome unknown")
        return original(selected, op, args)

    monkeypatch.setattr(workflow, "invoke", uncertain)
    args = {"treaty_id": old["treaty_id"], "operation_id": "uncertain"}
    result = run(settings, "gm_workflow_treaty_renew", **args)
    assert result["completed"] is False
    assert result["steps"]["steps"]["issue_treaty"]["result_identifiers"]["treaty_id"]
    assert result["steps"]["steps"]["revoke_old_treaty"]["status"] == "unknown"
    retried = run(settings, "gm_workflow_treaty_renew", **args)
    assert retried["error"]["code"] == "outcome_unknown"
    assert len(workflow._call(settings, "/recognition-treaties")["recognition_treaties"]) == 2


def test_audit_pack_held_anchors_and_verified_archive_end_to_end(configured):
    settings, _ = configured
    history(settings)
    pack = run(settings, "gm_workflow_audit_pack", operation_id="pack", artifact_store="audit")
    assert pack["completed"] is True, pack
    root = settings.artifact_roots["audit"]
    assert (root / pack["artifact"]["directory"] / "manifest.json").is_file()
    assert pack["independent_signature_verification"] is False
    held = run(settings, "gm_workflow_evidence_anchors_fetch", operation_id="hold", artifact_store="audit", anchor_now=True)
    assert held["completed"] is True and held["anchors"]["verified"] is True, held
    assert held["anchors"]["total_anchors"] >= 1
    archived = run(settings, "gm_workflow_audit_archive", operation_id="archive", artifact_store="audit", prune=True)
    assert archived["completed"] is True, archived
    assert archived["verification"]["verified"] is True
    assert archived["archive"]["archive"]["archive_id"]
    assert "removed_count" in archived["retention"]


def test_corrupt_pack_readback_never_records_or_prunes(configured, monkeypatch):
    settings, _ = configured
    history(settings)
    original = workflow.write_pack

    def corrupt(directory, files):
        original(directory, files)
        path = directory / "entries.jsonl"
        os.chmod(path, 0o600)
        path.write_bytes(b"corrupt\n")

    monkeypatch.setattr(workflow, "write_pack", corrupt)
    result = run(settings, "gm_workflow_audit_archive", operation_id="corrupt", artifact_store="audit", prune=True)
    assert result["completed"] is False
    assert result["error"]["code"] == "pack_readback_mismatch"
    assert "record_archive" not in result["steps"]["steps"]
    assert workflow._call(settings, "/admin/evidence/archives")["archived_through_sequence"] == 0


@pytest.mark.parametrize("change", ["missing", "rewritten"])
def test_held_anchor_history_cannot_be_removed_or_rewritten(configured, monkeypatch, change):
    settings, _ = configured
    history(settings)
    first = run(settings, "gm_workflow_evidence_anchors_fetch", operation_id="first", artifact_store="audit")
    assert first["completed"] is True, first
    directory = settings.artifact_roots["audit"] / first["anchors"]["directory"]
    before = {path.name: path.read_bytes() for path in directory.iterdir()}
    rows = workflow._fetch_anchors(settings)
    if change == "missing":
        rows = []
    else:
        rows[0]["store_sequence"] += 1
    monkeypatch.setattr(workflow, "_fetch_anchors", lambda selected: rows)
    result = run(settings, "gm_workflow_evidence_anchors_fetch", operation_id="second", artifact_store="audit")
    assert result["completed"] is False
    assert result["error"]["code"] == "anchor_history_changed"
    assert {path.name: path.read_bytes() for path in directory.iterdir()} == before


def test_concurrent_anchor_copies_do_not_share_core_temporary_file(configured, monkeypatch):
    settings, _ = configured
    history(settings)
    rows = workflow._fetch_anchors(settings)
    original = workflow._write_anchor
    entered = threading.Event()
    release = threading.Event()
    calls = []
    # Secure and create workflow storage before racing the two operations.
    with workflow.resource_lock(settings, "artifact", "audit"):
        pass

    def observed_write(directory, anchor):
        calls.append(anchor.anchor_sequence)
        entered.set()
        assert release.wait(timeout=10)
        return original(directory, anchor)

    monkeypatch.setattr(workflow, "_write_anchor", observed_write)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(run, settings, "gm_workflow_evidence_anchors_fetch",
                            operation_id="concurrent-first", artifact_store="audit")
        assert entered.wait(timeout=10)
        try:
            second = run(settings, "gm_workflow_evidence_anchors_fetch", operation_id="concurrent-second",
                         artifact_store="audit")
            assert second["completed"] is False
            assert second["error"]["code"] == "workflow_busy"
        finally:
            release.set()
        result = first.result(timeout=10)
    assert result["completed"] is True
    resumed = run(settings, "gm_workflow_evidence_anchors_fetch", operation_id="concurrent-second", artifact_store="audit")
    assert resumed["completed"] is True and resumed["anchors"]["new_anchors"] == 0
    assert len(calls) == len(rows)


def test_anchor_now_refusal_keeps_prior_anchors_and_reports_refusal(configured, monkeypatch):
    settings, _ = configured
    history(settings)
    original = workflow.invoke

    def refused(selected, op, args):
        if op["path"] == "/admin/evidence/anchors" and op["method"] == "POST":
            return {"http_ok": False, "http_status": 409, "response_format": "json",
                    "result": {"error": {"code": "evidence_anchor_refused", "message": "test refusal"}}}
        return original(selected, op, args)

    monkeypatch.setattr(workflow, "invoke", refused)
    result = run(settings, "gm_workflow_evidence_anchors_fetch", operation_id="refused", artifact_store="audit", anchor_now=True)
    assert result["anchors"]["total_anchors"] >= 1
    assert result["anchor_now_refusal"]["code"] == "evidence_anchor_refused"
    assert result["head_anchored"] is False and result["recent_entries_covered"] is False


def test_empty_store_response_does_not_claim_an_anchor_was_held(configured, monkeypatch):
    settings, _ = configured
    original = workflow.invoke

    def empty(selected, operation, arguments):
        if operation["path"] == "/admin/evidence/anchors":
            body = ({"anchor": None, "status": "unchanged"} if operation["method"] == "POST"
                    else {"anchors": [], "next_after_anchor": None})
            return {"http_ok": True, "http_status": 200, "response_format": "json", "result": body}
        return original(selected, operation, arguments)

    monkeypatch.setattr(workflow, "invoke", empty)
    result = run(settings, "gm_workflow_evidence_anchors_fetch", operation_id="empty", artifact_store="audit", anchor_now=True)
    assert result["completed"] is True, result
    assert result["anchors"]["total_anchors"] == 0
    assert result["head_anchored"] is False


def test_anchor_now_result_must_appear_in_verified_held_history(configured, monkeypatch):
    settings, _ = configured
    history(settings)
    monkeypatch.setattr(workflow, "_fetch_anchors", lambda selected: [])
    result = run(settings, "gm_workflow_evidence_anchors_fetch", operation_id="missing-head", artifact_store="audit", anchor_now=True)
    assert result["completed"] is False
    assert result["error"]["code"] == "requested_anchor_missing"
    assert list(settings.artifact_roots["audit"].iterdir()) == []


def test_untrusted_pack_path_is_refused_before_any_file_write(configured, monkeypatch):
    settings, _ = configured
    history(settings)
    pack = workflow._call(settings, "/admin/evidence/audit-pack", "POST", body={})
    pack["files"]["../escape"] = "do not write"
    original = workflow._call

    def malicious(selected, path, method="GET", **kwargs):
        return pack if path == "/admin/evidence/audit-pack" else original(selected, path, method, **kwargs)

    monkeypatch.setattr(workflow, "_call", malicious)
    result = run(settings, "gm_workflow_audit_pack", operation_id="unsafe", artifact_store="audit")
    assert result["completed"] is False
    assert result["error"]["code"] == "invalid_pack_path"
    assert list(settings.artifact_roots["audit"].iterdir()) == []


def test_anchor_pagination_rejects_nonadvancing_cursor(configured, monkeypatch):
    settings, _ = configured
    monkeypatch.setattr(workflow, "_call", lambda *_args, **_kwargs: {"anchors": [], "next_after_anchor": 0})
    with pytest.raises(ToolError, match="pagination"):
        workflow._fetch_anchors(settings)


def test_named_authority_permission_and_profiles_are_enforced(configured):
    settings, _ = configured
    disabled = replace(settings, profiles=settings.profiles - {"write"})
    with pytest.raises(ToolError, match="not enabled"):
        run(disabled, "gm_workflow_treaty_renew", operation_id="no-write", treaty_id="id")
    forbidden = replace(settings, authorities={"test": replace(settings.authorities["test"], allowed_tools=frozenset())})
    with pytest.raises(ToolError, match="not enabled"):
        run(forbidden, "gm_workflow_treaty_renew", operation_id="no-authority", treaty_id="id")


def test_operation_id_cannot_change_inputs(configured):
    settings, keys = configured
    old = issue_treaty(settings, keys["node"].public_key_b64)
    run(settings, "gm_workflow_treaty_renew", operation_id="same", treaty_id=old["treaty_id"])
    with pytest.raises(ToolError, match="different inputs"):
        run(settings, "gm_workflow_treaty_renew", operation_id="same", treaty_id=old["treaty_id"], validity_hours=48)


def test_local_step_journal_contains_no_private_key_material(configured):
    settings, keys = configured
    old = issue_treaty(settings, keys["node"].public_key_b64)
    run(settings, "gm_workflow_treaty_renew", operation_id="secrets", treaty_id=old["treaty_id"])
    record = json.loads(next(settings.workflow_state_dir.glob("*.json")).read_text("utf-8"))
    encoded = json.dumps(record)
    assert "operator_key_file" not in encoded
    assert str(settings.operator_key_file) not in encoded
    assert "private_key" not in encoded
