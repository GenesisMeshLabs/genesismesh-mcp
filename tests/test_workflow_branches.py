"""Registered workflow execution, held-state refusals and process-loss recovery."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from dataclasses import replace

import pytest
from genesis_mesh.crypto import verify_model_signature, verify_signature
from genesis_mesh.models import GenesisBlock
from genesis_mesh.models.evidence_store import StoreAnchor
from test_authority_integration import authority as authority
from test_canary_workflows import canary_store as canary_store
from test_local_workflows import configured as configured
from test_local_workflows import history
from test_multi_workflows import pair as pair
from test_proof_workflows import proof_store as proof_store

from genesismesh_mcp import local_workflows as local
from genesismesh_mcp import multi_support, multi_workflows, proof_workflows, provision_workflows, workflow_support
from genesismesh_mcp.proof_workflows import CANARY, CLEANUP, PREVIEW, TABLES
from genesismesh_mcp.settings import Settings
from genesismesh_mcp.types import ToolError
from genesismesh_mcp.workflow_config import AuthorityConfig, ProofStoreConfig, ProvisionConfig, parse_records


def call(settings, name, arguments):
    """Call the actual registered handler so the receipt can bind scenario to tool."""
    for module in (local, multi_workflows, proof_workflows, provision_workflows, workflow_support):
        tool = next((tool for tool in module.build_tools(settings) if tool.name == name), None)
        if tool is not None:
            return tool.handler(arguments)
    raise AssertionError(f"No workflow registered as {name}")


def test_registered_federation_and_fleet_handlers_execute_real_authorities(pair):
    settings, _ = pair
    args = {"acceptor": "alpha", "issuer": "beta", "roles": ["role:client"]}
    preview = call(settings, "gm_workflow_federation_preview", args)
    assert preview["genesis_signatures_verified"]
    result = call(settings, "gm_workflow_federation_bootstrap", {
        **args, "operation_id": "registered-bootstrap", "preview_digest": preview["preview_digest"]})
    assert result["status"] == "completed" and result["result"]["trust_path"]["trusted"]
    assert call(settings, "gm_workflow_fleet_status", {"fleet": "two"})["healthy"]
    before = call(settings, "gm_workflow_fleet_verify", {"fleet": "two"})
    assert before["untrusted"] == 1
    mesh = call(settings, "gm_workflow_fleet_mesh", {"fleet": "two", "operation_id": "registered-mesh",
                                                   "roles": ["role:client"]})
    assert mesh["status"] == "completed" and mesh["created"] == 1 and mesh["skipped"] == 1
    assert call(settings, "gm_workflow_fleet_verify", {"fleet": "two"})["untrusted"] == 0
    state = call(settings, "gm_workflow_operation_status", {
        "workflow": "gm_workflow_fleet_mesh", "operation_id": "registered-mesh"})
    assert state["complete"] and state["result_sha256"]


def test_registered_proof_remote_handler_observes_real_revocation(pair):
    settings, keys = pair
    args = {"acceptor": "alpha", "issuer": "beta", "operation_id": "registered-proof",
            "subject_public_key": keys["beta"][0]["subject"].public_key_b64}
    result = call(settings, "gm_workflow_proof_remote", args)
    assert result["status"] == "completed" and result["inspection"]["valid"]
    assert result["result"]["pre_revocation"]["accepted"] is True
    assert result["result"]["post_revocation"]["accepted"] is False
    assert call(settings, "gm_workflow_proof_remote", args) == result


def test_registered_canary_handler_persists_verifiable_receipt(canary_store):
    settings, keys = canary_store
    args = {"store": "canary", "acceptor": "alpha", "issuer": "beta", "operation_id": "registered-canary"}
    result = call(settings, CANARY, args)
    assert result["status"] == "completed", result
    receipt = result["receipt"]
    canonical = json.dumps(receipt["payload"], sort_keys=True, separators=(",", ":")).encode()
    assert verify_signature(canonical, receipt["signature"]["value"], keys["alpha"][0]["subject"].public_key_b64)
    config = settings.proof_stores["canary"]
    assert json.loads((config.receipt_dir / result["receipt_file"]).read_text()) == receipt
    with sqlite3.connect(config.db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone() == (1,)
    with pytest.raises(ToolError, match="not authorized"):
        call(replace(settings, signer_permissions={}), CANARY, {**args, "operation_id": "denied"})


def test_registered_cleanup_handlers_verify_backup_before_deletion(proof_store):
    settings, path = proof_store
    preview = call(settings, PREVIEW, {"store": "lab"})
    result = call(settings, CLEANUP, {"store": "lab", "operation_id": "registered-cleanup",
                                      "preview_digest": preview["scope_digest"]})
    assert result["status"] == "completed" and result["backup_verified"]
    backup = settings.proof_stores["lab"].backup_dir / result["backup"]
    assert hashlib.sha256(backup.read_bytes()).hexdigest() == result["backup_sha256"]
    with sqlite3.connect(backup) as before, sqlite3.connect(path) as after:
        for table in TABLES:
            assert before.execute(f"SELECT COUNT(*) FROM {table}").fetchone() == (2,)
            assert after.execute(f"SELECT COUNT(*) FROM {table}").fetchone() == (0,)


def test_registered_generation_handler_builds_private_ipv6_fleet(tmp_path):
    settings = Settings(profiles={"local", "write", "provision"}, workflow_state_dir=tmp_path / "state",
                        provisioning={"lab": {"root": tmp_path / "fleet", "host": "::1"}})
    args = {"provisioning": "lab", "operation_id": "registered", "names": ["north"]}
    result = call(settings, provision_workflows.NAME, args)
    assert result["status"] == "completed" and result["servers_started"] is False
    assert result["members"][0]["endpoint"] == "http://[::1]:8443"
    genesis = GenesisBlock.model_validate_json((tmp_path / "fleet/registered/north/genesis.signed.json").read_text())
    assert verify_model_signature(genesis, genesis.signatures[0], result["members"][0]["root_public_key"])
    assert genesis.network_authority.public_key == result["members"][0]["authority_public_key"]
    assert call(settings, provision_workflows.NAME, args) == result
    with pytest.raises(ToolError, match="configured"):
        call(settings, provision_workflows.NAME, {**args, "provisioning": "missing"})


@pytest.mark.parametrize("tool,args", [
    ("gm_workflow_federation_preview", {"acceptor": "alpha", "issuer": "beta"}),
    ("gm_workflow_federation_bootstrap", {"acceptor": "alpha", "issuer": "beta", "operation_id": "deny", "preview_digest": "wrong"}),
    ("gm_workflow_fleet_status", {"fleet": "two"}),
    ("gm_workflow_fleet_verify", {"fleet": "two"}),
    ("gm_workflow_fleet_mesh", {"fleet": "two", "operation_id": "deny"}),
    ("gm_workflow_proof_remote", {"acceptor": "alpha", "issuer": "beta", "operation_id": "deny", "subject_public_key": "AA=="}),
])
def test_registered_multi_handlers_refuse_unconfigured_destinations(tool, args):
    settings = Settings(profiles={"read", "verify", "operator", "write", "local"})
    with pytest.raises(ToolError) as exc:
        call(settings, tool, args)
    assert exc.value.code in {"authority_not_configured", "fleet_not_configured"}


@pytest.mark.parametrize("tool,args", [
    (PREVIEW, {"store": "missing"}),
    (CLEANUP, {"store": "missing", "operation_id": "no", "preview_digest": "no"}),
    (CANARY, {"store": "missing", "acceptor": "a", "issuer": "b", "operation_id": "no"}),
])
def test_registered_proof_handlers_refuse_unowned_storage(tool, args):
    settings = Settings(profiles={"read", "verify", "operator", "write", "local", "maintain", "sign"})
    with pytest.raises(ToolError) as exc:
        call(settings, tool, args)
    assert exc.value.code == "proof_store_not_owned"


def test_registered_local_handlers_preserve_known_authority_refusals(configured, monkeypatch):
    settings, _ = configured
    def denied(*_):
        return {"http_ok": False, "http_status": 403, "result": {"error": "operator_denied"}}
    monkeypatch.setattr(local, "invoke", denied)
    for name in ("audit_pack", "audit_archive", "evidence_anchors_fetch", "treaty_renew", "treaty_replace"):
        args = {"authority": "test", "operation_id": name}
        args.update({"treaty_id": "missing"} if name.startswith("treaty") else {"artifact_store": "audit"})
        if name == "evidence_anchors_fetch":
            args["anchor_now"] = True
        result = call(settings, "gm_workflow_" + name, args)
        assert not result["completed"] and result["error"]["code"] == "authority_rejected", result
        assert result["error"]["authority_result"]["http_status"] == 403


@pytest.mark.parametrize("kind", ["unexpected", "too_large", "too_many", "directory"])
def test_pack_reader_bounds_untrusted_files(tmp_path, kind):
    if kind == "unexpected":
        (tmp_path / "unexpected.txt").write_text("no")
    elif kind == "too_large":
        (tmp_path / "manifest.json").write_bytes(b"x" * 11)
    elif kind == "too_many":
        for i in range(65):
            (tmp_path / f"directory{i}").mkdir()
    else:
        (tmp_path / "empty").mkdir()
        assert local._read_pack(tmp_path, 10) == {}
        return
    with pytest.raises(ToolError) as exc:
        local._read_pack(tmp_path, 10)
    assert exc.value.code == ("artifact_too_large" if kind == "too_large" else "invalid_pack_path")


@pytest.mark.parametrize("failure", ["missing_manifest", "size", "manifest"])
def test_pack_validation_before_persistence(configured, failure):
    settings, _ = configured
    history(settings)
    pack = local._call(settings, "/admin/evidence/audit-pack", "POST", body={})
    limit = settings.max_output_bytes
    if failure == "missing_manifest":
        pack = {}
    elif failure == "size":
        limit = 1
    else:
        pack["files"]["entries.jsonl"] += "tamper"
    with pytest.raises(ToolError) as exc:
        local._checked_pack_files(pack, limit)
    assert exc.value.code == {"missing_manifest": "invalid_pack", "size": "artifact_too_large",
                              "manifest": "pack_manifest_mismatch"}[failure]


@pytest.mark.parametrize("fault", ["not_list", "duplicate", "size", "pages"])
def test_anchor_pagination_validates_all_pages_and_total_bytes(configured, monkeypatch, fault):
    settings, _ = configured
    history(settings)
    rows = local._fetch_anchors(settings)
    assert rows
    if fault == "not_list":
        response = {"anchors": {}}
    elif fault == "duplicate":
        response = {"anchors": [rows[0], rows[0]]}
    else:
        response = {"anchors": [rows[0]], "next_after_anchor": rows[0]["anchor_sequence"]}
    if fault == "pages":
        monkeypatch.setattr(local, "MAX_PAGES", 1)
    monkeypatch.setattr(local, "_call", lambda *_args, **_kwargs: response)
    with pytest.raises(ToolError) as exc:
        local._fetch_anchors(replace(settings, max_output_bytes=1024) if fault == "size" else settings)
    assert exc.value.code in {"anchor_limit", "invalid_anchor_history"}


@pytest.mark.parametrize("fault", ["unexpected", "size", "filename", "chain", "start"])
def test_held_anchor_store_refuses_unverified_or_misnamed_records(configured, tmp_path, fault):
    settings, _ = configured
    history(settings)
    rows = local._fetch_anchors(settings)
    root = tmp_path / "held"
    root.mkdir()
    if fault in {"chain", "start"}:
        rows[0]["store_sequence" if fault == "chain" else "anchor_sequence"] += 1
        with pytest.raises(ToolError) as exc:
            local._copy_anchors(root, "anchors", rows, [settings.authority_public_key], settings.max_output_bytes)
        assert exc.value.code == ("anchor_verification_failed" if fault == "chain" else "anchor_history_incomplete")
        return
    anchor = StoreAnchor.model_validate(rows[0])
    filename = f"anchor-{anchor.anchor_sequence:010d}.json"
    if fault == "unexpected":
        filename = "untrusted.txt"
    elif fault == "filename":
        filename = "anchor-0000009999.json"
    (root / filename).write_text(json.dumps(rows[0]))
    with pytest.raises(ToolError) as exc:
        local._read_held(root, 1 if fault == "size" else settings.max_output_bytes)
    assert exc.value.code == ("anchor_limit" if fault == "size" else "invalid_anchor_store")


@pytest.mark.parametrize("failure", [OSError("disk unavailable"), ValueError("corrupt data"), TypeError("wrong shape")])
def test_local_workflow_reports_artifact_failures_without_remote_commit(configured, monkeypatch, failure):
    settings, _ = configured
    history(settings)
    def fail(*_args, **_kwargs):
        raise failure
    monkeypatch.setattr(local, "_persist_pack", fail)
    result = call(settings, "gm_workflow_audit_pack", {"authority": "test", "operation_id": "fault", "artifact_store": "audit"})
    assert result["completed"] is False
    assert result["error"]["code"] == ("artifact_io_failed" if isinstance(failure, OSError) else "invalid_workflow_data")
    assert result["steps"]["steps"]["persist_pack"]["status"] == "unknown"


@pytest.mark.parametrize("kind,values", [
    ("authorities", []), ("authorities", {str(i): {} for i in range(65)}),
    ("authorities", {"a": {"url": "https://example.test", "public_key": "key", "extra": 1}}),
    ("authorities", {"a": None}),
])
def test_workflow_registry_rejects_unknown_or_unbounded_configuration(kind, values):
    with pytest.raises(ValueError):
        parse_records(kind, values)


def test_workflow_config_paths_permissions_and_limits(tmp_path):
    with pytest.raises(ValueError, match="pin"):
        AuthorityConfig("https://example.test", "")
    with pytest.raises(ValueError, match="exact"):
        AuthorityConfig("https://example.test", "key", allowed_tools={"*"})
    for values in ({"base_port": 1}, {"max_members": 17}):
        with pytest.raises(ValueError):
            ProvisionConfig(tmp_path, **values)
    assert ProvisionConfig(tmp_path, host="localhost").host == "localhost"
    for values in ({"allowed_tools": {"*"}}, {"disposable": 1}, {"owned": 1}):
        with pytest.raises(ValueError):
            ProofStoreConfig(tmp_path / "db", tmp_path / "backup", tmp_path / "receipt", "signer", **values)
    parsed = parse_records("authorities", {"a": {"url": "https://example.test", "public_key": "key"}}, tmp_path)
    assert parsed["a"].operator_key_file is None
    assert parse_records("provisioning", {"p": ProvisionConfig(tmp_path)})["p"].root == tmp_path
    with pytest.raises(TypeError):
        parsed["b"] = parsed["a"]


def test_durable_mutation_process_death_leaves_intent_and_prevents_reexecution(tmp_path):
    """A hard process exit occurs after a durable external write but before the reply."""
    script = tmp_path / "crash.py"
    script.write_text('''import os, sys
from pathlib import Path
from genesismesh_mcp.settings import Settings
from genesismesh_mcp.workflow_support import WorkflowJournal
root = Path(sys.argv[1])
settings = Settings(profiles={"local", "read"}, workflow_state_dir=root / "state")
with WorkflowJournal(settings, "gm_workflow_fleet_generate", "crash", {}) as journal:
    def mutate():
        with (root / "effect").open("a") as stream:
            stream.write("executed\\n")
            stream.flush()
            os.fsync(stream.fileno())
        os._exit(73)
    journal.step("external_commit", mutate, mutation=True)
''')
    completed = subprocess.run([sys.executable, str(script), str(tmp_path)], capture_output=True, timeout=30)
    assert completed.returncode == 73, completed.stderr.decode()
    restart = tmp_path / "restart.py"
    restart.write_text('''import sys
from pathlib import Path
from genesismesh_mcp.settings import Settings
from genesismesh_mcp.types import ToolError
from genesismesh_mcp.workflow_support import WorkflowJournal
root = Path(sys.argv[1])
settings = Settings(profiles={"local", "read"}, workflow_state_dir=root / "state")
with WorkflowJournal(settings, "gm_workflow_fleet_generate", "crash", {}) as journal:
    try:
        journal.step("external_commit", lambda: (root / "effect").write_text("REPEATED"), mutation=True)
    except ToolError as error:
        print(error.code)
    else:
        raise AssertionError("The committed effect was repeated")
''')
    resumed = subprocess.run([sys.executable, str(restart), str(tmp_path)], capture_output=True, timeout=30)
    assert resumed.returncode == 0 and resumed.stdout.decode().strip() == "outcome_unknown", resumed.stderr.decode()
    settings = Settings(profiles={"local", "read"}, workflow_state_dir=tmp_path / "state")
    with workflow_support.WorkflowJournal(settings, "gm_workflow_fleet_generate", "crash", {}) as journal:
        assert journal.data["steps"]["external_commit"]["status"] == "started"
        with pytest.raises(ToolError) as exc:
            journal.step("external_commit", lambda: pytest.fail("A committed effect was repeated"), mutation=True)
        assert exc.value.code == "outcome_unknown"
    assert (tmp_path / "effect").read_text() == "executed\n"
    # The dead process released the OS lock; another operation can proceed.
    with workflow_support.WorkflowJournal(settings, "gm_workflow_fleet_generate", "new", {}) as journal:
        assert journal.step("read", lambda: "available") == "available"


def test_journal_state_corruption_expiry_and_bounded_status(tmp_path):
    settings = Settings(profiles={"local", "read"}, workflow_state_dir=tmp_path / "state")
    with pytest.raises(ToolError, match="identifier"):
        workflow_support.WorkflowJournal(settings, "bad/path", "id", {})
    with workflow_support.WorkflowJournal(settings, "gm_workflow_fleet_status", "expired", {}) as journal:
        journal.data["created_at"] = 0
        with pytest.raises(ToolError) as exc:
            journal.step("later", lambda: True)
        assert exc.value.code == "operation_expired"
    path = settings.workflow_state_dir / "gm_workflow_fleet_status--expired.json"
    path.write_text("{")
    with pytest.raises(json.JSONDecodeError):
        with workflow_support.WorkflowJournal(settings, "gm_workflow_fleet_status", "expired", {}):
            pass
    # Failed load released the OS lock too.
    path.write_text(json.dumps({"tool": "unknown", "operation_id": "expired", "steps": {}}))
    with pytest.raises(ToolError) as exc:
        call(settings, "gm_workflow_operation_status", {"workflow": "gm_workflow_fleet_status", "operation_id": "expired"})
    assert exc.value.code == "operation_not_found"
    with pytest.raises(ToolError):
        call(settings, "gm_workflow_operation_status", {"workflow": "gm_workflow_missing", "operation_id": "absent"})


def test_atomic_json_preserves_existing_and_cleans_temporary_files(tmp_path, monkeypatch):
    target = tmp_path / "state.json"
    workflow_support.atomic_json(target, {"old": True})
    with pytest.raises(FileExistsError):
        workflow_support.atomic_json(target, {"new": True}, overwrite=False)
    assert json.loads(target.read_text()) == {"old": True}
    assert not list(tmp_path.glob(".write-*"))
    with pytest.raises(ToolError) as exc:
        workflow_support.atomic_json(target, {"large": "x" * 20}, max_bytes=4)
    assert exc.value.code == "workflow_state_too_large"
    monkeypatch.setattr(workflow_support.os, "replace", lambda *_: (_ for _ in ()).throw(OSError("disk failure")))
    with pytest.raises(OSError):
        workflow_support.atomic_json(target, {"new": True})
    assert json.loads(target.read_text()) == {"old": True}
    assert not list(tmp_path.glob(".write-*"))


def test_multi_support_rejects_unsupported_operations_and_excess_responses(pair):
    settings, _ = pair
    deadline = multi_support.Deadline(settings)
    client = multi_support.Client(settings, "alpha", "gm_workflow_fleet_status", deadline)
    with pytest.raises(ToolError, match="unsupported"):
        client.raw("DELETE", "/arbitrary")
    deadline.remaining_bytes = 1
    with pytest.raises(ToolError) as exc:
        deadline.consume("too large")
    assert exc.value.code == "workflow_response_budget"
    assert multi_support.safe_error(ValueError("secret")) == {
        "code": "workflow_failed", "message": "The composed workflow could not complete."}
    without_operator = replace(settings, authorities={**settings.authorities, "alpha": replace(settings.authorities["alpha"],
                              operator_key_id=None, operator_key_file=None)})
    with pytest.raises(ToolError, match="operator"):
        multi_support.Client(without_operator, "alpha", "gm_workflow_fleet_status", multi_support.Deadline(settings)).require_operator()


def test_fleet_verification_reports_every_failed_review(pair, monkeypatch):
    settings, _ = pair
    def unavailable(*_):
        raise ToolError("offline", "Authority unavailable")
    monkeypatch.setattr(multi_workflows, "review", unavailable)
    result = call(settings, "gm_workflow_fleet_verify", {"fleet": "two"})
    assert result["untrusted"] == 2
    assert all(row["error"]["code"] == "authority_review_failed" for row in result["pairs"])


def test_proof_scope_includes_blobs_and_absent_tables_and_enforces_rows(tmp_path):
    with sqlite3.connect(tmp_path / "partial.db") as connection:
        connection.execute(f"CREATE TABLE {TABLES[0]} (value BLOB)")
        connection.execute(f"INSERT INTO {TABLES[0]} VALUES (?)", (b"\x00\xff",))
        scope = proof_workflows._scope(connection)
        assert scope["tables"] == {TABLES[0]: 1, **dict.fromkeys(TABLES[1:], 0)}
        connection.executemany(f"INSERT INTO {TABLES[0]} VALUES (?)", [(b"x",)] * 50_000)
        with pytest.raises(ToolError) as exc:
            proof_workflows._scope(connection)
        assert exc.value.code == "proof_scope_too_large"


def test_cleanup_backup_deadline_never_deletes_rows(proof_store, monkeypatch):
    settings, path = proof_store
    preview = call(settings, PREVIEW, {"store": "lab"})
    clock = iter([0, settings.timeout_seconds + 1])
    monkeypatch.setattr(proof_workflows, "monotonic", lambda: next(clock))
    result = call(settings, CLEANUP, {"store": "lab", "operation_id": "timeout", "preview_digest": preview["scope_digest"]})
    assert result["status"] == "partial" and result["error"] == "backup_deadline"
    with sqlite3.connect(path) as connection:
        assert connection.execute(f"SELECT COUNT(*) FROM {TABLES[0]}").fetchone() == (2,)


def test_proof_database_missing_and_oversized_are_refused(tmp_path):
    path = tmp_path / "db"
    with pytest.raises(ToolError) as exc:
        proof_workflows._connect(path)
    assert exc.value.code == "proof_database_missing"
    with path.open("wb") as stream:
        stream.truncate(67_108_865)
    with pytest.raises(ToolError) as exc:
        proof_workflows._connect(path)
    assert exc.value.code == "proof_database_too_large"


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL setup has no POSIX subprocess equivalent")
@pytest.mark.parametrize("fault", ["sid", "icacls"])
def test_failed_private_acl_setup_cannot_be_bypassed_on_retry(tmp_path, monkeypatch, fault):
    root = tmp_path / "private"
    settings = Settings(profiles={"local"}, workflow_state_dir=root)
    original = workflow_support.subprocess.run
    attempts = []
    failed = False
    def fail_once(command, **kwargs):
        nonlocal failed
        attempts.append(command[0])
        if not failed and ((fault == "sid" and command[0] == "whoami")
                           or (fault == "icacls" and command[0] == "icacls")):
            failed = True
            if fault == "sid":
                return subprocess.CompletedProcess(command, 0, stdout='"user","invalid-sid"\n')
            raise subprocess.CalledProcessError(1, command)
        return original(command, **kwargs)
    monkeypatch.setattr(workflow_support.subprocess, "run", fail_once)
    with pytest.raises(ToolError) as exc:
        workflow_support.WorkflowJournal(settings, "gm_workflow_fleet_generate", "retry", {})
    assert exc.value.code == "private_storage_unavailable"
    assert not root.exists()
    with workflow_support.WorkflowJournal(settings, "gm_workflow_fleet_generate", "retry", {}) as journal:
        assert journal.step("safe", lambda: True)
    assert attempts.count("whoami") == 2
    assert attempts[-1] == "icacls"


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL setup has no POSIX subprocess equivalent")
@pytest.mark.parametrize("cleanup_failure", ["access_denied", "concurrent_file"])
def test_failed_acl_and_cleanup_never_publish_or_reuse_unsecured_storage(tmp_path, monkeypatch, cleanup_failure):
    from pathlib import Path

    root = tmp_path / "private"
    settings = Settings(profiles={"local"}, workflow_state_dir=root)
    original_run, original_rmdir = workflow_support.subprocess.run, Path.rmdir
    stages = []
    fail_acl = True
    def fail_permissions(command, **kwargs):
        if command[0] == "icacls":
            stages.append(Path(command[1]))
            if fail_acl:
                if cleanup_failure == "concurrent_file":
                    (stages[-1] / "concurrent-user-file").write_text("preserve")
                raise subprocess.CalledProcessError(1, command)
        return original_run(command, **kwargs)
    def refuse_empty_cleanup(path):
        if cleanup_failure == "access_denied" and path in stages:
            raise PermissionError("ACL prevented cleanup")
        return original_rmdir(path)
    monkeypatch.setattr(workflow_support.subprocess, "run", fail_permissions)
    monkeypatch.setattr(Path, "rmdir", refuse_empty_cleanup)
    for _ in range(2):
        with pytest.raises(ToolError) as exc:
            workflow_support.WorkflowJournal(settings, "gm_workflow_fleet_generate", "retry", {})
        assert exc.value.code == "private_storage_unavailable"
        assert not root.exists()
    assert len(stages) == 2 and stages[0] != stages[1]
    assert all(stage.exists() for stage in stages)
    if cleanup_failure == "concurrent_file":
        assert all((stage / "concurrent-user-file").read_text() == "preserve" for stage in stages)
    # Recovery performs security setup for another fresh directory; neither
    # failed directory is adopted, and no user file is removed or moved.
    fail_acl = False
    with workflow_support.WorkflowJournal(settings, "gm_workflow_fleet_generate", "retry", {}) as journal:
        assert journal.step("secured", lambda: True)
    assert len(stages) == 3 and root.is_dir() and not stages[-1].exists()
    assert not (root / "concurrent-user-file").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows-only atomic ACL publication")
def test_private_directory_never_changes_preexisting_destination(tmp_path, monkeypatch):
    root = tmp_path / "existing"
    root.mkdir()
    (root / "user-file").write_text("untouched")
    monkeypatch.setattr(workflow_support.subprocess, "run", lambda *_args, **_kwargs: pytest.fail("Existing ACL changed"))
    with pytest.raises(FileExistsError):
        workflow_support.private_directory(root)
    assert (root / "user-file").read_text() == "untouched"


@pytest.mark.skipif(os.name != "nt", reason="Windows-only atomic ACL publication")
def test_private_directory_publish_race_preserves_other_destination(tmp_path, monkeypatch):
    root = tmp_path / "race"
    original = workflow_support.subprocess.run
    def competing_creation(command, **kwargs):
        result = original(command, **kwargs)
        if command[0] == "icacls":
            root.mkdir()
            (root / "user-file").write_text("untouched")
        return result
    monkeypatch.setattr(workflow_support.subprocess, "run", competing_creation)
    with pytest.raises(FileExistsError):
        workflow_support.private_directory(root)
    assert (root / "user-file").read_text() == "untouched"
    assert not list(tmp_path.glob(".private-init-*"))
