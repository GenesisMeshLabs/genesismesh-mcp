"""Residual workflow races and corrupted dependency results; verifiers stay real."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sqlite3
import stat
import subprocess
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from genesis_mesh.crypto import generate_keypair, sign_model
from genesis_mesh.models import JoinCertificate
from genesis_mesh.transport.noise_handshake import NoiseHandshake
from genesis_mesh.transport.protocol import MeshMessage
from genesis_mesh.transport.websocket_transport import accept_websocket_with_noise
from test_authority_integration import authority as authority
from test_canary_workflows import canary_store as canary_store
from test_local_workflows import configured as configured
from test_local_workflows import history, issue_treaty
from test_multi_workflows import pair as pair
from test_proof_workflows import proof_store as proof_store
from test_runtime_workflows import node_settings
from test_workflow_branches import call
from websockets.asyncio.server import serve

from genesismesh_mcp import authority as http
from genesismesh_mcp import local_workflows as local
from genesismesh_mcp import multi_workflows, proof_workflows, runtime_workflows
from genesismesh_mcp.proof_workflows import CANARY, CLEANUP, PREVIEW, TABLES
from genesismesh_mcp.runtime_config import PeerConfig
from genesismesh_mcp.runtime_workflows import JOIN, SEND
from genesismesh_mcp.settings import Settings
from genesismesh_mcp.types import ToolError
from genesismesh_mcp.workflow_support import WorkflowJournal, private_directory


def test_local_authority_nonobject_response_is_refused(configured, monkeypatch):
    settings, _ = configured
    monkeypatch.setattr(local, "invoke", lambda *_: {"http_ok": True, "result": []})
    with pytest.raises(ToolError) as exc:
        local._call(settings, "/admin/evidence/archives")
    assert exc.value.code == "invalid_authority_response"


def test_artifact_child_replaced_with_symlink_is_refused(tmp_path):
    root, outside = tmp_path / "store", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    try:
        (root / "pack").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Platform does not permit symbolic links")
    with pytest.raises(ToolError) as exc:
        local._child(root, "pack")
    assert exc.value.code == "invalid_artifact_path" and list(outside.iterdir()) == []


def test_anchor_pagination_aggregate_limit_applies_across_valid_pages(configured, monkeypatch):
    settings, _ = configured
    for _ in range(3):
        history(settings)
    rows = local._fetch_anchors(settings)
    assert sum(len(json.dumps(row).encode()) for row in rows) > 1024
    def one_per_page(_settings, _path, *, query):
        remaining = [row for row in rows if row["anchor_sequence"] > query["after_anchor"]]
        row = remaining[0]
        return {"anchors": [row], "next_after_anchor": row["anchor_sequence"] if len(remaining) > 1 else None}
    monkeypatch.setattr(local, "_call", one_per_page)
    with pytest.raises(ToolError) as exc:
        local._fetch_anchors(replace(settings, max_output_bytes=1024))
    assert exc.value.code == "anchor_limit"


def _corrupt_pack(settings, operation_id):
    entry = settings.artifact_roots["audit"] / local._operation_child("archive", operation_id) / "entries.jsonl"
    os.chmod(entry, 0o600)
    entry.write_bytes(b"changed after previous readback\n")


@pytest.mark.parametrize("timing", ["after_persist", "after_verify"])
def test_archive_rechecks_bytes_at_each_mutation_boundary(configured, monkeypatch, timing):
    settings, _ = configured
    history(settings)
    operation_id = timing
    if timing == "after_persist":
        original = local._persist_pack
        def changed(*args, **kwargs):
            result = original(*args, **kwargs)
            _corrupt_pack(settings, operation_id)
            return result
        monkeypatch.setattr(local, "_persist_pack", changed)
    else:
        original = local.verify_audit_pack
        def changed(*args, **kwargs):
            result = original(*args, **kwargs)
            assert result.verified
            _corrupt_pack(settings, operation_id)
            return result
        monkeypatch.setattr(local, "verify_audit_pack", changed)
    result = call(settings, "gm_workflow_audit_archive", {"authority": "test", "artifact_store": "audit",
                                                         "operation_id": operation_id, "prune": True})
    assert not result["completed"] and result["error"]["code"] == "pack_readback_mismatch"
    assert "record_archive" not in result["steps"]["steps"]
    assert local._call(settings, "/admin/evidence/archives")["archived_through_sequence"] == 0


def test_archive_refuses_signature_failure_with_wrong_root(configured):
    settings, _ = configured
    history(settings)
    settings = replace(settings, authorities={"test": replace(settings.authorities["test"],
                        root_public_key=generate_keypair().public_key_b64)})
    result = call(settings, "gm_workflow_audit_archive", {"authority": "test", "artifact_store": "audit",
                                                         "operation_id": "wrong-root", "prune": True})
    assert not result["completed"] and result["error"]["code"] == "pack_verification_failed"
    assert "record_archive" not in result["steps"]["steps"]


def test_archive_refuses_progress_changed_by_another_operator(configured, monkeypatch):
    settings, _ = configured
    history(settings)
    original = local._call
    manifest = None
    changed = False
    def concurrent(selected, path, method="GET", **kwargs):
        nonlocal manifest, changed
        if path == "/admin/evidence/archives" and method == "GET" and manifest is not None and not changed:
            changed = True
            original(selected, path, "POST", body={"manifest": manifest, "location": "mcp-test:concurrent-archive"})
        result = original(selected, path, method, **kwargs)
        if path == "/admin/evidence/audit-pack":
            manifest = result["manifest"]
        return result
    monkeypatch.setattr(local, "_call", concurrent)
    result = call(settings, "gm_workflow_audit_archive", {"authority": "test", "artifact_store": "audit",
                                                         "operation_id": "race"})
    assert not result["completed"] and result["error"]["code"] == "archive_state_changed"
    assert "apply_retention" not in result["steps"]["steps"]


@pytest.mark.parametrize("prune", [False, True])
def test_archive_can_preserve_records_or_apply_age_threshold(configured, prune):
    settings, _ = configured
    history(settings)
    result = call(settings, "gm_workflow_audit_archive", {"authority": "test", "artifact_store": "audit",
                  "operation_id": "age", "prune": prune, "older_than_days": 365})
    assert result["completed"], result
    assert ("retention" in result) is prune
    if prune:
        assert result["retention"]["removed_count"] == 0


def test_anchors_fail_closed_if_selected_configuration_dependency_loses_pin(configured, monkeypatch):
    """Defensive injected fault: ordinary AuthorityConfig forbids an empty pin.

    A future selector regression must still fail before evidence is fetched;
    this does not claim the public configuration accepts missing pins.
    """
    settings, _ = configured
    monkeypatch.setattr(local, "select_authority", lambda *_: replace(settings, authority_public_key=None))
    monkeypatch.setattr(local, "_call", lambda *_args, **_kwargs: pytest.fail("Unpinned fetch occurred"))
    result = call(settings, "gm_workflow_evidence_anchors_fetch", {"authority": "test", "artifact_store": "audit",
                                                                "operation_id": "lost-pin"})
    assert not result["completed"] and result["error"]["code"] == "authority_pin_required"


def test_anchor_copy_refuses_rollback_between_observations(configured, monkeypatch):
    settings, _ = configured
    history(settings)
    original = local._fetch_anchors
    observations = 0
    def rollback(selected):
        nonlocal observations
        observations += 1
        rows = original(selected)
        return rows if observations == 1 else []
    monkeypatch.setattr(local, "_fetch_anchors", rollback)
    result = call(settings, "gm_workflow_evidence_anchors_fetch", {"authority": "test", "artifact_store": "audit",
                                                                "operation_id": "rollback"})
    assert not result["completed"] and result["error"]["code"] == "anchor_history_changed"
    assert list(settings.artifact_roots["audit"].iterdir()) == []


@pytest.mark.parametrize("rooted", [True, False])
def test_anchor_history_uses_configured_verification_mode(configured, monkeypatch, rooted):
    settings, _ = configured
    history(settings)
    if rooted:
        original = local._call
        def bad_signature(selected, path, *args, **kwargs):
            result = original(selected, path, *args, **kwargs)
            if path == "/na/key-history":
                result["genesis"]["signatures"] = []
            return result
        monkeypatch.setattr(local, "_call", bad_signature)
    else:
        settings = replace(settings, authorities={"test": replace(settings.authorities["test"], root_public_key=None)})
    result = call(settings, "gm_workflow_evidence_anchors_fetch", {"authority": "test", "artifact_store": "audit",
                                                                "operation_id": "history"})
    if rooted:
        assert not result["completed"] and result["error"]["code"] == "key_history_verification_failed"
    else:
        assert result["completed"] and result["anchors"]["verified"]


def test_treaty_renew_refuses_concurrent_revocation_before_new_issuance(configured, monkeypatch):
    settings, keys = configured
    treaty = issue_treaty(settings, keys["node"].public_key_b64)
    original = local._call
    observations = 0
    def concurrent(selected, path, method="GET", **kwargs):
        nonlocal observations
        if path == "/recognition-treaties/<treaty_id>":
            observations += 1
            if observations == 2:
                original(selected, "/admin/recognition-treaties/<treaty_id>/revoke", "POST",
                         body={"reason": "concurrent operator"}, path_args={"treaty_id": treaty["treaty_id"]})
        return original(selected, path, method, **kwargs)
    monkeypatch.setattr(local, "_call", concurrent)
    result = call(settings, "gm_workflow_treaty_renew", {"authority": "test", "operation_id": "race",
                                                       "treaty_id": treaty["treaty_id"]})
    assert not result["completed"] and result["error"]["code"] == "treaty_state_changed"
    assert len(original(settings, "/recognition-treaties")["recognition_treaties"]) == 1


def test_federation_refuses_an_unsigned_issued_treaty(pair, monkeypatch):
    settings, _ = pair
    args = {"acceptor": "alpha", "issuer": "beta"}
    preview = call(settings, "gm_workflow_federation_preview", args)
    original = http.invoke
    def unsigned(config, operation, arguments):
        result = original(config, operation, arguments)
        if operation["path"] == "/admin/recognition-treaties":
            result["result"]["signatures"] = []
        return result
    monkeypatch.setattr(http, "invoke", unsigned)
    result = call(settings, "gm_workflow_federation_bootstrap", {
        **args, "operation_id": "unsigned", "preview_digest": preview["preview_digest"]})
    assert result["status"] == "partial" and result["error"]["code"] == "treaty_verification_failed"


def test_fleet_ignores_inactive_rows_and_replays_completed_operation(pair, monkeypatch):
    settings, _ = pair
    original = http.invoke
    def stale_inactive_row(config, operation, args):
        result = original(config, operation, args)
        if operation["path"] == "/recognition-treaties":
            result["result"]["recognition_treaties"].insert(0, {"status": "revoked", "treaty": {}})
        return result
    monkeypatch.setattr(http, "invoke", stale_inactive_row)
    args = {"fleet": "two", "operation_id": "mesh"}
    result = call(settings, "gm_workflow_fleet_mesh", args)
    assert result["status"] == "completed" and result["created"] == 2
    monkeypatch.setattr(http, "invoke", lambda *_: pytest.fail("Completed operation repeated network work"))
    assert call(settings, "gm_workflow_fleet_mesh", args) == result


def test_remote_proof_inspector_requires_the_specific_revocation_reason(pair, monkeypatch):
    settings, credentials = pair
    original = http.invoke
    def wrong_reason(config, operation, args):
        result = original(config, operation, args)
        if operation["path"] == "/attestations/verify-with-treaty" and result["result"].get("accepted") is False:
            result["result"]["reason"] = "unrelated_failure"
        return result
    monkeypatch.setattr(http, "invoke", wrong_reason)
    result = call(settings, "gm_workflow_proof_remote", {"acceptor": "alpha", "issuer": "beta", "operation_id": "reason",
                  "subject_public_key": credentials["beta"][0]["subject"].public_key_b64})
    assert result["status"] == "partial" and result["error"]["code"] == "proof_inspection_failed"


def test_proof_store_symlink_replacement_is_refused(proof_store, tmp_path):
    settings, path = proof_store
    target = tmp_path / "moved.db"
    path.rename(target)
    try:
        path.symlink_to(target)
    except OSError:
        target.rename(path)
        pytest.skip("Platform does not permit symbolic links")
    with pytest.raises(ToolError) as exc:
        call(settings, PREVIEW, {"store": "lab"})
    assert exc.value.code == "unsafe_storage"


def test_cleanup_refuses_a_real_integrity_failure_in_the_backup(proof_store):
    settings, path = proof_store
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE constrained (value INTEGER CHECK(value >= 0))")
        connection.execute("PRAGMA ignore_check_constraints=ON")
        connection.execute("INSERT INTO constrained VALUES (-1)")
    preview = call(settings, PREVIEW, {"store": "lab"})
    result = call(settings, CLEANUP, {"store": "lab", "operation_id": "invalid-backup", "preview_digest": preview["scope_digest"]})
    assert result["status"] == "partial" and result["error"] == "backup_invalid"
    with sqlite3.connect(path) as connection:
        assert connection.execute(f"SELECT COUNT(*) FROM {TABLES[0]}").fetchone() == (2,)


def test_prepare_database_in_existing_parent_preserves_sibling_files(canary_store):
    settings, _ = canary_store
    config = settings.proof_stores["canary"]
    config.db_path.parent.mkdir()
    sibling = config.db_path.parent / "user-file"
    sibling.write_text("preserve")
    assert proof_workflows._prepare_database(config)["initialized"]
    assert sibling.read_text() == "preserve"


@pytest.mark.parametrize("fault", ["proof", "signature", "saved_signature", "post_write"])
def test_canary_checks_every_signed_receipt_boundary(canary_store, monkeypatch, fault):
    settings, _ = canary_store
    args = {"store": "canary", "acceptor": "alpha", "issuer": "beta", "operation_id": "receipt-boundary"}
    config = settings.proof_stores["canary"]
    expected = {"proof": "canary_inspection_failed", "signature": "canary_signature_failed",
                "saved_signature": "receipt_identity_changed", "post_write": "receipt_readback_failed"}[fault]
    if fault == "proof":
        original = multi_workflows.run_proof
        def corrupt_summary(*args, **kwargs):
            result = original(*args, **kwargs)
            assert result["status"] == "completed"
            result["result"]["proof"] = "corrupted-summary"
            return result
        monkeypatch.setattr(multi_workflows, "run_proof", corrupt_summary)
    elif fault == "signature":
        original = proof_workflows.sign_data
        other_key = generate_keypair().private_key
        monkeypatch.setattr(proof_workflows, "sign_data", lambda data, _key: original(data, other_key))
    elif fault == "saved_signature":
        original = proof_workflows.atomic_json
        def interrupt_write(path, value, **kwargs):
            if path.parent == config.receipt_dir:
                raise OSError("disk failed after the signed receipt was journaled")
            return original(path, value, **kwargs)
        monkeypatch.setattr(proof_workflows, "atomic_json", interrupt_write)
        partial = call(settings, CANARY, args)
        assert partial["status"] == "partial" and partial["error"] == "canary_failed"
        monkeypatch.setattr(proof_workflows, "atomic_json", original)
        path = settings.workflow_state_dir / f"{CANARY}--receipt-boundary.json"
        record = json.loads(path.read_text())
        record["steps"]["signed_receipt"]["result"]["signature"]["key_id"] = "substituted-signer"
        path.write_text(json.dumps(record))
    else:
        original = WorkflowJournal.step
        def change_after_readback(self, name, function, **kwargs):
            result = original(self, name, function, **kwargs)
            if name == "receipt_write":
                (config.receipt_dir / result["receipt"]).write_text("{}")
            return result
        monkeypatch.setattr(WorkflowJournal, "step", change_after_readback)
    result = call(settings, CANARY, args)
    assert result["status"] == "partial" and result["error"] == expected, result
    with sqlite3.connect(config.db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone() == (0,)


def test_join_preserves_real_authority_refusal(authority, tmp_path):
    settings = node_settings(authority, tmp_path)
    settings = replace(settings, node_runtimes={"client": replace(settings.node_runtimes["client"],
                        invite_token="missing-invite-f9db44c538b746d7")})
    tool = next(tool for tool in runtime_workflows.build_tools(settings) if tool.name == JOIN)
    with pytest.raises(ToolError) as exc:
        tool.handler({"node": "client", "operation_id": "invalid-invite"})
    assert exc.value.code == "runtime_authority_refused"


@pytest.mark.asyncio
async def test_completed_peer_send_replays_without_a_second_connection(authority, tmp_path):
    settings = node_settings(authority, tmp_path)
    def invoke_tool(config, name, args):
        return next(tool for tool in runtime_workflows.build_tools(config) if tool.name == name).handler(args)
    await asyncio.to_thread(invoke_tool, settings, JOIN, {"node": "client", "operation_id": "join"})
    key, recipient = generate_keypair(), generate_keypair()
    now = datetime.now(timezone.utc)
    cert = JoinCertificate(cert_id="peer", node_public_key=key.public_key_b64, network_name="mcp-test",
                           roles=["role:client"], issued_at=now, expires_at=now + timedelta(hours=1), issued_by="test-na")
    cert.signatures = [sign_model(cert, authority[1]["root"].private_key, "test-na")]
    encoded = base64.b64encode(cert.model_dump_json().encode()).decode()
    received = []
    async def accept(websocket):
        transport, _, _ = await accept_websocket_with_noise(
            websocket, NoiseHandshake.keypair_from_join_cert_key(key.private_key), encoded)
        received.append(MeshMessage.from_bytes(await transport.receive()))
        await transport.close()
    async with serve(accept, "127.0.0.1", 0) as server:
        endpoint = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        settings = replace(settings, peers={"peer": PeerConfig("client", endpoint, key.public_key_b64, recipient.public_key_b64)})
        args = {"peer": "peer", "operation_id": "single-send", "message": "one transport submission"}
        first = await asyncio.to_thread(invoke_tool, settings, SEND, args)
        assert first["transport_sent"] and first["recipient_delivery_confirmed"] is False
        assert await asyncio.to_thread(invoke_tool, settings, SEND, args) == first
    assert len(received) == 1 and received[0].recipient_id == recipient.public_key_b64


def test_published_private_directory_retains_platform_permissions(tmp_path):
    """Inspect the published object, not just the ACL command's exit status."""
    destination = tmp_path / "published"
    private_directory(destination)
    assert destination.is_dir() and not list(tmp_path.glob(".private-init-*"))
    if os.name == "nt":
        control = tmp_path / "native-owner-control"
        control.mkdir(mode=0o700)
        script = r'''
$ErrorActionPreference = 'Stop'
$acl = Get-Acl -LiteralPath $env:GENESISMESH_TEST_ACL_PATH
$control = Get-Acl -LiteralPath $env:GENESISMESH_TEST_ACL_CONTROL_PATH
$rules = @($acl.Access | ForEach-Object {
    [PSCustomObject]@{
        sid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        allow = $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow
        inherited = $_.IsInherited
        full_control = ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -eq [System.Security.AccessControl.FileSystemRights]::FullControl
        inheritance = [int]$_.InheritanceFlags
    }
})
[PSCustomObject]@{
    protected = $acl.AreAccessRulesProtected
    owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    native_owner = $control.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    current_user = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    rules = $rules
} | ConvertTo-Json -Depth 5 -Compress
'''
        # An invoking PowerShell 7 host can export module paths incompatible
        # with Windows PowerShell 5. Let the child discover its bundled modules.
        child_env = {key: value for key, value in os.environ.items() if key.casefold() != "psmodulepath"}
        child_env["GENESISMESH_TEST_ACL_PATH"] = str(destination)
        child_env["GENESISMESH_TEST_ACL_CONTROL_PATH"] = str(control)
        result = subprocess.run(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
                                env=child_env,
                                check=False, capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, result.stderr
        acl = json.loads(result.stdout)
        assert acl["protected"]
        # Elevated Windows tokens may choose local Administrators as the
        # default owner. Publication must retain the native creation owner,
        # and neither it nor OWNER RIGHTS may refer to an unrelated principal.
        assert acl["owner"] == acl["native_owner"]
        assert acl["owner"] in {acl["current_user"], "S-1-5-32-544"}
        grants = {rule["sid"]: rule for rule in acl["rules"] if rule["allow"]}
        required = {acl["current_user"], "S-1-5-18"}
        # Python's Windows 0700 implementation retains local Administrators
        # and OWNER RIGHTS ACEs. The owner was checked above; broad user groups
        # must never survive the protected ACL setup.
        assert required <= grants.keys() <= required | {"S-1-5-32-544", "S-1-3-4"}
        assert all(not rule["inherited"] for rule in acl["rules"])
        assert all(grants[sid]["full_control"] and grants[sid]["inheritance"] & 3 == 3 for sid in required)
    else:
        assert stat.S_IMODE(destination.stat().st_mode) == 0o700


def test_operation_status_reports_uncertain_operation_without_result_hash(tmp_path):
    settings = Settings(profiles={"local", "read", "write", "provision"}, workflow_state_dir=tmp_path / "operations")
    name = "gm_workflow_fleet_generate"
    with WorkflowJournal(settings, name, "pending", {}) as journal:
        def lost_reply():
            raise TimeoutError("The mutation result is unavailable")
        with pytest.raises(TimeoutError):
            journal.step("publish", lost_reply, mutation=True)
    status = call(settings, "gm_workflow_operation_status", {"workflow": name, "operation_id": "pending"})
    assert status["tool"] == name and status["operation_id"] == "pending"
    assert status["complete"] is False
    assert status["steps"]["publish"]["status"] == "unknown"
    assert status["steps"]["publish"]["mutation"] is True
    assert "result" not in status and "result_sha256" not in status
    assert "result_sha256" not in status["steps"]["publish"]
