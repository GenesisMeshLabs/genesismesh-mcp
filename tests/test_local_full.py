"""Real signed, nonempty files and adversarial workspace boundaries."""

import copy
import json

import pytest
from genesis_mesh.models.audit_pack import AuditPackManifest
from test_authority_full import active_policy, request
from test_authority_integration import authority as authority
from test_offline import environment as environment
from test_offline_remaining import evidence_artifacts as evidence_artifacts

from genesismesh_mcp.local import build_tools
from genesismesh_mcp.offline.adapter import json_value
from genesismesh_mcp.settings import Settings
from genesismesh_mcp.types import ToolError


def call(root, name, arguments, **configuration):
    settings = Settings(workspace=root, profiles=frozenset({"verify", "local"}), **configuration)
    tool = next(tool for tool in build_tools(settings) if tool.name == "gm_local_" + name)
    return tool.handler(arguments)


def write_pack(root, files):
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def test_nonempty_audit_pack_root_pin_anchors_and_tampering(tmp_path, authority):
    settings, keys, _ = authority
    active_policy(settings)
    attestation = request(settings, "/admin/attestations", status=201,
        body={"subject_id": "vendor", "roles": ["role:client"], "claims": {"capabilities": ["secret.manage"]}})
    decision = request(settings, "/admin/boundary/evaluate", status=201, body={
        "attestation_id": attestation["attestation_id"], "requested_capability": "secret.manage",
        "context": {"request_parameters": {"lifetime_days": 30}}})
    assert decision["decision"]["authorized"]
    pack = request(settings, "/admin/evidence/audit-pack")
    files = {name: text.encode() for name, text in pack["files"].items()}
    files["manifest.json"] = AuditPackManifest.model_validate(pack["manifest"]).file_bytes()
    write_pack(tmp_path / "pack", files)
    args = {"directory": "pack", "root_public_key": keys["root"].public_key_b64}
    result = call(tmp_path, "audit_verify", args)
    assert result["verified"] is True, result
    args["held_anchors"] = request(settings, "/admin/evidence/anchors", "GET")["anchors"]
    assert call(tmp_path, "audit_verify", args)["verified"] is True
    altered = bytearray((tmp_path / "pack" / "entries.jsonl").read_bytes())
    altered[0] = ord("!")
    (tmp_path / "pack" / "entries.jsonl").write_bytes(altered)
    result = call(tmp_path, "audit_verify", args)
    assert result["verified"] is False and result["failures"]


def test_workspace_audit_missing_directory_nested_entries_and_cumulative_bounds(tmp_path, evidence_artifacts):
    args = {"directory": "missing", "root_public_key": evidence_artifacts["root_public_key"]}
    with pytest.raises(ToolError) as caught:
        call(tmp_path, "audit_verify", args)
    assert caught.value.code == "artifact_not_found"
    pack = tmp_path / "pack"
    (pack / "nested").mkdir(parents=True)
    (pack / "nested" / "first").write_bytes(b"a" * 600)
    (pack / "second").write_bytes(b"b" * 600)
    args["directory"] = "pack"
    with pytest.raises(ToolError) as caught:
        call(tmp_path, "audit_verify", args, max_input_bytes=1024)
    assert caught.value.code == "artifact_too_large"
    for index in range(129):
        (pack / str(index)).touch()
    with pytest.raises(ToolError) as caught:
        call(tmp_path, "audit_verify", args)
    assert caught.value.code == "too_many_files"


def test_nonempty_evidence_independent_keys_history_anchors_and_tamper(tmp_path, evidence_artifacts):
    artifact = evidence_artifacts
    path = tmp_path / "events.jsonl"
    path.write_bytes(artifact["jsonl"])
    args = {"path": path.name, "executor_keys": json_value(artifact["executor_keys"]),
            "na_public_keys": artifact["na_public_keys"]}
    result = call(tmp_path, "evidence_verify_export", args)
    assert result["verified"] is True and result["anchors_supplied"] is False
    anchored = {**args, "held_anchors": json_value(artifact["anchors"])}
    assert call(tmp_path, "evidence_verify_export", anchored)["verified"] is True
    history = {"genesis": json_value(artifact["genesis"]), "successions": []}
    historical = {**anchored, "key_history": history, "root_public_key": artifact["root_public_key"]}
    assert call(tmp_path, "evidence_verify_export", historical)["verified"] is True
    partial = call(tmp_path, "evidence_verify_export", {**anchored, "partial": True})
    assert partial["verified"] is True and partial["scope"] == "partial"
    changed = copy.deepcopy(anchored)
    changed["held_anchors"][0]["entry_digest"] = "0" * 64
    assert call(tmp_path, "evidence_verify_export", changed)["verified"] is False
    events = [json.loads(line) for line in artifact["jsonl"].decode().splitlines()]
    events[0]["payload"]["actor"] = "altered-after-signature"
    path.write_text("\n".join(json.dumps(event) for event in events), encoding="utf-8")
    refused = call(tmp_path, "evidence_verify_export", args)
    assert refused["verified"] is False and refused["failures"]


def test_evidence_history_and_anchor_preconditions(tmp_path, evidence_artifacts):
    artifact = evidence_artifacts
    (tmp_path / "events.jsonl").write_bytes(artifact["jsonl"])
    args = {"path": "events.jsonl", "executor_keys": json_value(artifact["executor_keys"]),
            "key_history": {"genesis": json_value(artifact["genesis"]), "successions": []}}
    with pytest.raises(ToolError) as caught:
        call(tmp_path, "evidence_verify_export", args)
    assert caught.value.code == "root_pin_required"
    wrong = copy.deepcopy(args)
    wrong["key_history"]["genesis"]["network_name"] = "forged"
    result = call(tmp_path, "evidence_verify_export", {**wrong, "root_public_key": artifact["root_public_key"]})
    assert result["verified"] is False and result["stage"] == "key_history" and result["failures"]
    # The handler retains its defensive check even when called without MCP schema validation.
    with pytest.raises(ToolError) as caught:
        call(tmp_path, "evidence_verify_export", {"path": "events.jsonl", "executor_keys": {},
             "na_public_keys": artifact["na_public_keys"], "held_anchors": []})
    assert caught.value.code == "anchors_required"


def test_real_bundle_inspection_keeps_structural_and_signature_claims_separate(tmp_path, evidence_artifacts):
    artifact = evidence_artifacts
    genesis = json_value(artifact["genesis"])
    metadata = {"sovereign_id": "alpha", "network_version": "1.8.1", "network_authority": genesis["network_authority"],
                "root_public_key": artifact["root_public_key"], "policy_manifest": genesis["policy_manifest"]}
    bundle = {"bundle_type": "genesis-mesh.trust-bundle", "bundle_version": "v1", "sovereign_id": "alpha",
        "created_at": "2026-10-25T12:00:00Z", "source_endpoint": "https://example.invalid",
        "sovereign_metadata": metadata, "genesis": genesis,
        "recognition_policy": {"status": "not_configured"}, "revocation_feed": {"status": "skipped"},
        "connectome": {"sovereigns": [], "recognition_edges": [], "active_treaties": [], "revoked_trust_material": []}}
    (tmp_path / "bundle.json").write_text(json.dumps(bundle), encoding="utf-8")
    checked = call(tmp_path, "trust_bundle_inspect", {"path": "bundle.json"})
    assert checked["signatures_verified"] is False
    assert checked["summary"]["sovereign_id"] == "alpha" and checked["validation"]["errors"] == []
