import json

import pytest
from genesis_mesh.crypto import generate_keypair

from genesismesh_mcp.local import build_tools
from genesismesh_mcp.settings import Settings
from genesismesh_mcp.types import ToolError


def tools_at(root, **kwargs):
    settings = Settings(workspace=root, profiles=frozenset({"local", "verify"}), **kwargs)
    return {tool.name: tool for tool in build_tools(settings)}


def test_bundle_inspection_never_claims_signature_verification(tmp_path):
    (tmp_path / "bundle.json").write_text(json.dumps({"bundle_type": "genesis-mesh.trust-bundle", "bundle_version": "v1",
        "created_at": "2026-01-01T00:00:00Z", "source_endpoint": "https://example.org", "sovereign_metadata": {},
        "genesis": {}, "recognition_policy": {"status": "skipped"}, "revocation_feed": {"status": "skipped"},
        "connectome": {}}))
    result = tools_at(tmp_path)["gm_local_trust_bundle_inspect"].handler({"path": "bundle.json"})
    assert result["signatures_verified"] is False
    assert "does not grant trust" in result["meaning"]


def test_invalid_bundle_and_oversize_file_are_rejected(tmp_path):
    (tmp_path / "bad.json").write_text("[]")
    tools = tools_at(tmp_path, max_input_bytes=1024)
    with pytest.raises(ToolError, match="JSON object"):
        tools["gm_local_trust_bundle_inspect"].handler({"path": "bad.json"})
    (tmp_path / "large.json").write_text(" " * 1025)
    with pytest.raises(ToolError, match="input limit"):
        tools["gm_local_trust_bundle_inspect"].handler({"path": "large.json"})


def test_empty_audit_pack_does_not_verify(tmp_path):
    (tmp_path / "pack").mkdir()
    key = generate_keypair().public_key_b64
    result = tools_at(tmp_path)["gm_local_audit_verify"].handler({"directory": "pack", "root_public_key": key})
    assert result["verified"] is False
    assert result["failures"]


def test_evidence_requires_independent_key_material_and_valid_jsonl(tmp_path):
    (tmp_path / "export.jsonl").write_text("")
    verify = tools_at(tmp_path)["gm_local_evidence_verify_export"].handler
    with pytest.raises(ToolError, match="public keys"):
        verify({"path": "export.jsonl", "executor_keys": {}})
    (tmp_path / "export.jsonl").write_text('{"made_up": true}\n')
    with pytest.raises(ValueError):
        verify({"path": "export.jsonl", "executor_keys": {}, "na_public_keys": [generate_keypair().public_key_b64]})
