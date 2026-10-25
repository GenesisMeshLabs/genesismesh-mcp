import pytest
from test_authority_integration import authority  # noqa: F401 -- reuse the disposable authority fixture

from genesismesh_mcp.settings import Settings
from genesismesh_mcp.types import ToolError
from genesismesh_mcp.workflows import _PublicSession, build_tools


def test_trust_bundle_export_reads_real_authority_but_does_not_grant_trust(authority):  # noqa: F811
    settings, _, _ = authority
    tool = build_tools(settings)[0]
    result = tool.handler({"include_revocation_feed": False})
    assert result["bundle"]["bundle_type"] == "genesis-mesh.trust-bundle"
    assert result["bundle"]["sovereign_id"]
    assert result["signatures_verified"] is False
    assert result["trust_granted"] is False
    receipt = build_tools(settings)[2].handler({"bundle": result["bundle"]})
    assert receipt["accepted_for_review"] is True
    assert receipt["trust_granted"] is False


def test_exporter_cannot_change_authority_or_call_admin_routes():
    session = _PublicSession(Settings(authority_url="https://configured.example"))
    with pytest.raises(ToolError):
        session.get("https://other.example/genesis")
    with pytest.raises(ToolError):
        session.get("https://configured.example/admin/evidence")


def test_atlas_returns_content_with_unverified_graph_labeled():
    result = build_tools(Settings())[1].handler({"graph": {"sovereigns": [], "recognition_edges": []}})
    assert "<html" in result["html"]
    assert result["atlas"]["graph_digest"]
    assert result["trust_granted"] is False


def test_invalid_bundle_is_refused_for_review():
    result = build_tools(Settings())[2].handler({"bundle": {}})
    assert result["accepted_for_review"] is False
    assert result["validation"]["errors"]
