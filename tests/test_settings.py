import json
from pathlib import Path

import pytest

from genesismesh_mcp.settings import Settings
from genesismesh_mcp.types import ToolError


@pytest.mark.parametrize("url", ["http://example.com", "https://u:p@example.com", "https://example.com/path",
    "https://example.com/?secret=x", "https://example.com/#x", "file:///secret", "https://example.com\\@evil",
    "http://localhost:bad", "https://example.com:99999", "https://exam\nple.com"])
def test_rejects_invalid_authority_origins(url):
    with pytest.raises(ValueError):
        Settings(authority_url=url, allow_http_loopback=True)


def test_loopback_http_requires_explicit_configuration():
    with pytest.raises(ValueError):
        Settings(authority_url="http://127.0.0.1:8443")
    assert Settings(authority_url="http://127.0.0.1:8443", allow_http_loopback=True)
    assert Settings(authority_url="https://na.example.org")


@pytest.mark.parametrize("name", ["../secret", "/etc/passwd", "C:secret", "C:/secret", "//server/share",
                                 "folder/../../secret", "folder\\secret", "a:stream", "nul\x00x"])
def test_workspace_rejects_escape_paths(tmp_path, name):
    settings = Settings(workspace=tmp_path, profiles=frozenset({"local"}))
    with pytest.raises(ToolError):
        settings.confined_path(name, must_exist=False)


def test_workspace_resolves_files_and_rejects_symlink_escape(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "okay.json").write_text("{}")
    settings = Settings(workspace=workspace, profiles=frozenset({"local"}))
    assert settings.confined_path("okay.json") == workspace / "okay.json"
    (tmp_path / "outside.json").write_text("{}")
    try:
        (workspace / "link.json").symlink_to(tmp_path / "outside.json")
    except OSError:
        # Windows may deny unprivileged symlink creation; traversal tests above still run.
        return
    with pytest.raises(ToolError):
        settings.confined_path("link.json")


def test_config_paths_are_relative_to_config_and_status_excludes_secrets(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"profiles": ["read"], "signer_files": {"issuer": "issuer.key"},
                               "workspace": "data", "invite_token": "secret-invite"}))
    settings = Settings.from_file(path)
    assert settings.workspace == tmp_path / "data"
    assert settings.signer_files["issuer"] == tmp_path / "issuer.key"
    assert "secret-invite" not in repr(settings)
    assert "secret-invite" not in json.dumps(settings.public_status())
    assert str(tmp_path) not in json.dumps(settings.public_status())
    with pytest.raises(TypeError):
        settings.signer_files["bad"] = Path("bad")


def test_disabled_profiles_and_unconfigured_signer_are_denied():
    with pytest.raises(ToolError, match="not enabled"):
        Settings().load_signer("issuer")
    with pytest.raises(ToolError, match="not configured"):
        Settings(profiles=frozenset({"sign"})).load_signer("issuer")


def test_signer_permission_is_checked_before_loading_a_key(tmp_path):
    settings = Settings(profiles=frozenset({"sign"}), signer_files={"issuer": tmp_path / "missing.key"},
                        signer_permissions={"issuer": frozenset({"gm_offline_approved_operation"})})
    with pytest.raises(ToolError) as denied:
        settings.load_signer("issuer", "gm_offline_other_operation")
    assert denied.value.code == "signer_not_authorized"
    with pytest.raises(ToolError) as unavailable:
        settings.load_signer("issuer", "gm_offline_approved_operation")
    assert unavailable.value.code == "signer_unavailable"
    with pytest.raises(ValueError, match="explicit tool names"):
        Settings(signer_files={"issuer": tmp_path / "missing.key"}, signer_permissions={"issuer": frozenset({"*"})})
