"""Configuration trust boundaries and invalid input classes."""

import json

import pytest
from genesis_mesh.crypto import generate_keypair

from genesismesh_mcp.settings import Settings
from genesismesh_mcp.types import ToolError


@pytest.mark.parametrize("arguments,message", [
    ({"profiles": {"unknown"}}, "Unknown configuration profile"),
    ({"signer_permissions": {"absent": {"operation"}}}, "unconfigured signer"),
    ({"timeout_seconds": float("nan")}, "timeout_seconds"),
    ({"timeout_seconds": 0}, "timeout_seconds"),
    ({"timeout_seconds": 301}, "timeout_seconds"),
    ({"max_input_bytes": True}, "Byte limits"),
    ({"max_output_bytes": 1023}, "Byte limits"),
    ({"max_output_bytes": 67_108_865}, "Byte limits"),
    ({"tool_page_size": True}, "tool_page_size"),
    ({"tool_page_size": 0}, "tool_page_size"),
    ({"tool_page_size": 1001}, "tool_page_size"),
    ({"operator_key_file": "missing.key"}, "operator_key_id"),
])
def test_configuration_refuses_invalid_profiles_permissions_and_bounds(arguments, message):
    with pytest.raises(ValueError, match=message):
        Settings(**arguments)


def test_config_file_size_shape_and_unknown_fields_are_refused(tmp_path):
    path = tmp_path / "config.json"
    for data in ([], {"unexpected_setting": "do-not-disclose"}):
        path.write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(ValueError, match="documented settings"):
            Settings.from_file(path)
    path.write_bytes(b" " * 65_537)
    with pytest.raises(ValueError, match="too large"):
        Settings.from_file(path)


def test_local_profile_workspace_and_missing_artifact_fail_distinctly(tmp_path):
    with pytest.raises(ToolError) as no_profile:
        Settings().confined_path("data.json")
    assert no_profile.value.code == "profile_required"
    with pytest.raises(ToolError) as no_workspace:
        Settings(profiles={"local"}).confined_path("data.json")
    assert no_workspace.value.code == "workspace_required"
    settings = Settings(workspace=tmp_path, profiles={"local"})
    with pytest.raises(ToolError) as missing:
        settings.confined_path("missing.json")
    assert missing.value.code == "artifact_not_found"
    with pytest.raises(ToolError) as empty:
        settings.confined_path("")
    assert empty.value.code == "invalid_path"


def test_runtime_registries_are_parsed_instead_of_silently_ignored(tmp_path):
    config = tmp_path / "settings.json"
    config.write_text(json.dumps({"peers": {"peer": {"url": "ws://127.0.0.1:9000", "server_public_key": "pin"}}}), encoding="utf-8")
    # A malformed configured peer must reach the runtime parser rather than be silently ignored.
    with pytest.raises((TypeError, ValueError)):
        Settings.from_file(config)
    peer = {"node": "client", "endpoint": "ws://127.0.0.1:9000", "peer_public_key": generate_keypair().public_key_b64}
    config.write_text(json.dumps({"node_runtimes": {}, "peers": {"peer": peer}, "guard_actions": {}}), encoding="utf-8")
    loaded = Settings.from_file(config)
    assert loaded.node_runtimes == loaded.guard_actions == {}
    assert loaded.peers["peer"].node == "client"
    assert loaded.peers["peer"].endpoint == peer["endpoint"]
