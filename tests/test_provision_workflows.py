"""Real core key/genesis/config provisioning in disposable private storage."""

import json
import tomllib

import pytest
from genesis_mesh.crypto import verify_model_signature
from genesis_mesh.models import GenesisBlock

from genesismesh_mcp.provision_workflows import generate_fleet
from genesismesh_mcp.settings import Settings
from genesismesh_mcp.types import ToolError


def test_fleet_generation_writes_usable_final_paths_and_replays(tmp_path):
    settings = Settings(profiles={"local", "write", "provision"}, workflow_state_dir=tmp_path / "state",
                        provisioning={"lab": {"root": tmp_path / "fleets"}})
    args = {"provisioning": "lab", "operation_id": "fleet-one", "names": ["north", "south"]}
    result = generate_fleet(settings, args)
    assert result["status"] == "completed", result
    assert result["servers_started"] is False
    root = tmp_path / "fleets/fleet-one"
    assert tomllib.loads((root / "fleet.toml").read_text())["fleet"]["nodes"] == [
        "north/genesis-mesh.toml", "south/genesis-mesh.toml"]
    for name in args["names"]:
        member = tomllib.loads((root / name / "genesis-mesh.toml").read_text())
        assert member["paths"]["home"] == (root / name).as_posix()
        assert ".staging-" not in json.dumps(member)
        genesis = GenesisBlock.model_validate_json((root / name / "genesis.signed.json").read_text())
        assert verify_model_signature(genesis, genesis.signatures[0], genesis.root_public_key)
        secret = (root / name / "keys/root.key").read_text().strip()
        assert secret not in json.dumps(result)
    assert generate_fleet(settings, args) == result
    assert generate_fleet(settings, {**args, "operation_id": "fleet-two"})["status"] == "completed"


@pytest.mark.parametrize("name", ["../escape", "CON", "member.", "a/b", "a\\b"])
def test_fleet_rejects_unsafe_names_before_creating_private_material(tmp_path, name):
    settings = Settings(profiles={"local", "write", "provision"}, workflow_state_dir=tmp_path / "state",
                        provisioning={"lab": {"root": tmp_path / "fleets"}})
    with pytest.raises(ToolError):
        generate_fleet(settings, {"provisioning": "lab", "operation_id": "one", "names": [name]})
    assert not (tmp_path / "fleets").exists()


def test_fleet_rejects_case_collisions_before_writes(tmp_path):
    settings = Settings(profiles={"local", "write", "provision"}, workflow_state_dir=tmp_path / "state",
                        provisioning={"lab": {"root": tmp_path / "fleets"}})
    with pytest.raises(ToolError, match="distinct"):
        generate_fleet(settings, {"provisioning": "lab", "operation_id": "one", "names": ["Alpha", "alpha"]})
    assert not (tmp_path / "fleets").exists()
