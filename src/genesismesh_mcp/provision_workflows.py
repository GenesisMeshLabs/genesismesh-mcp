"""Explicit private fleet provisioning, reusing the pinned core scaffold."""

from __future__ import annotations

import os
import tomllib
import uuid
from pathlib import Path

from genesis_mesh.cli.config import save_config
from genesis_mesh.cli.fleet_ops import _scaffold_sovereign
from genesis_mesh.crypto import verify_model_signature
from genesis_mesh.models import GenesisBlock

from .settings import Settings
from .types import ToolError, ToolSpec
from .workflow_config import reference
from .workflow_support import WorkflowJournal, private_directory, resource_lock

NAME = "gm_workflow_fleet_generate"
PROFILES = frozenset({"local", "write", "provision"})


def generate_fleet(settings: Settings, args: dict):
    settings.require(PROFILES)
    config = settings.provisioning.get(args["provisioning"])
    if config is None:
        raise ToolError("provisioning_not_configured", "Choose a configured private provisioning destination.")
    names = args["names"]
    try:
        for name in names:
            reference(name)
            if name.upper().split(".")[0] in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)),
                                             *(f"LPT{i}" for i in range(10))} or name.endswith("."):
                raise ValueError("Reserved name")
    except ValueError:
        raise ToolError("invalid_member_name", "Fleet members need portable simple directory names.") from None
    if not 1 <= len(names) <= config.max_members or len({name.casefold() for name in names}) != len(names):
        raise ToolError("invalid_fleet_size", "Fleet member names must be distinct and within the configured limit.")
    version = args.get("network_version", "v0.1")
    days = args.get("na_valid_days", 90)
    if type(days) is not int or not 1 <= days <= 3650:
        raise ToolError("invalid_validity", "NA validity must be between 1 and 3650 days.")
    with resource_lock(settings, "provisioning", args["provisioning"]):
        with WorkflowJournal(settings, NAME, args["operation_id"], args) as journal:
            if journal.completed_result is not None:
                return journal.completed_result

            def create():
                config.root.mkdir(parents=True, exist_ok=True)
                target = config.root / args["operation_id"]
                if target.exists() or target.is_symlink():
                    raise ToolError("provisioning_conflict", "The requested fleet already exists; overwrite is not supported.")
                stage = config.root / (".staging-" + uuid.uuid4().hex)
                private_directory(stage)
                public = []
                for index, name in enumerate(names):
                    home = stage / name
                    host = config.host
                    wire_host = f"[{host}]" if ":" in host else host
                    endpoint = f"http://{wire_host}:{config.base_port + index}"
                    _scaffold_sovereign(home=home, name=name, network_version=version, endpoint=endpoint,
                                        host=host, port=config.base_port + index, na_valid_days=days)
                    config_path = home / "genesis-mesh.toml"
                    member = tomllib.loads(config_path.read_text("utf-8"))
                    for key, value in member["paths"].items():
                        relative = Path(value).relative_to(stage)
                        member["paths"][key] = (target / relative).as_posix()
                    save_config(member, str(config_path))
                    genesis = GenesisBlock.model_validate_json((home / "genesis.signed.json").read_text("utf-8"))
                    if not any(verify_model_signature(genesis, sig, genesis.root_public_key)
                               for sig in genesis.signatures):
                        raise ToolError("generated_genesis_invalid", "A generated genesis failed core signature verification.")
                    public.append({"name": name, "endpoint": endpoint, "root_public_key": genesis.root_public_key,
                                   "authority_public_key": genesis.network_authority.public_key,
                                   "configuration": f"{name}/genesis-mesh.toml"})
                save_config({"fleet": {"host": config.host,
                                       "nodes": [f"{name}/genesis-mesh.toml" for name in names]}},
                            str(stage / "fleet.toml"))
                os.rename(stage, target)
                return {"storage": args["provisioning"], "fleet_directory": args["operation_id"],
                        "manifest": "fleet.toml", "members": public, "servers_started": False,
                        "policy_manifest": "placeholder; replace with the real policy hash before deployment",
                        "root_custody": "Root keys are in private provisioned storage beside NA keys. Move root keys offline before managed deployment."}

            try:
                result = journal.step("generate", create, mutation=True)
                return journal.finish({"status": "completed", "operation_id": args["operation_id"], **result})
            except Exception as error:
                return {"status": "partial", "operation_id": args["operation_id"], "steps": journal.summary(),
                        "error": error.code if isinstance(error, ToolError) else "provisioning_failed",
                        "private_partial_files_may_exist": True}


def build_tools(settings: Settings) -> list[ToolSpec]:
    schema = {"type": "object", "properties": {
        "provisioning": {"type": "string"}, "operation_id": {"type": "string", "maxLength": 80},
        "names": {"type": "array", "items": {"type": "string", "maxLength": 80},
                  "minItems": 1, "maxItems": 16, "uniqueItems": True},
        "network_version": {"type": "string", "maxLength": 80},
        "na_valid_days": {"type": "integer", "minimum": 1, "maximum": 3650}},
        "required": ["provisioning", "operation_id", "names"], "additionalProperties": False}
    return [ToolSpec(NAME, "Generate a private fleet using core genesis/key/config construction. Returns public metadata only; does not start servers.",
                     schema, lambda args: generate_fleet(settings, args), PROFILES,
                     core_targets=("cli:fleet generate",))]
