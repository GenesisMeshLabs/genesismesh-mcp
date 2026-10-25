"""Generate the reference for every core CLI command; never execute commands."""

import argparse
import json
from pathlib import Path

import click
from genesis_mesh.cli.main import cli

OUTPUT = Path(__file__).resolve().parents[1] / "src/genesismesh_mcp/data/cli-reference.json"


def snapshot():
    found = {}

    def walk(command, prefix):
        if isinstance(command, click.Group):
            for name, child in sorted(command.commands.items()):
                walk(child, [*prefix, name])
            return
        parameters = []
        for parameter in command.params:
            parameters.append({"name": parameter.name, "options": parameter.opts,
                               "type": parameter.type.name, "required": parameter.required,
                               "multiple": getattr(parameter, "multiple", False),
                               "help": getattr(parameter, "help", None)})
        found[" ".join(prefix)] = {"command": "genesis-mesh " + " ".join(prefix),
                                 "description": command.help or "", "parameters": parameters,
                                 "execution": "CLI reference only. Check the coverage resource for MCP equivalents."}

    walk(cli, [])
    return json.dumps(found, ensure_ascii=False, indent=2) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    content = snapshot()
    if args.check:
        if OUTPUT.read_text(encoding="utf-8") != content:
            raise SystemExit("CLI parameter reference differs from installed core")
    else:
        OUTPUT.write_text(content, encoding="utf-8", newline="\n")
