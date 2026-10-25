"""CLI references must be stable across Python's docstring compiler changes."""

import json
import runpy
from pathlib import Path

import click

snapshot = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/snapshot_cli.py"))["snapshot"]


def command_tree(help_text, *, required=False):
    command = click.Command("verify", help=help_text,
                            params=[click.Option(["--artifact"], required=required)])
    return click.Group("core", commands={"verify": command})


def test_docstring_compiler_indentation_does_not_change_snapshot():
    python_312_help = "Verify an artifact.\n\n    Example:\n\n    \b\n        core verify --artifact proof.json\n    "
    python_314_help = "Verify an artifact.\n\nExample:\n\n\b\n    core verify --artifact proof.json\n"
    before = snapshot(command_tree(python_312_help))
    after = snapshot(command_tree(python_314_help))
    assert before == after
    assert json.loads(after)["verify"]["description"] == (
        "Verify an artifact.\n\nExample:\n\n\b\n    core verify --artifact proof.json"
    )


def test_real_description_and_parameter_changes_still_change_snapshot():
    original = snapshot(command_tree("Verify an artifact."))
    assert snapshot(command_tree("Verify an artifact and its authority.")) != original
    assert snapshot(command_tree("Verify an artifact.", required=True)) != original
