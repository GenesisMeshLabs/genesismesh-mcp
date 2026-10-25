"""Offline MCP operations reuse the pinned Genesis Mesh implementation."""

from __future__ import annotations

import importlib
from dataclasses import replace
from typing import Any

from .adapter import make_tool
from .registry import OPERATIONS


def build_tools(settings: Any) -> list:
    from genesismesh_mcp.catalog import contract_items

    contracted = contract_items()
    tools = []
    for module, functions in OPERATIONS.items():
        imported = importlib.import_module("genesis_mesh." + module)
        for name, cli in functions.items():
            # Custom regular expressions are intentionally not an MCP input.
            # The core built-in injection scanner remains available.
            fixed = {"patterns": None} if name == "scan_for_injection_markers" else None
            if name == "check_grant":
                fixed = {"check_basis": True}
            tools.append(make_tool(settings, getattr(imported, name), module, name, cli, fixed=fixed))
    from .workflows import build_workflow_tools
    tools.extend(build_workflow_tools(settings))
    # Some shipped CLI implementations call helpers that are not themselves
    # declared public Python symbols. Keep those real tools while attributing
    # contract coverage only to declared CLI/artifact/Python surfaces.
    return [replace(tool, core_targets=tuple(t for t in tool.core_targets if t in contracted)) for tool in tools]
