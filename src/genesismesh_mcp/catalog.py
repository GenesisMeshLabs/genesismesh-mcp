"""Pinned public-surface accounting, independent of transport and core test helpers.

The inventory is exhaustive. Executable coverage is derived from actual tool
registrations and is deliberately distinct from schemas and documentation.
"""

from __future__ import annotations

import hashlib
import importlib
import inspect
import json
import re
import subprocess
from collections import Counter
from collections.abc import Iterable, Mapping
from importlib import metadata, resources
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from .types import ToolSpec

SCHEMA_KINDS = frozenset({"schema", "reference", "support"})
SURFACE_KINDS = frozenset({"tool", "schema", "reference", "support", "manual", "internal"})
VERIFICATION_STATES = frozenset({"not_exercised", "unit_tested", "integration_tested"})
_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


class CatalogError(ValueError):
    """The pinned inventory or a runtime mapping is internally inconsistent."""


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CatalogError(f"Duplicate JSON object key: {key}")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise CatalogError(f"Non-finite JSON constant: {value}")


def _parse(text: str) -> dict[str, Any]:
    value = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_invalid_constant)
    if not isinstance(value, dict):
        raise CatalogError("Packaged metadata must be a JSON object")
    return value


def _data_text(name: str) -> str:
    return resources.files("genesismesh_mcp").joinpath("data", name).read_text(encoding="utf-8")


def contract_digest(text: str) -> str:
    """Hash UTF-8/LF source bytes, consistently across Windows and Linux."""
    return hashlib.sha256(text.replace("\r\n", "\n").encode("utf-8")).hexdigest()


def load_contract() -> dict[str, Any]:
    return _parse(_data_text("public-surface.json"))


def load_compatibility() -> dict[str, Any]:
    return _parse(_data_text("compatibility.json"))


def load_coverage() -> dict[str, Any]:
    return _parse(_data_text("coverage.json"))


def contract_items(contract: Mapping[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    """Flatten every classified surface, retaining signatures and source fields."""
    contract = load_contract() if contract is None else contract
    items: dict[str, dict[str, Any]] = {}

    def add(identifier: str, section: str, declaration: dict[str, Any]) -> None:
        if identifier in items:
            raise CatalogError(f"Duplicate contract item: {identifier}")
        items[identifier] = {"id": identifier, "section": section, "declaration": declaration}

    for route in contract["http_routes"]:
        for method in route["methods"]:
            add(f"http:{method} {route['path']}", "http_routes", {**route, "method": method})
    for section, prefix, field in (
        ("cli_commands", "cli", "command"),
        ("python", "python", "symbol"),
        ("signed_artifacts", "artifact", "model"),
        ("packages", "package", "package"),
    ):
        for item in contract[section]:
            add(f"{prefix}:{item[field]}", section, dict(item))
    for code in contract["error_codes"]:
        add(f"error:{code}", "error_codes", {"code": code})
    for name, rule in contract["rules"].items():
        add(f"rule:{name}", "rules", {"name": name, "rule": rule})
    return items


def compare_contract(
    candidate: Mapping[str, Any], expected: Mapping[str, Any] | None = None
) -> list[str]:
    """Describe source drift, including signature/default/stability changes."""
    expected = load_contract() if expected is None else expected
    problems: list[str] = []
    try:
        actual_items, expected_items = contract_items(candidate), contract_items(expected)
    except (KeyError, TypeError, CatalogError) as exc:
        return [f"Invalid public contract: {exc}"]
    for identifier in sorted(actual_items.keys() - expected_items.keys()):
        problems.append(f"Unclassified source item: {identifier}")
    for identifier in sorted(expected_items.keys() - actual_items.keys()):
        problems.append(f"Source item removed: {identifier}")
    for identifier in sorted(actual_items.keys() & expected_items.keys()):
        if actual_items[identifier] != expected_items[identifier]:
            problems.append(f"Source declaration changed: {identifier}")
    accounted = {"http_routes", "cli_commands", "python", "signed_artifacts", "error_codes", "packages", "rules"}
    for key in sorted(set(expected) | set(candidate)):
        if key not in accounted and candidate.get(key) != expected.get(key):
            problems.append(f"Contract metadata changed: {key}")
    return problems


def validate_catalog(
    tools: Iterable[ToolSpec],
    *,
    resources: Mapping[str, Iterable[str]] | None = None,
    contract: Mapping[str, Any] | None = None,
    coverage: Mapping[str, Any] | None = None,
) -> list[str]:
    """Check accounting and actual registrations; gaps are reported separately."""
    items = contract_items(contract)
    coverage = load_coverage() if coverage is None else coverage
    problems: list[str] = []
    rows = coverage.get("rows", [])
    row_ids = [row.get("id") for row in rows]
    duplicate_rows = [key for key, count in Counter(row_ids).items() if count > 1]
    problems.extend(f"Duplicate coverage mapping: {key}" for key in duplicate_rows)
    problems.extend(f"Missing coverage mapping: {key}" for key in sorted(items.keys() - set(row_ids)))
    problems.extend(f"Unknown coverage mapping: {key}" for key in sorted(set(row_ids) - items.keys()))
    row_map = {row["id"]: row for row in rows}
    for row in rows:
        identifier = row.get("id")
        if row.get("intended_surface") not in SURFACE_KINDS:
            problems.append(f"Invalid intended surface: {identifier}")
        if not isinstance(row.get("reason"), str) or not row["reason"].strip():
            problems.append(f"Missing coverage rationale: {identifier}")
        if row.get("verification_status") not in VERIFICATION_STATES:
            problems.append(f"Invalid verification status: {identifier}")
        if row.get("verification_status") != "not_exercised" and not row.get("tests"):
            problems.append(f"Verification claim without test references: {identifier}")
        source = items.get(identifier)
        if source and source["section"] != row.get("section"):
            problems.append(f"Incorrect source section: {identifier}")
        if source and "level" in source["declaration"] and source["declaration"]["level"] != row.get("stability"):
            problems.append(f"Incorrect stability classification: {identifier}")
        for target in [*row.get("covered_by", []), *row.get("components", [])]:
            if target not in items:
                problems.append(f"Unknown alias target: {identifier} -> {target}")

    def walk_alias(identifier: str, visited: frozenset[str]) -> None:
        if identifier in visited:
            problems.append(f"Cyclic coverage alias: {identifier}")
            return
        for target in row_map.get(identifier, {}).get("covered_by", []):
            walk_alias(target, visited | {identifier})

    for identifier in row_map:
        walk_alias(identifier, frozenset())
    names: set[str] = set()
    for tool in tools:
        if tool.name in names:
            problems.append(f"Duplicate registered tool: {tool.name}")
        if not _NAME.fullmatch(tool.name):
            problems.append(f"Invalid tool name: {tool.name}")
        names.add(tool.name)
        if not callable(tool.handler):
            problems.append(f"Registered tool lacks a handler: {tool.name}")
        if len(tool.core_targets) != len(set(tool.core_targets)):
            problems.append(f"Duplicate target on tool: {tool.name}")
        for target in tool.core_targets:
            if target not in items:
                problems.append(f"Tool references unknown source target: {tool.name} -> {target}")
    for uri, targets in (resources or {}).items():
        if not uri or not isinstance(uri, str):
            problems.append("Invalid registered resource URI")
        for target in targets:
            if target not in items:
                problems.append(f"Resource references unknown source target: {uri} -> {target}")
    return sorted(set(problems))


def build_catalog(
    tools: Iterable[ToolSpec],
    *,
    resources: Mapping[str, Iterable[str]] | None = None,
    profiles: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Resolve coverage against real registrations without upgrading test claims."""
    tools = list(tools)
    resource_map = {uri: tuple(targets) for uri, targets in (resources or {}).items()}
    problems = validate_catalog(tools, resources=resource_map)
    if problems:
        raise CatalogError("\n".join(problems))
    coverage = load_coverage()
    source = contract_items()
    rows_by_id = {row["id"]: row for row in coverage["rows"]}
    tool_map: dict[str, list[ToolSpec]] = {}
    resource_index: dict[str, list[str]] = {}
    for tool in tools:
        for target in tool.core_targets:
            tool_map.setdefault(target, []).append(tool)
    for uri, targets in resource_map.items():
        for target in targets:
            resource_index.setdefault(target, []).append(uri)

    def targets_for(identifier: str) -> set[str]:
        found = {identifier}
        for target in rows_by_id[identifier].get("covered_by", []):
            found.update(targets_for(target))
        return found

    enabled_profiles = None if profiles is None else frozenset(profiles)
    resolved = []
    for mapping in coverage["rows"]:
        identifier = mapping["id"]
        targets = targets_for(identifier)
        mapped_tools = {tool.name: tool for target in targets for tool in tool_map.get(target, [])}
        component_tools = {
            target: {tool.name: tool for dependency in targets_for(target) for tool in tool_map.get(dependency, [])}
            for target in mapping.get("components", [])
        }
        direct_resources = sorted(resource_index.get(identifier, []))
        kind = mapping["intended_surface"]
        if mapped_tools:
            status = "support" if kind == "support" else "implemented"
        elif component_tools and all(component_tools.values()):
            status = "components_available"
        elif kind in {"manual", "internal"}:
            status = "operational_boundary" if kind == "manual" else "internal_boundary"
        elif kind in SCHEMA_KINDS and direct_resources:
            status = "schema" if kind == "schema" else "reference"
        else:
            status = "gap"
        runnable = [tool.name for tool in mapped_tools.values()
                    if enabled_profiles is None or tool.profiles <= enabled_profiles]
        if mapped_tools:
            availability = "enabled" if runnable else "profile_disabled"
        elif component_tools:
            availability = "components_only"
        elif direct_resources:
            availability = "documentation_only" if kind == "tool" else "resource"
        else:
            availability = "unavailable"
        resolved.append({
            **mapping,
            "accounting_status": "mapped",
            "implementation_status": status,
            "registered": bool(mapped_tools) or (kind in SCHEMA_KINDS and bool(direct_resources)),
            "directly_registered": bool(tool_map.get(identifier)),
            "tools": sorted(mapped_tools),
            "component_tools": {target: sorted(registered) for target, registered in component_tools.items()},
            "resources": direct_resources,
            "enabled_tools": sorted(runnable),
            "required_profiles": {name: sorted(tool.profiles) for name, tool in sorted(mapped_tools.items())},
            "availability": availability,
            "declaration": source[identifier]["declaration"],
        })
    sections: dict[str, dict[str, int]] = {}
    for row in resolved:
        counts = sections.setdefault(row["section"], {"total": 0})
        counts["total"] += 1
        counts[row["implementation_status"]] = counts.get(row["implementation_status"], 0) + 1
    return {
        "format_version": 1,
        "compatibility": load_compatibility(),
        "summary": {
            "accounted": len(resolved),
            "total": len(source),
            "implementation": dict(sorted(Counter(row["implementation_status"] for row in resolved).items())),
            "verification": dict(sorted(Counter(row["verification_status"] for row in resolved).items())),
            "registered_tools": len(tools),
            "sections": sections,
        },
        "notes": [
            "All public contract items are accounted for; this is not a claim of full behavioral parity.",
            "Implemented means an adapter is registered. Verification status is separate and requires explicit test evidence.",
            "Enabled means the required profiles are enabled; configured credentials and authority reachability are checked at execution.",
            "Schema/reference resources are not cryptographic verification or executable workflows.",
            "Support mappings are internal use of core helpers; components_available does not implement a complete workflow.",
        ],
        "rows": resolved,
    }


def verify_packaged_snapshot() -> list[str]:
    compatibility = load_compatibility()
    problems = []
    actual = contract_digest(_data_text("public-surface.json"))
    if actual != compatibility["contract_sha256"]:
        problems.append("Packaged public contract digest differs from compatibility pin")
    if load_coverage().get("core_contract_sha256") != compatibility["contract_sha256"]:
        problems.append("Coverage manifest refers to a different public contract")
    if load_contract().get("contract_version") != compatibility["contract_version"]:
        problems.append("Public contract format version differs from compatibility pin")
    return problems


def verify_core_source(path: Path, *, check_revision: bool = True) -> list[str]:
    """Verify an explicitly supplied checkout; never locate sibling repos implicitly."""
    compatibility = load_compatibility()
    path = path.resolve()
    problems: list[str] = []
    try:
        version = (path / "VERSION").read_text(encoding="utf-8").strip()
        raw = (path / compatibility["contract_path"]).read_text(encoding="utf-8")
        source = _parse(raw)
    except (OSError, UnicodeError, ValueError) as exc:
        return [f"Cannot read explicit core checkout: {type(exc).__name__}"]
    if version != compatibility["core_version"]:
        problems.append(f"Core version differs: expected {compatibility['core_version']}, got {version}")
    problems.extend(compare_contract(source))
    if contract_digest(raw) != compatibility["contract_sha256"]:
        problems.append("Core public-contract content differs from the pinned digest")
    if check_revision:
        try:
            result = subprocess.run(
                ["git", "-C", str(path), "rev-parse", "HEAD"],
                capture_output=True, text=True, check=False, timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            problems.append("Cannot establish core Git revision")
        else:
            if result.returncode != 0 or result.stdout.strip() != compatibility["core_commit"]:
                problems.append("Core Git revision differs from the pinned commit")
            else:
                try:
                    status = subprocess.run(
                        ["git", "-C", str(path), "status", "--porcelain", "--untracked-files=no"],
                        capture_output=True, text=True, check=False, timeout=10,
                    )
                except (OSError, subprocess.TimeoutExpired):
                    problems.append("Cannot establish whether the pinned core checkout is clean")
                else:
                    if status.returncode != 0 or status.stdout.strip():
                        problems.append("Core checkout has tracked changes; it is not the pinned source snapshot")
    return problems


def verify_installed_core(*, signatures: bool = False) -> list[str]:
    """Validate the installed release without importing excluded core test helpers."""
    compatibility = load_compatibility()
    try:
        installed = metadata.version(compatibility["core_package"])
    except metadata.PackageNotFoundError:
        return ["The pinned genesis-mesh package is not installed"]
    problems = []
    if installed != compatibility["core_version"]:
        problems.append(f"Installed core version differs: expected {compatibility['core_version']}, got {installed}")
    if not signatures:
        return problems
    for entry in load_contract()["python"]:
        module_name, name = entry["symbol"].split(":", 1)
        try:
            obj = getattr(importlib.import_module(module_name), name)
            if inspect.isclass(obj) and issubclass(obj, BaseModel):
                parameters = None
            elif callable(obj):
                target = obj.__init__ if inspect.isclass(obj) else obj
                parameters = [
                    {"name": parameter.name, "kind": parameter.kind.name.lower(),
                     "required": parameter.default is inspect.Parameter.empty
                     and parameter.kind not in (parameter.VAR_POSITIONAL, parameter.VAR_KEYWORD)}
                    for parameter in inspect.signature(target).parameters.values() if parameter.name != "self"
                ]
            else:
                parameters = None
            if parameters != entry.get("parameters"):
                problems.append(f"Installed public signature changed: {entry['symbol']}")
        except (ImportError, AttributeError, TypeError, ValueError):
            problems.append(f"Installed public symbol cannot be resolved: {entry['symbol']}")
    return problems
