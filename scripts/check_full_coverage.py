"""Verify four source-bound matrix jobs before requiring a complete line/arc union."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import tokenize
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from coverage import Coverage  # noqa: E402

from genesismesh_mcp.catalog import build_catalog, load_coverage  # noqa: E402
from genesismesh_mcp.coverage_union import merge_measurements  # noqa: E402
from genesismesh_mcp.server import build_resource_targets, build_tools  # noqa: E402
from genesismesh_mcp.settings import Settings  # noqa: E402
from genesismesh_mcp.test_evidence import load_receipt, source_identity, verify_evidence  # noqa: E402
from genesismesh_mcp.tool_evidence import load_tool_evidence, verify_tool_evidence  # noqa: E402

SUPPORTED = {("Linux", "3.12"), ("Linux", "3.14"), ("Windows", "3.12"), ("Windows", "3.14")}
OPTIONS = ("run:branch", "run:source", "run:source_pkgs", "run:include", "run:omit", "run:core",
           "report:exclude_lines", "report:exclude_also", "report:partial_branches")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(inputs: Path, root: Path = ROOT) -> dict:
    problems, reports, jobs, slots = [], [], [], set()
    identity = source_identity(root)
    expected_files = {name for name in identity["files"] if name.startswith("src/genesismesh_mcp/") and name.endswith(".py")}
    for name in expected_files:
        text = (root / name).read_text(encoding="utf-8")
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.COMMENT and re.search(r"pragma[:\s]?\s*no\s*(cover|branch)", token.string, re.I):
                problems.append(f"Coverage suppression is not allowed for the full target: {name}:{token.start[0]}")
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    configured = project.get("tool", {}).get("coverage", {})
    if any(name in configured.get("report", {}) for name in ("exclude_lines", "exclude_also", "partial_branches", "partial_also")):
        problems.append("Full coverage cannot override line/partial-branch exclusions")
    configuration = Coverage(config_file=str(root / "pyproject.toml"))
    expected_config = {name: configuration.get_option(name) for name in OPTIONS}
    expected_config_sha = hashlib.sha256(json.dumps(expected_config, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    tools = build_tools(Settings())
    catalog = build_catalog(tools, resources=build_resource_targets())
    ledger, claims = load_tool_evidence(), load_coverage()
    for folder in sorted(path for path in inputs.iterdir() if path.is_dir()):
        try:
            receipt_path, report_path = folder / "tests.json", folder / "branches.json"
            receipt, report, verified = load_receipt(receipt_path), load_receipt(report_path), load_receipt(folder / "verification.json")
            execution = verified["test_execution_evidence"]
            if (verified.get("validation", {}).get("passed") is not True or execution.get("valid") is not True
                    or execution.get("branch_coverage", {}).get("valid") is not True
                    or execution.get("receipt_sha256") != digest(receipt_path)
                    or execution.get("branch_coverage", {}).get("report_sha256") != digest(report_path)):
                raise ValueError("Input artifacts lack a successful matching verification envelope")
            if receipt.get("measurement_config") != expected_config or receipt.get("measurement_config_sha256") != expected_config_sha:
                raise ValueError("Measurement configuration differs from the checked source")
            errors, _ = verify_evidence(root, receipt, claims, require_clean=True)
            behavior_errors, _ = verify_tool_evidence(receipt, tools, ledger, catalog)
            if errors or behavior_errors:
                raise ValueError("Matrix job lacks valid full execution/behavior evidence: " + "; ".join(errors + behavior_errors))
            platform = "Windows" if receipt["platform"].startswith("Windows") else "Linux" if receipt["platform"].startswith("Linux") else "unsupported"
            slot = (platform, ".".join(receipt["python"].split(".")[:2]))
            if slot not in SUPPORTED or slot in slots:
                raise ValueError("Duplicate or unsupported matrix slot")
            slots.add(slot)
            reports.append(report)
            jobs.append({"platform": slot[0], "python": slot[1], "source_revision": receipt["source_start"]["revision"],
                         "measurement": execution["branch_coverage"]})
        except (OSError, ValueError, TypeError, KeyError) as exc:
            problems.append(f"{folder.name}: {exc}")
    if slots != SUPPORTED:
        problems.append("Full coverage requires every distinct supported OS/Python job")
    union = None
    if reports:
        try:
            union = merge_measurements(reports, expected_files, "genesismesh-source:" + identity["content_sha256"])
            if not union["complete"]:
                problems.append(f"Uncovered adapter behavior: {union['missing_statements']} statements, {union['missing_branch_arcs']} branch arcs")
        except (ValueError, TypeError, KeyError) as exc:
            problems.append(f"Cannot merge measurements: {exc}")
    return {"complete": not problems, "problems": problems, "source_revision": identity["revision"],
            "source_sha256": identity["content_sha256"], "jobs": jobs, "union": union}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "temp/coverage/full-coverage.json")
    args = parser.parse_args()
    result = check(args.inputs)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in result.items() if key not in {"union", "jobs"}}, indent=2))
    return 0 if result["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
