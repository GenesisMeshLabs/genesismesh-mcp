"""Check the packaged contract and resolve coverage against real registrations."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

# This is a checkout verifier. Never validate new sources with a stale installed checker/catalog.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from genesismesh_mcp.catalog import (  # noqa: E402
    CatalogError,
    build_catalog,
    load_coverage,
    verify_core_source,
    verify_installed_core,
    verify_packaged_snapshot,
)
from genesismesh_mcp.settings import Settings  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=Path, help="Explicit core checkout to compare with the pinned commit and contract")
    parser.add_argument("--require-http", action="store_true", help="Fail unless all public HTTP operations have tools")
    parser.add_argument("--require-no-gaps", action="store_true", help="Fail for any unresolved tool/schema/reference gap")
    parser.add_argument("--json", action="store_true", help="Print complete resolved catalog as JSON")
    parser.add_argument("--test-evidence", type=Path, help="Require collected and passing tests for all exercised claims")
    parser.add_argument("--test-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--branch-coverage", type=Path, help="Require source-bound coverage.py branch measurements")
    parser.add_argument("--require-clean-evidence", action="store_true", help="Require evidence from a clean Git revision")
    args = parser.parse_args()
    problems = verify_packaged_snapshot() + verify_installed_core(signatures=True)
    if args.core:
        problems.extend(verify_core_source(args.core))
    evidence = None
    if args.test_evidence:
        from genesismesh_mcp.test_evidence import load_receipt, verify_branch_coverage, verify_evidence

        try:
            receipt = load_receipt(args.test_evidence)
            evidence_problems, evidence = verify_evidence(
                args.test_root, receipt, load_coverage(),
                require_clean=args.require_clean_evidence)
            problems.extend(evidence_problems)
            evidence["receipt_sha256"] = hashlib.sha256(args.test_evidence.read_bytes()).hexdigest()
            if args.branch_coverage:
                branch_problems, branch_summary = verify_branch_coverage(
                    receipt, load_receipt(args.branch_coverage), root=args.test_root)
                problems.extend(branch_problems)
                branch_summary["report_sha256"] = hashlib.sha256(args.branch_coverage.read_bytes()).hexdigest()
                evidence["branch_coverage"] = branch_summary
        except (OSError, ValueError, TypeError, KeyError) as exc:
            problems.append(f"Cannot validate test execution evidence: {exc}")
    elif args.require_clean_evidence or args.branch_coverage:
        problems.append("--require-clean-evidence and --branch-coverage require --test-evidence")
    try:
        from genesismesh_mcp.server import build_resource_targets, build_tools

        settings = Settings()
        catalog = build_catalog(build_tools(settings), resources=build_resource_targets(), profiles=settings.profiles)
    except (CatalogError, ImportError, AttributeError) as exc:
        problems.append(f"Cannot verify actual MCP registrations: {exc}")
        catalog = None
    if catalog:
        gaps = [row for row in catalog["rows"] if row["implementation_status"] in {"gap", "components_available"}]
        if args.require_no_gaps:
            problems.extend(f"Unimplemented source capability: {row['id']}" for row in gaps)
        if args.require_http:
            problems.extend(f"Public HTTP operation lacks a registered tool: {row['id']}" for row in catalog["rows"]
                            if row["section"] == "http_routes" and row["stability"] != "internal"
                            and row["implementation_status"] != "implemented")
        if args.json:
            catalog["validation"] = {"passed": not problems, "problems": problems}
            if evidence is not None:
                catalog["test_execution_evidence"] = evidence
            print(json.dumps(catalog, indent=2))
        else:
            print(json.dumps(catalog["summary"], indent=2))
            if evidence is not None:
                print(json.dumps({"test_execution_evidence": evidence}, indent=2))
            if gaps:
                print(f"Executable/schema/reference gaps: {len(gaps)}; use --json for individual mappings.")
    for problem in problems:
        print(f"ERROR: {problem}", file=sys.stderr)
    if problems:
        return 1
    if not args.json:
        print("PASS: pinned contract, installed core and registered-target accounting are consistent.")
        print("This check does not claim that every registered operation was behavior-tested.")
        if not args.test_evidence:
            print("No execution receipt supplied; only registration accounting was checked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
