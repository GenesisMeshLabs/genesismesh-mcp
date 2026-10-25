"""Check the packaged contract and resolve coverage against real registrations."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from genesismesh_mcp.catalog import (
    CatalogError,
    build_catalog,
    verify_core_source,
    verify_installed_core,
    verify_packaged_snapshot,
)
from genesismesh_mcp.settings import Settings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=Path, help="Explicit core checkout to compare with the pinned commit and contract")
    parser.add_argument("--require-http", action="store_true", help="Fail unless all public HTTP operations have tools")
    parser.add_argument("--require-no-gaps", action="store_true", help="Fail for any unresolved tool/schema/reference gap")
    parser.add_argument("--json", action="store_true", help="Print complete resolved catalog as JSON")
    args = parser.parse_args()
    problems = verify_packaged_snapshot() + verify_installed_core(signatures=True)
    if args.core:
        problems.extend(verify_core_source(args.core))
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
            print(json.dumps(catalog, indent=2))
        else:
            print(json.dumps(catalog["summary"], indent=2))
            if gaps:
                print(f"Executable/schema/reference gaps: {len(gaps)}; use --json for individual mappings.")
    for problem in problems:
        print(f"ERROR: {problem}", file=sys.stderr)
    if problems:
        return 1
    if not args.json:
        print("PASS: pinned contract, installed core and registered-target accounting are consistent.")
        print("This check does not claim that every registered operation was behavior-tested.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
