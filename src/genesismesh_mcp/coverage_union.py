"""Merge measured source lines/arcs across the supported interpreter/platform matrix."""

from __future__ import annotations

from pathlib import PurePosixPath


def canonical_source(filename: str) -> str:
    parts = PurePosixPath(filename.replace("\\", "/")).parts
    if ".." in parts or "genesismesh_mcp" not in parts or not filename.endswith(".py"):
        raise ValueError("Measurement does not identify an adapter Python source")
    start = len(parts) - 1 - parts[::-1].index("genesismesh_mcp")
    return "src/" + "/".join(parts[start:])


def merge_measurements(reports: list[dict], expected_files: set[str], context: str) -> dict:
    """Union observed lines/arcs, preserving the complete possible denominator.

    Callers first verify each report's source-bound receipt and artifact hashes.
    No line/arc is removed merely because another platform cannot execute it.
    """
    if not reports or not expected_files or not context:
        raise ValueError("A union needs reports, source inventory and source context")
    union = {name: {"lines": set(), "executed_lines": set(), "arcs": set(), "executed_arcs": set()}
             for name in expected_files}
    for report in reports:
        if not isinstance(report.get("meta"), dict) or report["meta"].get("branch_coverage") is not True:
            raise ValueError("Every union input must measure branches")
        measured = report.get("files")
        if not isinstance(measured, dict):
            raise ValueError("Every union input needs a complete source inventory")
        seen, contexts = set(), set()
        for filename, data in measured.items():
            name = canonical_source(filename)
            if name not in union or name in seen or not isinstance(data, dict):
                raise ValueError("Union input contains unknown or duplicate measured sources")
            seen.add(name)
            if data.get("excluded_lines") != []:
                raise ValueError("Full source coverage cannot hide excluded lines")
            for key in ("executed_lines", "missing_lines"):
                values = data.get(key)
                if not isinstance(values, list) or any(type(value) is not int or value < 1 for value in values):
                    raise ValueError("Invalid measured source lines")
                union[name]["lines"].update(values)
            union[name]["executed_lines"].update(data["executed_lines"])
            for key in ("executed_branches", "missing_branches"):
                values = data.get(key)
                if (not isinstance(values, list) or any(not isinstance(value, list) or len(value) != 2
                        or any(type(line) is not int for line in value) for value in values)):
                    raise ValueError("Invalid measured branch arcs")
                union[name]["arcs"].update(map(tuple, values))
            union[name]["executed_arcs"].update(map(tuple, data["executed_branches"]))
            executed_lines, missing_lines = set(data["executed_lines"]), set(data["missing_lines"])
            executed_arcs, missing_arcs = set(map(tuple, data["executed_branches"])), set(map(tuple, data["missing_branches"]))
            if (executed_lines & missing_lines or executed_arcs & missing_arcs
                    or len(executed_lines) != len(data["executed_lines"]) or len(missing_lines) != len(data["missing_lines"])
                    or len(executed_arcs) != len(data["executed_branches"]) or len(missing_arcs) != len(data["missing_branches"])):
                raise ValueError("Measured and missing inventories must be disjoint and unique")
            expected = {"covered_lines": len(executed_lines), "num_statements": len(executed_lines | missing_lines),
                        "covered_branches": len(executed_arcs), "num_branches": len(executed_arcs | missing_arcs)}
            summary = data.get("summary")
            if not isinstance(summary, dict) or any(type(summary.get(key)) is not int or summary[key] != value for key, value in expected.items()):
                raise ValueError("Measured arrays do not match per-file coverage totals")
            line_contexts = data.get("contexts")
            if not isinstance(line_contexts, dict):
                raise ValueError("Union inputs need source measurement contexts")
            for values in line_contexts.values():
                if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
                    raise ValueError("Invalid measurement contexts")
                contexts.update(values)
        if seen != expected_files or context not in contexts or contexts - {"", context}:
            raise ValueError("Union input source inventory/context differs")
    files, missing_lines, missing_arcs = {}, 0, 0
    for name, data in sorted(union.items()):
        lines = data["lines"] - data["executed_lines"]
        arcs = data["arcs"] - data["executed_arcs"]
        missing_lines += len(lines)
        missing_arcs += len(arcs)
        files[name] = {"statements": len(data["lines"]), "branches": len(data["arcs"]),
                       "missing_lines": sorted(lines), "missing_branches": [list(arc) for arc in sorted(arcs)]}
    if not any(data["statements"] for data in files.values()) or not any(data["branches"] for data in files.values()):
        raise ValueError("Full coverage needs a nonempty executable and branch denominator")
    return {"complete": missing_lines == 0 and missing_arcs == 0,
            "reports": len(reports), "measured_files": len(files), "source_context": context,
            "statements": sum(data["statements"] for data in files.values()),
            "branches": sum(data["branches"] for data in files.values()),
            "missing_statements": missing_lines, "missing_branch_arcs": missing_arcs, "files": files}
