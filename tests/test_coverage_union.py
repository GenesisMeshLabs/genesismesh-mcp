"""A platform union retains uncovered behavior and refuses mismatched evidence."""

import copy

import pytest

from genesismesh_mcp.coverage_union import canonical_source, merge_measurements

SOURCE = "src/genesismesh_mcp/example.py"
CONTEXT = "genesismesh-source:fixture"


def report(executed_lines, missing_lines, executed_arcs, missing_arcs):
    return {"meta": {"branch_coverage": True}, "files": {SOURCE: {
        "executed_lines": executed_lines, "missing_lines": missing_lines, "excluded_lines": [],
        "executed_branches": executed_arcs, "missing_branches": missing_arcs, "contexts": {"1": [CONTEXT]},
        "summary": {"num_statements": len(executed_lines) + len(missing_lines), "covered_lines": len(executed_lines),
                    "num_branches": len(executed_arcs) + len(missing_arcs), "covered_branches": len(executed_arcs)}}}}


def test_union_requires_every_possible_statement_and_arc_to_be_executed():
    windows = report([1, 2], [3], [[1, 2]], [[1, 3]])
    linux = report([1, 3], [2], [[1, 3]], [[1, 2]])
    incomplete = merge_measurements([windows], {SOURCE}, CONTEXT)
    assert not incomplete["complete"]
    assert incomplete["missing_statements"] == incomplete["missing_branch_arcs"] == 1
    complete = merge_measurements([windows, linux], {SOURCE}, CONTEXT)
    assert complete["complete"]
    assert complete["statements"] == 3 and complete["branches"] == 2
    linux["files"][SOURCE]["missing_branches"].append([3, -1])
    linux["files"][SOURCE]["summary"]["num_branches"] += 1
    assert not merge_measurements([windows, linux], {SOURCE}, CONTEXT)["complete"]


@pytest.mark.parametrize("filename", ["src/genesismesh_mcp/example.py", r"C:\work\src\genesismesh_mcp\example.py",
                                       "/venv/lib/python3.12/site-packages/genesismesh_mcp/example.py"])
def test_supported_source_and_installed_package_paths_share_a_canonical_identity(filename):
    assert canonical_source(filename) == SOURCE


@pytest.mark.parametrize("filename", ["unrelated.py", "src/genesismesh_mcp/../escape.py", "genesismesh_mcp/data.json"])
def test_unrelated_and_traversal_sources_are_refused(filename):
    with pytest.raises(ValueError):
        canonical_source(filename)


@pytest.mark.parametrize("reports,expected,context", [([], {SOURCE}, CONTEXT), ([{}], set(), CONTEXT), ([{}], {SOURCE}, "")])
def test_union_cannot_claim_success_without_evidence(reports, expected, context):
    with pytest.raises(ValueError):
        merge_measurements(reports, expected, context)


@pytest.mark.parametrize("field,value", [
    ("excluded_lines", [2]), ("executed_lines", [True]), ("missing_lines", None),
    ("executed_branches", [[1]]), ("missing_branches", [[1, "other"]]),
    ("contexts", None), ("contexts", {"1": [False]}), ("contexts", {"1": ["other-source"]}),
])
def test_invalid_or_hidden_measurements_cannot_satisfy_union(field, value):
    measured = report([1], [], [], [])
    measured["files"][SOURCE][field] = value
    with pytest.raises(ValueError):
        merge_measurements([measured], {SOURCE}, CONTEXT)


def test_every_report_requires_exact_inventory_and_branch_measurement():
    good = report([1], [], [], [])
    for altered in ({**good, "meta": {}}, {**good, "files": None}):
        with pytest.raises(ValueError):
            merge_measurements([altered], {SOURCE}, CONTEXT)
    altered = copy.deepcopy(good)
    altered["files"]["/site-packages/genesismesh_mcp/example.py"] = copy.deepcopy(altered["files"][SOURCE])
    with pytest.raises(ValueError):
        merge_measurements([altered], {SOURCE}, CONTEXT)
    with pytest.raises(ValueError):
        merge_measurements([good], {SOURCE, "src/genesismesh_mcp/missing.py"}, CONTEXT)


def test_zero_or_inconsistent_denominators_cannot_report_full_coverage():
    with pytest.raises(ValueError, match="nonempty"):
        merge_measurements([report([], [], [], [])], {SOURCE}, CONTEXT)
    for changed in (report([1], [1], [[1, 2]], []), report([1, 1], [], [[1, 2]], []),
                    report([1], [], [[1, 2]], [[1, 2]])):
        with pytest.raises(ValueError, match="disjoint and unique"):
            merge_measurements([changed], {SOURCE}, CONTEXT)
    changed = report([1], [], [[1, 2]], [])
    changed["files"][SOURCE]["summary"]["covered_lines"] = 0
    with pytest.raises(ValueError, match="totals"):
        merge_measurements([changed], {SOURCE}, CONTEXT)
