"""Regression tests for evidence claims, including actual failing pytest sessions."""

from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from genesismesh_mcp.test_evidence import load_receipt, source_identity, verify_branch_coverage, verify_evidence


@pytest.fixture
def evidence(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests/test_case.py").write_text("def test_case(): pass\n", encoding="utf-8")
    (tmp_path / "src/genesismesh_mcp").mkdir(parents=True)
    (tmp_path / "src/genesismesh_mcp/__init__.py").write_text("# fixture\n", encoding="utf-8")
    source = source_identity(tmp_path)
    imported = {"files": {name: digest for name, digest in source["files"].items() if name.startswith("src/")}}
    ids = ["tests/test_case.py::test_case[one]", "tests/test_case.py::test_case[two]"]
    receipt = {"format_version": 1, "exit_status": 0, "source_start": source, "source_end": source,
               "collected": ids, "outcomes": dict.fromkeys(ids, "passed"), "collection_errors": [],
               "adapter_start": imported, "adapter_end": imported,
               "collection_scope": {"args": ["tests"], "restricted": False}}
    catalog = {"rows": [{"id": "example", "verification_status": "unit_tested",
                         "tests": ["tests/test_case.py::test_case"]}]}
    return tmp_path, receipt, catalog


def test_all_parameterized_cases_must_pass(evidence):
    root, receipt, catalog = evidence
    problems, summary = verify_evidence(root, receipt, catalog)
    assert not problems
    assert summary["valid"]
    assert summary["matched_cases"] == 2
    assert summary["references"] == 1
    receipt["outcomes"][receipt["collected"][1]] = "skipped"
    assert any("did not pass" in p for p in verify_evidence(root, receipt, catalog)[0])


@pytest.mark.parametrize("outcome", ["failed", "skipped", "xfailed", "xpassed", "not_run", "deselected", None, []])
def test_nonpassing_or_malformed_outcome_cannot_support_claim(evidence, outcome):
    root, receipt, catalog = evidence
    receipt["outcomes"][receipt["collected"][0]] = outcome
    assert verify_evidence(root, receipt, catalog)[0]


@pytest.mark.parametrize("reference", ["tests/missing.py::test_missing", "tests/test_case.py::test_case[absent]",
                                       "../tests/test_case.py::test_case", "tests\\test_case.py::test_case",
                                       "tests/test_case.py", "tests/test_case.py::", "::test_case", None])
def test_missing_or_unsafe_reference_fails(evidence, reference):
    root, receipt, catalog = evidence
    catalog["rows"][0]["tests"] = [reference]
    assert verify_evidence(root, receipt, catalog)[0]


def test_source_changes_and_revision_mismatches_invalidate_evidence(evidence):
    root, receipt, catalog = evidence
    changed = copy.deepcopy(receipt)
    changed["source_start"]["revision"] = "other-revision"
    assert verify_evidence(root, changed, catalog)[0]
    (root / "tests/test_case.py").write_text("def test_case(): assert False\n", encoding="utf-8")
    assert verify_evidence(root, receipt, catalog)[0]


@pytest.mark.parametrize("key,value", [("format_version", 2), ("exit_status", 1), ("collection_errors", ["tests/bad.py"]),
                                      ("collected", []), ("collected", [False]), ("outcomes", {}),
                                      ("source_start", None), ("source_end", [])])
def test_invalid_or_incomplete_session_fails(evidence, key, value):
    root, receipt, catalog = evidence
    receipt[key] = value
    assert verify_evidence(root, receipt, catalog)[0]


def test_duplicate_or_uncollected_outcome_fails(evidence):
    root, receipt, catalog = evidence
    receipt["collected"].append(receipt["collected"][0])
    assert verify_evidence(root, receipt, catalog)[0]
    receipt["collected"].pop()
    receipt["outcomes"]["not-collected"] = "passed"
    assert verify_evidence(root, receipt, catalog)[0]


def test_no_evidence_claim_and_clean_git_requirement_are_explicit(evidence):
    root, receipt, catalog = evidence
    catalog["rows"][0]["tests"] = []
    assert verify_evidence(root, receipt, catalog)[0]
    catalog["rows"][0]["verification_status"] = "not_exercised"
    assert not verify_evidence(root, receipt, catalog)[0]
    assert verify_evidence(root, receipt, catalog, require_clean=True)[0]


def test_identity_normalizes_git_crlf_and_tracks_nonignored_sources(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / ".gitignore").write_text("/temp/\n", encoding="utf-8")
    source = tmp_path / "example.py"
    source.write_bytes(b"one\r\ntwo\r\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "-c", "user.name=Test", "-c", "user.email=test@example.org",
                    "-c", "commit.gpgsign=false", "commit", "-qm", "fixture"], check=True)
    original = source_identity(tmp_path)
    assert original["dirty"] is False
    source.write_bytes(b"one\ntwo\n")
    assert source_identity(tmp_path)["content_sha256"] == original["content_sha256"]
    (tmp_path / "temp").mkdir()
    (tmp_path / "temp/report.json").write_text("{}", encoding="utf-8")
    assert source_identity(tmp_path)["content_sha256"] == original["content_sha256"]
    (tmp_path / "extra.py").write_text("changed", encoding="utf-8")
    assert source_identity(tmp_path)["content_sha256"] != original["content_sha256"]


@pytest.fixture
def child_pytest(tmp_path):
    checkout = Path(__file__).resolve().parents[1]
    shutil.copyfile(checkout / "conftest.py", tmp_path / "conftest.py")
    shutil.copytree(checkout / "src", tmp_path / "src", ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
    (tmp_path / "tests").mkdir()
    (tmp_path / "pyproject.toml").write_text('[tool.pytest.ini_options]\ntestpaths = ["tests"]\n', encoding="utf-8")

    def run(source, *args, covered=False):
        (tmp_path / "tests/test_case.py").write_text(source, encoding="utf-8")
        destination = tmp_path / "temp/receipt.json"
        prefix = ["coverage", "run", "--branch", "--source=genesismesh_mcp", "-m"] if covered else []
        result = subprocess.run([sys.executable, "-m", *prefix, "pytest", "-q", "--evidence-report", str(destination), *args],
                                cwd=tmp_path, env={**os.environ, "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
                                                  "PYTEST_ADDOPTS": "", "COVERAGE_CORE": "ctrace"},
                                capture_output=True, text=True, timeout=60)
        assert destination.is_file(), result.stdout + result.stderr
        return result.returncode, load_receipt(destination)

    return run


def test_real_pytest_receipt_distinguishes_fail_skip_xfail_and_teardown(child_pytest):
    code, receipt = child_pytest('''import pytest
@pytest.mark.parametrize("value", [1, 2])
def test_pass(value): assert value > 0
def test_fail(): assert False
@pytest.mark.skip(reason="not exercised")
def test_skip(): pass
@pytest.mark.xfail(reason="known failure")
def test_xfail(): assert False
@pytest.mark.xfail(reason="unexpected pass")
def test_xpass(): pass
@pytest.mark.xfail(reason="")
def test_xpass_blank(): pass
@pytest.mark.xfail(reason="")
def test_xfail_blank(): assert False
@pytest.fixture
def broken_setup(): raise RuntimeError("setup")
def test_setup(broken_setup): pass
@pytest.fixture
def broken_teardown():
    yield
    raise RuntimeError("teardown")
def test_teardown(broken_teardown): pass
''')
    assert code == 1
    outcomes = {n.split("::")[1]: v for n, v in receipt["outcomes"].items()}
    assert outcomes == {"test_pass[1]": "passed", "test_pass[2]": "passed", "test_fail": "failed",
                        "test_skip": "skipped", "test_xfail": "xfailed", "test_xpass": "xpassed",
                        "test_xpass_blank": "xpassed", "test_xfail_blank": "xfailed",
                        "test_setup": "failed", "test_teardown": "failed"}
    assert receipt["source_start"] == receipt["source_end"]


def test_real_collect_only_and_deselection_cannot_be_passes(child_pytest):
    source = "def test_one(): pass\ndef test_two(): pass\n"
    code, receipt = child_pytest(source, "--collect-only")
    assert code == 0
    assert set(receipt["outcomes"].values()) == {"not_run"}
    code, receipt = child_pytest(source, "-k", "one")
    assert code == 0
    assert receipt["outcomes"]["tests/test_case.py::test_one"] == "passed"
    assert receipt["outcomes"]["tests/test_case.py::test_two"] == "deselected"


def test_real_collection_failure_and_fail_fast_are_recorded(child_pytest):
    code, receipt = child_pytest("raise RuntimeError('collection failed')\n")
    assert code != 0
    assert receipt["collection_errors"] == ["tests/test_case.py"]
    code, receipt = child_pytest("def test_one(): assert False\ndef test_two(): pass\n", "-x")
    assert code == 1
    assert receipt["outcomes"]["tests/test_case.py::test_two"] == "not_run"


@pytest.mark.parametrize("selection", [("tests/test_case.py::test_parameter[1]",), ("-k", "1"),
                                       ("-m", "selected"), ("--deselect=tests/test_case.py::test_parameter[2]",),
                                       ("--runxfail",), ("-o", "python_functions=test_parameter")])
def test_partial_parameter_selection_and_overrides_cannot_support_claim(child_pytest, tmp_path, selection):
    code, receipt = child_pytest('''import pytest
@pytest.mark.selected
@pytest.mark.parametrize("value", [1, 2])
def test_parameter(value): assert value > 0
''', *selection)
    assert code == 0
    claims = {"rows": [{"id": "parameter", "verification_status": "unit_tested",
                         "tests": ["tests/test_case.py::test_parameter"]}]}
    problems, summary = verify_evidence(tmp_path, receipt, claims)
    assert problems and summary["valid"] is False


@pytest.mark.parametrize("changed", ["settings.py", "data/coverage.json"])
def test_real_imported_adapter_must_match_checkout_code_and_data(child_pytest, tmp_path, changed):
    path = tmp_path / "src/genesismesh_mcp" / changed
    path.write_bytes(path.read_bytes() + b"\n ")
    code, receipt = child_pytest("def test_case(): pass\n")
    assert code == 0
    claims = {"rows": [{"id": "changed", "verification_status": "unit_tested",
                         "tests": ["tests/test_case.py::test_case"]}]}
    problems, _ = verify_evidence(tmp_path, receipt, claims)
    assert any("imported adapter does not match" in p for p in problems)


def test_runxfail_cannot_turn_an_unexpected_pass_into_evidence(child_pytest, tmp_path):
    code, receipt = child_pytest('''import pytest
@pytest.mark.xfail(reason="")
def test_case(): pass
''', "--runxfail")
    assert code == 0
    assert receipt["outcomes"]["tests/test_case.py::test_case"] == "passed"
    problems, _ = verify_evidence(tmp_path, receipt, {"rows": [{"id": "xfail", "verification_status": "unit_tested",
                                               "tests": ["tests/test_case.py::test_case"]}]})
    assert any("unrestricted" in p for p in problems)


def test_receipt_requires_object_and_size_bound(tmp_path):
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps([]), encoding="utf-8")
    with pytest.raises(ValueError, match="object"):
        load_receipt(path)
    path.write_bytes(b" " * (16 * 1024 * 1024 + 1))
    with pytest.raises(ValueError, match="16 MiB"):
        load_receipt(path)


@pytest.fixture
def branches(evidence):
    root, receipt, _ = evidence
    context = "genesismesh-source:" + receipt["source_start"]["content_sha256"]
    receipt["coverage_context"] = context
    totals = {"num_statements": 10, "covered_lines": 9, "num_branches": 4, "covered_branches": 3}
    report = {"meta": {"branch_coverage": True, "show_contexts": True},
              "files": {str(root / "src/genesismesh_mcp/__init__.py"): {"contexts": {"1": ["", context]}, "summary": totals.copy()}},
              "totals": totals}
    return receipt, report


def test_branch_measurements_require_matching_source_context(branches):
    receipt, report = branches
    problems, summary = verify_branch_coverage(receipt, report)
    assert not problems
    assert summary["line_percent"] == 90
    assert summary["branch_percent"] == 75
    next(iter(report["files"].values()))["contexts"]["1"] = ["genesismesh-source:stale"]
    assert verify_branch_coverage(receipt, report)[0]
    assert verify_branch_coverage(receipt, report)[1]["valid"] is False


@pytest.mark.parametrize("field,value", [("meta", {}), ("files", {}), ("files", {"bad": None}),
                                        ("files", {"bad": {"contexts": {"1": [None]}}}),
                                        ("files", {"bad": {"contexts": []}}),
                                        ("totals", {}), ("totals", {"num_statements": True})])
def test_invalid_or_statement_only_measurement_fails(branches, field, value):
    receipt, report = branches
    report[field] = value
    assert verify_branch_coverage(receipt, report)[0]


def test_uninstrumented_receipt_cannot_claim_branch_measurement(branches):
    receipt, report = branches
    receipt["coverage_context"] = None
    assert verify_branch_coverage(receipt, report)[0]


def test_unrelated_files_missing_inventory_and_inconsistent_totals_fail(branches):
    receipt, report = branches
    changed = copy.deepcopy(report)
    changed["files"] = {"unrelated.py": next(iter(changed["files"].values()))}
    assert verify_branch_coverage(receipt, changed)[0]
    changed = copy.deepcopy(report)
    changed["totals"]["covered_lines"] += 1
    assert verify_branch_coverage(receipt, changed)[0]
    changed = copy.deepcopy(report)
    measured_path = Path(next(iter(changed["files"])))
    measured_path.write_text("# different contents\n", encoding="utf-8")
    assert verify_branch_coverage(receipt, changed)[0]


def test_real_branch_report_is_bound_to_executed_sources(child_pytest, tmp_path):
    code, receipt = child_pytest('''from genesismesh_mcp.test_evidence import valid_reference
def test_real_code():
    assert valid_reference("tests/test_case.py::test_real_code")
    assert not valid_reference("missing")
''', covered=True)
    assert code == 0
    subprocess.run([sys.executable, "-m", "coverage", "json", "--show-contexts", "-o", "temp/branches.json"],
                   cwd=tmp_path, check=True, capture_output=True, text=True, timeout=60)
    report = load_receipt(tmp_path / "temp/branches.json")
    problems, summary = verify_branch_coverage(receipt, report)
    assert not problems
    assert summary["covered_branches"] > 0
    assert summary["num_branches"] > summary["covered_branches"]
    assert not verify_evidence(tmp_path, receipt, {"rows": [{"id": "real", "verification_status": "unit_tested",
                                  "tests": ["tests/test_case.py::test_real_code"]}]})[0]
