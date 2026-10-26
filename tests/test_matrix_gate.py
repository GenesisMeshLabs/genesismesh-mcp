"""Cross-job validation refuses partial, failed, stale and inconsistent artifacts."""

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from coverage import Coverage

from genesismesh_mcp.test_evidence import source_identity


@pytest.fixture
def matrix(tmp_path, monkeypatch):
    checkout = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("full_coverage_check", checkout / "scripts/check_full_coverage.py")
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    (tmp_path / "pyproject.toml").write_text((checkout / "pyproject.toml").read_text(encoding="utf-8"), encoding="utf-8")
    source = tmp_path / "src/genesismesh_mcp/example.py"
    source.parent.mkdir(parents=True)
    source.write_text("def choose(value):\n    return 1 if value else 2\n", encoding="utf-8")
    identity = source_identity(tmp_path)
    configuration = Coverage(config_file=str(tmp_path / "pyproject.toml"))
    config = {name: configuration.get_option(name) for name in gate.OPTIONS}
    config_sha = hashlib.sha256(json.dumps(config, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    inputs = tmp_path / "temp/matrix"
    inputs.mkdir(parents=True)
    for platform, python in sorted(gate.SUPPORTED):
        folder = inputs / (platform + python)
        folder.mkdir()
        receipt = {"platform": platform, "python": python + ".0", "source_start": identity,
                   "measurement_config": config, "measurement_config_sha256": config_sha}
        report = {"meta": {"branch_coverage": True}, "files": {"src/genesismesh_mcp/example.py": {
            "executed_lines": [1, 2], "missing_lines": [], "excluded_lines": [],
            "executed_branches": [[2, -1], [2, 2]], "missing_branches": [],
            "contexts": {"2": ["genesismesh-source:" + identity["content_sha256"]]},
            "summary": {"covered_lines": 2, "num_statements": 2, "covered_branches": 2, "num_branches": 2}}}}
        (folder / "tests.json").write_text(json.dumps(receipt), encoding="utf-8")
        (folder / "branches.json").write_text(json.dumps(report), encoding="utf-8")
        verified = {"validation": {"passed": True}, "test_execution_evidence": {"valid": True,
            "receipt_sha256": gate.digest(folder / "tests.json"),
            "branch_coverage": {"valid": True, "report_sha256": gate.digest(folder / "branches.json")}}}
        (folder / "verification.json").write_text(json.dumps(verified), encoding="utf-8")
    monkeypatch.setattr(gate, "build_tools", lambda settings: [])
    monkeypatch.setattr(gate, "build_resource_targets", lambda: {})
    monkeypatch.setattr(gate, "build_catalog", lambda *args, **kwargs: {})
    monkeypatch.setattr(gate, "load_tool_evidence", lambda: {})
    monkeypatch.setattr(gate, "load_coverage", lambda: {})
    # These validators have their own real receipt/handler regressions; here their result is an input.
    monkeypatch.setattr(gate, "verify_evidence", lambda *args, **kwargs: ([], {}))
    monkeypatch.setattr(gate, "verify_tool_evidence", lambda *args, **kwargs: ([], {}))
    return gate, tmp_path, inputs


def test_exact_successful_matrix_can_complete_the_source_union(matrix):
    gate, root, inputs = matrix
    result = gate.check(inputs, root)
    assert result["complete"] and len(result["jobs"]) == 4
    assert result["union"]["missing_branch_arcs"] == result["union"]["missing_statements"] == 0


@pytest.mark.parametrize("failure", ["envelope", "measurement", "duplicate", "receipt", "branch", "missing"])
def test_failed_foreign_duplicate_or_tampered_jobs_do_not_complete_union(matrix, failure):
    gate, root, inputs = matrix
    folder = next(inputs.iterdir())
    path = folder / "verification.json"
    verified = json.loads(path.read_text(encoding="utf-8"))
    if failure == "envelope":
        verified["validation"]["passed"] = False
    elif failure in {"measurement", "duplicate", "receipt"}:
        receipt_path = folder / "tests.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        if failure == "measurement":
            receipt["measurement_config_sha256"] = "foreign"
        elif failure == "duplicate":
            receipt["platform"], receipt["python"] = "Windows", "3.14.0"
        receipt_path.write_text(json.dumps(receipt) + " ", encoding="utf-8")
        if failure != "receipt":
            verified["test_execution_evidence"]["receipt_sha256"] = gate.digest(receipt_path)
    elif failure == "branch":
        (folder / "branches.json").write_text("{}", encoding="utf-8")
    else:
        path.unlink()
    if failure != "missing":
        path.write_text(json.dumps(verified), encoding="utf-8")
    result = gate.check(inputs, root)
    assert result["complete"] is False and result["problems"]


def test_invalid_execution_or_handler_evidence_cannot_be_hidden_by_complete_arcs(matrix, monkeypatch):
    gate, root, inputs = matrix
    monkeypatch.setattr(gate, "verify_tool_evidence", lambda *args, **kwargs: (["unverified handler"], {}))
    assert gate.check(inputs, root)["complete"] is False


def test_coverage_suppression_is_not_a_way_to_satisfy_full_target(matrix):
    gate, root, inputs = matrix
    source = root / "src/genesismesh_mcp/example.py"
    source.write_text(source.read_text(encoding="utf-8") + "# pragma no branch\n", encoding="utf-8")
    result = gate.check(inputs, root)
    assert not result["complete"]
    assert any("suppression" in problem for problem in result["problems"])
