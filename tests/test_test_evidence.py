"""Regression tests for evidence claims, including actual failing pytest sessions."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from genesismesh_mcp.test_evidence import (
    file_digest,
    load_receipt,
    source_identity,
    verify_branch_coverage,
    verify_evidence,
)


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
                                      ("collected", []), ("collected", [False]), ("outcomes", {}), ("outcomes", None),
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


def test_real_receipt_observes_handler_calls_without_payloads(child_pytest):
    code, receipt = child_pytest('''from genesismesh_mcp.types import ToolSpec
from genesismesh_mcp.settings import Settings
from genesismesh_mcp.offline import build_tools
def test_case():
    settings = Settings()
    tools = {tool.name: tool for tool in build_tools(settings)}
    result = tools["gm_offline_context_gate_types"].handler({})
    assert result
    def fail(arguments): raise ValueError("sensitive-never-record")
    tool = ToolSpec("failure", "probe", {"type": "object"}, fail)
    try: tool.handler({"secret": "sensitive-never-record"})
    except ValueError: pass
''')
    assert code == 0
    calls = receipt["tool_calls"]
    assert any(call["tool"] == "gm_offline_context_gate_types" and call["schema_valid"]
               and call["outcome"] == "returned" for call in calls)
    assert any(call["tool"] == "failure" and call["outcome"] == "ValueError" for call in calls)
    assert "sensitive-never-record" not in json.dumps(receipt)


def test_late_thread_calls_cannot_be_attributed_to_the_next_test(child_pytest):
    code, receipt = child_pytest('''import contextvars
import threading
from genesismesh_mcp.types import ToolSpec
release, started = threading.Event(), threading.Event()
worker = None
def test_first():
    global worker
    tool = ToolSpec("late", "probe", {"type": "object"}, lambda args: {"ok": True})
    def later():
        started.set()
        release.wait(5)
        tool.handler({})
    context = contextvars.copy_context()
    worker = threading.Thread(target=context.run, args=(later,))
    worker.start()
    assert started.wait(2)
def test_second():
    release.set()
    worker.join(2)
    assert not worker.is_alive()
    ToolSpec("current", "probe", {"type": "object"}, lambda args: True).handler({})
''')
    assert code == 0
    assert not any(call["tool"] == "late" for call in receipt["tool_calls"])
    assert any(call["tool"] == "current" and call["test"].endswith("::test_second")
               and call["phase"] == "call" for call in receipt["tool_calls"])


def test_decorated_http_mock_remains_marked_as_mocked(child_pytest):
    code, receipt = child_pytest('''from functools import wraps
import requests
from genesismesh_mcp.types import ToolSpec
def test_case(monkeypatch):
    @wraps(requests.Session.request)
    def substitute(*args, **kwargs): return None
    monkeypatch.setattr(requests.Session, "request", substitute)
    ToolSpec("workflow", "probe", {"type": "object"}, lambda args: {"verified": True}).handler({})
''')
    assert code == 0
    assert receipt["tool_calls"][0]["transport_mocked"] is True


def test_binary_sources_are_hashed_without_text_coercion(tmp_path):
    path = tmp_path / "binary.dat"
    raw = b"\xff\x00\xfe\r\n"
    path.write_bytes(raw)
    assert file_digest(path) == hashlib.sha256(raw).hexdigest()


def test_subdirectory_cannot_borrow_its_parent_repository_identity(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    child = tmp_path / "child"
    child.mkdir()
    identity = source_identity(child)
    assert identity["revision"] is None and identity["dirty"] is None


def test_tracked_file_replaced_by_symlink_parent_never_hashes_outside_source(tmp_path):
    root, outside = tmp_path / "repo", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "record.py").write_text("outside-private-material", encoding="utf-8")
    nested = root / "nested"
    nested.mkdir()
    (nested / "record.py").write_text("tracked", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(["git", "-C", str(root), "-c", "user.name=Test", "-c", "user.email=test@example.org",
                    "-c", "commit.gpgsign=false", "commit", "-qm", "fixture"], check=True)
    (nested / "record.py").unlink()
    nested.rmdir()
    try:
        nested.symlink_to(outside, target_is_directory=True)
    except OSError:
        return  # This attack path requires symlink support; Linux CI supplies it.
    identity = source_identity(root)
    assert "nested/record.py" not in identity["files"]


def test_malformed_inventory_paths_are_ignored_before_reading_files(tmp_path, monkeypatch):
    outside = tmp_path.parent / "outside-probe"

    def git(arguments, **kwargs):
        if "--show-toplevel" in arguments:
            return str(tmp_path).encode()
        if "ls-files" in arguments:
            return (str(outside) + "\0../outside-probe\0missing.py\0").encode()
        return b"revision" if "rev-parse" in arguments else b""

    monkeypatch.setattr("genesismesh_mcp.test_evidence.subprocess.check_output", git)
    assert source_identity(tmp_path)["files"] == {}


def test_coverage_rejects_malformed_contexts_for_an_actual_package_file(branches):
    receipt, report = branches
    next(iter(report["files"].values()))["contexts"] = []
    assert verify_branch_coverage(receipt, report)[0]


@pytest.mark.parametrize("explicit_root", [True, False])
def test_relative_measured_paths_are_checked_against_producing_root(branches, monkeypatch, explicit_root):
    receipt, report = branches
    filename, measurement = next(iter(report["files"].items()))
    root = Path(filename).parents[2]
    report["files"] = {"src/genesismesh_mcp/__init__.py": measurement}
    monkeypatch.chdir(root)
    assert not verify_branch_coverage(receipt, report, root=root if explicit_root else None)[0]


def test_receipt_distinguishes_domain_refusal_from_success_and_historical_records(child_pytest):
    code, receipt = child_pytest('''from genesismesh_mcp.types import ToolSpec
def test_case():
    results = {
        "false_predicate": False,
        "http_denied": {"http_ok": True, "result": {"authorized": False}},
        "http_invalid": {"http_ok": True, "result": {"verified": False}},
        "http_allowed": {"http_ok": True, "result": {"authorized": True}},
        "decision_denied": {"decision": {"authorized": False}, "executed": False},
        "decision_allowed": {"decision": {"authorized": True}, "executed": False},
        "historical_deny": {"http_ok": True, "result": {"record": {"verdict": "deny"}, "verified": True}},
    }
    for name, result in results.items():
        ToolSpec(name, "probe", {"type": "object"}, lambda args, result=result: result).handler({})
''')
    assert code == 0
    observed = {call["tool"]: call["domain_denial"] for call in receipt["tool_calls"]}
    assert observed == {"false_predicate": True, "http_denied": True, "http_invalid": True,
                        "http_allowed": False, "decision_denied": True, "decision_allowed": False,
                        "historical_deny": False}


def test_signed_rejection_constructor_success_is_distinct_from_a_refused_call(child_pytest):
    code, receipt = child_pytest('''import base64
from pathlib import Path
from datetime import datetime, timezone
from nacl.signing import SigningKey
from genesis_mesh.crypto import verify_model_signature
from genesis_mesh.models.oversight import HumanApprovalResponse
from genesismesh_mcp.offline import build_tools
from genesismesh_mcp.settings import Settings
from genesismesh_mcp.types import ToolError
def test_case():
    names = {"gm_offline_oversight_propose_commitment", "gm_offline_oversight_reject_commitment"}
    key = SigningKey.generate()
    path = Path("signer.key")
    path.write_text(base64.b64encode(bytes(key)).decode())
    settings = Settings(profiles=frozenset({"read", "verify", "sign"}), signer_files={"reviewer": path.resolve()},
                        signer_permissions={"reviewer": frozenset(names)})
    tools = {tool.name: tool for tool in build_tools(settings)}
    now = datetime.now(timezone.utc).isoformat()
    policy = {"policy_id": "p", "agreement_id": "a", "human_sovereign_id": "human",
              "allowed_capabilities": ["write"], "value_threshold": 10, "created_at": now}
    request, _ = tools["gm_offline_oversight_propose_commitment"].handler({"policy": policy,
        "proposed_action": {"capability": "write", "value": 100}, "requesting_sovereign_id": "alpha",
        "agent_signer_ref": "reviewer", "issued_by": "alpha", "now": now})
    response = tools["gm_offline_oversight_reject_commitment"].handler({"request": request, "policy": policy,
        "human_signer_ref": "reviewer", "issued_by": "human", "note": "Refused", "now": now})
    model = HumanApprovalResponse.model_validate(response)
    assert model.approved is False
    assert verify_model_signature(model, model.human_signature, base64.b64encode(bytes(key.verify_key)).decode())
    disabled = {tool.name: tool for tool in build_tools(Settings())}
    try: disabled["gm_offline_oversight_reject_commitment"].handler({})
    except ToolError as error: assert error.code == "profile_required"
    else: raise AssertionError("disabled signing tool ran")
''')
    assert code == 0
    calls = [event for event in receipt["tool_calls"] if event["tool"] == "gm_offline_oversight_reject_commitment"]
    assert any(event["outcome"] == "returned" and event["schema_valid"] and not event["domain_denial"] for event in calls)
    assert any(event["outcome"] == "ToolError" for event in calls)


def test_empty_named_scanner_finding_is_an_adverse_outcome_not_a_clean_result():
    from genesis_mesh.trust.context_integrity import scan_for_injection_markers

    from conftest import _denial
    from genesismesh_mcp.offline import build_tools
    from genesismesh_mcp.settings import Settings

    tools = {tool.name: tool for tool in build_tools(Settings())}
    # The adapter deliberately fixes the injection scanner's pattern set, while
    # core also supports custom patterns. Both scanners can represent a finding
    # with an empty string; the metadata case reaches the registered adapter.
    results = {
        "gm_offline_context_integrity_scan_for_injection_markers": scan_for_injection_markers("x", patterns=[""]),
        "gm_offline_privacy_scan_metadata_fingerprints": tools["gm_offline_privacy_scan_metadata_fingerprints"].handler(
            {"headers": {"": "x"}, "profile": {"sovereign_id": "alpha"}}),
    }
    for name, result in results.items():
        assert result == [""]
        assert _denial(result, name) is True
        assert _denial([], name) is False


def test_http_record_creation_and_verification_do_not_reinterpret_recorded_denials():
    from conftest import _denial

    cases = {
        "na_boundary_verify": {"accepted": True, "authorized": False},
        "na_out_of_band_propose_holder": {"proposal_id": "pending", "approved": False},
        "na_remediation_get_remediation": {"subject_id": "decision", "verdict": "deny", "state": "alerted"},
        "na_remediation_record_notice": {"subject_id": "decision", "verdict": "deny", "state": "alerted"},
    }
    for name, body in cases.items():
        assert not _denial({"http_ok": True, "result": body}, name)
        assert _denial({"http_ok": False, "result": body}, name)
        assert _denial({"http_ok": True, "result": {**body, "accepted": False}}, name)
    assert _denial({"http_ok": True, "result": {"authorized": False}}, "na_boundary_policy_evaluate")
    assert _denial({"http_ok": True, "result": {"trusted": False}}, "na_treaties_connectome_trust_path")
