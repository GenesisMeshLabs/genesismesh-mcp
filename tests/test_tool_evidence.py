"""Behavior claims need observed calls as well as passing tests."""

from __future__ import annotations

import copy
from dataclasses import replace
from functools import wraps

import pytest

from genesismesh_mcp.tool_evidence import definition_digest, register_observer, verify_tool_evidence
from genesismesh_mcp.types import ToolSpec

REF = "tests/test_scenario.py::test_domain"


@pytest.fixture
def proof():
    tools = [ToolSpec("verify", "fixture", {"type": "object"}, lambda value: value)]
    receipt = {"collected": [REF], "outcomes": {REF: "passed"}, "tool_calls": [
        {"test": REF, "tool": "verify", "schema_valid": True, "outcome": "returned", "count": 1,
         "definition": definition_digest(tools[0]), "transport_mocked": False, "domain_denial": False, "phase": "call"},
        {"test": REF, "tool": "verify", "schema_valid": True, "outcome": "ToolError", "count": 1,
         "definition": definition_digest(tools[0]), "transport_mocked": False, "domain_denial": False, "phase": "call"}]}
    ledger = {"format_version": 1, "tools": {"verify": {"scope": "real signed record",
                                                       "positive": [REF], "negative": [REF]}}}
    catalog = {"rows": [{"id": "capability", "implementation_status": "implemented", "verification_status": "unit_tested"}]}
    return tools, receipt, ledger, catalog


def test_passing_citation_without_handler_call_is_insufficient(proof):
    tools, receipt, ledger, catalog = proof
    assert not verify_tool_evidence(receipt, tools, ledger, catalog)[0]
    receipt["tool_calls"] = []
    problems, summary = verify_tool_evidence(receipt, tools, ledger, catalog)
    assert problems and not summary["valid"] and summary["qualified_tools"] == 0


@pytest.mark.parametrize("field,value", [("schema_valid", False), ("outcome", "ToolError"), ("test", "not-collected"),
                                        ("count", 0), ("count", True), ("tool", "different"), ("definition", "fake"),
                                        ("transport_mocked", True), ("transport_mocked", None)])
def test_invalid_or_refused_call_cannot_support_positive_claim(proof, field, value):
    tools, receipt, ledger, catalog = proof
    receipt["tool_calls"][0][field] = value
    assert verify_tool_evidence(receipt, tools, ledger, catalog)[0]


@pytest.mark.parametrize("field,value", [("positive", []), ("negative", []), ("scope", ""),
                                        ("positive", ["tests/missing.py::test_missing"]), ("positive", [None])])
def test_incomplete_ledger_and_unknown_citations_fail(proof, field, value):
    tools, receipt, ledger, catalog = proof
    ledger["tools"]["verify"][field] = value
    assert verify_tool_evidence(receipt, tools, ledger, catalog)[0]


def test_every_registered_tool_and_implemented_capability_requires_evidence(proof):
    tools, receipt, ledger, catalog = proof
    ledger["tools"]["unknown"] = copy.deepcopy(ledger["tools"]["verify"])
    del ledger["tools"]["verify"]
    catalog["rows"][0]["verification_status"] = "not_exercised"
    problems, _ = verify_tool_evidence(receipt, tools, ledger, catalog)
    assert any("unregistered" in p for p in problems)
    assert any("no reviewed" in p for p in problems)
    assert any("Implemented capability" in p for p in problems)


@pytest.mark.parametrize("target,value", [("format_version", 2), ("tools", [])])
def test_ledger_format_is_checked(proof, target, value):
    tools, receipt, ledger, catalog = proof
    ledger[target] = value
    assert verify_tool_evidence(receipt, tools, ledger, catalog)[0]


@pytest.mark.parametrize("value", [None, [None], [{"test": REF}]])
def test_malformed_observations_fail(proof, value):
    tools, receipt, ledger, catalog = proof
    receipt["tool_calls"] = value
    assert verify_tool_evidence(receipt, tools, ledger, catalog)[0]


def test_failed_parameter_case_cannot_support_handler_evidence(proof):
    tools, receipt, ledger, catalog = proof
    receipt["collected"] = [REF + "[first]", REF + "[second]"]
    receipt["outcomes"] = {REF + "[first]": "passed", REF + "[second]": "skipped"}
    receipt["tool_calls"][0]["test"] = REF + "[first]"
    assert verify_tool_evidence(receipt, tools, ledger, catalog)[0]


def test_decorated_substitute_cannot_impersonate_registered_handler(proof):
    tools, receipt, ledger, catalog = proof
    original = tools[0]

    @wraps(original.handler)
    def substituted(arguments):
        return {"invented": "success"}

    fake = replace(original, handler=substituted)
    assert definition_digest(fake) != definition_digest(original)
    receipt["tool_calls"][0]["definition"] = definition_digest(fake)
    assert verify_tool_evidence(receipt, tools, ledger, catalog)[0]


def test_injected_handlers_cannot_qualify_but_do_not_invalidate_genuine_calls(proof):
    tools, receipt, ledger, catalog = proof
    injected = {**receipt["tool_calls"][0], "definition": "substituted", "count": 3}
    receipt["tool_calls"].append(injected)
    problems, summary = verify_tool_evidence(receipt, tools, ledger, catalog)
    assert not problems and summary["qualified_tools"] == 1 and summary["ignored_definition_calls"] == 3
    receipt["tool_calls"] = [injected]
    problems, summary = verify_tool_evidence(receipt, tools, ledger, catalog)
    assert problems and summary["qualified_tools"] == 0
    injected["transport_mocked"] = None
    assert any("mocked HTTP" in problem for problem in verify_tool_evidence(receipt, tools, ledger, catalog)[0])


def test_successful_only_calls_cannot_satisfy_negative_evidence(proof):
    tools, receipt, ledger, catalog = proof
    receipt["tool_calls"] = receipt["tool_calls"][:1]
    assert verify_tool_evidence(receipt, tools, ledger, catalog)[0]
    receipt["tool_calls"][0]["domain_denial"] = True
    problems, summary = verify_tool_evidence(receipt, tools, ledger, catalog)
    assert problems and summary["qualified_tools"] == 0
    receipt["tool_calls"].append({**receipt["tool_calls"][0], "domain_denial": False})
    assert not verify_tool_evidence(receipt, tools, ledger, catalog)[0]


def test_teardown_calls_do_not_qualify_cited_behavior(proof):
    tools, receipt, ledger, catalog = proof
    for event in receipt["tool_calls"]:
        event["phase"] = "teardown"
    assert verify_tool_evidence(receipt, tools, ledger, catalog)[0]


def test_only_identity_registered_observers_preserve_handler_fingerprint(proof):
    tools, _, _, _ = proof
    original = tools[0]

    @wraps(original.handler)
    def observed(arguments):
        return original.handler(arguments)

    wrapped = replace(original, handler=observed)
    assert definition_digest(wrapped) != definition_digest(original)
    register_observer(observed, original.handler)
    assert definition_digest(wrapped) == definition_digest(original)


def test_generated_builtin_and_unhashable_callable_have_stable_definition_identity():
    namespace = {}
    exec(compile("def generated(args): return args", "<generated>", "exec"), namespace)
    generated = ToolSpec("generated", "probe", {}, namespace["generated"])
    assert definition_digest(generated) == definition_digest(generated)
    builtin = ToolSpec("builtin", "probe", {}, str)
    assert definition_digest(builtin) == definition_digest(builtin)

    class Unhashable:
        __hash__ = None

        def __call__(self, arguments):
            return arguments

    custom = ToolSpec("callable", "probe", {}, Unhashable())
    assert definition_digest(custom) == definition_digest(custom)
