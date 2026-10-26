"""Checkout verification of reviewed tool scenarios and observed handler execution."""

from __future__ import annotations

import hashlib
import json
import weakref
from importlib.resources import files
from pathlib import Path

from .coverage_union import canonical_source
from .test_evidence import file_digest, matching_cases, valid_reference

_OBSERVERS = weakref.WeakKeyDictionary()


def register_observer(wrapper, original, source_files=None) -> None:
    """Register only pytest's own wrapper by object identity, never by copied attributes."""
    _OBSERVERS[wrapper] = (original, source_files)


def load_tool_evidence() -> dict:
    return json.loads(files("genesismesh_mcp").joinpath("data/tool-evidence.json").read_text("utf-8"))


def definition_digest(tool, source_files=None) -> str:
    handler = tool.handler
    while True:
        try:
            observed = _OBSERVERS.get(handler)
        except TypeError:
            observed = None
        if observed is None:
            break
        handler, observed_sources = observed
        if source_files is None:
            source_files = observed_sources
    code = getattr(handler, "__code__", None)
    origin = None
    if code is not None:
        try:
            filename = canonical_source(code.co_filename)
        except ValueError:
            filename = "external:" + Path(code.co_filename).name
        source = Path(code.co_filename)
        if source_files is not None and filename in source_files:
            source_sha = source_files[filename]
        else:
            source_sha = file_digest(source) if source.is_file() else None
        origin = {"file": filename, "line": code.co_firstlineno,
                  "source_sha256": source_sha}
    definition = {"name": tool.name, "schema": tool.input_schema, "profiles": sorted(tool.profiles),
                  "targets": list(tool.core_targets),
                  "handler_module": getattr(handler, "__module__", type(handler).__module__),
                  "handler_name": getattr(handler, "__qualname__", type(handler).__qualname__), "origin": origin}
    return hashlib.sha256(json.dumps(definition, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def verify_tool_evidence(receipt: dict, tools, ledger: dict, catalog: dict) -> tuple[list[str], dict]:
    """Link reviewed positive/refusal citations to real calls; assertions still need review."""
    problems = []
    imported = receipt.get("adapter_end", {})
    source_files = imported.get("files") if isinstance(imported, dict) else None
    expected_definitions = {tool.name: definition_digest(tool, source_files) for tool in tools}
    expected = set(expected_definitions)
    if ledger.get("format_version") != 1 or not isinstance(ledger.get("tools"), dict):
        return ["Invalid tool evidence ledger"], {"valid": False}
    rows = ledger["tools"]
    for name in expected - rows.keys():
        problems.append(f"Registered tool has no reviewed behavioral scenarios: {name}")
    for name in rows.keys() - expected:
        problems.append(f"Tool evidence names an unregistered tool: {name}")
    collected, outcomes = receipt.get("collected", []), receipt.get("outcomes", {})
    events = receipt.get("tool_calls")
    if not isinstance(events, list):
        problems.append("Execution receipt has no observed tool calls")
        events = []
    calls, ignored_definition_calls = set(), 0
    for event in events:
        if (not isinstance(event, dict) or not isinstance(event.get("test"), str)
                or not isinstance(event.get("tool"), str) or type(event.get("schema_valid")) is not bool
                or not isinstance(event.get("outcome"), str) or type(event.get("count")) is not int
                or not isinstance(event.get("definition"), str)
                or event.get("phase") not in {"setup", "call", "teardown"}
                or type(event.get("domain_denial")) is not bool
                or event["count"] < 1 or event["test"] not in collected):
            problems.append("Execution receipt contains an invalid tool-call observation")
            continue
        if type(event.get("transport_mocked")) is not bool:
            problems.append("Tool-call observation must identify mocked HTTP transport")
            continue
        if event["tool"] in expected and event["definition"] != expected_definitions[event["tool"]]:
            # Fault-injection tests may deliberately construct a substituted
            # handler. Those observations establish no registered-tool claim.
            ignored_definition_calls += event["count"]
            continue
        if event["phase"] != "teardown":
            calls.add((event["test"], event["tool"], event["schema_valid"], event["outcome"],
                       event["transport_mocked"], event["domain_denial"]))
    qualified = set()
    for name, row in rows.items():
        if not isinstance(row, dict) or not isinstance(row.get("scope"), str) or not row["scope"].strip():
            problems.append(f"Tool scenario scope is missing: {name}")
            continue
        for kind in ("positive", "negative"):
            refs = row.get(kind)
            if not isinstance(refs, list) or not refs:
                problems.append(f"Tool lacks reviewed {kind} scenarios: {name}")
                continue
            for ref in refs:
                if not valid_reference(ref):
                    problems.append(f"Invalid {kind} scenario citation for {name}: {ref!r}")
                    continue
                cases = matching_cases(ref, collected)
                if not cases or any(outcomes.get(case) != "passed" for case in cases):
                    problems.append(f"Tool {kind} scenario was not collected and passing: {name}: {ref}")
                    continue
                observed = [call for call in calls if call[0] in cases and call[1] == name]
                qualifies = (any(c[2] and c[3] == "returned" and not c[4] and not c[5] for c in observed) if kind == "positive"
                             else any(not c[2] or c[3] != "returned" or c[5] for c in observed))
                if not qualifies:
                    problems.append(f"Tool {kind} scenario did not invoke the registered handler as claimed: {name}: {ref}")
                elif kind == "positive":
                    qualified.add(name)
    unexercised = [row["id"] for row in catalog["rows"] if row["implementation_status"] == "implemented"
                   and row["verification_status"] == "not_exercised"]
    problems.extend(f"Implemented capability lacks behavior evidence: {identifier}" for identifier in unexercised)
    return sorted(set(problems)), {"valid": not problems, "registered_tools": len(expected),
                                  "qualified_tools": len(qualified & expected), "observed_calls": len(calls),
                                  "ignored_definition_calls": ignored_definition_calls,
                                  "unexercised_implemented": len(unexercised),
                                  "meaning": "Reviewed scenarios passed and invoked handlers; generic dispatch mocks do not qualify domain claims."}
