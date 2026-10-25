"""Coverage accounting must fail on drift without overstating implementation."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from genesismesh_mcp.catalog import (
    CatalogError,
    build_catalog,
    compare_contract,
    contract_digest,
    contract_items,
    load_compatibility,
    load_contract,
    load_coverage,
    validate_catalog,
    verify_core_source,
    verify_installed_core,
    verify_packaged_snapshot,
)
from genesismesh_mcp.types import ToolSpec

TARGET = "python:genesis_mesh.trust.attestation:verify_membership_attestation"


def tool(*targets: str, name: str = "verify_membership", profiles: frozenset[str] = frozenset({"verify"})) -> ToolSpec:
    return ToolSpec(name, "Test fixture registration", {"type": "object"}, lambda value: value,
                    profiles=profiles, core_targets=targets)


def row(catalog: dict, identifier: str) -> dict:
    return next(item for item in catalog["rows"] if item["id"] == identifier)


def test_snapshot_accounts_for_every_source_section_and_method() -> None:
    items = contract_items()
    assert len(items) == 782
    assert sum(item["section"] == "http_routes" for item in items.values()) == 130
    assert len(load_coverage()["rows"]) == len(items)
    assert validate_catalog([]) == []
    assert verify_packaged_snapshot() == []
    assert verify_installed_core(signatures=True) == []


def test_contract_documentation_never_counts_as_executable_coverage() -> None:
    catalog = build_catalog([], resources={"genesismesh://contract": contract_items()})
    item = row(catalog, TARGET)
    assert item["implementation_status"] == "gap"
    assert item["availability"] == "documentation_only"
    assert item["registered"] is False
    assert catalog["summary"]["accounted"] == catalog["summary"]["total"]


def test_registered_tool_is_not_implicitly_behavior_tested(monkeypatch) -> None:
    # Use an explicitly uncited declaration so this invariant is independent of
    # the real adapter gaining reviewed behavioral evidence over time.
    coverage = copy.deepcopy(load_coverage())
    declaration = next(item for item in coverage["rows"] if item["id"] == TARGET)
    declaration["verification_status"], declaration["tests"] = "not_exercised", []
    monkeypatch.setattr("genesismesh_mcp.catalog.load_coverage", lambda: coverage)
    catalog = build_catalog([tool(TARGET)], profiles={"read"})
    item = row(catalog, TARGET)
    assert item["implementation_status"] == "implemented"
    assert item["verification_status"] == "not_exercised"
    assert item["availability"] == "profile_disabled"
    assert item["tools"] == ["verify_membership"]
    enabled = row(build_catalog([tool(TARGET)], profiles={"verify"}), TARGET)
    assert enabled["availability"] == "enabled"


def test_model_resource_is_schema_coverage_not_execution_or_authentication() -> None:
    target = "artifact:genesis_mesh.models.agreement:AgreementRecord"
    catalog = build_catalog([], resources={"genesismesh://schemas/agreement": (target,)})
    item = row(catalog, target)
    assert item["implementation_status"] == "schema"
    assert item["verification_status"] == "not_exercised"
    assert item["tools"] == []


def test_available_workflow_components_do_not_claim_completed_orchestration() -> None:
    catalog = build_catalog([
        tool("http:GET /recognition-treaties/<treaty_id>", name="read_treaty"),
        tool("http:POST /admin/recognition-treaties", name="issue_treaty"),
        tool("http:POST /admin/recognition-treaties/<treaty_id>/revoke", name="revoke_treaty"),
    ])
    item = row(catalog, "cli:treaty renew")
    assert item["implementation_status"] == "components_available"
    assert item["registered"] is False
    assert item["tools"] == []
    assert len(item["component_tools"]) == 3


def test_internal_helper_support_is_distinct_from_a_generic_signing_tool() -> None:
    catalog = build_catalog([tool("python:genesis_mesh.trust.context:sign_boundary_policy")])
    item = row(catalog, "python:genesis_mesh.crypto:sign_model")
    assert item["implementation_status"] == "support"
    assert item["directly_registered"] is False
    assert item["coverage_scope"] == "internal_helper"


def test_unknown_or_duplicate_runtime_registrations_are_rejected() -> None:
    problems = validate_catalog([tool("python:unlisted:execute"), tool(TARGET)])
    assert any("Duplicate registered tool" in item for item in problems)
    assert any("unknown source target" in item for item in problems)
    with pytest.raises(CatalogError, match="unknown source target"):
        build_catalog([tool("python:unlisted:execute")])


def test_missing_or_duplicate_source_accounting_is_rejected() -> None:
    coverage = load_coverage()
    removed = coverage["rows"].pop()
    coverage["rows"].append(copy.deepcopy(coverage["rows"][0]))
    problems = validate_catalog([], coverage=coverage)
    assert f"Missing coverage mapping: {removed['id']}" in problems
    assert any("Duplicate coverage mapping" in item for item in problems)


def test_alias_targets_must_exist_and_cannot_form_cycles() -> None:
    coverage = load_coverage()
    first, second = coverage["rows"][:2]
    first["covered_by"] = [second["id"]]
    second["covered_by"] = [first["id"], "cli:not a real command"]
    problems = validate_catalog([], coverage=coverage)
    assert any("Unknown alias target" in item for item in problems)
    assert any("Cyclic coverage alias" in item for item in problems)


def test_unsubstantiated_test_claims_fail_integrity_check() -> None:
    coverage = load_coverage()
    coverage["rows"][0]["verification_status"] = "integration_tested"
    coverage["rows"][0]["tests"] = []
    assert any("without test references" in item for item in validate_catalog([], coverage=coverage))


@pytest.mark.parametrize("mutation, message", [
    ("addition", "Unclassified source item"),
    ("removal", "Source item removed"),
    ("signature", "Source declaration changed"),
    ("stability", "Source declaration changed"),
    ("rule", "Source declaration changed"),
    ("format", "Contract metadata changed"),
])
def test_source_drift_is_detected(mutation: str, message: str) -> None:
    contract = load_contract()
    if mutation == "addition":
        contract["cli_commands"].append({"command": "new workflow", "level": "beta"})
    elif mutation == "removal":
        contract["http_routes"].pop()
    elif mutation == "signature":
        contract["python"][0]["parameters"].append({"name": "new", "kind": "keyword_only", "required": True})
    elif mutation == "stability":
        contract["signed_artifacts"][0]["level"] = "internal"
    elif mutation == "rule":
        contract["rules"]["grant_fallback"] = "Changed rule"
    else:
        contract["contract_version"] += 1
    assert any(message in item for item in compare_contract(contract))


def test_digest_is_portable_between_lf_and_crlf_checkouts() -> None:
    assert contract_digest('{\n  "a": 1\n}\n') == contract_digest('{\r\n  "a": 1\r\n}\r\n')


def test_explicit_core_check_reads_source_instead_of_a_sibling_repo(tmp_path: Path) -> None:
    (tmp_path / "contract").mkdir()
    (tmp_path / "VERSION").write_text("0.0.0\n", encoding="utf-8")
    contract = load_contract()
    contract["cli_commands"].append({"command": "unreviewed operation", "level": "beta"})
    (tmp_path / "contract" / "public-surface.json").write_text(json.dumps(contract), encoding="utf-8")
    problems = verify_core_source(tmp_path, check_revision=False)
    assert any("Core version differs" in item for item in problems)
    assert any("Unclassified source item: cli:unreviewed operation" == item for item in problems)
    assert any("pinned digest" in item for item in problems)


def test_pin_identifies_exact_release_and_revision() -> None:
    compatibility = load_compatibility()
    assert compatibility["core_version"] == "1.8.1"
    assert compatibility["core_commit"] == "9e4d5c01e6ba7a22e73c17388796ec274f73a2fc"
    assert len(compatibility["contract_sha256"]) == 64
