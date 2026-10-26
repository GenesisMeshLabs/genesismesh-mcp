"""Corrupt declarations and unavailable provenance must fail compatibility checks."""

from __future__ import annotations

import copy
import subprocess
from importlib import metadata
from types import SimpleNamespace

import pytest

from genesismesh_mcp import catalog
from genesismesh_mcp.types import ToolSpec

TARGET = "python:genesis_mesh.trust.attestation:verify_membership_attestation"


@pytest.mark.parametrize("text", ['{"duplicate":1,"duplicate":2}', '{"number":NaN}', '[]', '{'])
def test_packaged_metadata_rejects_duplicates_nonfinite_and_nonobject_json(monkeypatch, text):
    monkeypatch.setattr(catalog, "_data_text", lambda name: text)
    with pytest.raises(ValueError):
        catalog.load_contract()


def test_duplicate_or_incomplete_contract_is_refused():
    source = catalog.load_contract()
    source["http_routes"].append(copy.deepcopy(source["http_routes"][0]))
    with pytest.raises(catalog.CatalogError, match="Duplicate contract item"):
        catalog.contract_items(source)
    del source["http_routes"]
    assert catalog.compare_contract(source)[0].startswith("Invalid public contract")


@pytest.mark.parametrize("field,value,message", [
    ("intended_surface", "unsupported", "Invalid intended surface"),
    ("reason", "", "Missing coverage rationale"),
    ("verification_status", "untested-claim", "Invalid verification status"),
    ("section", "incorrect", "Incorrect source section"),
    ("stability", "incorrect", "Incorrect stability classification"),
])
def test_coverage_declarations_cannot_change_classification_silently(field, value, message):
    coverage = catalog.load_coverage()
    coverage["rows"][0][field] = value
    assert any(message in p for p in catalog.validate_catalog([], coverage=coverage))


def test_unknown_mappings_handlers_names_targets_and_resources_are_refused():
    coverage = catalog.load_coverage()
    extra = copy.deepcopy(coverage["rows"][0])
    extra["id"] = "unknown:capability"
    coverage["rows"].append(extra)
    invalid = ToolSpec("invalid name", "probe", {"type": "object"}, None, core_targets=(TARGET, TARGET))
    problems = catalog.validate_catalog([invalid], coverage=coverage, resources={None: ("unknown:target",)})
    for text in ("Unknown coverage mapping", "Invalid tool name", "lacks a handler", "Duplicate target",
                 "Invalid registered resource URI", "Resource references unknown source target"):
        assert any(text in p for p in problems)


def test_snapshot_verification_checks_digest_catalog_pin_and_format(monkeypatch):
    pin = catalog.load_compatibility()
    monkeypatch.setattr(catalog, "load_compatibility", lambda: {**pin, "contract_sha256": "bad", "contract_version": -1})
    problems = catalog.verify_packaged_snapshot()
    assert len(problems) == 3
    assert any("format version" in p for p in problems)


@pytest.fixture
def core_snapshot(tmp_path):
    pin = catalog.load_compatibility()
    (tmp_path / "VERSION").write_text(pin["core_version"], encoding="utf-8")
    path = tmp_path / pin["contract_path"]
    path.parent.mkdir(parents=True)
    path.write_text(catalog._data_text("public-surface.json"), encoding="utf-8")
    return tmp_path, pin


def test_unreadable_core_source_is_refused(tmp_path):
    assert catalog.verify_core_source(tmp_path)[0].startswith("Cannot read explicit core checkout")


@pytest.mark.parametrize("failure,message", [
    ("revision_unavailable", "Cannot establish core Git revision"),
    ("revision_timeout", "Cannot establish core Git revision"),
    ("wrong_revision", "Core Git revision differs"),
    ("revision_error", "Core Git revision differs"),
    ("status_unavailable", "Cannot establish whether"),
    ("status_timeout", "Cannot establish whether"),
    ("dirty", "tracked changes"),
    ("status_error", "tracked changes"),
    ("clean", None),
])
def test_revision_and_cleanliness_require_positive_git_evidence(monkeypatch, core_snapshot, failure, message):
    root, pin = core_snapshot

    def git(arguments, **kwargs):
        status = "status" in arguments
        if failure == ("status_unavailable" if status else "revision_unavailable"):
            raise OSError("Git unavailable")
        if failure == ("status_timeout" if status else "revision_timeout"):
            raise subprocess.TimeoutExpired(arguments, 10)
        if status:
            return SimpleNamespace(returncode=1 if failure == "status_error" else 0,
                                   stdout=" M core.py" if failure == "dirty" else "")
        return SimpleNamespace(returncode=1 if failure == "revision_error" else 0,
                               stdout="other" if failure == "wrong_revision" else pin["core_commit"])

    monkeypatch.setattr(catalog.subprocess, "run", git)
    problems = catalog.verify_core_source(root)
    assert bool(problems) == (message is not None)
    if message:
        assert any(message in p for p in problems)


def test_missing_or_wrong_installed_core_is_reported(monkeypatch):
    def missing(package):
        raise metadata.PackageNotFoundError(package)

    monkeypatch.setattr(catalog.metadata, "version", missing)
    assert catalog.verify_installed_core() == ["The pinned genesis-mesh package is not installed"]
    monkeypatch.setattr(catalog.metadata, "version", lambda package: "0.0.0")
    assert any("Installed core version differs" in p for p in catalog.verify_installed_core())


def test_installed_signature_checks_constants_class_constructors_and_variadics(monkeypatch):
    class Constructor:
        def __init__(self, required, *values, optional=1, **extra):
            pass

    module = SimpleNamespace(Value=3, Constructor=Constructor)
    signature = [{"name": "required", "kind": "positional_or_keyword", "required": True},
                 {"name": "values", "kind": "var_positional", "required": False},
                 {"name": "optional", "kind": "keyword_only", "required": False},
                 {"name": "extra", "kind": "var_keyword", "required": False}]
    rows = [{"symbol": "sample:Value", "parameters": None}, {"symbol": "sample:Constructor", "parameters": signature}]
    monkeypatch.setattr(catalog, "load_contract", lambda: {"python": rows})
    monkeypatch.setattr(catalog, "importlib", SimpleNamespace(import_module=lambda name: module))
    assert catalog.verify_installed_core(signatures=True) == []
    rows[1]["parameters"] = []
    assert any("signature changed" in p for p in catalog.verify_installed_core(signatures=True))
    rows[1]["symbol"] = "sample:Missing"
    assert any("cannot be resolved" in p for p in catalog.verify_installed_core(signatures=True))
