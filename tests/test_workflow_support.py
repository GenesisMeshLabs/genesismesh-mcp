"""Journal replay, ambiguity and configured dependency boundaries."""

import json
from dataclasses import replace

import pytest

from genesismesh_mcp.settings import Settings
from genesismesh_mcp.types import ToolError
from genesismesh_mcp.workflow_support import WorkflowJournal, select_authority


def test_journal_replays_completed_steps_and_refuses_conflicting_inputs(tmp_path):
    settings = Settings(profiles={"local"}, workflow_state_dir=tmp_path / "state")
    calls = []
    with WorkflowJournal(settings, "test", "one", {"input": 1}) as journal:
        assert journal.step("issue", lambda: calls.append(1) or {"treaty_id": "issued"}, mutation=True)
    with WorkflowJournal(settings, "test", "one", {"input": 1}) as journal:
        assert journal.step("issue", lambda: calls.append(2), mutation=True) == {"treaty_id": "issued"}
        journal.finish({"status": "completed"})
    assert calls == [1]
    with WorkflowJournal(settings, "test", "one", {"input": 1}) as journal:
        assert journal.completed_result == {"status": "completed"}
    with pytest.raises(ToolError, match="different inputs"):
        with WorkflowJournal(settings, "test", "one", {"input": 2}):
            pass
    with pytest.raises(ToolError, match="different inputs"):
        with WorkflowJournal(replace(settings, timeout_seconds=16), "test", "one", {"input": 1}):
            pass


def test_journal_prevents_concurrent_execution_and_uncertain_replay(tmp_path):
    settings = Settings(profiles={"local"}, workflow_state_dir=tmp_path / "state")
    calls = []
    with WorkflowJournal(settings, "test", "one", {}) as journal:
        with pytest.raises(ToolError, match="already running"):
            with WorkflowJournal(settings, "test", "one", {}):
                pass
        def lose_reply():
            calls.append(1)
            raise TimeoutError()
        with pytest.raises(TimeoutError):
            journal.step("issue", lose_reply, mutation=True)
    with WorkflowJournal(settings, "test", "one", {}) as journal:
        with pytest.raises(ToolError, match="uncertain"):
            journal.step("issue", lambda: calls.append(2), mutation=True)
        assert journal.summary()["steps"]["issue"]["status"] == "unknown"
    assert calls == [1]


def test_journal_keeps_inputs_private_and_summary_bounded(tmp_path):
    settings = Settings(profiles={"local"}, workflow_state_dir=tmp_path / "state")
    with WorkflowJournal(settings, "test", "one", {"token": "sensitive-input"}) as journal:
        journal.step("pack", lambda: {"files": {"entries": "x" * 500_000}, "manifest": {"pack_id": "pack"}})
        assert len(json.dumps(journal.summary())) < 1000
        assert journal.summary()["steps"]["pack"]["result_identifiers"]["manifest.pack_id"] == "pack"
    assert "sensitive-input" not in (tmp_path / "state/test--one.json").read_text()


def test_named_authorities_and_relative_config(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"authorities": {"one": {"url": "https://one.example", "public_key": "pin",
                                "operator_key_file": "op.key", "operator_key_id": "operator", "allowed_tools": ["tool"]}},
                               "fleets": {"pair": ["one"]}, "artifact_roots": {"audit": "artifacts"},
                               "workflow_state_dir": "state"}))
    settings = Settings.from_file(path)
    selected = select_authority(settings, "one", "tool")
    assert selected.operator_key_file == tmp_path / "op.key"
    assert selected.authority_url == "https://one.example"
    with pytest.raises(ToolError):
        select_authority(settings, "one", "other")
    with pytest.raises(ValueError, match="outside"):
        replace(settings, workspace=tmp_path)
    with pytest.raises(ValueError):
        replace(settings, fleets={"wrong": ["absent"]})


def test_private_storage_cannot_contain_workspace_or_overlap_artifacts(tmp_path):
    with pytest.raises(ValueError, match="outside"):
        Settings(workflow_state_dir=tmp_path / "private", workspace=tmp_path / "private/readable")
    with pytest.raises(ValueError, match="overlap"):
        Settings(workflow_state_dir=tmp_path / "private", artifact_roots={"audit": tmp_path / "private/audit"})


def test_key_rotation_in_place_refuses_old_operation_replay(tmp_path):
    key = tmp_path / "key"
    key.write_text("old-identity")
    settings = Settings(profiles={"local"}, workflow_state_dir=tmp_path / "state", signer_files={"signer": key})
    with WorkflowJournal(settings, "test", "one", {}) as journal:
        journal.step("effect", lambda: {"treaty_id": "created"}, mutation=True)
    key.write_text("new-identity")
    with pytest.raises(ToolError, match="different inputs"):
        with WorkflowJournal(settings, "test", "one", {}):
            pass
