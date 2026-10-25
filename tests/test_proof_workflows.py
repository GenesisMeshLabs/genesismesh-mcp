"""Proof-store maintenance must back up exact scoped rows before deleting them."""

import sqlite3
from dataclasses import replace

import pytest

from genesismesh_mcp.proof_workflows import CLEANUP, PREVIEW, TABLES, cleanup, cleanup_preview
from genesismesh_mcp.settings import Settings
from genesismesh_mcp.types import ToolError


@pytest.fixture
def proof_store(tmp_path):
    path = tmp_path / "proof.db"
    connection = sqlite3.connect(path)
    for table in TABLES:
        connection.execute(f"CREATE TABLE {table} (id INTEGER PRIMARY KEY, value TEXT)")
        connection.execute(f"INSERT INTO {table} VALUES (1,'proof')")
        connection.execute(f"INSERT INTO {table} VALUES (2,'ordinary trust record')")
    connection.execute("CREATE TABLE audit_events (id INTEGER)")
    connection.execute("INSERT INTO audit_events VALUES (1)")
    connection.commit()
    connection.close()
    settings = Settings(profiles={"local", "write", "read", "maintain"}, workflow_state_dir=tmp_path / "state",
                        proof_stores={"lab": {"db_path": path, "backup_dir": tmp_path / "backups",
                                              "receipt_dir": tmp_path / "receipts", "receipt_signer": "canary",
                                              "owned": True, "disposable": True,
                                              "allowed_tools": [CLEANUP, PREVIEW]}})
    return settings, path


def test_cleanup_backups_exact_entire_tables_and_preserves_other_data(proof_store):
    settings, path = proof_store
    preview = cleanup_preview(settings, {"store": "lab"})
    assert set(preview["tables"].values()) == {2}
    args = {"store": "lab", "operation_id": "cleanup", "preview_digest": preview["scope_digest"]}
    result = cleanup(settings, args)
    assert result["status"] == "completed", result
    assert result["backup_verified"]
    with sqlite3.connect(path) as connection:
        assert all(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone() == (0,) for table in TABLES)
        assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone() == (1,)
    with sqlite3.connect(settings.proof_stores["lab"].backup_dir / result["backup"]) as connection:
        assert all(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone() == (2,) for table in TABLES)
    assert cleanup(settings, args) == result


def test_cleanup_refuses_stale_scope_and_non_disposable_store(proof_store):
    settings, path = proof_store
    preview = cleanup_preview(settings, {"store": "lab"})
    with sqlite3.connect(path) as connection:
        connection.execute(f"UPDATE {TABLES[0]} SET value='changed' WHERE id=1")
    result = cleanup(settings, {"store": "lab", "operation_id": "cleanup", "preview_digest": preview["scope_digest"]})
    assert result["status"] == "partial" and result["error"] == "cleanup_preview_changed"
    with sqlite3.connect(path) as connection:
        assert connection.execute(f"SELECT COUNT(*) FROM {TABLES[0]}").fetchone() == (2,)
    safe = replace(settings, proof_stores={"lab": replace(settings.proof_stores["lab"], disposable=False)})
    with pytest.raises(ToolError, match="disposable"):
        cleanup_preview(safe, {"store": "lab"})


def test_failed_backup_never_deletes_rows(proof_store, monkeypatch):
    settings, path = proof_store
    preview = cleanup_preview(settings, {"store": "lab"})
    import genesismesh_mcp.proof_workflows as workflows
    original = workflows._scope
    calls = 0
    def mismatch(connection):
        nonlocal calls
        calls += 1
        result = original(connection)
        if calls == 2:
            result["scope_digest"] = "wrong"
        return result
    monkeypatch.setattr(workflows, "_scope", mismatch)
    result = cleanup(settings, {"store": "lab", "operation_id": "cleanup", "preview_digest": preview["scope_digest"]})
    assert result["error"] == "backup_mismatch"
    with sqlite3.connect(path) as connection:
        assert connection.execute(f"SELECT COUNT(*) FROM {TABLES[0]}").fetchone() == (2,)
