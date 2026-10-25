"""Real remote proof, signed receipt and core audit persistence."""

import json
import sqlite3
from dataclasses import replace

import pytest
from genesis_mesh.crypto import verify_signature
from genesis_mesh.na_service.db import NADatabase
from test_multi_workflows import pair as pair

from genesismesh_mcp.proof_workflows import CANARY, canary
from genesismesh_mcp.types import ToolError


@pytest.fixture
def canary_store(pair, tmp_path):
    settings, credentials = pair
    _, paths = credentials["alpha"]
    configured = replace(settings, profiles=settings.profiles | {"maintain", "sign"},
                         authorities={name: replace(config, allowed_tools=config.allowed_tools | {CANARY})
                                      for name, config in settings.authorities.items()},
                         signer_files={"receipt": paths["subject"]}, signer_permissions={"receipt": {CANARY}},
                         proof_stores={"canary": {"db_path": tmp_path / "owned/audit.db", "owned": True,
                                                  "backup_dir": tmp_path / "backups",
                                                  "receipt_dir": tmp_path / "receipts", "receipt_signer": "receipt",
                                                  "allowed_tools": [CANARY]}})
    return configured, credentials


def test_canary_signs_persists_and_audits_actual_remote_proof(canary_store):
    settings, credentials = canary_store
    args = {"store": "canary", "acceptor": "alpha", "issuer": "beta", "operation_id": "canary-one"}
    result = canary(settings, args)
    assert result["status"] == "completed", result
    receipt = result["receipt"]
    assert receipt["payload"]["pre_revocation"]["accepted"] is True
    assert receipt["payload"]["post_revocation"]["accepted"] is False
    canonical = json.dumps(receipt["payload"], sort_keys=True, separators=(",", ":")).encode()
    assert verify_signature(canonical, receipt["signature"]["value"], credentials["alpha"][0]["subject"].public_key_b64)
    config = settings.proof_stores["canary"]
    assert json.loads((config.receipt_dir / result["receipt_file"]).read_text()) == receipt
    with sqlite3.connect(config.db_path) as connection:
        row = connection.execute("SELECT event_json FROM audit_events").fetchall()
        assert len(row) == 1
        assert json.loads(row[0][0])["event_type"] == "trust_cycle_canary_completed"
    assert canary(settings, args) == result


def test_canary_audit_lost_reply_retains_receipt_and_never_repeats_event(canary_store, monkeypatch):
    settings, _ = canary_store
    args = {"store": "canary", "acceptor": "alpha", "issuer": "beta", "operation_id": "canary-one"}
    original = NADatabase.add_audit_event
    def lost_reply(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        if self.db_path == str(settings.proof_stores["canary"].db_path):
            raise TimeoutError()
        return result
    monkeypatch.setattr(NADatabase, "add_audit_event", lost_reply)
    first = canary(settings, args)
    assert first["status"] == "partial", first
    assert first["steps"]["steps"]["audit_record"]["status"] == "unknown"
    second = canary(settings, args)
    assert second["error"] == "outcome_unknown", second
    config = settings.proof_stores["canary"]
    assert len(list(config.receipt_dir.glob("*.json"))) == 1
    with sqlite3.connect(config.db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone() == (1,)


def test_canary_refuses_missing_purpose_permission_before_mutating(canary_store):
    settings, _ = canary_store
    settings = replace(settings, signer_permissions={"receipt": set()})
    with pytest.raises(ToolError, match="not authorized"):
        canary(settings, {"store": "canary", "acceptor": "alpha", "issuer": "beta", "operation_id": "one"})
    assert not settings.proof_stores["canary"].db_path.exists()
