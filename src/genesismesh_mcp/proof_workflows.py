"""Purpose-bound canary receipts and explicitly disposable proof-store maintenance."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path
from time import monotonic

from genesis_mesh.crypto import sign_data, verify_signature
from genesis_mesh.na_service.db import NADatabase, expected_schema_version
from genesis_mesh.workflows.proof import inspect_proof_bundle

from .settings import Settings
from .types import ToolError, ToolSpec
from .workflow_support import WorkflowJournal, atomic_json, private_directory, resource_lock

TABLES = ("imported_sovereign_revocations", "sovereign_revocation_feeds",
          "recognition_treaties", "membership_attestations")
CANARY = "gm_workflow_proof_canary"
CLEANUP = "gm_workflow_proof_cleanup"
PREVIEW = "gm_workflow_proof_cleanup_preview"


def _store(settings, alias, tool, *, disposable=False):
    config = settings.proof_stores.get(alias)
    if config is None or not config.owned:
        raise ToolError("proof_store_not_owned", "Configure an explicitly owned proof store.")
    if tool not in config.allowed_tools:
        raise ToolError("proof_store_not_authorized", "This proof store is not enabled for the requested operation.")
    if disposable and not config.disposable:
        raise ToolError("disposable_store_required", "Cleanup requires an explicitly disposable proof database.")
    if config.db_path.is_symlink():
        raise ToolError("unsafe_storage", "The proof database must not be a symbolic link.")
    return config


def _connect(path: Path, *, read_only=False):
    if not path.is_file():
        raise ToolError("proof_database_missing", "The configured proof database does not exist.")
    total = sum(p.stat().st_size for p in (path, Path(str(path) + "-wal")) if p.exists())
    if total > 67_108_864:
        raise ToolError("proof_database_too_large", "Proof maintenance is limited to 64 MiB databases.")
    return sqlite3.connect(path.as_uri() + ("?mode=ro" if read_only else "?mode=rw"), uri=True, timeout=2)


def _scope(connection):
    digest = hashlib.sha256()
    counts = {}
    for table in TABLES:
        exists = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
        digest.update(table.encode())
        if not exists:
            counts[table] = 0
            digest.update(b"absent")
            continue
        counts[table] = connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        if counts[table] > 50_000:
            raise ToolError("proof_scope_too_large", "Proof cleanup is limited to 50000 rows per table.")
        for row in connection.execute(f"SELECT * FROM {table} ORDER BY rowid"):
            digest.update(json.dumps(tuple(row), separators=(",", ":"),
                                     default=lambda value: {"bytes": value.hex()}).encode())
            digest.update(b"\n")
    return {"tables": counts, "scope_digest": digest.hexdigest(),
            "scope": "ALL rows in these four tables; not only records labeled as proofs"}


def cleanup_preview(settings, args):
    settings.require(frozenset({"local", "read", "maintain"}))
    config = _store(settings, args["store"], PREVIEW, disposable=True)
    with resource_lock(settings, "proof_store", args["store"]):
        connection = _connect(config.db_path, read_only=True)
        try:
            connection.execute("BEGIN")
            return {"store": args["store"], **_scope(connection)}
        finally:
            connection.close()


def _backup_and_cleanup(settings, config, operation_id, expected):
    connection = _connect(config.db_path)
    deadline = monotonic() + settings.timeout_seconds
    try:
        connection.execute("BEGIN IMMEDIATE")
        scope = _scope(connection)
        if scope["scope_digest"] != expected:
            raise ToolError("cleanup_preview_changed", "The database changed since the cleanup preview; review it again.")
        if not config.backup_dir.exists():
            private_directory(config.backup_dir)
        name = "before-cleanup-" + hashlib.sha256(operation_id.encode()).hexdigest()[:32] + ".sqlite3"
        backup = config.backup_dir / name
        descriptor = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        source = _connect(config.db_path, read_only=True)
        destination = sqlite3.connect(backup)
        try:
            def progress(*_):
                if monotonic() > deadline:
                    raise ToolError("backup_deadline", "The backup exceeded its time budget; no rows were deleted.")
            source.backup(destination, pages=128, progress=progress)
            if destination.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise ToolError("backup_invalid", "The proof database backup failed its integrity check.")
            if _scope(destination)["scope_digest"] != scope["scope_digest"]:
                raise ToolError("backup_mismatch", "The proof database backup does not match the selected rows.")
        finally:
            source.close()
            destination.close()
        with backup.open("r+b") as stream:
            os.fsync(stream.fileno())
        backup_digest = hashlib.sha256(backup.read_bytes()).hexdigest()
        for table, count in scope["tables"].items():
            if count:
                connection.execute(f"DELETE FROM {table}")
        connection.commit()
        return {"deleted_rows": scope["tables"], "scope": scope["scope"], "backup": name,
                "backup_sha256": backup_digest, "backup_verified": True}
    finally:
        connection.close()


def cleanup(settings, args):
    settings.require(frozenset({"local", "write", "maintain"}))
    config = _store(settings, args["store"], CLEANUP, disposable=True)
    with resource_lock(settings, "proof_store", args["store"]):
        with WorkflowJournal(settings, CLEANUP, args["operation_id"], args) as journal:
            if journal.completed_result is not None:
                return journal.completed_result
            try:
                result = journal.step("verified_backup_and_delete", lambda: _backup_and_cleanup(
                    settings, config, args["operation_id"], args["preview_digest"]), mutation=True)
                return journal.finish({"status": "completed", "operation_id": args["operation_id"],
                                       "store": args["store"], **result})
            except Exception as error:
                return {"status": "partial", "operation_id": args["operation_id"], "steps": journal.summary(),
                        "error": error.code if isinstance(error, ToolError) else "proof_cleanup_failed"}


def _prepare_database(config):
    exists = config.db_path.exists()
    if exists:
        connection = _connect(config.db_path, read_only=True)
        try:
            version = connection.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
            if version != expected_schema_version():
                raise ToolError("proof_schema_mismatch", "The owned audit store requires the pinned core schema; no automatic upgrade is performed.")
        finally:
            connection.close()
    elif not config.db_path.parent.exists():
        private_directory(config.db_path.parent)
    database = NADatabase(str(config.db_path))
    try:
        if not exists:
            database.migrate()
    finally:
        database.close()
    return {"ready": True, "initialized": not exists}


def canary(settings, args):
    settings.require(frozenset({"read", "verify", "operator", "write", "local", "maintain", "sign"}))
    config = _store(settings, args["store"], CANARY)
    key = settings.load_signer(config.receipt_signer, CANARY)
    from .multi_workflows import run_proof

    with resource_lock(settings, "proof_store", args["store"]):
        with WorkflowJournal(settings, CANARY, args["operation_id"], args) as journal:
            if journal.completed_result is not None:
                return journal.completed_result
            try:
                journal.step("audit_store_ready", lambda: _prepare_database(config), mutation=True)
                remote_id = "canary-" + hashlib.sha256(args["operation_id"].encode()).hexdigest()[:32]
                remote = run_proof(settings, {"acceptor": args["acceptor"], "issuer": args["issuer"],
                                             "operation_id": remote_id, "role": "role:service:maintainer",
                                             "subject_id": "trust-cycle-" + remote_id,
                                             "subject_public_key": "trust-cycle-canary-subject",
                                             "claims": {"purpose": "continuous-verification-canary"},
                                             "validity_hours": 25}, tool_name=CANARY)
                if remote["status"] != "completed":
                    return {"status": "partial", "operation_id": args["operation_id"], "remote": remote,
                            "steps": journal.summary(), "receipt_signed": False}
                bundle = remote["result"]
                if not inspect_proof_bundle(bundle)["valid"]:
                    raise ToolError("canary_inspection_failed", "The completed remote proof failed core inspection.")
                payload = {"schema": "genesis-mesh/trust-cycle-canary/v1", "completed_at": bundle["created_at"],
                           "acceptor_sovereign_id": bundle["acceptor"]["network_name"],
                           "issuer_sovereign_id": bundle["issuer"]["network_name"],
                           **{k: bundle[k] for k in ("attestation_id", "treaty_id", "feed_id", "feed_sequence",
                                                   "pre_revocation", "post_revocation")}}
                canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
                signature = sign_data(canonical, key)
                if not verify_signature(canonical, signature, key.verify_key):
                    raise ToolError("canary_signature_failed", "The canary receipt failed core signature verification.")
                receipt = journal.step("signed_receipt", lambda: {
                    "payload": payload, "signature": {"key_id": config.receipt_signer, "value": signature}})
                if (receipt["payload"] != payload or receipt["signature"]["key_id"] != config.receipt_signer
                        or not verify_signature(canonical, receipt["signature"]["value"], key.verify_key)):
                    raise ToolError("receipt_identity_changed", "The saved receipt no longer matches the proof or configured signer.")
                filename = "canary-" + hashlib.sha256(args["operation_id"].encode()).hexdigest()[:32] + ".json"

                def write():
                    if not config.receipt_dir.exists():
                        private_directory(config.receipt_dir)
                    target = config.receipt_dir / filename
                    if target.exists() or target.is_symlink():
                        raise ToolError("receipt_exists", "The receipt already exists; overwrite is not supported.")
                    atomic_json(target, receipt, overwrite=False)
                    if json.loads(target.read_text("utf-8")) != receipt:
                        raise ToolError("receipt_readback_failed", "The saved receipt did not match its signed content.")
                    return {"receipt": filename, "verified": True}

                journal.step("receipt_write", write, mutation=True)
                receipt_path = config.receipt_dir / filename
                if (receipt_path.is_symlink() or receipt_path.stat().st_size > settings.max_output_bytes
                        or json.loads(receipt_path.read_text("utf-8")) != receipt):
                    raise ToolError("receipt_readback_failed", "The persisted receipt changed before audit recording.")

                def record():
                    database = NADatabase(str(config.db_path))
                    try:
                        event_id = database.add_audit_event("trust_cycle_canary_completed", {
                            **payload, "receipt_digest": "sha256:" + hashlib.sha256(canonical).hexdigest(),
                            "receipt_key_id": config.receipt_signer}, event_id="mcp-" + remote_id)
                        return {"audit_event_id": event_id}
                    finally:
                        database.close()

                event = journal.step("audit_record", record, mutation=True)
                return journal.finish({"status": "completed", "operation_id": args["operation_id"],
                                       "receipt": receipt, "receipt_file": filename, **event})
            except Exception as error:
                return {"status": "partial", "operation_id": args["operation_id"], "steps": journal.summary(),
                        "error": error.code if isinstance(error, ToolError) else "canary_failed"}


def build_tools(settings: Settings) -> list[ToolSpec]:
    def schema(properties):
        return {"type": "object", "properties": {key: {"type": "string", "minLength": 1, "maxLength": 80}
                                                   for key in properties},
                "required": list(properties), "additionalProperties": False}
    return [
        ToolSpec(PREVIEW, "Preview ALL rows to be deleted from four trust tables in a configured disposable proof database.",
                 schema(("store",)), lambda a: cleanup_preview(settings, a),
                 frozenset({"local", "read", "maintain"}), read_only=True),
        ToolSpec(CLEANUP, "Verify a new backup, then delete ALL rows in four trust tables of an explicitly disposable proof store. Requires the preview digest.",
                 schema(("store", "operation_id", "preview_digest")), lambda a: cleanup(settings, a),
                 frozenset({"local", "write", "maintain"}), destructive=True, core_targets=("cli:proof cleanup",)),
        ToolSpec(CANARY, "Run a recognition/revocation proof, sign and persist a canary receipt, then record a local core audit event.",
                 schema(("store", "acceptor", "issuer", "operation_id")), lambda a: canary(settings, a),
                 frozenset({"read", "verify", "operator", "write", "local", "maintain", "sign"}),
                 core_targets=("cli:proof canary",), open_world=True),
    ]
