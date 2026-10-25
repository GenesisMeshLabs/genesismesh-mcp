"""Durable, bounded compositions for held evidence and treaty lifecycle."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Callable

from genesis_mesh.cli.audit_ops import _executor_key_rows, _manifest_problems, _pack_bytes, write_pack
from genesis_mesh.cli.evidence_store_ops import _same, _write_anchor
from genesis_mesh.models.audit_pack import MANIFEST_FILE, OPTIONAL_PACK_FILES, PACK_FILES
from genesis_mesh.models.evidence_store import StoreAnchor
from genesis_mesh.strict_json import loads as strict_loads
from genesis_mesh.trust.evidence_store import verify_store_anchors
from genesis_mesh.trust.key_succession import verify_key_history
from genesis_mesh.workflows.audit_pack import verify_audit_pack

from .authority import invoke, operations
from .settings import Settings
from .types import ToolError, ToolSpec
from .workflow_support import (
    WorkflowJournal,
    artifact_root,
    normalize_roles,
    pinned_root,
    resource_lock,
    select_authority,
)

MAX_ANCHORS = 10_000
MAX_PAGES = 32
PACK_PATHS = frozenset((*PACK_FILES, *OPTIONAL_PACK_FILES, MANIFEST_FILE))
LOCAL_PROFILES = frozenset({"read", "operator", "write", "local"})
VERIFIED_PROFILES = LOCAL_PROFILES | {"verify"}
TREATY_PROFILES = frozenset({"read", "operator", "write", "local"})


class AuthorityRejection(ToolError):
    def __init__(self, result: dict[str, Any]):
        self.result = result
        super().__init__("authority_rejected", "The authority rejected this workflow step; inspect the returned result.")


def _call(settings: Settings, path: str, method: str = "GET", *, body=None, query=None, path_args=None):
    operation = next(op for op in operations() if op["path"] == path and op["method"] == method)
    args = {}
    if body is not None:
        args["body"] = body
    if query is not None:
        args["query"] = query
    if path_args is not None:
        args["path"] = path_args
    result = invoke(settings, operation, args)
    if not result["http_ok"]:
        raise AuthorityRejection(result)
    if not isinstance(result["result"], dict):
        raise ToolError("invalid_authority_response", "This workflow requires an object response.")
    return result["result"]


def _child(root: Path, name: str) -> Path:
    target = root / name
    if root.resolve() != root or root.is_symlink() or target.is_symlink() or not target.resolve().is_relative_to(root):
        raise ToolError("invalid_artifact_path", "The configured artifact location contains an escaping path.")
    return target


def _operation_child(kind: str, operation_id: str) -> str:
    return f"{kind}-{hashlib.sha256(operation_id.encode()).hexdigest()[:32]}"


def _read_pack(directory: Path, limit: int) -> dict[str, bytes]:
    files = {}
    total = 0
    count = 0
    for path in directory.rglob("*"):
        count += 1
        if count > 64 or path.is_symlink() or not path.resolve().is_relative_to(directory.resolve()):
            raise ToolError("invalid_pack_path", "The pack has excessive entries or a symbolic link.")
        if not path.is_file():
            continue
        relative = path.relative_to(directory).as_posix()
        if relative not in PACK_PATHS:
            raise ToolError("invalid_pack_path", "The pack contains a file outside the pinned pack format.")
        with path.open("rb") as stream:
            body = stream.read(limit - total + 1)
        total += len(body)
        if total > limit:
            raise ToolError("artifact_too_large", "The audit pack exceeds the configured byte limit.")
        files[relative] = body
    return files


def _checked_pack_files(pack: dict[str, Any], limit: int) -> dict[str, bytes]:
    try:
        files = _pack_bytes(pack)
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ToolError("invalid_pack", "The authority did not return a valid audit pack.") from None
    if set(files) - PACK_PATHS:
        raise ToolError("invalid_pack_path", "The pack contains a file outside the pinned pack format.")
    if sum(map(len, files.values())) > limit:
        raise ToolError("artifact_too_large", "The audit pack exceeds the configured byte limit.")
    if _manifest_problems(files, files[MANIFEST_FILE]):
        raise ToolError("pack_manifest_mismatch", "The supplied pack does not match its signed manifest.")
    return files


def _persist_pack(root: Path, name: str, pack: dict[str, Any], limit: int):
    files = _checked_pack_files(pack, limit)
    root.mkdir(parents=True, exist_ok=True)
    target = _child(root, name)
    target.mkdir(exist_ok=False)
    write_pack(target, files)
    if _manifest_problems(_read_pack(target, limit), files[MANIFEST_FILE]):
        raise ToolError("pack_readback_mismatch", "The persisted pack differs from its manifest; nothing was archived or pruned.")
    return {"directory": name, "file_count": len(files), "bytes": sum(map(len, files.values())),
            "readback_matches_manifest": True}


def _fetch_anchors(settings: Settings) -> list[dict[str, Any]]:
    served: dict[int, StoreAnchor] = {}
    after = 0
    total = 0
    for _ in range(MAX_PAGES):
        page = _call(settings, "/admin/evidence/anchors", query={"after_anchor": after, "limit": 1000})
        rows = page.get("anchors", [])
        if not isinstance(rows, list):
            raise ToolError("invalid_anchor_history", "The authority returned an invalid anchor page.")
        for raw in rows:
            anchor = StoreAnchor.model_validate(raw)
            if anchor.anchor_sequence <= after or anchor.anchor_sequence in served:
                raise ToolError("invalid_anchor_history", "The authority served duplicate or out-of-order anchors.")
            served[anchor.anchor_sequence] = anchor
            total += len(json.dumps(anchor.to_wire()).encode())
            if len(served) > MAX_ANCHORS or total > settings.max_output_bytes:
                raise ToolError("anchor_limit", "The full anchor history exceeds the configured workflow bounds.")
        nxt = page.get("next_after_anchor")
        if nxt is None:
            return [served[n].to_wire() for n in sorted(served)]
        if type(nxt) is not int or nxt <= after or not rows or nxt != max(served):
            raise ToolError("invalid_anchor_history", "The authority anchor pagination does not advance consistently.")
        after = nxt
    raise ToolError("anchor_limit", "The anchor history exceeds the bounded page count.")


def _read_held(directory: Path, limit: int) -> list[StoreAnchor]:
    if not directory.exists():
        return []
    anchors = []
    total = 0
    for path in directory.iterdir():
        if path.is_symlink() or not path.is_file() or not path.name.startswith("anchor-") or path.suffix != ".json":
            raise ToolError("invalid_anchor_store", "The held anchor store contains an unexpected entry.")
        with path.open("rb") as stream:
            raw = stream.read(limit - total + 1)
        total += len(raw)
        if total > limit or len(anchors) >= MAX_ANCHORS:
            raise ToolError("anchor_limit", "The held anchor store exceeds the configured bounds.")
        anchor = StoreAnchor.model_validate(strict_loads(raw))
        if path.name != f"anchor-{anchor.anchor_sequence:010d}.json":
            raise ToolError("invalid_anchor_store", "A held anchor filename does not match its signed sequence.")
        anchors.append(anchor)
    return anchors


def _copy_anchors(root: Path, name: str, rows: list[dict[str, Any]], na_keys: Any, limit: int):
    directory = _child(root, name)
    held = _read_held(directory, limit)
    served = {a.anchor_sequence: a for a in (StoreAnchor.model_validate(raw) for raw in rows)}
    for anchor in held:
        if anchor.anchor_sequence not in served or not _same(anchor, served[anchor.anchor_sequence]):
            raise ToolError("anchor_history_changed", "The authority removed or rewrote a held anchor; no new anchors were written.")
    if served and min(served) != 1:
        raise ToolError("anchor_history_incomplete", "The served history does not start at anchor one; no anchors were written.")
    ordered = [served[n] for n in sorted(served)]
    checked = verify_store_anchors(ordered, na_public_keys=na_keys,
                                   sovereign_id=held[0].sovereign_id if held else None)
    if not checked.verified:
        raise ToolError("anchor_verification_failed", "The served anchor signatures or chain failed verification; no anchors were written.")
    held_sequences = {a.anchor_sequence for a in held}
    missing = [a for a in ordered if a.anchor_sequence not in held_sequences]
    directory.mkdir(parents=True, exist_ok=True)
    for anchor in missing:
        _write_anchor(directory, anchor)
    return {"directory": name, "new_anchors": len(missing), "total_anchors": len(ordered),
            "latest_anchor_sequence": ordered[-1].anchor_sequence if ordered else None,
            "latest_store_sequence": ordered[-1].store_sequence if ordered else None,
            "verified": True}


def _run(settings: Settings, name: str, args: dict[str, Any], profiles: frozenset[str],
         action: Callable[[WorkflowJournal, Settings], dict[str, Any]]):
    settings.require(profiles)
    selected = select_authority(settings, args["authority"], name)
    with WorkflowJournal(settings, name, args["operation_id"], args) as journal:
        if journal.completed_result is not None:
            return journal.completed_result
        try:
            result = action(journal, selected)
        except ToolError as exc:
            error: dict[str, Any] = {"code": exc.code, "message": str(exc)}
            if isinstance(exc, AuthorityRejection):
                error["authority_result"] = exc.result
            return {"completed": False, "operation_id": args["operation_id"], "error": error,
                    "steps": journal.summary(), "retry": "Reuse this operation_id; ambiguous mutations require operator reconciliation."}
        except OSError:
            return {"completed": False, "operation_id": args["operation_id"],
                    "error": {"code": "artifact_io_failed", "message": "The configured artifact operation failed."},
                    "steps": journal.summary(), "retry": "Inspect partial artifacts before reconciling the operation."}
        except (ValueError, KeyError, TypeError):
            return {"completed": False, "operation_id": args["operation_id"],
                    "error": {"code": "invalid_workflow_data", "message": "A configured artifact or authority result has an invalid structure."},
                    "steps": journal.summary(), "retry": "Inspect the recorded steps before reconciling the operation."}
        result.update(completed=True, operation_id=args["operation_id"])
        return journal.finish(result)


def _range(args, *, start=None):
    body = {key: args[key] for key in ("from_sequence", "since", "until_sequence", "until") if key in args}
    if start is not None:
        body["from_sequence"] = start
    return body


def _audit_pack(settings: Settings, args: dict[str, Any]):
    name = "gm_workflow_audit_pack"

    def action(journal, selected):
        root = artifact_root(settings, args["artifact_store"])
        pack = journal.step("fetch_pack", lambda: _call(selected, "/admin/evidence/audit-pack", "POST", body=_range(args)))
        artifact = journal.step("persist_pack", lambda: _persist_pack(root, _operation_child("pack", args["operation_id"]),
                                pack, settings.max_output_bytes), mutation=True)
        return {"artifact_store": args["artifact_store"], "artifact": artifact, "manifest": pack["manifest"],
                "verification_scope": "manifest_readback_only", "independent_signature_verification": False}

    return _run(settings, name, args, LOCAL_PROFILES, action)


def _audit_archive(settings: Settings, args: dict[str, Any]):
    name = "gm_workflow_audit_archive"

    def action(journal, selected):
        root = artifact_root(settings, args["artifact_store"])
        root_key = pinned_root(settings, args["authority"])
        archives = journal.step("list_archives", lambda: _call(selected, "/admin/evidence/archives"))
        body = _range(args, start=int(archives["archived_through_sequence"]) + 1)
        pack = journal.step("fetch_pack", lambda: _call(selected, "/admin/evidence/audit-pack", "POST", body=body))
        child = _operation_child("archive", args["operation_id"])
        artifact = journal.step("persist_pack", lambda: _persist_pack(root, child, pack, settings.max_output_bytes), mutation=True)

        def verify():
            files = _read_pack(_child(root, child), settings.max_output_bytes)
            original = _checked_pack_files(pack, settings.max_output_bytes)
            if _manifest_problems(files, original[MANIFEST_FILE]):
                raise ToolError("pack_readback_mismatch", "The stored pack changed before archival; nothing was recorded or pruned.")
            anchors = [StoreAnchor.model_validate(a) for a in _fetch_anchors(selected)]
            keys = _call(selected, "/admin/evidence/executor-keys")
            checked = verify_audit_pack(files, root_public_key=root_key, held_anchors=anchors,
                                       executor_keys=_executor_key_rows(keys.get("executor_keys", [])))
            if not checked.verified:
                raise ToolError("pack_verification_failed", "Independent pack verification failed; nothing was recorded or pruned.")
            return checked.to_dict()

        checked = journal.step("verify_readback", verify)
        # Recheck persisted bytes even when resuming from a completed verification step.
        original = _checked_pack_files(pack, settings.max_output_bytes)
        if _manifest_problems(_read_pack(_child(root, child), settings.max_output_bytes), original[MANIFEST_FILE]):
            raise ToolError("pack_readback_mismatch", "The persisted pack changed; no further remote mutation was attempted.")
        location = f"mcp-artifact:{args['artifact_store']}/{child}"

        def record_archive():
            current = _call(selected, "/admin/evidence/archives")
            if current["archived_through_sequence"] != archives["archived_through_sequence"]:
                raise ToolError("archive_state_changed", "Archive progress changed since the pack was prepared; no archive was recorded.")
            return _call(selected, "/admin/evidence/archives", "POST", body={"manifest": pack["manifest"], "location": location})

        recorded = journal.step("record_archive", record_archive, mutation=True)
        result = {"artifact_store": args["artifact_store"], "artifact": artifact, "verification": checked,
                  "archive": recorded, "storage_guarantee": "Durable local files; external storage immutability is operator-managed."}
        if args.get("prune", False):
            retention = {"through_sequence": int(pack["manifest"]["through_sequence"])}
            if "older_than_days" in args:
                retention["older_than_days"] = args["older_than_days"]
            result["retention"] = journal.step("apply_retention", lambda: _call(selected,
                "/admin/evidence/retention/apply", "POST", body=retention), mutation=True)
        return result

    return _run(settings, name, args, VERIFIED_PROFILES, action)


def _anchors_fetch(settings: Settings, args: dict[str, Any]):
    name = "gm_workflow_evidence_anchors_fetch"

    def locked_action(journal, selected):
        root = artifact_root(settings, args["artifact_store"])
        if not selected.authority_public_key:
            raise ToolError("authority_pin_required", "Configure the authority public key before holding signed anchors.")
        refusal = None
        requested_anchor = None
        if args.get("anchor_now", False):
            def request_anchor():
                try:
                    return {"created": _call(selected, "/admin/evidence/anchors", "POST")}
                except AuthorityRejection as exc:
                    payload = exc.result.get("result", {})
                    error = payload.get("error", {}) if isinstance(payload, dict) else {}
                    if exc.result["http_status"] == 409 and isinstance(error, dict) and error.get("code") == "evidence_anchor_refused":
                        return {"refused": error}
                    raise
            requested = journal.step("anchor_now", request_anchor, mutation=True)
            refusal = requested.get("refused")
            raw_anchor = requested.get("created", {}).get("anchor")
            if raw_anchor is not None:
                requested_anchor = StoreAnchor.model_validate(raw_anchor)
        rows = journal.step("fetch_anchors", lambda: _fetch_anchors(selected))
        child = _operation_child("anchors", args["authority"])

        def persist():
            # Check fresh history before adding held copies, including on a resumed run.
            fresh = _fetch_anchors(selected)
            if fresh[:len(rows)] != rows:
                raise ToolError("anchor_history_changed", "Anchor history changed during the operation; no new anchors were written.")
            if requested_anchor is not None and not any(
                    _same(requested_anchor, StoreAnchor.model_validate(row)) for row in fresh):
                raise ToolError("requested_anchor_missing", "The requested head anchor is missing or changed in the served history; no anchors were written.")
            na_keys: Any = [selected.authority_public_key]
            config = settings.authorities[args["authority"]]
            if config.root_public_key:
                view = _call(selected, "/na/key-history")
                verified = verify_key_history(view.get("genesis"), view.get("successions", []), config.root_public_key)
                if not verified.verified or verified.history is None:
                    raise ToolError("key_history_verification_failed", "The authority key history did not verify against the configured root.")
                na_keys = verified.history
            return _copy_anchors(root, child, fresh, na_keys, settings.max_output_bytes)

        copied = journal.step("persist_anchors", persist, mutation=True)
        return {"artifact_store": args["artifact_store"], "anchors": copied, "anchor_now_refusal": refusal,
                "outcome": "anchor_request_refused" if refusal else "anchors_copied",
                "head_anchored": requested_anchor is not None and refusal is None,
                "recent_entries_covered": False if refusal else None}

    def action(journal, selected):
        # Distinct operation IDs can still write the same held-history store.
        # Serialize the full fetch/reconcile/write sequence across threads and
        # processes; core's atomic anchor writer uses a PID-based temp filename.
        with resource_lock(settings, "artifact", args["artifact_store"]):
            return locked_action(journal, selected)

    return _run(settings, name, args, VERIFIED_PROFILES, action)


def _treaty(settings: Settings, args: dict[str, Any], action: str):
    name = f"gm_workflow_treaty_{action}"

    def execute(journal, selected):
        treaty_id = args["treaty_id"]
        old_row = journal.step("fetch_old_treaty", lambda: _call(selected, "/recognition-treaties/<treaty_id>",
                               path_args={"treaty_id": treaty_id}))
        old = old_row["treaty"]
        scope = old.get("scope", {})
        body = {"subject_sovereign_id": old["subject_sovereign_id"], "subject_public_keys": old["subject_public_keys"],
                "scope": {"allowed_roles": normalize_roles(args.get("roles", scope.get("allowed_roles", []))),
                          "accepted_statuses": args.get("accepted_statuses", scope.get("accepted_statuses", ["active"])),
                          "claims": args.get("claims", scope.get("claims", {}))},
                "validity_hours": args.get("validity_hours", 24),
                "metadata": {**(old.get("metadata") or {}), f"{action}_of": treaty_id}}

        def issue():
            current = _call(selected, "/recognition-treaties/<treaty_id>", path_args={"treaty_id": treaty_id})
            # Lifecycle expiry-risk annotations depend on the clock; compare persisted state.
            for field in ("treaty", "status", "revoked_at", "revocation_reason"):
                if current.get(field) != old_row.get(field):
                    raise ToolError("treaty_state_changed", "The original treaty changed since this operation began; no replacement was issued.")
            return _call(selected, "/admin/recognition-treaties", "POST", body=body)

        issued = journal.step("issue_treaty", issue, mutation=True)
        reason = "renewed_by" if action == "renew" else "replaced_by"
        revoked = journal.step("revoke_old_treaty", lambda: _call(selected,
                               "/admin/recognition-treaties/<treaty_id>/revoke", "POST",
                               body={"reason": f"{reason}:{issued['treaty_id']}"}, path_args={"treaty_id": treaty_id}), mutation=True)
        return {"old_treaty_id": treaty_id, "new_treaty": issued, "old_treaty_revocation": revoked}

    return _run(settings, name, args, TREATY_PROFILES, execute)


def build_tools(settings: Settings) -> list[ToolSpec]:
    reference = {"type": "string", "minLength": 1, "maxLength": 128}
    positive = {"type": "integer", "minimum": 1}
    timestamp = {"type": "string", "format": "date-time"}
    base = {"authority": reference, "operation_id": reference}

    def schema(extra, *, artifact=False):
        props = {**base, **extra}
        required = ["authority", "operation_id"]
        if artifact:
            props["artifact_store"] = reference
            required.append("artifact_store")
        if "treaty_id" in props:
            required.append("treaty_id")
        return {"type": "object", "properties": props, "required": required, "additionalProperties": False}

    ranges = {"from_sequence": positive, "since": timestamp, "until_sequence": positive, "until": timestamp}
    lifecycle = {"treaty_id": reference, "validity_hours": {**positive, "maximum": 87600, "default": 24}}
    return [
        ToolSpec("gm_workflow_audit_pack", "Fetch a complete audit pack, persist it in a configured artifact store, and compare every byte to its manifest. Does not independently verify signatures.",
                 schema(ranges, artifact=True), lambda a: _audit_pack(settings, a), LOCAL_PROFILES,
                 core_targets=("cli:audit pack",), open_world=True),
        ToolSpec("gm_workflow_audit_archive", "Persist and independently verify an audit pack from the configured root pin, record the archive, and optionally prune. Returns partial step outcomes; local storage alone is not an immutability guarantee.",
                 schema({"until_sequence": positive, "until": timestamp, "older_than_days": positive,
                         "prune": {"type": "boolean", "default": False}}, artifact=True),
                 lambda a: _audit_archive(settings, a), VERIFIED_PROFILES, destructive=True,
                 core_targets=("cli:audit archive",), open_world=True),
        ToolSpec("gm_workflow_evidence_anchors_fetch", "Verify the full served anchor history against held copies and the configured NA pin, then append immutable-by-convention local copies. A refused anchor-now request is reported even when prior anchors were copied.",
                 schema({"anchor_now": {"type": "boolean", "default": False}}, artifact=True),
                 lambda a: _anchors_fetch(settings, a), VERIFIED_PROFILES,
                 core_targets=("cli:evidence anchors fetch",), open_world=True),
        ToolSpec("gm_workflow_treaty_renew", "Issue a linked renewal, then revoke the old treaty. A partial failure preserves the issued treaty in the operation journal; retries never blindly issue another treaty.",
                 schema(lifecycle), lambda a: _treaty(settings, a, "renew"), TREATY_PROFILES,
                 destructive=True, core_targets=("cli:treaty renew",), open_world=True),
        ToolSpec("gm_workflow_treaty_replace", "Issue a linked replacement with updated scope, then revoke the old treaty. Inspect partial outcomes before reconciling a failed operation.",
                 schema({**lifecycle, "roles": {"type": "array", "items": reference, "maxItems": 100},
                         "accepted_statuses": {"type": "array", "items": reference, "maxItems": 20},
                         "claims": {"type": "object", "additionalProperties": {"type": "string"}, "maxProperties": 100}}),
                 lambda a: _treaty(settings, a, "replace"), TREATY_PROFILES,
                 destructive=True, core_targets=("cli:treaty replace",), open_world=True),
    ]
