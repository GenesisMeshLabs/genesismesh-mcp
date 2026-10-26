"""Bounded, read-only workspace adapters for core verification workflows."""

from __future__ import annotations

from typing import Any

from genesis_mesh import strict_json
from genesis_mesh.trust.evidence_store import (
    ExecutorKey,
    check_events_against_anchors,
    export_checkpoint,
    parse_export_lines,
    verify_evidence_events,
    verify_store_anchors,
)
from genesis_mesh.trust.key_succession import verify_key_history
from genesis_mesh.workflows.audit_pack import verify_audit_pack
from genesis_mesh.workflows.trust_bundle import bundle_summary, validate_trust_bundle
from pydantic import TypeAdapter

from .settings import Settings
from .types import ToolError, ToolSpec


def _read(settings: Settings, name: str, remaining: int | None = None) -> bytes:
    path = settings.confined_path(name)
    limit = settings.max_input_bytes if remaining is None else remaining
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ToolError("artifact_too_large", "Workspace artifacts exceed the configured input limit.")
    return raw


def _schema(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required, "additionalProperties": False}


def build_tools(settings: Settings) -> list[ToolSpec]:
    path = {"type": "string", "minLength": 1, "maxLength": 512,
            "description": "Relative path within the server-configured workspace; use forward slashes."}
    public_key = {"type": "string", "minLength": 1, "description": "Independently held public key, base64."}
    local_profiles = frozenset({"verify", "local"})

    def bundle(args):
        settings.require(local_profiles)
        raw = _read(settings, args["path"])
        value = strict_json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ToolError("invalid_bundle", "A trust bundle must be a JSON object.")
        return {"summary": bundle_summary(value), "validation": validate_trust_bundle(value),
                "signatures_verified": False,
                "meaning": "Structural consistency and redaction review only. This does not grant trust."}

    def audit(args):
        from genesis_mesh.models.evidence_store import StoreAnchor

        settings.require(local_profiles)
        root = settings.confined_path(args["directory"], must_exist=False)
        if not root.is_dir():
            raise ToolError("artifact_not_found", "The requested audit pack is not a directory.")
        files = {}
        total = 0
        entries_seen = 0
        for item in root.rglob("*"):
            entries_seen += 1
            if entries_seen > 128:
                raise ToolError("too_many_files", "Audit pack exceeds the bounded directory entry count.")
            if item.is_file():
                relative = item.relative_to(settings.workspace).as_posix()
                raw = _read(settings, relative, settings.max_input_bytes - total)
                total += len(raw)
                files[item.relative_to(root).as_posix()] = raw
        held = TypeAdapter(list[StoreAnchor]).validate_python(args["held_anchors"]) if "held_anchors" in args else None
        # A pack holds only the registry records inside its range: keys registered before it come from the caller,
        # as with the core's `audit verify --executor-keys`.
        keys = ({name: TypeAdapter(ExecutorKey).validate_python(row) for name, row in args["executor_keys"].items()}
                if "executor_keys" in args else None)
        result = verify_audit_pack(files, root_public_key=args["root_public_key"], held_anchors=held, executor_keys=keys)
        return result.to_dict()

    def evidence(args):
        from genesis_mesh.models.evidence_store import StoreAnchor

        settings.require(local_profiles)
        events = parse_export_lines(_read(settings, args["path"]).decode("utf-8").split("\n"))
        keys = {name: TypeAdapter(ExecutorKey).validate_python(row) for name, row in args["executor_keys"].items()}
        na_keys = args.get("na_public_keys", [])
        if "key_history" in args:
            if not args.get("root_public_key"):
                raise ToolError("root_pin_required", "An independently held root public key is required for key history.")
            data = args["key_history"]
            checked = verify_key_history(data.get("genesis"), data.get("successions", []), args["root_public_key"])
            if not checked.verified or checked.history is None:
                return {"verified": False, "stage": "key_history", "failures": checked.failures}
            na_keys = checked.history
        elif not na_keys:
            raise ToolError("public_key_required", "Supply NA public keys or a root-pinned key history.")
        result = verify_evidence_events(events, na_public_keys=na_keys, executor_keys=keys,
                                       contiguous=True, checkpoint=export_checkpoint(events))
        if "held_anchors" in args:
            anchors = TypeAdapter(list[StoreAnchor]).validate_python(args["held_anchors"])
            if not anchors:
                raise ToolError("anchors_required", "held_anchors must contain at least one independently held anchor.")
            checked = verify_store_anchors(anchors, na_public_keys=na_keys)
            for failure in checked.failures:
                result.fail(None, failure["reason"], "Held anchor verification failed.")
            check_events_against_anchors(events, anchors, result, partial=args.get("partial", False),
                                        from_anchor=args.get("from_anchor", False))
        output = result.to_dict()
        output["anchors_supplied"] = "held_anchors" in args
        output["scope"] = "partial" if args.get("partial") else "contiguous export"
        return output

    return [
        ToolSpec("gm_local_trust_bundle_inspect", "Inspect and structurally validate a workspace trust bundle. "
                 "Does not verify signatures or import trust.", _schema({"path": path}, ["path"]), bundle,
                 local_profiles, read_only=True, idempotent=True,
                 core_targets=("cli:trust-bundle inspect", "cli:trust-bundle validate")),
        ToolSpec("gm_local_audit_verify", "Verify a workspace audit pack from an independently held root and optional "
                 "held anchors. A pack carries only the executor key registrations inside its range; supply "
                 "executor_keys for keys registered before it. Reads bounded files; never truncates signed evidence.",
                 _schema({"directory": path, "root_public_key": public_key,
                          "held_anchors": {"type": "array", "items": {"type": "object"}, "minItems": 1},
                          "executor_keys": {"type": "object",
                                            "additionalProperties": TypeAdapter(ExecutorKey).json_schema()}},
                         ["directory", "root_public_key"]), audit, local_profiles, read_only=True, idempotent=True,
                 core_targets=("cli:audit verify",)),
        ToolSpec("gm_local_evidence_verify_export", "Verify workspace evidence JSONL, record signatures and chains. "
                 "Optional root-pinned key history and independently held anchors detect changes across key succession "
                 "and anchored omissions. No network access.",
                 _schema({"path": path, "na_public_keys": {"type": "array", "items": public_key, "minItems": 1},
                          "executor_keys": {"type": "object", "additionalProperties": TypeAdapter(ExecutorKey).json_schema()},
                          "key_history": {"type": "object"}, "root_public_key": public_key,
                          "held_anchors": {"type": "array", "items": {"type": "object"}, "minItems": 1},
                          "partial": {"type": "boolean", "default": False},
                          "from_anchor": {"type": "boolean", "default": False}}, ["path", "executor_keys"]),
                 evidence, local_profiles, read_only=True, idempotent=True,
                 core_targets=("cli:evidence verify-export",))]
