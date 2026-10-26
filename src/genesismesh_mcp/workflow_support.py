"""Bounded configured workflow dependencies and durable mutation records."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import fields, is_dataclass, replace
from pathlib import Path
from time import time
from typing import Any

from .settings import Settings
from .types import ToolError, ToolSpec
from .workflow_config import reference


def normalize_roles(roles):
    """Use the same aliases and validation as the pinned core CLI workflows."""
    from click import ClickException
    from genesis_mesh.cli.support import _validate_cli_roles

    try:
        return _validate_cli_roles(roles)
    except (ClickException, AttributeError, TypeError):
        raise ToolError("invalid_roles", "Use core roles such as client, role:client, or service:<name>.") from None


def select_authority(settings: Settings, alias: str, tool_name: str) -> Settings:
    config = settings.authorities.get(alias)
    if config is None:
        raise ToolError("authority_not_configured", "Choose a configured authority reference.")
    if tool_name not in config.allowed_tools:
        raise ToolError("authority_not_authorized", "This authority is not enabled for the requested workflow.")
    return replace(settings, authority_url=config.url, authority_public_key=config.public_key,
                   operator_key_file=config.operator_key_file, operator_key_id=config.operator_key_id,
                   node_key_file=None, executor_key_file=None, invite_token=None)


def pinned_root(settings: Settings, alias: str) -> str:
    config = settings.authorities.get(alias)
    if config is None or not config.root_public_key:
        raise ToolError("root_pin_required", "This workflow requires a configured root public key.")
    return config.root_public_key


def fleet_members(settings: Settings, name: str) -> tuple[str, ...]:
    if name not in settings.fleets:
        raise ToolError("fleet_not_configured", "Choose a configured fleet reference.")
    return settings.fleets[name]


def artifact_root(settings: Settings, name: str) -> Path:
    settings.require(frozenset({"local"}))
    if name not in settings.artifact_roots:
        raise ToolError("artifact_root_not_configured", "Choose a configured artifact storage reference.")
    root = settings.artifact_roots[name]
    root.mkdir(parents=True, exist_ok=True)
    return root


def resource_lock(settings: Settings, kind: str, name: str):
    """Serialize stateful workflows sharing a configured resource, across processes."""
    group = {"proof_store": settings.proof_stores, "provisioning": settings.provisioning,
             "node": settings.node_runtimes, "artifact": settings.artifact_roots}.get(kind, {})
    value = group.get(name)
    path = next((getattr(value, field, None) for field in ("db_path", "root", "state_dir")
                 if getattr(value, field, None) is not None), value if isinstance(value, Path) else name)
    lock_id = hashlib.sha256(str(path).encode()).hexdigest()
    return WorkflowJournal(settings, "gm_lock_" + kind, lock_id, {}, bind_config=False)


def private_directory(path: Path) -> None:
    """Create a new private directory before any keys or sensitive state exist."""
    if os.name != "nt":
        path.mkdir(mode=0o700, parents=True, exist_ok=False)
        return
    if path.exists() or path.is_symlink():
        raise FileExistsError(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Windows mkdir does not establish the required ACL on all supported
    # Python versions. Publish the configured path only after a fresh sibling
    # is secured. Windows rename refuses an existing destination, including a
    # directory created by another initializer while ACL setup was running.
    stage = Path(tempfile.mkdtemp(prefix=".private-init-", dir=path.parent))
    try:
        try:
            result = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], check=True,
                                    capture_output=True, text=True, timeout=10)
            sid = next(csv.reader(io.StringIO(result.stdout.strip())))[1]
            if not sid.startswith("S-1-"):
                raise ValueError("Invalid current-user SID")
            subprocess.run(["icacls", str(stage), "/inheritance:r", "/grant:r", f"*{sid}:(OI)(CI)F",
                            "/grant:r", "*S-1-5-18:(OI)(CI)F"], check=True, capture_output=True, timeout=10)
        except (OSError, ValueError, IndexError, StopIteration, subprocess.SubprocessError):
            raise ToolError("private_storage_unavailable", "Could not secure the new private directory.") from None
        os.rename(stage, path)
    finally:
        if stage.exists():
            try:
                stage.rmdir()
            except OSError:
                # A failed cleanup or a concurrent file must never cause
                # recursive deletion. This unpublished directory is not reused.
                pass


def atomic_json(path: Path, value: Any, *, max_bytes: int = 16_777_216, overwrite: bool = True) -> None:
    data = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    if len(data) > max_bytes:
        raise ToolError("workflow_state_too_large", "The workflow state exceeds its storage limit.")
    if path.is_symlink():
        raise ToolError("unsafe_storage", "Workflow storage must not contain symbolic links.")
    descriptor, temporary = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            os.replace(temporary, path)
        else:
            os.link(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _config_value(value):
    if is_dataclass(value):
        return {f.name: _config_value(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, Mapping):
        return {str(key): _config_value(item) for key, item in value.items()}
    if isinstance(value, (set, frozenset)):
        return sorted(_config_value(item) for item in value)
    if isinstance(value, (list, tuple)):
        return [_config_value(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


def _bound_configuration(settings):
    value = _config_value(settings)
    paths = [*settings.signer_files.values(), settings.operator_key_file, settings.node_key_file,
             settings.executor_key_file]
    paths.extend(config.operator_key_file for config in settings.authorities.values())
    paths.extend(config.node_key_file for config in settings.node_runtimes.values())
    fingerprints = {}
    for path in paths:
        if path is None:
            continue
        try:
            fingerprint = hashlib.sha256(path.read_bytes()).hexdigest() if path.stat().st_size <= 65536 else "oversized"
        except OSError:
            fingerprint = "unavailable"
        fingerprints[str(path)] = fingerprint
    value["credential_fingerprints"] = fingerprints
    return value


def _step_summaries(steps):
    summaries = {}
    for name, step in steps.items():
        summary = {key: item for key, item in step.items() if key != "result"}
        if "result" in step:
            encoded = json.dumps(step["result"], sort_keys=True, separators=(",", ":")).encode()
            summary["result_sha256"] = hashlib.sha256(encoded).hexdigest()
            identifiers = {}

            def collect(value, prefix="", depth=0):
                if depth > 3 or not isinstance(value, dict):
                    return
                for key, item in value.items():
                    label = prefix + key
                    if (key.endswith("_id") or key in {"http_status", "http_ok", "accepted", "status", "backup"}) and isinstance(item, (str, int, bool)):
                        if len(identifiers) < 32 and (not isinstance(item, str) or len(item) <= 256):
                            identifiers[label] = item
                    elif isinstance(item, dict):
                        collect(item, label + ".", depth + 1)

            collect(step["result"])
            summary["result_identifiers"] = identifiers
        summaries[name] = summary
    return summaries


class WorkflowJournal:
    """Store intent before effects; a missing reply is never silently replayed."""

    def __init__(self, settings: Settings, tool_name: str, operation_id: str, inputs: dict, *, bind_config=True):
        settings.require(frozenset({"local"}))
        try:
            reference(operation_id)
            reference(tool_name)
        except ValueError:
            raise ToolError("invalid_operation_id", "Use a simple operation identifier of at most 80 characters.") from None
        if settings.workflow_state_dir is None:
            raise ToolError("workflow_state_required", "Configure workflow_state_dir before running durable workflows.")
        self.root = settings.workflow_state_dir
        if not self.root.exists():
            try:
                private_directory(self.root)
            except FileExistsError:
                pass
        self.path = self.root / f"{tool_name}--{operation_id}.json"
        self.lock_path = self.path.with_suffix(".lock")
        self.operation_id = operation_id
        self.tool_name = tool_name
        bound = {"inputs": inputs, "configuration": _bound_configuration(settings) if bind_config else None}
        self.input_digest = hashlib.sha256(json.dumps(bound, sort_keys=True, separators=(",", ":"),
                                                    allow_nan=False).encode()).hexdigest()
        self.data: dict[str, Any] = {}
        self.lock = None

    def __enter__(self):
        if self.path.is_symlink() or self.lock_path.is_symlink():
            raise ToolError("unsafe_storage", "Workflow storage must not contain symbolic links.")
        self.lock = open(self.lock_path, "a+b")
        if self.lock.seek(0, 2) == 0:
            self.lock.write(b"0")
            self.lock.flush()
        self.lock.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.lock.close()
            self.lock = None
            raise ToolError("workflow_busy", "This operation is already running.") from None
        try:
            if self.path.exists():
                if self.path.stat().st_size > 16_777_216:
                    raise ToolError("workflow_state_too_large", "The stored workflow exceeds its storage limit.")
                self.data = json.loads(self.path.read_text("utf-8"))
                if self.data.get("input_digest") != self.input_digest or self.data.get("tool") != self.tool_name:
                    raise ToolError("operation_conflict", "This operation ID was already used with different inputs.")
            else:
                self.data = {"tool": self.tool_name, "operation_id": self.operation_id,
                             "input_digest": self.input_digest, "created_at": time(), "steps": {}, "complete": False}
                self._save()
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        if self.lock is not None:
            self.lock.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.lock.fileno(), fcntl.LOCK_UN)
            self.lock.close()
            self.lock = None

    def _save(self):
        atomic_json(self.path, self.data)

    @property
    def completed_result(self):
        return self.data.get("result") if self.data.get("complete") else None

    def step(self, name: str, function, *, mutation: bool = False):
        previous = self.data["steps"].get(name)
        if previous and previous["status"] == "completed":
            return previous["result"]
        if previous and previous.get("mutation"):
            raise ToolError("outcome_unknown", "A prior mutation has an uncertain outcome. Inspect state before recovery.")
        if time() - self.data["created_at"] > 86400:
            raise ToolError("operation_expired", "This unfinished operation is over 24 hours old; reconcile its state.")
        self.data["steps"][name] = {"status": "started", "mutation": mutation}
        self._save()
        try:
            result = function()
        except Exception as error:
            self.data["steps"][name].update(status="unknown" if mutation else "failed",
                                            error=error.code if isinstance(error, ToolError) else "step_failed")
            self._save()
            raise
        self.data["steps"][name].update(status="completed", result=result)
        self._save()
        return result

    def finish(self, result):
        self.data.update(complete=True, result=result)
        self._save()
        return result

    def summary(self):
        return {"workflow": self.tool_name, "operation_id": self.operation_id, "complete": self.data.get("complete", False),
                "steps": _step_summaries(self.data.get("steps", {}))}


def build_tools(settings: Settings) -> list[ToolSpec]:
    def status(args):
        settings.require(frozenset({"local", "read"}))
        try:
            reference(args["workflow"])
            reference(args["operation_id"])
        except ValueError:
            raise ToolError("invalid_operation_id", "Use configured workflow and operation identifiers.") from None
        if settings.workflow_state_dir is None:
            raise ToolError("workflow_state_required", "Configure workflow_state_dir to inspect operations.")
        path = settings.workflow_state_dir / f"{args['workflow']}--{args['operation_id']}.json"
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 16_777_216:
            raise ToolError("operation_not_found", "The requested operation record is unavailable.")
        data = json.loads(path.read_text("utf-8"))
        from .server import build_tools
        original = next((tool for tool in build_tools(settings) if tool.name == data.get("tool")), None)
        if original is None:
            raise ToolError("operation_not_found", "The requested operation is not a registered workflow.")
        settings.require(original.profiles)
        result = {key: data[key] for key in ("tool", "operation_id", "complete") if key in data}
        result["steps"] = _step_summaries(data.get("steps", {}))
        if "result" in data:
            result["result_sha256"] = hashlib.sha256(json.dumps(data["result"], sort_keys=True).encode()).hexdigest()
        return result
    return [ToolSpec("gm_workflow_operation_status", "Inspect a durable workflow and any uncertain mutation outcomes.",
                     {"type": "object", "properties": {"workflow": {"type": "string", "pattern": "^gm_workflow_",
                      "description": "Exact MCP tool name from the operation's workflow field, e.g. gm_workflow_federation_bootstrap."},
                      "operation_id": {"type": "string"}}, "required": ["workflow", "operation_id"],
                      "additionalProperties": False}, status, frozenset({"local", "read"}), read_only=True,
                     idempotent=True)]
