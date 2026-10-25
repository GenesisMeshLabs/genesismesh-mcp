"""Explicit server configuration; MCP calls cannot alter credentials or destinations."""

from __future__ import annotations

import ipaddress
import json
import math
from dataclasses import dataclass, field, fields
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping
from urllib.parse import urlsplit

from genesis_mesh.crypto import load_private_key

from .types import ToolError

PROFILES = frozenset({"read", "verify", "operator", "node", "write", "sign", "local", "execute", "provision", "maintain"})


@dataclass(frozen=True)
class Settings:
    authority_url: str | None = None
    allow_http_loopback: bool = False
    profiles: frozenset[str] = frozenset({"read", "verify"})
    operator_key_file: Path | None = None
    operator_key_id: str | None = None
    node_key_file: Path | None = None
    executor_key_file: Path | None = None
    authority_public_key: str | None = None
    invite_token: str | None = field(default=None, repr=False)
    signer_files: Mapping[str, Path] = field(default_factory=dict, repr=False)
    signer_permissions: Mapping[str, frozenset[str]] = field(default_factory=dict)
    workspace: Path | None = None
    timeout_seconds: float = 15.0
    max_input_bytes: int = 1_048_576
    max_output_bytes: int = 4_194_304
    tool_page_size: int | None = None
    authorities: Mapping[str, Any] = field(default_factory=dict, repr=False)
    fleets: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    workflow_state_dir: Path | None = None
    artifact_roots: Mapping[str, Path] = field(default_factory=dict, repr=False)
    provisioning: Mapping[str, Any] = field(default_factory=dict, repr=False)
    proof_stores: Mapping[str, Any] = field(default_factory=dict, repr=False)
    node_runtimes: Mapping[str, Any] = field(default_factory=dict, repr=False)
    peers: Mapping[str, Any] = field(default_factory=dict, repr=False)
    guard_actions: Mapping[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "profiles", frozenset(self.profiles))
        object.__setattr__(self, "signer_files", MappingProxyType({k: Path(v).resolve() for k, v in self.signer_files.items()}))
        object.__setattr__(self, "signer_permissions", MappingProxyType({
            k: frozenset(v) for k, v in self.signer_permissions.items()}))
        if set(self.signer_permissions) - set(self.signer_files):
            raise ValueError("Signer permissions reference an unconfigured signer")
        if any("*" in names for names in self.signer_permissions.values()):
            raise ValueError("Signer permissions require explicit tool names")
        for name in ("operator_key_file", "node_key_file", "executor_key_file", "workspace", "workflow_state_dir"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, Path(value).resolve())
        if not self.profiles <= PROFILES:
            raise ValueError("Unknown configuration profile")
        if not math.isfinite(self.timeout_seconds) or not 0 < self.timeout_seconds <= 300:
            raise ValueError("timeout_seconds must be in (0, 300]")
        for value in (self.max_input_bytes, self.max_output_bytes):
            if type(value) is not int or not 1024 <= value <= 67_108_864:
                raise ValueError("Byte limits must be integers between 1024 and 67108864")
        if self.tool_page_size is not None and (type(self.tool_page_size) is not int or not 1 <= self.tool_page_size <= 1000):
            raise ValueError("tool_page_size must be null or an integer between 1 and 1000")
        if self.operator_key_file is not None and not self.operator_key_id:
            raise ValueError("operator_key_id is required with operator_key_file")
        if self.authority_url:
            self._validate_authority()
        self._validate_workflow_configuration()

    def _validate_workflow_configuration(self) -> None:
        from .workflow_config import parse_records, reference

        for name in ("authorities", "provisioning", "proof_stores"):
            object.__setattr__(self, name, parse_records(name, getattr(self, name)))
        for authority in self.authorities.values():
            # Validate every origin under the parent's explicit HTTP policy.
            self._validate_origin(authority.url)
        fleets = {}
        for name, members in self.fleets.items():
            reference(name)
            if (not isinstance(members, (list, tuple)) or not 1 <= len(members) <= 16
                    or len(set(members)) != len(members) or set(members) - set(self.authorities)):
                raise ValueError("Fleets require 1-16 distinct configured authorities")
            fleets[name] = tuple(members)
        object.__setattr__(self, "fleets", MappingProxyType(fleets))
        object.__setattr__(self, "artifact_roots", MappingProxyType({
            reference(key): Path(value).resolve() for key, value in self.artifact_roots.items()}))
        for name in ("node_runtimes", "peers", "guard_actions"):
            if getattr(self, name):
                from .runtime_config import parse_runtime_config
                object.__setattr__(self, name, parse_runtime_config(name, getattr(self, name)))
            else:
                object.__setattr__(self, name, MappingProxyType({}))
        private_roots = [value.root for value in self.provisioning.values()]
        private_roots.extend(value.state_dir for value in self.node_runtimes.values())
        if self.workflow_state_dir:
            private_roots.append(self.workflow_state_dir)
        if self.workspace and any(root.is_relative_to(self.workspace) or self.workspace.is_relative_to(root)
                                  for root in private_roots):
            raise ValueError("Private workflow, node and provisioning storage must be outside the readable workspace")
        if any(root.is_relative_to(artifact) or artifact.is_relative_to(root)
               for root in private_roots for artifact in self.artifact_roots.values()):
            raise ValueError("Artifact roots must not overlap private workflow, node or provisioning storage")

    def _validate_authority(self) -> None:
        self._validate_origin(self.authority_url or "")

    def _validate_origin(self, url: str) -> None:
        parsed = urlsplit(url)
        if (not parsed.hostname or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment or parsed.path not in ("", "/")
                or "\\" in url or any(ord(c) < 33 for c in url)):
            raise ValueError("authority_url must be an origin without credentials, path, query or fragment")
        try:
            parsed.port
        except ValueError:
            raise ValueError("authority_url has an invalid port") from None
        try:
            loopback = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            loopback = parsed.hostname == "localhost"
        if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback and self.allow_http_loopback):
            raise ValueError("Use HTTPS, or explicitly allow HTTP for a loopback development authority")

    def require(self, profiles: frozenset[str]) -> None:
        if not profiles <= self.profiles:
            raise ToolError("profile_required", "This operation is not enabled by the server configuration.")

    def load_signer(self, reference: str, operation: str | None = None):
        self.require(frozenset({"sign"}))
        path = self.signer_files.get(reference)
        if path is None:
            raise ToolError("signer_not_configured", "The requested signer reference is not configured.")
        if operation is None or operation not in self.signer_permissions.get(reference, frozenset()):
            raise ToolError("signer_not_authorized", "The configured signer is not authorized for this operation.")
        try:
            return load_private_key(str(path))
        except (OSError, ValueError, TypeError):
            raise ToolError("signer_unavailable", "The configured signer could not be loaded.") from None

    def confined_path(self, relative_path: str, *, must_exist: bool = True) -> Path:
        self.require(frozenset({"local"}))
        if self.workspace is None:
            raise ToolError("workspace_required", "Configure a workspace before using local artifacts.")
        candidate = Path(relative_path)
        if (not relative_path or candidate.is_absolute() or candidate.drive or "\\" in relative_path
                or ":" in relative_path or "\x00" in relative_path or ".." in candidate.parts):
            raise ToolError("invalid_path", "Use a relative path inside the configured workspace.")
        resolved = (self.workspace / candidate).resolve()
        if not resolved.is_relative_to(self.workspace):
            raise ToolError("invalid_path", "The artifact path escapes the configured workspace.")
        if must_exist and not resolved.is_file():
            raise ToolError("artifact_not_found", "The requested workspace artifact is not a file.")
        return resolved

    @classmethod
    def from_file(cls, path: Path) -> Settings:
        path = path.resolve()
        if path.stat().st_size > 65_536:
            raise ValueError("Configuration file is too large")
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or set(data) - {f.name for f in fields(cls)}:
            raise ValueError("Configuration must contain only documented settings")
        for name in ("operator_key_file", "node_key_file", "executor_key_file", "workspace", "workflow_state_dir"):
            if data.get(name) is not None:
                data[name] = path.parent / data[name]
        if "signer_files" in data:
            data["signer_files"] = {k: path.parent / v for k, v in data["signer_files"].items()}
        if "profiles" in data:
            data["profiles"] = frozenset(data["profiles"])
        from .workflow_config import parse_records
        for name in ("authorities", "provisioning", "proof_stores"):
            if name in data:
                data[name] = parse_records(name, data[name], path.parent)
        if "artifact_roots" in data:
            data["artifact_roots"] = {key: path.parent / value for key, value in data["artifact_roots"].items()}
        for name in ("node_runtimes", "peers", "guard_actions"):
            if name in data:
                from .runtime_config import parse_runtime_config
                data[name] = parse_runtime_config(name, data[name], path.parent)
        return cls(**data)

    def public_status(self) -> dict[str, Any]:
        return {"profiles": sorted(self.profiles), "authority_configured": bool(self.authority_url),
                "operator_configured": bool(self.operator_key_file), "node_configured": bool(self.node_key_file),
                "signer_references": sorted(self.signer_files), "workspace_configured": bool(self.workspace),
                "signer_permissions": {key: sorted(value) for key, value in self.signer_permissions.items()},
                "signer_backend": "Local key files only; arbitrary key-provider backends are not exposed through MCP.",
                "authority_references": sorted(self.authorities), "fleets": {k: list(v) for k, v in self.fleets.items()},
                "artifact_roots": sorted(self.artifact_roots), "provisioning_references": sorted(self.provisioning),
                "proof_stores": sorted(self.proof_stores), "node_runtimes": sorted(self.node_runtimes),
                "peers": sorted(self.peers), "guard_actions": sorted(self.guard_actions),
                "workflow_state_configured": self.workflow_state_dir is not None,
                "tool_page_size": self.tool_page_size,
                "max_input_bytes": self.max_input_bytes, "max_output_bytes": self.max_output_bytes}
