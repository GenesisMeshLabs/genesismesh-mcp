"""Immutable, server-owned node, peer and guard configuration."""

from __future__ import annotations

import base64
import ipaddress
import re
from dataclasses import dataclass, field, fields
from pathlib import Path
from types import MappingProxyType
from typing import Mapping
from urllib.parse import urlsplit

_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


def _key(value: str | None, name: str, *, optional: bool = False) -> None:
    if optional and value is None:
        return
    try:
        if not isinstance(value, str) or len(base64.b64decode(value, validate=True)) != 32:
            raise ValueError
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a base64 Ed25519 public key") from None


def _name(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        raise ValueError(f"{field_name} must be a bounded configuration reference")


@dataclass(frozen=True)
class NodeConfig:
    authority: str
    state_dir: Path
    root_public_key: str | None = None
    node_key_file: Path | None = None
    invite_token: str | None = field(default=None, repr=False)

    def __post_init__(self):
        _name(self.authority, "authority")
        object.__setattr__(self, "state_dir", Path(self.state_dir).resolve())
        if self.node_key_file is not None:
            object.__setattr__(self, "node_key_file", Path(self.node_key_file).resolve())
        _key(self.root_public_key, "root_public_key", optional=True)
        if self.invite_token is not None and (not isinstance(self.invite_token, str)
                                             or not 1 <= len(self.invite_token) <= 4096):
            raise ValueError("invite_token must be a bounded string")


@dataclass(frozen=True)
class PeerConfig:
    node: str
    endpoint: str
    peer_public_key: str
    recipient_public_key: str | None = None

    def __post_init__(self):
        _name(self.node, "node")
        _key(self.peer_public_key, "peer_public_key")
        _key(self.recipient_public_key, "recipient_public_key", optional=True)
        uri = urlsplit(self.endpoint)
        if (uri.scheme not in {"ws", "wss"} or not uri.hostname or uri.username is not None
                or uri.password is not None or uri.query or uri.fragment or "\\" in self.endpoint
                or any(ord(c) < 33 for c in self.endpoint) or len(self.endpoint) > 2048):
            raise ValueError("Peer endpoint must be a ws/wss URL without credentials, query or fragment")
        try:
            uri.port
        except ValueError:
            raise ValueError("Peer endpoint has an invalid port") from None


@dataclass(frozen=True)
class GuardAction:
    port: int
    guard_public_key: str
    guard_sovereign_id: str
    agent_sovereign_id: str
    signer: str
    capability: str
    command: tuple[str, ...]
    host: str = "127.0.0.1"
    allowed_env: tuple[str, ...] = ()

    def __post_init__(self):
        # TCP mediation has no TLS. Restrict it to literal loopback addresses;
        # do not allow DNS names that can resolve elsewhere after validation.
        try:
            loopback = ipaddress.ip_address(self.host).is_loopback
        except ValueError:
            loopback = False
        if not loopback or type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("Guard actions require a literal loopback host and a valid port")
        _key(self.guard_public_key, "guard_public_key")
        _name(self.signer, "signer")
        for key in ("guard_sovereign_id", "agent_sovereign_id", "capability"):
            value = getattr(self, key)
            if not isinstance(value, str) or not value or len(value) > 512 or any(ord(c) < 32 for c in value):
                raise ValueError(f"{key} must be a nonempty bounded string")
        if isinstance(self.command, str) or not 1 <= len(self.command) <= 64:
            raise ValueError("Guard command must be an explicit bounded argument list")
        if any(not isinstance(v, str) or not v or len(v) > 4096 or "\x00" in v for v in self.command):
            raise ValueError("Guard command arguments must be nonempty bounded strings")
        if isinstance(self.allowed_env, str) or len(self.allowed_env) > 64 or any(
            not isinstance(v, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", v)
            for v in self.allowed_env
        ):
            raise ValueError("Guard environment entries must be variable names")
        object.__setattr__(self, "command", tuple(self.command))
        object.__setattr__(self, "allowed_env", tuple(self.allowed_env))


def parse_runtime_config(kind: str, mapping: Mapping, base: Path | None = None) -> Mapping:
    """Parse only known fields, resolving configured paths before freezing."""
    classes = {"node_runtimes": NodeConfig, "peers": PeerConfig, "guard_actions": GuardAction}
    cls = classes[kind]
    if not isinstance(mapping, Mapping) or len(mapping) > 64:
        raise ValueError(f"{kind} must be a mapping of at most 64 configured entries")
    result = {}
    for name, raw in mapping.items():
        _name(name, kind)
        if isinstance(raw, cls):
            result[name] = raw
            continue
        if not isinstance(raw, Mapping) or set(raw) - {f.name for f in fields(cls)}:
            raise ValueError(f"{kind} entries contain only documented fields")
        values = dict(raw)
        if cls is NodeConfig:
            for field_name in ("state_dir", "node_key_file"):
                if values.get(field_name) is not None:
                    values[field_name] = (base or Path.cwd()) / values[field_name]
        try:
            result[name] = cls(**values)
        except TypeError:
            raise ValueError(f"{kind} entry is missing a required field") from None
    return MappingProxyType(result)
