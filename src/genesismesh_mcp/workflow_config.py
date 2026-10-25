"""Immutable destinations and storage owned by the MCP server operator."""

from __future__ import annotations

import re
from dataclasses import dataclass, fields
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")


def reference(value: str) -> str:
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise ValueError("Configuration references must be simple names of at most 80 characters")
    return value


@dataclass(frozen=True)
class AuthorityConfig:
    url: str
    public_key: str
    root_public_key: str | None = None
    operator_key_file: Path | None = None
    operator_key_id: str | None = None
    allowed_tools: frozenset[str] = frozenset()

    def __post_init__(self):
        from .settings import Settings

        Settings(authority_url=self.url, allow_http_loopback=True, operator_key_file=self.operator_key_file,
                 operator_key_id=self.operator_key_id)
        if not self.public_key:
            raise ValueError("Every named authority requires a public-key pin")
        object.__setattr__(self, "allowed_tools", frozenset(self.allowed_tools))
        if "*" in self.allowed_tools:
            raise ValueError("Authority permissions require exact tool names")
        if self.operator_key_file is not None:
            object.__setattr__(self, "operator_key_file", Path(self.operator_key_file).resolve())


@dataclass(frozen=True)
class ProvisionConfig:
    root: Path
    host: str = "127.0.0.1"
    base_port: int = 8443
    max_members: int = 16

    def __post_init__(self):
        import ipaddress

        object.__setattr__(self, "root", Path(self.root).resolve())
        if self.host != "localhost":
            ipaddress.ip_address(self.host)
        if type(self.base_port) is not int or not 1024 <= self.base_port <= 65520:
            raise ValueError("Provisioning base_port must be between 1024 and 65520")
        if type(self.max_members) is not int or not 1 <= self.max_members <= 16:
            raise ValueError("Provisioning supports at most 16 members")


@dataclass(frozen=True)
class ProofStoreConfig:
    db_path: Path
    backup_dir: Path
    receipt_dir: Path
    receipt_signer: str
    disposable: bool = False
    owned: bool = False
    allowed_tools: frozenset[str] = frozenset()

    def __post_init__(self):
        for key in ("db_path", "backup_dir", "receipt_dir"):
            object.__setattr__(self, key, Path(getattr(self, key)).resolve())
        reference(self.receipt_signer)
        object.__setattr__(self, "allowed_tools", frozenset(self.allowed_tools))
        if "*" in self.allowed_tools or type(self.disposable) is not bool or type(self.owned) is not bool:
            raise ValueError("Proof stores require explicit permissions and a boolean disposable flag")


def parse_records(kind: str, values: Mapping[str, Any], base: Path | None = None) -> Mapping[str, Any]:
    classes = {"authorities": (AuthorityConfig, ("operator_key_file",)),
               "provisioning": (ProvisionConfig, ("root",)),
               "proof_stores": (ProofStoreConfig, ("db_path", "backup_dir", "receipt_dir"))}
    cls, path_fields = classes[kind]
    if not isinstance(values, Mapping) or len(values) > 64:
        raise ValueError("Configuration registries must contain at most 64 named entries")
    result = {}
    for name, value in values.items():
        reference(name)
        if isinstance(value, cls):
            result[name] = value
            continue
        if not isinstance(value, dict) or set(value) - {f.name for f in fields(cls)}:
            raise ValueError(f"Unknown fields in {kind} configuration")
        data = dict(value)
        if base is not None:
            for key in path_fields:
                if data.get(key) is not None:
                    data[key] = base / data[key]
        result[name] = cls(**data)
    return MappingProxyType(result)
