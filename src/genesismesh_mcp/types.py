"""Small shared adapter interfaces, independent of the MCP transport."""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


class ToolError(Exception):
    """An intentional safe error whose message may be shown to an MCP client."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[dict[str, Any]], Any] = field(repr=False, compare=False)
    profiles: frozenset[str] = frozenset({"verify"})
    read_only: bool = False
    destructive: bool = False
    idempotent: bool = False
    core_targets: tuple[str, ...] = ()
    open_world: bool = False
