"""Bounded authority access and pinned core review for composed workflows."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from time import monotonic
from typing import Any
from urllib.parse import urlsplit

from genesis_mesh.crypto import verify_model_signature
from genesis_mesh.models import GenesisBlock
from genesis_mesh.workflows.federation import _review_sovereign

from . import authority
from .settings import Settings
from .types import ToolError
from .workflow_support import pinned_root, select_authority
from .workflows import _PublicSession


class Deadline:
    """Shared elapsed-time and response-memory budgets for one workflow call."""

    def __init__(self, settings: Settings):
        self.end = monotonic() + settings.timeout_seconds
        self.remaining_bytes = settings.max_output_bytes

    def settings(self, settings: Settings) -> Settings:
        remaining = self.end - monotonic()
        if remaining <= 0:
            raise ToolError("workflow_deadline", "The workflow exceeded its elapsed-time budget.")
        if self.remaining_bytes < 1024:
            raise ToolError("workflow_response_budget", "The workflow exhausted its aggregate response budget.")
        return replace(settings, timeout_seconds=min(settings.timeout_seconds, remaining),
                       max_output_bytes=min(settings.max_output_bytes, self.remaining_bytes))

    def consume(self, response: Any) -> None:
        size = len(json.dumps(response, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8"))
        self.remaining_bytes -= size
        if self.remaining_bytes < 0:
            raise ToolError("workflow_response_budget", "The workflow exceeded its aggregate response budget.")


class WorkflowFailure(ToolError):
    def __init__(self, code: str, message: str, details: Any = None):
        super().__init__(code, message)
        self.details = details


def safe_error(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, ToolError):
        result = {"code": exc.code, "message": str(exc)}
        if isinstance(exc, WorkflowFailure) and exc.details is not None:
            result["details"] = exc.details
        return result
    return {"code": "workflow_failed", "message": "The composed workflow could not complete."}


def digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


class Client:
    def __init__(self, settings: Settings, alias: str, tool_name: str, deadline: Deadline, *, require_root=True):
        self.alias = alias
        self.settings = select_authority(settings, alias, tool_name)
        self.root = pinned_root(settings, alias) if require_root else None
        self.deadline = deadline

    def raw(self, method: str, path: str, *, body=None, query=None, parameters=None):
        operation = next((op for op in authority.operations() if op["method"] == method and op["path"] == path), None)
        if operation is None:
            raise ToolError("operation_not_allowed", "The workflow requested an unsupported authority operation.")
        arguments = {}
        if body is not None:
            arguments["body"] = body
        if query is not None:
            arguments["query"] = query
        if parameters is not None:
            arguments["path"] = parameters
        response = authority.invoke(self.deadline.settings(self.settings), operation, arguments)
        self.deadline.consume(response["result"])
        return response

    def call(self, method: str, path: str, *, expected: int = 200, **kwargs):
        return checked(self.raw(method, path, **kwargs), expected)

    def require_operator(self):
        self.settings.require(frozenset({"read", "operator", "write"}))
        if not self.settings.authority_public_key or not self.settings.operator_key_id:
            raise ToolError("operator_required", "Every writing authority requires a pinned operator identity.")
        authority._key(self.settings, "operator")

    def identity(self):
        return {"alias": self.alias, "url": self.settings.authority_url,
                "authority_public_key": self.settings.authority_public_key, "root_public_key": self.root}


def checked(response: dict[str, Any], expected: int = 200):
    if response["http_status"] != expected:
        raise WorkflowFailure("authority_rejected", "The authority rejected a workflow step.", response)
    return response["result"]


class ReviewSession(_PublicSession):
    def __init__(self, client: Client):
        super().__init__(client.settings)
        self.client = client
        self.material: dict[str, Any] = {}

    def request(self, method: str, url: str, **kwargs):
        self.settings = self.client.deadline.settings(self.client.settings)
        response = super().request(method, url, **kwargs)
        self.client.deadline.consume(response.payload)
        self.material[urlsplit(url).path] = response.payload
        return response


def review(client: Client) -> dict[str, Any]:
    """Reuse core review, then authenticate its genesis against configured pins."""
    session = ReviewSession(client)
    result = _review_sovereign(session, client.settings.authority_url, client.alias)
    genesis = GenesisBlock.model_validate(session.material["/genesis"])
    if (genesis.root_public_key != client.root
            or result["root_public_key"] != client.root
            or result["network_authority"]["public_key"] != client.settings.authority_public_key):
        raise ToolError("authority_pin_mismatch", "The authority's public material differs from its configured pins.")
    if not any(verify_model_signature(genesis, signature, client.root) for signature in genesis.signatures):
        raise ToolError("genesis_signature_invalid", "The authority genesis does not verify against its configured root.")
    result["genesis_signature_verified"] = True
    return result


def distinct_pair(acceptor: Client, issuer: Client, reviews: tuple[dict, dict]) -> None:
    if (acceptor.alias == issuer.alias or acceptor.settings.authority_url == issuer.settings.authority_url
            or reviews[0]["sovereign_id"] == reviews[1]["sovereign_id"]):
        raise ToolError("distinct_authorities_required", "Select two distinct configured sovereign authorities.")
