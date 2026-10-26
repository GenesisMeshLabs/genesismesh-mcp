"""Named, constrained adapters for the pinned Network Authority HTTP contract."""

from __future__ import annotations

import base64
import json
import re
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from functools import lru_cache
from importlib.resources import files
from time import monotonic
from typing import Any
from urllib.parse import quote, urlencode

import requests
from genesis_mesh.crypto import sign_data, sign_model
from genesis_mesh.crypto.admin_auth import sign_admin_request
from genesis_mesh.crypto.node_auth import NODE_PURPOSES, sign_executor_proof, sign_node_request
from genesis_mesh.models import AgentDescriptor
from genesis_mesh.strict_json import loads as strict_loads
from jsonschema import Draft202012Validator, FormatChecker
from urllib3.exceptions import HTTPError as ResponseReadError

from .authority_schemas import S, body_schema, obj, query_schema
from .settings import Settings, load_key_file
from .types import ToolError, ToolSpec

PATH_FIELD = re.compile(r"<(path:)?([^>]+)>")


@lru_cache(maxsize=1)
def operations() -> tuple[dict[str, Any], ...]:
    data = files("genesismesh_mcp").joinpath("data/authority_operations.json").read_text("utf-8")
    return tuple(json.loads(data))


def input_schema(operation: dict[str, Any]) -> dict[str, Any]:
    method, path = operation["method"], operation["path"]
    properties: dict[str, Any] = {}
    required: list[str] = []
    params = {name: {**S, "minLength": 1} for _, name in PATH_FIELD.findall(path)}
    if operation["auth"] == "agent_delete":
        # Deregistration always targets the configured node's own key.
        params = {}
    if params:
        properties["path"] = obj(params, tuple(params))
        required.append("path")
    query = query_schema(method, path)
    if path == "/attestations" and operation["auth"] == "public":
        query = obj({"status": S})
    if query["properties"]:
        properties["query"] = query
        if "allOf" in query:
            required.append("query")
    body = body_schema(method, path)
    if body["properties"]:
        properties["body"] = body
        if body["required"] or "oneOf" in body:
            required.append("body")
    return obj(properties, tuple(required))


def profiles_for(operation: dict[str, Any]) -> frozenset[str]:
    if operation["auth"] in {"node", "agent_descriptor", "agent_delete"}:
        return frozenset({"node", "write"})
    if operation["auth"] == "operator":
        return frozenset({"operator", "read" if operation["effect"] == "read" else "write"})
    if operation["effect"] == "verify":
        return frozenset({"verify"})
    return frozenset({"read" if operation["effect"] == "read" else "write"})


def _key(settings: Settings, kind: str):
    path = getattr(settings, f"{kind}_key_file")
    if path is None:
        raise ToolError("identity_not_configured", f"A dedicated {kind} identity is required.")
    try:
        return load_key_file(path)
    except ToolError:
        raise
    except Exception:
        raise ToolError("identity_unavailable", "The configured identity could not be loaded.") from None


def _public_key(key: Any) -> str:
    return base64.b64encode(bytes(key.verify_key)).decode("ascii")


def _render_path(template: str, parameters: dict[str, str]) -> tuple[str, str]:
    """Return decoded signing path and independently encoded wire path."""
    def substitute(match: re.Match[str], *, encoded: bool) -> str:
        is_path, name = match.groups()
        value = parameters[name]
        if (not isinstance(value, str) or not value or "\\" in value or "%" in value
                or any(ord(char) < 32 or ord(char) == 127 for char in value)
                or any(part in {".", ".."} for part in value.split("/"))
                or (not is_path and "/" in value)):
            raise ToolError("invalid_path_parameter", "Path identifiers must not contain traversal or ambiguous escapes.")
        # path converters permit slashes, including the consecutive slashes of
        # base64 keys. Percent-encode them; Flask decodes the captured value.
        return quote(value, safe="") if encoded else value
    return (PATH_FIELD.sub(lambda match: substitute(match, encoded=False), template),
            PATH_FIELD.sub(lambda match: substitute(match, encoded=True), template))


def _request_parts(settings: Settings, operation: dict[str, Any], arguments: dict[str, Any]):
    body = deepcopy(arguments.get("body", {}))
    path_parameters = dict(arguments.get("path", {}))
    query = dict(arguments.get("query", {}))
    headers = {"Accept": "application/json", "Accept-Encoding": "identity"}
    auth = operation["auth"]
    now = datetime.now(timezone.utc).isoformat()
    if auth in {"node", "agent_descriptor", "agent_delete"}:
        node_key = _key(settings, "node")
        public_key = _public_key(node_key)
        if auth == "agent_delete":
            path_parameters = {"node_public_key": public_key}
            body = {"version": "v1", "signed_at": now,
                    "signature": sign_data(f"delete-agent|v1|{public_key}|{now}".encode(), node_key)}
        elif auth == "agent_descriptor":
            descriptor = AgentDescriptor.model_validate({**body, "node_public_key": public_key, "registered_at": now})
            descriptor.signatures = [sign_model(descriptor, node_key, public_key)]
            body = descriptor.model_dump(mode="json")
        else:
            body.update(node_public_key=public_key, timestamp=now, nonce=str(uuid.uuid4()))
            if operation["path"] in NODE_PURPOSES:
                if not settings.authority_public_key:
                    raise ToolError("audience_required", "Configure the pinned authority public key for node requests.")
                body.update(purpose=NODE_PURPOSES[operation["path"]], audience=settings.authority_public_key)
            if operation["path"] == "/join":
                token = getattr(settings, "invite_token", None)
                if not token:
                    raise ToolError("invite_required", "Configure the enrollment invite token outside the conversation.")
                body["invite_token"] = token
                if body.pop("edge", False):
                    executor = _key(settings, "executor")
                    body["executor_public_key"] = _public_key(executor)
                    body = sign_executor_proof(body, executor)
            body = sign_node_request(body, node_key)
    decoded_path, wire_path = _render_path(operation["path"], path_parameters)
    if auth == "operator":
        if not settings.authority_public_key:
            raise ToolError("audience_required", "Configure the pinned authority public key for operator requests.")
        if not settings.operator_key_id:
            raise ToolError("operator_id_required", "Configure an operator key identifier.")
        headers.update(sign_admin_request(_key(settings, "operator"), settings.operator_key_id,
                                         method=operation["method"], path=decoded_path,
                                         audience=settings.authority_public_key, body=body, query=query))
    url = (settings.authority_url or "").rstrip("/") + wire_path
    if query:
        url += "?" + urlencode(query)
    data = None
    if operation["method"] != "GET":
        data = json.dumps(body, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
        if len(data) > settings.max_input_bytes:
            raise ToolError("input_too_large", "The signed request exceeds the configured input limit.")
    return url, headers, data


def _contains_secret(value: Any, secrets: tuple[str, ...]) -> bool:
    # Refuse the response rather than rewriting signed content. Public keys and
    # user-requested newly issued invite tokens are legitimate result fields.
    encoded = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
    return any(secret and secret in encoded for secret in secrets)


def _read_response(settings: Settings, operation: dict[str, Any], response: requests.Response,
                   deadline: float) -> dict[str, Any]:
    def check_deadline() -> None:
        if monotonic() > deadline:
            raise ToolError("authority_response_deadline", "The response exceeded its elapsed-time budget. It was not retried; a mutation's outcome may be unknown.")

    check_deadline()
    if 300 <= response.status_code < 400:
        raise ToolError("authority_redirect_refused", "The authority returned a redirect; it was not followed.")
    length = response.headers.get("Content-Length")
    if length:
        try:
            if int(length) < 0 or int(length) > settings.max_output_bytes:
                raise ToolError("output_too_large", "The authority response exceeds the configured byte limit.")
        except ValueError:
            raise ToolError("invalid_response", "The authority sent an invalid content length.") from None
    chunks: list[bytes] = []
    size = 0
    def chunks_available():
        # urllib3 read1 yields available bytes after at most one underlying
        # read, unlike read(65536), which may wait indefinitely for a complete
        # chunk from a peer trickling bytes within its inactivity timeout.
        read1 = getattr(response.raw, "read1", None)
        if callable(read1):
            while True:
                check_deadline()
                chunk = read1(min(65536, settings.max_output_bytes + 1), decode_content=True)
                if not chunk:
                    break
                yield chunk
        else:
            yield from response.iter_content(chunk_size=min(65536, settings.max_output_bytes + 1))

    for chunk in chunks_available():
        check_deadline()
        size += len(chunk)
        if size > settings.max_output_bytes:
            raise ToolError("output_too_large", "The authority response exceeds the configured byte limit; no signed content was truncated.")
        chunks.append(chunk)
    raw = b"".join(chunks)
    check_deadline()
    try:
        if operation["response"] == "json" or response.status_code >= 400:
            body = strict_loads(raw)
        else:
            body = raw.decode("utf-8", errors="strict")
    except Exception:
        raise ToolError("invalid_authority_response", "The authority returned an invalid response encoding or JSON document.") from None
    # The only secret placed in outbound bodies is the configured enrollment
    # token. Signer seeds are never sent and transport errors never reveal them.
    if _contains_secret(body, (getattr(settings, "invite_token", None) or "",)):
        raise ToolError("sensitive_authority_response", "The authority response unexpectedly contained a configured credential.")
    return {"http_status": response.status_code, "http_ok": 200 <= response.status_code < 300,
            "response_format": operation["response"], "result": body}


def invoke(settings: Settings, operation: dict[str, Any], arguments: dict[str, Any]) -> dict[str, Any]:
    settings.require(profiles_for(operation))
    validator = Draft202012Validator(input_schema(operation), format_checker=FormatChecker())
    if next(validator.iter_errors(arguments), None) is not None:
        raise ToolError("invalid_arguments", "Arguments do not match this operation's request schema.")
    try:
        if len(json.dumps(arguments, allow_nan=False).encode("utf-8")) > settings.max_input_bytes:
            raise ToolError("input_too_large", "Arguments exceed the configured input limit.")
    except (ValueError, TypeError):
        raise ToolError("invalid_arguments", "Arguments must contain finite JSON values.") from None
    if not settings.authority_url:
        raise ToolError("authority_not_configured", "Configure an authority origin before invoking HTTP tools.")
    url, headers, data = _request_parts(settings, operation, arguments)
    # A fresh session avoids shared cookies, mutable request state and credentials
    # inherited from proxies/netrc. Both transport and HTTP retries are disabled.
    with requests.Session() as session:
        session.trust_env = False
        session.mount("http://", requests.adapters.HTTPAdapter(max_retries=0))
        session.mount("https://", requests.adapters.HTTPAdapter(max_retries=0))
        try:
            deadline = monotonic() + settings.timeout_seconds
            with session.request(operation["method"], url, headers=headers, data=data,
                                 timeout=settings.timeout_seconds, allow_redirects=False, stream=True) as response:
                return _read_response(settings, operation, response, deadline)
        except (requests.RequestException, ResponseReadError):
            raise ToolError("authority_unavailable", "The authority request failed. It was not retried; a mutation's outcome may be unknown.") from None


def build_tools(settings: Settings) -> list[ToolSpec]:
    tools: list[ToolSpec] = []
    for operation in operations():
        description = (f"{operation['description']} [{operation['stability']}; {operation['auth']}; "
                       f"{operation['method']} {operation['path']}]. Returns the authority result unchanged; "
                       "HTTP success is not proof of authorization or external execution.")
        if operation["path"] == "/admin/invite":
            description += " Sensitive output: the newly issued enrollment token is a bearer capability."
        if operation["name"] == "na_health_list_nodes":
            description += " Public count only; use na_nodes_roster for the operator-signed inventory."
        if operation["name"] == "na_attestations_list_attestations":
            description += " Public count only; use na_attestations_roster for signed listing and subject/issuer filters."
        tools.append(ToolSpec(name=operation["name"], description=description,
                              input_schema=input_schema(operation),
                              handler=lambda args, op=operation: invoke(settings, op, args),
                              profiles=profiles_for(operation), read_only=operation["effect"] in {"read", "verify"},
                              destructive=operation["destructive"], idempotent=operation["method"] == "GET",
                              core_targets=(f"http:{operation['method']} {operation['path']}",)))
    return tools
