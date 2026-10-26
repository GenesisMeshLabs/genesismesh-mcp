"""MCP protocol composition, authorization, bounded results and discovery."""

from __future__ import annotations

import importlib
import json
import logging
from collections.abc import Callable
from importlib.metadata import version
from importlib.resources import files
from typing import Any

import anyio
import mcp_types as mt
from jsonschema import Draft202012Validator
from mcp.server.lowlevel import Server
from pydantic import BaseModel, ValidationError

from . import __version__
from .settings import Settings
from .types import ToolError, ToolSpec

logger = logging.getLogger(__name__)
CORE_VERSION = "1.8.1"
PREFIX = "genesis-mesh://"


def build_tools(settings: Settings) -> list[ToolSpec]:
    """All registered definitions; profile filtering is applied by the dispatcher."""
    from .catalog import verify_packaged_snapshot

    if version("genesis-mesh") != CORE_VERSION:
        raise ValueError("The installed Genesis Mesh version does not match the supported core version")
    if verify_packaged_snapshot():
        raise ValueError("Packaged core contract metadata does not match its compatibility pin")
    from .authority import build_tools as authority_tools
    from .local import build_tools as local_tools
    from .local_workflows import build_tools as local_workflow_tools
    from .multi_workflows import build_tools as multi_workflow_tools
    from .offline import build_tools as offline_tools
    from .proof_workflows import build_tools as proof_tools
    from .provision_workflows import build_tools as provision_tools
    from .runtime_workflows import build_tools as runtime_tools
    from .workflow_support import build_tools as support_tools
    from .workflows import build_tools as workflow_tools

    tools = [*authority_tools(settings), *offline_tools(settings), *local_tools(settings), *workflow_tools(settings),
             *local_workflow_tools(settings), *multi_workflow_tools(settings), *proof_tools(settings),
             *provision_tools(settings), *runtime_tools(settings), *support_tools(settings)]
    if len({tool.name for tool in tools}) != len(tools):
        raise ValueError("Duplicate MCP tool registration")
    registered_names = {tool.name for tool in tools}
    for permissions in settings.signer_permissions.values():
        if not permissions <= registered_names:
            raise ValueError("Signer permissions reference an unregistered tool")
    for tool in tools:
        Draft202012Validator.check_schema(tool.input_schema)
    return sorted(tools, key=lambda tool: tool.name)


def _schema_models() -> dict[str, tuple[type[BaseModel], tuple[str, ...]]]:
    from .catalog import load_contract

    contract = load_contract()
    model_targets: dict[str, list[str]] = {}
    for entry in contract["signed_artifacts"]:
        model_targets.setdefault(entry["model"], []).append("artifact:" + entry["model"])
    for entry in contract["python"]:
        symbol = entry["symbol"]
        module, name = symbol.split(":")
        obj = getattr(importlib.import_module(module), name)
        if isinstance(obj, type) and issubclass(obj, BaseModel):
            model_targets.setdefault(symbol, []).append("python:" + symbol)
    found = {}
    for symbol, targets in model_targets.items():
        module, name = symbol.split(":")
        model = getattr(importlib.import_module(module), name)
        found[PREFIX + "schema/" + symbol] = (model, tuple(targets))
    return found


def build_resource_targets() -> dict[str, tuple[str, ...]]:
    from .catalog import load_contract

    contract = load_contract()
    targets = {uri: values for uri, (_, values) in _schema_models().items()}
    targets[PREFIX + "errors"] = tuple("error:" + entry["code"] if isinstance(entry, dict)
                                      else "error:" + entry for entry in contract["error_codes"])
    targets[PREFIX + "packages"] = tuple("package:" + entry["package"] for entry in contract["packages"])
    targets[PREFIX + "rules"] = tuple("rule:" + name for name in contract["rules"])
    targets[PREFIX + "configuration"] = ("python:genesis_mesh.na_service.key_provider:Signer",
                                         "python:genesis_mesh.na_service.key_provider:KeyProviderConfig")
    return targets


resource_targets = build_resource_targets


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def build_resources(tools: list[ToolSpec], settings: Settings) -> dict[str, str]:
    from .catalog import build_catalog, load_compatibility, load_contract
    from .tool_evidence import load_tool_evidence

    contract = load_contract()
    resources = {PREFIX + "contract": _json(contract), PREFIX + "errors": _json(contract["error_codes"]),
                 PREFIX + "packages": _json(contract["packages"]), PREFIX + "rules": _json(contract["rules"]),
                 PREFIX + "tool-evidence": _json(load_tool_evidence()),
                 PREFIX + "compatibility": _json({**load_compatibility(), "installed_core": version("genesis-mesh"),
                                                 "compatible": version("genesis-mesh") == CORE_VERSION}),
                 PREFIX + "configuration": _json(settings.public_status())}
    for uri, (model, _) in _schema_models().items():
        resources[uri] = _json({"model": model.__name__, "schema": model.model_json_schema(),
                                "meaning": "Structural schema only; parsing does not verify signatures or trust."})
    cli_reference = json.loads(files("genesismesh_mcp").joinpath("data/cli-reference.json").read_text("utf-8"))
    for command, reference in cli_reference.items():
        resources[PREFIX + "cli/" + command.replace(" ", "/")] = _json(reference)
    resources[PREFIX + "coverage"] = _json(build_catalog(tools, resources=build_resource_targets(),
                                                        profiles=settings.profiles))
    return resources


PROMPTS = {
    "inspect_trust": "Inspect the configured Genesis Mesh authority using enabled read tools. Explain issuer, sovereign, "
    "trust path, policy, freshness and revocation evidence. Missing information is unknown, never permission.",
    "verify_evidence": "Verify the supplied signed records or audit pack using the Genesis Mesh verification tools. "
    "Obtain root/public-key pins independently of the artifacts. Report verification failures, missing anchors and "
    "completeness limits. Structural validation alone does not establish authenticity.",
    "governed_operation": "Inspect the enabled tool catalog and applicable policy. A boundary ALLOW is an assessment, "
    "not proof an external action executed. Respect named-holder approvals and credentials. Report the actual action, "
    "decision and evidence recorded; do not manufacture approval or successful execution.",
}


def create_server(settings: Settings | None = None, *, tools: list[ToolSpec] | None = None,
                  granted_profiles: Callable[[], frozenset[str]] | None = None) -> Server:
    """The MCP server. ``granted_profiles``, when given, returns the profiles the current
    request may use (the HTTP transport's access token scopes); the configured profiles are
    narrowed to them for listing and calling tools. stdio passes none."""
    settings = settings or Settings()

    def allowed() -> frozenset[str]:
        return settings.profiles if granted_profiles is None else settings.profiles & granted_profiles()

    definitions = build_tools(settings) if tools is None else tools
    by_name = {tool.name: tool for tool in definitions}
    if len(by_name) != len(definitions):
        raise ValueError("Duplicate MCP tool registration")
    validators = {tool.name: Draft202012Validator(tool.input_schema) for tool in definitions}
    resources = build_resources(definitions, settings)

    def page(items, params, prefix: str, size: int | None = 25):
        cursor = params.cursor if params and params.cursor else None
        start = 0
        if cursor:
            if not cursor.startswith(prefix) or not cursor[len(prefix):].isdigit():
                raise ValueError("Invalid pagination cursor")
            start = int(cursor[len(prefix):])
            if start > len(items):
                raise ValueError("Invalid pagination cursor")
        end = len(items) if size is None else min(start + size, len(items))
        return items[start:end], prefix + str(end) if end < len(items) else None

    async def list_tools(ctx, params):
        permitted = allowed()
        enabled = [tool for tool in definitions if tool.profiles <= permitted]
        entries, cursor = page(enabled, params, "tools:", settings.tool_page_size)
        return mt.ListToolsResult(tools=[mt.Tool(name=t.name, description=t.description, inputSchema=t.input_schema,
            annotations=mt.ToolAnnotations(readOnlyHint=t.read_only, destructiveHint=t.destructive,
                                           idempotentHint=t.idempotent,
                                           openWorldHint=t.open_world or any(target.startswith("http:") for target in t.core_targets)),
            _meta={"genesisMesh": {"profiles": sorted(t.profiles), "coreTargets": list(t.core_targets)}})
            for t in entries], nextCursor=cursor)

    async def call_tool(ctx, params):
        try:
            tool = by_name.get(params.name)
            if tool is None:
                raise ToolError("unknown_tool", "No such tool is registered.")
            settings.require(tool.profiles)
            if not tool.profiles <= allowed():
                raise ToolError("scope_required", "The access token's scopes do not include this tool's profiles.")
            args = params.arguments or {}
            if len(_json(args).encode("utf-8")) > settings.max_input_bytes:
                raise ToolError("input_too_large", "The request exceeds the configured input limit.")
            if not validators[tool.name].is_valid(args):
                raise ToolError("invalid_arguments", "Arguments do not match this tool's published JSON schema.")
            result = await anyio.to_thread.run_sync(tool.handler, args)
            encoded = _json(result)
            if len(encoded.encode("utf-8")) > settings.max_output_bytes:
                raise ToolError("output_too_large", "The result exceeds the output limit; no partial artifact is returned.")
            logger.info("tool=%s outcome=completed", tool.name)
            # MCP structuredContent is an object. Preserve the exact JSON value
            # in text, and wrap non-object core results without changing them.
            structured = result if isinstance(result, dict) else {"result": result}
            return mt.CallToolResult(content=[mt.TextContent(type="text", text=encoded)], structuredContent=structured,
                                     isError=isinstance(result, dict) and (result.get("http_ok") is False
                                         or result.get("completed") is False
                                         or result.get("complete") is False
                                         or result.get("status") in ("partial", "unknown", "failed")))
        except ToolError as exc:
            error = {"error": {"code": exc.code, "message": str(exc)}}
        except ValidationError:
            error = {"error": {"code": "invalid_record", "message": "A record failed core model validation."}}
        except (ValueError, TypeError, KeyError, OSError):
            error = {"error": {"code": "operation_failed", "message": "The operation rejected the input or its configuration."}}
        except Exception as exc:  # Transport boundary: never disclose exception arguments or credentials.
            logger.error("tool=%s outcome=failed exception_type=%s", params.name, type(exc).__name__)
            error = {"error": {"code": "internal_error", "message": "The adapter could not complete the operation."}}
        return mt.CallToolResult(content=[mt.TextContent(type="text", text=_json(error))],
                                 structuredContent=error, isError=True)

    async def list_resources(ctx, params):
        entries, cursor = page(sorted(resources), params, "resources:")
        return mt.ListResourcesResult(resources=[mt.Resource(uri=uri, name=uri.removeprefix(PREFIX),
            mimeType="application/json", size=len(resources[uri].encode("utf-8"))) for uri in entries], nextCursor=cursor)

    async def read_resource(ctx, params):
        uri = str(params.uri)
        if uri not in resources:
            raise ValueError("Unknown resource")
        text = resources[uri]
        if len(text.encode("utf-8")) > settings.max_output_bytes:
            raise ValueError("Resource exceeds configured output limit")
        return mt.ReadResourceResult(contents=[mt.TextResourceContents(uri=uri, mimeType="application/json", text=text)])

    async def list_prompts(ctx, params):
        return mt.ListPromptsResult(prompts=[mt.Prompt(name=name, description=text) for name, text in PROMPTS.items()])

    async def get_prompt(ctx, params):
        if params.name not in PROMPTS or params.arguments:
            raise ValueError("Unknown prompt or unexpected arguments")
        return mt.GetPromptResult(messages=[mt.PromptMessage(role="user", content=mt.TextContent(
            type="text", text=PROMPTS[params.name]))])

    return Server("genesismesh-mcp", version=__version__,
        instructions="Genesis Mesh portable-trust adapters. Use coverage and compatibility resources to inspect scope. "
        "Verification, policy assessment, evidence recording and external execution are distinct outcomes.",
        get_tool_input_schema=lambda name: by_name[name].input_schema if name in by_name else None,
        on_list_tools=list_tools, on_call_tool=call_tool, on_list_resources=list_resources,
        on_read_resource=read_resource, on_list_prompts=list_prompts, on_get_prompt=get_prompt)
