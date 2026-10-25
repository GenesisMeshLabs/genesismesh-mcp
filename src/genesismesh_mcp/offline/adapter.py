"""Typed JSON adaptation for the reviewed operation list.

Imports, callables, registries and signer paths are never client controlled.
No domain rules are reimplemented here.
"""

from __future__ import annotations

import base64
import collections.abc
import dataclasses
import inspect
import json
import types
from datetime import date, datetime, timedelta
from enum import Enum
from typing import Annotated, Any, Union, get_args, get_origin, get_type_hints

from genesis_mesh.models.evidence_store import EvidenceEvent
from jsonschema import Draft202012Validator
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, TypeAdapter, create_model

from genesismesh_mcp.types import ToolSpec

SIGNER_PARAMETERS = frozenset({
    "signing_key", "private_key", "agent_signing_key", "human_signing_key",
    "assembler_signing_key",
})


def json_value(value: Any) -> Any:
    """Preserve structured core results; binary values use standard base64."""
    if isinstance(value, BaseModel):
        # Some core records omit absent fields as part of their signed wire
        # contract. Preserve that form, including when nested in a dataclass.
        to_wire = getattr(value, "to_wire", None)
        if callable(to_wire):
            return json_value(to_wire())
        # Honor core Field(exclude_if=...) and serializer field selection, but
        # retain nested model types long enough to honor their wire methods.
        dumped = value.model_dump(mode="python", by_alias=True)
        fields = {field.serialization_alias or field.alias or name: name
                  for name, field in type(value).model_fields.items()}
        return {name: json_value(getattr(value, fields[name]) if name in fields else raw)
                for name, raw in dumped.items()}
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: json_value(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, Enum):
        return json_value(value.value)
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if isinstance(value, (datetime, date)):
        # Match core Pydantic JSON serialization (notably UTC 'Z') exactly.
        return TypeAdapter(type(value)).dump_python(value, mode="json")
    if isinstance(value, timedelta):
        return TypeAdapter(timedelta).dump_python(value, mode="json")
    if isinstance(value, dict):
        return {str(k): json_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [json_value(v) for v in value]
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    raise TypeError("Core returned an unsupported result type")


def _received_evidence_event(value: Any) -> EvidenceEvent:
    """Let core validate and retain the envelope digest before Pydantic normalization."""
    from genesis_mesh.trust.evidence_store import parse_export_lines

    return parse_export_lines([json.dumps(value, ensure_ascii=False, allow_nan=False)])[0]


def wire_type(annotation: Any) -> Any:
    """Use eager JSON collections instead of lazy generators for validation."""
    origin, args = get_origin(annotation), get_args(annotation)
    if annotation is EvidenceEvent:
        return Annotated[EvidenceEvent, BeforeValidator(_received_evidence_event)]
    if annotation is bytes:
        return str
    if origin in (collections.abc.Iterable, collections.abc.Sequence):
        return list[wire_type(args[0])]
    if origin in (collections.abc.Mapping, dict):
        return dict[wire_type(args[0]), wire_type(args[1])]
    if origin in (list, set, frozenset):
        return origin[wire_type(args[0])]
    if origin is tuple:
        return tuple[tuple(wire_type(a) if a is not Ellipsis else a for a in args)]
    if origin in (Union, types.UnionType):
        return Union[tuple(wire_type(a) for a in args)]
    return annotation


def decode_bytes(value: Any, annotation: Any) -> Any:
    if annotation is bytes:
        try:
            return base64.b64decode(value, validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("Binary arguments must be standard base64") from exc
    origin, args = get_origin(annotation), get_args(annotation)
    if value is None:
        return None
    if origin in (dict, collections.abc.Mapping):
        return {k: decode_bytes(v, args[1]) for k, v in value.items()}
    if origin in (list, set, frozenset, collections.abc.Iterable, collections.abc.Sequence):
        return [decode_bytes(v, args[0]) for v in value]
    if origin is tuple:
        return tuple(decode_bytes(v, args[0] if len(args) == 2 and args[1] is Ellipsis else args[i]) for i, v in enumerate(value))
    return value


def close_models(schema: Any) -> None:
    """Reject unknown model fields instead of silently changing signed payloads."""
    if isinstance(schema, dict):
        if schema.get("type") == "object" and "properties" in schema:
            schema["additionalProperties"] = False
        for value in schema.values():
            close_models(value)
    elif isinstance(schema, list):
        for value in schema:
            close_models(value)


def _check_allocation_bounds(kwargs: dict[str, Any], limit: int) -> None:
    block = kwargs.get("block_bytes")
    profile = kwargs.get("profile")
    if profile is not None and hasattr(profile, "message_length_block_bytes"):
        block = profile.message_length_block_bytes
        if profile.timestamp_bucket_seconds <= 0:
            raise ValueError("timestamp_bucket_seconds must be positive")
    if block is not None and not 1 <= block <= limit:
        raise ValueError("Padding block exceeds the configured output bound")
    if "bucket_seconds" in kwargs and kwargs["bucket_seconds"] <= 0:
        raise ValueError("bucket_seconds must be positive")


def _check_workload_bounds(name: str, kwargs: dict[str, Any]) -> None:
    """Bound known quadratic core operations before allocating their worksets."""
    max_comparisons = 100_000
    if name in {"check_completeness", "verify_audit_pack"} and kwargs.get("changes"):
        if name == "verify_audit_pack":
            files = kwargs.get("files", {})
            records = sum(len(data.splitlines()) for key, data in files.items()
                          if key.endswith(".jsonl") and isinstance(data, bytes))
        else:
            records = len(kwargs.get("entries", [])) + len(kwargs.get("cited", []))
        if len(kwargs["changes"]) * records > max_comparisons:
            raise ValueError("Audit completeness exceeds 100000 comparison budget; split the audit period")
    if name == "build_trust_path_cache":
        graph = kwargs.get("graph", {})
        size = len(graph.get("sovereigns", [])) + len(graph.get("recognition_edges", []))
        if len(kwargs.get("pairs", [])) * size > max_comparisons:
            raise ValueError("Atlas cache exceeds 100000 graph-work budget; request fewer pairs")


def make_tool(settings: Any, function: Any, module: str, name: str,
              cli: tuple[str, ...] = (), *, fixed: dict[str, Any] | None = None,
              extra_targets: tuple[str, ...] = (), target: str | None = None) -> ToolSpec:
    """Bind one reviewed callable; unknown annotations fail at construction."""
    from genesis_mesh.trust.context import GateRegistry

    signature = inspect.signature(function)
    annotations = get_type_hints(function)
    fixed = dict(fixed or {})
    fields: dict[str, Any] = {}
    signers: dict[str, str] = {}
    for param_name, parameter in signature.parameters.items():
        if param_name in fixed:
            continue
        if param_name in SIGNER_PARAMETERS:
            wire_name = "signer_ref" if param_name in {"signing_key", "private_key"} else param_name.removesuffix("_signing_key") + "_signer_ref"
            signers[param_name] = wire_name
            fields[wire_name] = (str, Field(description="Name of a server-configured signer; never a key or file path", min_length=1))
        elif annotations.get(param_name) is GateRegistry:
            fixed[param_name] = GateRegistry.default()
        else:
            annotation = annotations.get(param_name)
            if annotation is None or parameter.kind in (parameter.VAR_POSITIONAL, parameter.VAR_KEYWORD):
                raise TypeError(f"Unreviewed signature: {module}:{name}:{param_name}")
            default = ... if parameter.default is inspect.Parameter.empty else parameter.default
            if annotation is bytes:
                fields[param_name] = (str, Field(default=default, description="Standard base64-encoded binary data"))
            else:
                fields[param_name] = (wire_type(annotation), default)

    model = create_model("Offline_" + name, __config__=ConfigDict(extra="forbid"), **fields)
    schema = model.model_json_schema()
    close_models(schema)
    validator = Draft202012Validator(schema)
    profiles = frozenset({"sign"} if signers else {"verify"})
    domain = module.rsplit(".", 1)[-1]
    tool_name = f"gm_offline_{domain}_{name}"

    def invoke(arguments: dict[str, Any]) -> Any:
        settings.require(profiles)
        if len(json.dumps(arguments, ensure_ascii=False, allow_nan=False).encode("utf-8")) > settings.max_input_bytes:
            raise ValueError("Arguments exceed configured input limit")
        # Error text deliberately omits input values (which may contain secrets).
        if next(validator.iter_errors(arguments), None) is not None:
            raise ValueError("Arguments do not match the operation schema")
        parsed = model.model_validate(arguments)
        kwargs = {key: getattr(parsed, key) for key in fields}
        kwargs = {key: decode_bytes(value, annotations.get(key)) for key, value in kwargs.items()}
        kwargs.update(fixed)
        for parameter, reference in signers.items():
            kwargs[parameter] = settings.load_signer(kwargs.pop(reference), operation=tool_name)
        _check_allocation_bounds(kwargs, settings.max_output_bytes)
        _check_workload_bounds(name, kwargs)
        result = json_value(function(**kwargs))
        if len(json.dumps(result, ensure_ascii=False, allow_nan=False).encode("utf-8")) > settings.max_output_bytes:
            raise ValueError("Core result exceeds configured output limit; narrow the request")
        return result

    description = (inspect.getdoc(function) or name.replace("_", " ")).split("\n\n")[0]
    description += " Offline core operation; no external action is executed. Binary values are base64."
    description += f" Core adapter: {target or ('genesis_mesh.' + module + ':' + name)}."
    if signers:
        description += " Produces a signed artifact using only a configured signer."
    if name in {"approve_commitment", "reject_commitment"}:
        description += " Artifact signing does not establish that a separate human approved; the host must gate custodian-key use."
    return ToolSpec(
        name=tool_name, description=description,
        input_schema=schema, handler=invoke, profiles=profiles,
        read_only=not signers, destructive=False,
        idempotent=not signers and name.startswith(("verify_", "check_", "validate_", "lookup_", "bundle_")),
        core_targets=(target or f"python:genesis_mesh.{module}:{name}",)
        + tuple("cli:" + leaf for leaf in cli) + extra_targets,
    )
