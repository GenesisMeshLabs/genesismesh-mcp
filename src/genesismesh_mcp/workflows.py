"""Small composed adapters; the core owns bundle construction and Atlas rendering."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from genesis_mesh.models.evidence import TrustEvidence
from genesis_mesh.na_service.operator_console.atlas import render_atlas_standalone
from genesis_mesh.trust.evidence import graph_digest_from_export, verify_trust_evidence
from genesis_mesh.workflows.trust_bundle import (
    bundle_hash,
    bundle_summary,
    export_trust_bundle,
    fetch_public_material,
    validate_trust_bundle,
)

from . import authority
from .offline.adapter import close_models
from .settings import Settings
from .types import ToolError, ToolSpec


@dataclass
class _Response:
    status_code: int
    payload: Any

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400

    @property
    def text(self) -> str:
        return json.dumps(self.payload)

    def json(self) -> Any:
        return self.payload


class _PublicSession:
    """Give the core exporter only reviewed bounded public authority reads."""

    def __init__(self, settings: Settings):
        self.settings = settings

    def request(self, method: str, url: str, **kwargs) -> _Response:
        target = urlsplit(url)
        expected = urlsplit(self.settings.authority_url or "")
        if method != "GET" or (target.scheme, target.netloc) != (expected.scheme, expected.netloc):
            raise ToolError("destination_not_allowed", "A bundle may read only the configured authority.")
        operation = next((row for row in authority.operations() if row["method"] == "GET"
                          and row["path"] == target.path and row["auth"] == "public"), None)
        if operation is None:
            raise ToolError("operation_not_allowed", "The bundle requested an unsupported public operation.")
        pairs = parse_qsl(target.query, keep_blank_values=True)
        if len(dict(pairs)) != len(pairs):
            raise ToolError("invalid_query", "Duplicate bundle query fields are not supported.")
        arguments = {"query": dict(pairs)} if pairs else {}
        result = authority.invoke(self.settings, operation, arguments)
        return _Response(result["http_status"], result["result"])

    def get(self, url: str, **kwargs) -> _Response:
        return self.request("GET", url, **kwargs)


def build_tools(settings: Settings) -> list[ToolSpec]:
    evidence_schema = TrustEvidence.model_json_schema()
    definitions = evidence_schema.pop("$defs", {})
    close_models(evidence_schema)
    close_models(definitions)
    def export(args):
        settings.require(frozenset({"read"}))
        if not settings.authority_url:
            raise ToolError("authority_required", "Configure an authority before exporting a trust bundle.")
        bundle = export_trust_bundle(session=_PublicSession(settings), endpoint=settings.authority_url,
                                     include_revocation_feed=args.get("include_revocation_feed", True))
        return {"bundle": bundle, "signatures_verified": False, "trust_granted": False}

    def atlas(args):
        settings.require(frozenset({"verify"}))
        graph = args["graph"]
        digest = graph_digest_from_export(graph)
        evidence = []
        failures = 0
        for raw in args.get("evidence", []):
            record = TrustEvidence.model_validate(raw)
            checked = verify_trust_evidence(record, args.get("issuer_public_keys", []),
                expected_graph_digest=digest if args.get("issuer_public_keys") else None)
            value = record.model_dump(mode="json")
            value.update(_atlas_verified=checked.accepted, _atlas_reason=checked.reason)
            evidence.append(value)
            failures += not checked.accepted
        data = {"graph": graph, "graph_digest": digest, "evidence": evidence, "unverifiable_count": 0}
        return {"atlas": data, "html": render_atlas_standalone(graph, evidence, digest),
                "evidence_failures": failures, "trust_granted": False}

    def review_bundle(args):
        settings.require(frozenset({"verify"}))
        live = None
        if args.get("compare_live"):
            settings.require(frozenset({"read"}))
            if not settings.authority_url:
                raise ToolError("authority_required", "Configure an authority for live comparison.")
            live = fetch_public_material(session=_PublicSession(settings), endpoint=settings.authority_url,
                                         include_revocation_feed=False)
        bundle = args["bundle"]
        report = validate_trust_bundle(bundle, live_material=live)
        if report["errors"]:
            return {"accepted_for_review": False, "trust_granted": False, "validation": report}
        return {"workflow": "trust-bundle-import", "created_at": datetime.now(timezone.utc).isoformat(),
                "accepted_for_review": True, "trust_granted": False, "signatures_verified": False,
                "bundle_hash": bundle_hash(bundle), "summary": bundle_summary(bundle), "validation": report,
                "storage": "Review receipt returned to the client; no trust store or local file was modified."}

    return [ToolSpec("gm_workflow_trust_bundle_export", "Fetch public review material from the configured authority "
                     "using the core trust-bundle exporter. Does not verify signatures or grant trust.",
                     {"type": "object", "properties": {"include_revocation_feed": {"type": "boolean", "default": True}},
                      "additionalProperties": False}, export, frozenset({"read"}), read_only=True,
                     core_targets=("cli:trust-bundle export",), open_world=True),
            ToolSpec("gm_workflow_atlas_build", "Build self-contained Atlas JSON and HTML from a supplied recognition "
                     "graph and optional signed trust evidence. Returns content instead of writing arbitrary files.",
                     {"type": "object", "$defs": definitions, "properties": {"graph": {"type": "object"},
                         "evidence": {"type": "array", "items": evidence_schema, "maxItems": 100},
                         "issuer_public_keys": {"type": "array", "items": {"type": "string"}, "maxItems": 100}},
                      "required": ["graph"], "additionalProperties": False}, atlas, frozenset({"verify"}),
                     read_only=True, idempotent=True, core_targets=("cli:atlas build",)),
            ToolSpec("gm_workflow_trust_bundle_review", "Validate a trust bundle and return a review-import receipt. "
                     "Optionally compare public material with the configured authority. Never grants trust or verifies "
                     "signatures; returns the receipt instead of writing an arbitrary output path.",
                     {"type": "object", "properties": {"bundle": {"type": "object"},
                         "compare_live": {"type": "boolean", "default": False}}, "required": ["bundle"],
                      "additionalProperties": False}, review_bundle, frozenset({"verify"}), read_only=True,
                     core_targets=("cli:trust-bundle import",), open_world=True)]
