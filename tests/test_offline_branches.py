"""JSON boundary and refusal branches, using real records and isolated adapter construction."""

from __future__ import annotations

import collections.abc
import dataclasses
from datetime import date, timedelta
from enum import Enum
from typing import Any

import pytest
from genesis_mesh.models.grants import TimeToken
from pydantic import BaseModel, Field, TypeAdapter, computed_field
from test_offline import NOW, call, public
from test_offline import environment as environment
from test_offline_remaining import evidence_artifacts as evidence_artifacts

from genesismesh_mcp.offline.adapter import decode_bytes, json_value, make_tool, wire_type
from genesismesh_mcp.settings import Settings


def test_nested_event_aliases_and_signed_optional_fields_roundtrip(evidence_artifacts):
    class Envelope(BaseModel):
        event: Any = Field(serialization_alias="exported_event")
        token: TimeToken

        @computed_field(alias="schema")
        @property
        def kind(self) -> str:
            return "test.export.wrapper"

    token = TimeToken(grant_id="grant", use_sequence=0, issued_at=NOW, issuer_sovereign_id="alpha", issued_by="alpha")
    value = json_value(Envelope(event=evidence_artifacts["events"][0], token=token))
    assert value["exported_event"]["schema"] == "gm.evidence.event"
    assert value["schema"] == "test.export.wrapper"
    assert "schema_" not in value["exported_event"]
    assert "use_head_digest" not in value["token"]
    assert value["token"] == token.to_wire()
    assert "subject_id" not in value["exported_event"]["entry"]


def test_codec_preserves_json_types_and_rejects_opaque_results():
    class Status(Enum):
        COMPLETE = "complete"

    @dataclasses.dataclass
    class Receipt:
        status: Status
        body: bytes
        day: date
        elapsed: timedelta

    assert json_value(Receipt(Status.COMPLETE, b"\x00\xff", date(2026, 10, 25), timedelta(seconds=90))) == {
        "status": "complete", "body": "AP8=", "day": "2026-10-25", "elapsed": "PT1M30S"}
    assert json_value({1: (None, True, 2, 0.5), "sets": frozenset({"one"})}) == {
        "1": [None, True, 2, 0.5], "sets": ["one"]}
    with pytest.raises(TypeError, match="unsupported result"):
        json_value(object())


@pytest.mark.parametrize("annotation,value,expected", [
    (bytes, "YQ==", b"a"),
    (dict[str, bytes], {"x": "Yg=="}, {"x": b"b"}),
    (collections.abc.Mapping[str, bytes], {"x": "Yg=="}, {"x": b"b"}),
    (list[bytes], ["Yw=="], [b"c"]),
    (set[bytes], {"ZA=="}, [b"d"]),
    (frozenset[bytes], frozenset({"ZA=="}), [b"d"]),
    (collections.abc.Sequence[bytes], ["ZQ=="], [b"e"]),
    (collections.abc.Iterable[bytes], ["Zg=="], [b"f"]),
    (tuple[bytes, int], ("Zw==", 2), (b"g", 2)),
    (tuple[bytes, ...], ("aA==", "aQ=="), (b"h", b"i")),
    (list[bytes] | None, None, None),
])
def test_binary_collections_decode_eagerly(annotation, value, expected):
    assert decode_bytes(value, annotation) == expected
    # The accepted wire type is a JSON collection, never a lazy iterator.
    adapter = TypeAdapter(wire_type(annotation))
    if value is not None:
        validated = adapter.validate_python(value)
        assert not isinstance(validated, collections.abc.Iterator)
    else:
        assert adapter.validate_python(None) is None


@pytest.mark.parametrize("value", ["not-base64", 7])
def test_invalid_binary_input_does_not_become_raw_text(value):
    with pytest.raises(ValueError, match="standard base64"):
        decode_bytes(value, bytes)


def test_adapter_compilation_rejects_unreviewable_signatures():
    def missing_type(value):
        return value

    def variable(*values: str) -> tuple[str, ...]:
        return values

    for function in (missing_type, variable):
        with pytest.raises(TypeError, match="Unreviewed signature"):
            make_tool(Settings(), function, "test", function.__name__)


def test_registered_privacy_profile_and_artifact_schema_refusals(environment):
    profile = {"sovereign_id": "alpha", "timestamp_bucket_seconds": 0}
    with pytest.raises(ValueError, match="timestamp_bucket_seconds must be positive"):
        call(environment, "privacy_apply_privacy_profile", payload="YQ==", headers={}, dispatch_time=NOW,
             sender_sovereign_id="alpha", profile=profile, signer_ref="alpha", now=NOW)
    proof = call(environment, "freshness_issue_freshness_proof", feed_sovereign_id="alpha", feed_sequence=2,
                 feed_digest="a" * 64, issued_by="alpha", issuer_sovereign_id="alpha", signer_ref="alpha", now=NOW)
    with pytest.raises(ValueError, match="pinned model schema"):
        call(environment, "crypto_verify_artifact", artifact_type="genesis_mesh.models.freshness:FreshnessProof",
             artifact={}, signature=proof["signature"], public_key=public(environment))
    changed = {**proof, "feed_digest": "b" * 64}
    assert call(environment, "crypto_verify_artifact", artifact_type="genesis_mesh.models.freshness:FreshnessProof",
                artifact=changed, signature=proof["signature"], public_key=public(environment))["valid"] is False


def test_audit_comparison_budget_is_checked_before_matching(environment, evidence_artifacts):
    event = evidence_artifacts["events"][0]
    changes = [{"index": i, "resource_id": "kv:sample", "action": "create", "changed_at": NOW} for i in range(317)]
    with pytest.raises(ValueError, match="100000 comparison budget"):
        call(environment, "audit_pack_check_completeness", changes=changes, entries=[event] * 317,
             period=[NOW, NOW + timedelta(seconds=1)])
    result = call(environment, "audit_pack_verify_audit_pack", files=evidence_artifacts["files"],
                  root_public_key=evidence_artifacts["root_public_key"], held_anchors=evidence_artifacts["anchors"],
                  executor_keys=evidence_artifacts["executor_keys"], changes=changes[:1])
    assert result["verified"] and result["completeness"]["complete"]


def test_adapter_refuses_nonfinite_input_before_dispatch(environment):
    with pytest.raises(ValueError, match="JSON compliant"):
        environment[2]["gm_offline_context_integrity_scan_for_injection_markers"].handler({"content": float("nan")})
