"""Protocol discovery, startup compatibility and safe failure behavior."""

from __future__ import annotations

import json

import pytest
from genesis_mesh.models.context import ContextRecord
from mcp import Client

from genesismesh_mcp import authority, catalog, server
from genesismesh_mcp.settings import Settings
from genesismesh_mcp.types import ToolSpec

EMPTY = {"type": "object", "properties": {}, "additionalProperties": False}


@pytest.fixture(scope="module")
def default_server():
    return server.create_server()


def test_startup_refuses_wrong_core_version_or_corrupt_snapshot(monkeypatch):
    monkeypatch.setattr(server, "version", lambda package: "0.0.0")
    with pytest.raises(ValueError, match="installed Genesis Mesh version"):
        server.build_tools(Settings())
    monkeypatch.setattr(server, "version", lambda package: "1.8.1")
    monkeypatch.setattr(catalog, "verify_packaged_snapshot", lambda: ["corrupt"])
    with pytest.raises(ValueError, match="Packaged core contract"):
        server.build_tools(Settings())


def test_startup_refuses_duplicate_names_and_unknown_signer_permissions(monkeypatch, tmp_path):
    original = authority.build_tools
    monkeypatch.setattr(authority, "build_tools", lambda settings: original(settings) + original(settings)[:1])
    with pytest.raises(ValueError, match="Duplicate"):
        server.build_tools(Settings())
    monkeypatch.setattr(authority, "build_tools", original)
    settings = Settings(signer_files={"issuer": tmp_path / "issuer.key"},
                        signer_permissions={"issuer": frozenset({"not_registered"})})
    with pytest.raises(ValueError, match="unregistered"):
        server.build_tools(settings)
    allowed = Settings(
        signer_files={"issuer": tmp_path / "issuer.key", "second": tmp_path / "second.key"},
        signer_permissions={"issuer": frozenset({"gm_offline_freshness_issue_freshness_proof"}), "second": frozenset()})
    assert server.build_tools(allowed)
    duplicate = ToolSpec("same", "probe", EMPTY, lambda value: value)
    with pytest.raises(ValueError, match="Duplicate"):
        server.create_server(tools=[duplicate, duplicate])


async def test_every_resource_and_prompt_can_be_discovered_and_read(default_server):
    settings = Settings()
    expected = server.build_resources(server.build_tools(settings), settings)
    async with Client(default_server) as client:
        discovered = set()
        cursor = None
        while True:
            page = await client.list_resources(cursor=cursor)
            for resource in page.resources:
                uri = str(resource.uri)
                assert uri not in discovered
                discovered.add(uri)
                read = await client.read_resource(uri)
                assert len(read.contents) == 1
                assert read.contents[0].text == expected[uri]
                assert json.loads(read.contents[0].text) is not None
            cursor = page.next_cursor
            if cursor is None:
                break
        assert discovered == expected.keys()
        prompts = await client.list_prompts()
        assert {p.name for p in prompts.prompts} == server.PROMPTS.keys()
        for prompt in prompts.prompts:
            result = await client.get_prompt(prompt.name)
            assert result.messages[0].content.text == server.PROMPTS[prompt.name]


@pytest.mark.parametrize("value", [{"valid": True}, [{"wire": "unchanged"}], "text", False, 3, None])
async def test_nonobject_results_preserve_json_through_actual_mcp_client(value):
    definition = ToolSpec("probe", "protocol result", EMPTY, lambda arguments: value)
    async with Client(server.create_server(tools=[definition])) as client:
        result = await client.call_tool("probe", {})
        assert not result.is_error
        assert json.loads(result.content[0].text) == value
        assert result.structured_content == (value if isinstance(value, dict) else {"result": value})


async def test_real_export_parser_preserves_received_envelope_through_protocol():
    # Core-produced event containing an opaque record; parsing is structural,
    # so no signature or permission claim is made from this operation alone.
    from datetime import datetime, timezone

    from genesis_mesh.models.evidence_store import EvidenceEvent
    from genesis_mesh.trust.evidence_store import build_entry

    entry = build_entry(store_sequence=1, entry_kind="observation", recorded_at=datetime.now(timezone.utc),
                        payload={"sample": "opaque"}, prev_entry_digest=None, index={})
    event = EvidenceEvent(entry=entry, entry_digest=entry.digest(), payload={"sample": "opaque"})
    raw = json.loads(event.to_json_line())
    raw["entry"]["recorded_at"] = raw["entry"]["recorded_at"].replace("Z", "+00:00")
    async with Client(server.create_server()) as client:
        result = await client.call_tool("gm_offline_evidence_store_parse_export_lines", {"lines": [json.dumps(raw)]})
        assert not result.is_error
        assert result.structured_content == {"result": [raw]}
        assert json.loads(result.content[0].text) == [raw]


@pytest.mark.parametrize("cursor", ["wrong:25", "resources:x", "resources:999999", "tools:-1", ""])
async def test_resource_cursor_validation_refuses_invalid_pages(cursor, default_server):
    async with Client(default_server) as client:
        if cursor == "":
            assert (await client.list_resources(cursor=cursor)).resources
        else:
            with pytest.raises(Exception) as error:
                await client.list_resources(cursor=cursor)
            assert str(error.value) == "Internal server error"


@pytest.mark.parametrize("cursor", ["resources:25", "tools:x", "tools:999999"])
async def test_tool_cursor_validation_refuses_invalid_pages(cursor, default_server):
    async with Client(default_server) as client:
        with pytest.raises(Exception) as error:
            await client.list_tools(cursor=cursor)
        assert str(error.value) == "Internal server error"


async def test_unknown_resource_oversized_resource_and_unknown_prompts_are_safe():
    async with Client(server.create_server(Settings(max_output_bytes=1024))) as client:
        for uri in ("genesis-mesh://missing", "genesis-mesh://contract"):
            with pytest.raises(Exception) as error:
                await client.read_resource(uri)
            assert str(error.value) == "Internal server error"
        for name, arguments in (("missing", None), ("inspect_trust", {"secret": "do-not-disclose"})):
            with pytest.raises(Exception) as error:
                await client.get_prompt(name, arguments=arguments)
            assert str(error.value) == "Internal server error"
            assert "do-not-disclose" not in str(error.value)


@pytest.mark.parametrize("exception,code", [(TypeError, "operation_failed"), (KeyError, "operation_failed"),
                                         (OSError, "operation_failed"), (RuntimeError, "internal_error")])
async def test_handler_failures_never_disclose_exception_arguments(exception, code):
    def fail(arguments):
        raise exception("do-not-disclose")

    async with Client(server.create_server(tools=[ToolSpec("fail", "probe", EMPTY, fail)])) as client:
        result = await client.call_tool("fail", {})
        assert result.is_error and result.structured_content["error"]["code"] == code
        assert "do-not-disclose" not in result.content[0].text
        unknown = await client.call_tool("unregistered", {})
        assert unknown.is_error and unknown.structured_content["error"]["code"] == "unknown_tool"


async def test_core_record_failure_and_input_size_refusal_stay_structured():
    def invalid_record(arguments):
        return ContextRecord.model_validate({})

    schema = {"type": "object", "properties": {"text": {"type": "string"}}, "additionalProperties": False}
    async with Client(server.create_server(Settings(max_input_bytes=1024), tools=[
        ToolSpec("record", "probe", schema, invalid_record)])) as client:
        malformed = await client.call_tool("record", {})
        assert malformed.is_error and malformed.structured_content["error"]["code"] == "invalid_record"
        oversized = await client.call_tool("record", {"text": "x" * 1025})
        assert oversized.is_error and oversized.structured_content["error"]["code"] == "input_too_large"
