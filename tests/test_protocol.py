import asyncio
import json
import sys
import threading

import pytest
from mcp import Client, StdioServerParameters

from genesismesh_mcp.server import build_tools, create_server
from genesismesh_mcp.settings import Settings
from genesismesh_mcp.types import ToolSpec

EMPTY = {"type": "object", "properties": {}, "additionalProperties": False}


async def all_tools(client):
    found = []
    cursor = None
    while True:
        result = await client.list_tools(cursor=cursor)
        found.extend(result.tools)
        cursor = result.next_cursor
        if cursor is None:
            return found


@pytest.fixture(scope="module")
def server():
    return create_server()


async def test_official_client_discovers_resources_prompts_and_real_offline_tools(server):
    async with Client(server) as client:
        tools = await all_tools(client)
        assert len(tools) > 60
        assert len({tool.name for tool in tools}) == len(tools)
        assert next(t for t in tools if t.name == "gm_workflow_trust_bundle_export").annotations.open_world_hint
        assert next(t for t in tools if t.name == "gm_workflow_trust_bundle_review").annotations.open_world_hint
        assert not any("signer_ref" in tool.input_schema.get("properties", {}) for tool in tools)
        compatible = await client.read_resource("genesis-mesh://compatibility")
        assert json.loads(compatible.contents[0].text)["compatible"] is True
        prompts = await client.list_prompts()
        assert {p.name for p in prompts.prompts} == {"inspect_trust", "verify_evidence", "governed_operation"}
        prompt = await client.get_prompt("governed_operation")
        assert "not proof" in prompt.messages[0].content.text
        tool = next(t for t in tools if t.name.endswith("validate_trust_bundle"))
        result = await client.call_tool(tool.name, {"bundle": {}})
        assert not result.is_error
        assert result.structured_content["errors"]


async def test_hidden_mutation_cannot_be_invoked_directly(server):
    mutation = next(t for t in build_tools(Settings()) if "write" in t.profiles)
    async with Client(server) as client:
        result = await client.call_tool(mutation.name, {})
        assert result.is_error
        assert result.structured_content["error"]["code"] == "profile_required"


async def test_initial_tool_listing_includes_later_workflows_without_pagination():
    settings = Settings()
    expected = {tool.name for tool in build_tools(settings) if tool.profiles <= settings.profiles}
    assert len(expected) > 25
    async with Client(create_server(settings)) as client:
        result = await client.list_tools()
        assert result.next_cursor is None
        assert {tool.name for tool in result.tools} == expected
        assert "gm_workflow_fleet_status" in expected


async def test_explicit_tool_pagination_preserves_complete_discovery():
    settings = Settings(tool_page_size=25)
    expected = {tool.name for tool in build_tools(settings) if tool.profiles <= settings.profiles}
    async with Client(create_server(settings)) as client:
        first = await client.list_tools()
        assert len(first.tools) == 25
        assert first.next_cursor == "tools:25"
        assert {tool.name for tool in await all_tools(client)} == expected


async def test_denials_remain_structured_and_errors_do_not_echo_inputs():
    def exception(args):
        raise ValueError("do-not-leak-secret-seed")

    tools = [ToolSpec("denied", "policy test", EMPTY, lambda args: {"authorized": False, "reason": "revoked"}),
             ToolSpec("exception", "error test", EMPTY, exception),
             ToolSpec("oversized", "size test", EMPTY, lambda args: {"value": "a" * 2048})]
    server = create_server(Settings(max_output_bytes=1024), tools=tools)
    async with Client(server) as client:
        denied = await client.call_tool("denied", {})
        assert denied.structured_content == {"authorized": False, "reason": "revoked"}
        error = await client.call_tool("exception", {})
        assert error.is_error
        assert "do-not-leak" not in error.content[0].text
        malformed = await client.call_tool("denied", {"private_key": "do-not-leak-secret-seed"})
        assert malformed.is_error
        assert "do-not-leak" not in malformed.content[0].text
        size = await client.call_tool("oversized", {})
        assert size.is_error and "output_too_large" in size.content[0].text


async def test_blocking_tool_does_not_block_protocol_requests():
    started = threading.Event()
    release = threading.Event()

    def slow(args):
        started.set()
        release.wait(timeout=5)
        return {"done": True}

    server = create_server(tools=[ToolSpec("slow", "Concurrency test", EMPTY, slow)])
    async with Client(server) as client:
        task = asyncio.create_task(client.call_tool("slow", {}))
        try:
            for _ in range(100):
                if started.is_set():
                    break
                await asyncio.sleep(0.01)
            assert started.is_set()
            await asyncio.wait_for(client.get_prompt("inspect_trust"), 2)
            assert not task.done()
        finally:
            release.set()
        assert not (await task).is_error


async def test_real_stdio_process_uses_packaged_server(tmp_path):
    params = StdioServerParameters(command=sys.executable, args=["-m", "genesismesh_mcp"], cwd=tmp_path)
    async with Client(params, read_timeout_seconds=30) as client:
        assert client.server_info.name == "genesismesh-mcp"
        result = await client.read_resource("genesis-mesh://compatibility")
        assert json.loads(result.contents[0].text)["installed_core"] == "1.8.1"
        tools = await all_tools(client)
        tool = next(t for t in tools if t.name.endswith("validate_trust_bundle"))
        result = await client.call_tool(tool.name, {"bundle": {}})
        assert result.structured_content["errors"]
