"""Configured workflow execution through the actual MCP protocol boundary."""

import json
import sys
from dataclasses import replace

from mcp import Client, StdioServerParameters
from test_authority_integration import authority as authority
from test_multi_workflows import pair as pair
from test_runtime_workflows import node_settings

from genesismesh_mcp.server import create_server
from genesismesh_mcp.types import ToolSpec


async def test_stdio_named_fleet_reads_real_authorities(pair, tmp_path):
    settings, _ = pair
    configuration = {"profiles": ["read", "verify"], "allow_http_loopback": True,
                     "fleets": {"two": ["alpha", "beta"]},
                     "authorities": {name: {"url": config.url, "public_key": config.public_key,
                        "root_public_key": config.root_public_key, "allowed_tools": ["gm_workflow_fleet_status"]}
                        for name, config in settings.authorities.items()}}
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps(configuration))
    server = StdioServerParameters(command=sys.executable, args=["-m", "genesismesh_mcp", "--config", str(path)])
    async with Client(server) as client:
        result = await client.call_tool("gm_workflow_fleet_status", {"fleet": "two"})
        assert not result.is_error
        assert result.structured_content["healthy"] is True
        assert len(result.structured_content["authorities"]) == 2
        denied = await client.call_tool("gm_workflow_fleet_mesh", {"fleet": "two", "operation_id": "one"})
        assert denied.is_error
        assert denied.structured_content["error"]["code"] == "profile_required"


async def test_mcp_marks_partial_workflow_results_as_errors_without_losing_progress():
    schema = {"type": "object", "properties": {}, "additionalProperties": False}
    partial = {"status": "partial", "operation_id": "one", "created_treaty_id": "issued"}
    server = create_server(tools=[ToolSpec("partial", "Partial result fixture", schema, lambda _: partial)])
    async with Client(server) as client:
        result = await client.call_tool("partial", {})
        assert result.is_error
        assert result.structured_content == partial


async def test_mcp_node_enrollment_preserves_structured_status_and_replay(authority, tmp_path):
    settings = node_settings(authority, tmp_path, generate=True)
    async with Client(create_server(settings)) as client:
        args = {"node": "client", "operation_id": "mcp-join"}
        result = await client.call_tool("gm_workflow_node_join", args)
        assert not result.is_error, result.structured_content
        assert result.structured_content["complete"] is True
        assert isinstance(result.structured_content["status"], dict)
        again = await client.call_tool("gm_workflow_node_join", args)
        assert not again.is_error, again.structured_content
        assert again.structured_content == result.structured_content
        status = await client.call_tool("gm_workflow_operation_status", {
            "workflow": "gm_workflow_node_join", "operation_id": "mcp-join"})
        assert not status.is_error
        assert status.structured_content["complete"] is True
        assert "result" not in status.structured_content
    restricted = replace(settings, profiles={"read", "local"})
    async with Client(create_server(restricted)) as client:
        denied = await client.call_tool("gm_workflow_operation_status", {
            "workflow": "gm_workflow_node_join", "operation_id": "mcp-join"})
        assert denied.is_error
        assert denied.structured_content["error"]["code"] == "profile_required"
