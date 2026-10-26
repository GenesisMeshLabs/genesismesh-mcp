"""Run with the wheel-only environment's Python, outside the source tree."""

import asyncio
import json
import sys
import tempfile

from mcp import Client, StdioServerParameters


async def main():
    with tempfile.TemporaryDirectory(prefix="genesismesh-mcp-wheel-") as directory:
        command = StdioServerParameters(command=sys.executable, args=["-I", "-m", "genesismesh_mcp"], cwd=directory)
        async with Client(command, read_timeout_seconds=30) as client:
            assert client.server_info.name == "genesismesh-mcp"
            tools = await client.list_tools()
            assert tools.next_cursor is None
            assert "gm_workflow_fleet_status" in {tool.name for tool in tools.tools}
            compatible = await client.read_resource("genesis-mesh://compatibility")
            assert json.loads(compatible.contents[0].text)["compatible"] is True
            catalog = await client.read_resource("genesis-mesh://coverage")
            report = json.loads(catalog.contents[0].text)
            assert report["summary"]["sections"]["http_routes"]["implemented"] == 116
            result = await client.call_tool("gm_offline_trust_bundle_validate_trust_bundle", {"bundle": {}})
            assert not result.is_error and result.structured_content["errors"]
            parsed = await client.call_tool("gm_offline_evidence_store_parse_export_lines", {"lines": []})
            assert not parsed.is_error and parsed.structured_content == {"result": []}
            assert json.loads(parsed.content[0].text) == []
            print(json.dumps({"wheel_stdio_smoke": "passed", "tools": report["summary"]["registered_tools"],
                              "visible_tools": len(tools.tools), "core": "1.8.1"}))


if __name__ == "__main__":
    asyncio.run(main())
