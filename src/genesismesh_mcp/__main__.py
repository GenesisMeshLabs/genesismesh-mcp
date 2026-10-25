"""The MCP entry point uses stdio; diagnostics always go to stderr."""

import argparse
import asyncio
import json
import logging
from pathlib import Path

from mcp.server.stdio import stdio_server

from .server import build_resource_targets, build_tools, create_server
from .settings import Settings


def main() -> None:
    parser = argparse.ArgumentParser(description="Genesis Mesh MCP stdio server")
    parser.add_argument("--config", type=Path, help="Local JSON settings file; paths resolve relative to this file")
    parser.add_argument("--check", action="store_true", help="Validate configuration, registration and coverage; then exit")
    args = parser.parse_args()
    logging.basicConfig(level=logging.WARNING)
    try:
        settings = Settings.from_file(args.config) if args.config else Settings()
        if args.check:
            from .catalog import build_catalog

            tools = build_tools(settings)
            catalog = build_catalog(tools, resources=build_resource_targets(), profiles=settings.profiles)
            print(json.dumps(catalog["summary"], indent=2))
            return
        server = create_server(settings)
    except (ValueError, TypeError, KeyError, OSError):
        parser.error("Invalid configuration or incompatible installation; check the documented settings and dependency pins.")

    async def run() -> None:
        async with stdio_server() as (reader, writer):
            await server.run(reader, writer, server.create_initialization_options())

    asyncio.run(run())


if __name__ == "__main__":
    main()
