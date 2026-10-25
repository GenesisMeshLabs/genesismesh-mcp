"""CLI startup validates configuration and runs the stdio lifecycle."""

import json
import runpy
import sys
from contextlib import asynccontextmanager

import pytest

from genesismesh_mcp import __main__ as cli


def test_cli_check_prints_the_actual_registered_catalog(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["genesismesh-mcp", "--check"])
    cli.main()
    result = json.loads(capsys.readouterr().out)
    assert result["registered_tools"] == 284
    assert result["sections"]["http_routes"]["implemented"] == 116


def test_python_module_entrypoint_uses_config_file(monkeypatch, tmp_path, capsys):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"profiles": ["read"]}), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["genesismesh-mcp", "--config", str(path), "--check"])
    monkeypatch.delitem(sys.modules, "genesismesh_mcp.__main__", raising=False)
    runpy.run_module("genesismesh_mcp", run_name="__main__")
    result = json.loads(capsys.readouterr().out)
    assert result["registered_tools"] == 284


def test_invalid_configuration_is_refused_without_disclosing_contents(monkeypatch, tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text('{"unexpected": "private-do-not-disclose"}', encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["genesismesh-mcp", "--config", str(path)])
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "Invalid configuration" in output.err
    assert "private-do-not-disclose" not in output.err


def test_stdio_lifecycle_passes_streams_and_initialization_options(monkeypatch):
    entered = []
    reader, writer = object(), object()

    @asynccontextmanager
    async def streams():
        entered.append("open")
        yield reader, writer
        entered.append("closed")

    class Server:
        def create_initialization_options(self):
            return {"name": "initialization"}

        async def run(self, incoming, outgoing, options):
            assert incoming is reader and outgoing is writer
            assert options == {"name": "initialization"}
            entered.append("run")

    monkeypatch.setattr(sys, "argv", ["genesismesh-mcp"])
    monkeypatch.setattr(cli, "stdio_server", streams)
    monkeypatch.setattr(cli, "create_server", lambda settings: Server())
    cli.main()
    assert entered == ["open", "run", "closed"]
