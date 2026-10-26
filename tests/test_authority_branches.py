"""Transport and configuration refusals, without contacting a real authority."""

import os
from dataclasses import replace

import pytest
from test_authority import Response, by_path
from test_authority import identities as identities
from test_authority import transport as transport
from urllib3.exceptions import ProtocolError

from genesismesh_mcp.authority import build_tools
from genesismesh_mcp.authority_schemas import body_schema
from genesismesh_mcp.types import ToolError


def call(settings, path, arguments=None, method="POST"):
    name = by_path(path, method)["name"]
    return next(tool for tool in build_tools(settings) if tool.name == name).handler(arguments or {})


@pytest.mark.parametrize("change,path,args,code", [
    ({"authority_url": None}, "/health", {}, "authority_not_configured"),
    ({"authority_public_key": None}, "/node/state", {"body": {"cert_id": "cert"}}, "audience_required"),
    ({"invite_token": None}, "/join", {}, "invite_required"),
    ({"authority_public_key": None}, "/admin/invite", {}, "audience_required"),
    ({"operator_key_id": None, "operator_key_file": None}, "/admin/invite", {}, "operator_id_required"),
])
def test_required_config_refused_before_transport(identities, transport, change, path, args, code):
    settings, _ = identities
    calls, _ = transport
    with pytest.raises(ToolError) as caught:
        call(replace(settings, **change), path, args, "GET" if path == "/health" else "POST")
    assert caught.value.code == code
    assert calls == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits; Windows relies on directory ACLs")
def test_identity_file_others_can_read_is_refused_not_sanitized(identities, transport, tmp_path):
    settings, _ = identities
    exposed = tmp_path / "exposed-private-key"
    exposed.write_text("never-display-this-private-material")
    os.chmod(exposed, 0o644)
    with pytest.raises(ToolError) as caught:
        call(replace(settings, operator_key_file=exposed), "/admin/invite")
    assert caught.value.code == "key_file_exposed"
    assert "never-display" not in str(caught.value)


def test_unreadable_identity_is_sanitized(identities, transport, tmp_path):
    settings, _ = identities
    bad = tmp_path / "broken-private-key"
    bad.write_text("never-display-this-private-material")
    os.chmod(bad, 0o600)
    with pytest.raises(ToolError) as caught:
        call(replace(settings, operator_key_file=bad), "/admin/invite")
    assert caught.value.code == "identity_unavailable"
    assert "never-display" not in str(caught.value)
    assert transport[0] == []


@pytest.mark.parametrize("headers,code", [
    ({"Content-Length": "not-a-number"}, "invalid_response"),
    ({"Content-Length": "-1"}, "output_too_large"),
])
def test_malformed_content_length_is_refused(identities, transport, headers, code):
    settings, _ = identities
    transport[1][0] = Response(headers=headers)
    with pytest.raises(ToolError) as caught:
        call(settings, "/health", method="GET")
    assert caught.value.code == code
    assert len(transport[0]) == 1


@pytest.mark.parametrize("value", [float("nan"), float("inf"), {"not", "json"}])
def test_non_json_extension_values_never_reach_transport(identities, transport, value):
    settings, _ = identities
    with pytest.raises(ToolError) as caught:
        call(settings, "/admin/policy", {"body": {"routing": {"value": value}}})
    assert caught.value.code == "invalid_arguments"
    assert transport[0] == []


def test_input_limit_includes_generated_node_signature(identities, transport):
    settings, _ = identities
    settings = replace(settings, max_input_bytes=1024)
    with pytest.raises(ToolError) as caught:
        call(settings, "/heartbeat", {"body": {"cert_id": "cert", "status": "x" * 850}})
    assert caught.value.code == "input_too_large"
    assert "signed request" in str(caught.value)
    with pytest.raises(ToolError) as caught:
        call(settings, "/admin/policy", {"body": {"routing": {"padding": "x" * 1100}}})
    assert caught.value.code == "input_too_large"
    assert "Arguments" in str(caught.value)
    assert transport[0] == []


def test_broken_stream_is_not_retried_or_exposed(identities, transport):
    class BrokenResponse(Response):
        def iter_content(self, chunk_size):
            yield b'{"partial":'
            raise ProtocolError("private wire diagnostics")

    settings, _ = identities
    transport[1][0] = BrokenResponse()
    with pytest.raises(ToolError) as caught:
        call(settings, "/health", method="GET")
    assert caught.value.code == "authority_unavailable"
    assert "private wire" not in str(caught.value)
    assert len(transport[0]) == 1


def test_unreviewed_route_cannot_gain_an_untyped_schema():
    with pytest.raises(ValueError, match="has not been reviewed"):
        body_schema("POST", "/unreviewed-operation")
