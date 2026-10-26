"""Where a client learns how a node that holds its own key joins: the invite result, the guide
resource, the enroll_node prompt and the server instructions."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest
from test_authority_integration import authority as authority
from test_authority_integration import operation

from genesismesh_mcp.authority import invoke
from genesismesh_mcp.enrollment import GUIDE_URI, TOKEN_MEANING, guide, instructions, invite_guidance
from genesismesh_mcp.server import PROMPTS, build_resources, build_tools, create_server
from genesismesh_mcp.settings import Settings

PUBLIC = "https://na.mesh.example.org"


def test_invite_result_says_token_id_is_the_token_and_where_the_node_joins(authority):
    settings, keys, _ = authority
    settings = replace(settings, node_enrollment_url=PUBLIC)
    invite = invoke(settings, operation("/admin/invite"), {"body": {
        "roles": ["role:client"], "recipient_public_key": keys["node"].public_key_b64}})
    assert invite["http_status"] == 201, invite
    assert invite["enrollment"]["invite_token"] == TOKEN_MEANING
    assert invite["enrollment"]["join_url"] == PUBLIC and GUIDE_URI in invite["enrollment"]["next"]
    assert set(invite["result"]) == {"token_id", "expires_at"}  # the authority's own result, unchanged
    # As the guidance says: token_id alone enrolls the node that holds the bound key.
    joined = invoke(replace(settings, invite_token=invite["result"]["token_id"]), operation("/join"), {"body": {}})
    assert joined["http_status"] == 201, joined
    refused = invoke(settings, operation("/admin/invite"), {"body": {"roles": ["not a valid role!"]}})
    assert refused["http_ok"] is False and "enrollment" not in refused


def test_guidance_without_a_public_node_url_says_so():
    settings = Settings()
    guidance = invite_guidance(settings)
    assert guidance["join_url"] is None and guidance["join_url_status"].startswith("not configured")
    assert guide(settings)["join_url"] is None
    assert '"<node_enrollment_url: ask the operator>"' in guide(settings)["python"]
    assert " at " not in instructions(settings) and GUIDE_URI in instructions(settings)


def test_guide_prompt_and_instructions_reach_every_client():
    settings = Settings(node_enrollment_url=PUBLIC + "/")
    assert settings.node_enrollment_url == PUBLIC and settings.public_status()["node_enrollment_url"] == PUBLIC
    resources = build_resources(build_tools(settings), settings)
    served = json.loads(resources[GUIDE_URI])
    assert served["join_url"] == PUBLIC and len(served["steps"]) == 6
    assert f'NA = "{PUBLIC}"' in served["python"] and "token_id" in served["steps"][1]
    assert GUIDE_URI in PROMPTS["enroll_node"] and "private key" in PROMPTS["enroll_node"]
    text = create_server(settings).instructions
    assert f"registers itself at {PUBLIC}" in text and GUIDE_URI in text


@pytest.mark.parametrize("url", ["http://na.example.org", "https://na.example.org/join", "https://na.example.org?x=1",
                                 "https://user@na.example.org", "na.example.org", "https://na.example.org:99999"])
def test_node_enrollment_url_must_be_a_public_https_origin(url):
    with pytest.raises(ValueError, match="node_enrollment_url"):
        Settings(node_enrollment_url=url)
