"""Every registered handler must enforce its configured profile before using inputs."""

import pytest

from genesismesh_mcp.server import build_tools
from genesismesh_mcp.settings import Settings
from genesismesh_mcp.types import ToolError

DISABLED = {tool.name: tool for tool in build_tools(Settings(profiles=frozenset()))}


@pytest.mark.parametrize("name", sorted(DISABLED))
def test_every_registered_handler_refuses_disabled_profile(name):
    with pytest.raises(ToolError) as error:
        DISABLED[name].handler({})
    assert error.value.code == "profile_required"
