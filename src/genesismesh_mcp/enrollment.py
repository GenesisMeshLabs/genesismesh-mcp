"""How a node that holds its own key joins the authority, told where an MCP client will look.

The connector issues invites; it never holds an outside node's private key, so it cannot
join or register on that node's behalf. The node does both itself, signing with its own key,
at the authority's public node URL (``node_enrollment_url``). This module is the single
source of that guidance: the invite tool's result, the ``genesis-mesh://guide/enroll-node``
resource, the ``enroll_node`` prompt and the server instructions all point here.
"""

from __future__ import annotations

from typing import Any

from .settings import Settings

GUIDE_URI = "genesis-mesh://guide/enroll-node"

TOKEN_MEANING = ("The invite result's token_id is the single-use invite token itself, not a reference to a "
                 "withheld secret. Treat it as a secret and give it only to the node that holds the bound key.")


def _join_url(settings: Settings) -> str | None:
    return settings.node_enrollment_url


def invite_guidance(settings: Settings) -> dict[str, Any]:
    """What an invite result means and what the node does next."""
    url = _join_url(settings)
    return {
        "invite_token": TOKEN_MEANING,
        "join_url": url,
        "join_url_status": "configured" if url else
        "not configured: the operator sets node_enrollment_url to the authority's public node URL",
        "next": "The node joins and registers itself, signing with its own key; this connector cannot. "
                f"Read {GUIDE_URI} for the steps.",
    }


def guide(settings: Settings) -> dict[str, Any]:
    """The enrollment guide served as a resource."""
    url = _join_url(settings) or "<node_enrollment_url: ask the operator>"
    return {
        "title": "Enroll a node or agent that holds its own key",
        "join_url": _join_url(settings),
        "division_of_work": {
            "connector": "Issues the invite (na_admin_create_invite), bound to the node's public key, and checks "
                         "the result afterwards (discovery, certificates, revocation).",
            "node": "Generates and keeps its private key, joins, registers its descriptor, renews. Every one of "
                    "these requests is signed with the node's key, so only the node can make them.",
        },
        "steps": [
            "1. On the node's machine, generate an Ed25519 key (genesis_mesh.crypto.generate_keypair) and keep the "
            "private key there. Send only the public key.",
            "2. With this connector, call na_admin_create_invite with body {\"recipient_public_key\": <node public "
            "key>, \"roles\": [\"role:client\"], \"max_validity_hours\": 720}. " + TOKEN_MEANING,
            f"3. On the node's machine (pip install genesis-mesh=={_core_version()}), join at {url} with the "
            "invite and the node's own key; save the returned certificate beside the key (python below).",
            "4. On the node's machine, build an AgentDescriptor (agent_id, capabilities, endpoint, expires_at), "
            "sign it with the node key and POST it to /agents at the same URL (python below).",
            "5. Verify with GET /agents?capability=<one of its capabilities>: the node is listed. An unfiltered "
            "GET /agents returns only a count, by design.",
            "6. Keep it current: a running node renews its certificate before expiry (/renew) and re-registers its "
            "descriptor before expires_at.",
        ],
        "python": _snippet(url),
        "notes": [
            "An invite bound to a public key is useless without the matching private key.",
            "A node's genesis block (GET /genesis) must verify from the root key the operator gave you "
            "independently; the snippet fetches it, so check its root_public_key against your pin.",
            "Use least privilege: role:client unless the node needs more.",
        ],
    }


def instructions(settings: Settings) -> str:
    url = _join_url(settings)
    where = f" at {url}" if url else ""
    return (" To enroll a node or agent that holds its own key: issue a key-bound invite (its token_id is the "
            f"single-use invite token); the node then joins and registers itself{where}, signing with its own key. "
            f"Read {GUIDE_URI}.")


PROMPT = ("Enroll a node or agent that holds its own private key. Read " + GUIDE_URI + " first. Issue one invite "
          "per node with na_admin_create_invite bound to the node's public key; the result's token_id is the "
          "single-use invite token. The node joins and registers itself at the guide's join_url, signing with its "
          "own key: give the person or agent running each node the guide's python steps. Afterwards, verify each "
          "node with a capability lookup. Never ask for or handle a node's private key.")


def _core_version() -> str:
    from .server import CORE_VERSION

    return CORE_VERSION


def _snippet(url: str) -> str:
    return f'''import json, requests
from datetime import datetime, timedelta, timezone
from genesis_mesh.crypto import load_private_key, sign_model
from genesis_mesh.crypto.keys import KeyPair
from genesis_mesh.models import AgentDescriptor, AgentEndpoint, GenesisBlock
from genesis_mesh.node.discovery_client import register_descriptor
from genesis_mesh.node.node import MeshNode

NA = "{url}"
key = load_private_key("node.key")                     # the node's own key, never sent
genesis = GenesisBlock.model_validate(requests.get(NA + "/genesis", timeout=10).json())
assert genesis.root_public_key == ROOT_PUBLIC_KEY        # your independently held pin
node = MeshNode(genesis, KeyPair(key, key.verify_key), roles=["role:client"])
cert = node.join_network(NA, validity_hours=720, invite_token=INVITE_TOKEN)  # token_id from the invite
open("certificate.json", "w").write(cert.model_dump_json(indent=2))

now = datetime.now(timezone.utc)
descriptor = AgentDescriptor(agent_id=AGENT_ID, node_public_key=node.node_keypair.public_key_b64,
    network_name=genesis.network_name, capabilities=CAPABILITIES,
    endpoint=AgentEndpoint(host=HOST, port=PORT, scheme="wss"),
    registered_at=now, expires_at=now + timedelta(days=30), metadata={{}})
descriptor.signatures.append(sign_model(descriptor, key, key_id=descriptor.node_public_key))
print(register_descriptor(NA, descriptor))
'''
