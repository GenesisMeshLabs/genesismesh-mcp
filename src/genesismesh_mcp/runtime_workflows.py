"""Configured node enrollment, peer messages and purpose-bound guard requests."""

from __future__ import annotations

import asyncio
import hashlib
import os
import socket
import uuid
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic

from genesis_mesh.crypto import (
    KeyPair,
    generate_keypair,
    load_private_key,
    save_keypair,
    sign_model,
    verify_model_signature,
)
from genesis_mesh.gossip.crl_gossip import CRLGossip
from genesis_mesh.models import GenesisBlock, JoinCertificate, PolicyManifest
from genesis_mesh.models.context import BoundaryDecision
from genesis_mesh.models.invocation_token import InvocationToken
from genesis_mesh.models.mediation import ExecutionMediationRequest, MediatedExecutionReceipt, MediationRejection
from genesis_mesh.models.revocation import CertificateRevocationList
from genesis_mesh.node.node import MeshNode
from genesis_mesh.node.peer_identity import RuntimePeerIdentity
from genesis_mesh.strict_json import loads as strict_loads
from genesis_mesh.transport.noise_handshake import NoiseHandshake
from genesis_mesh.transport.protocol import create_data_message
from genesis_mesh.transport.websocket_transport import WebSocketTransport
from websockets.asyncio.client import connect

from . import authority
from .offline.adapter import close_models, json_value
from .runtime_config import GuardAction, NodeConfig
from .settings import Settings
from .types import ToolError, ToolSpec
from .workflow_support import WorkflowJournal, atomic_json, pinned_root, private_directory, select_authority

JOIN = "gm_workflow_node_join"
STATUS = "gm_workflow_node_status"
SEND = "gm_workflow_peer_send"
GUARD = "gm_workflow_guard_request"
_REF = {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"}
_OP = {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"}


def _schema(properties, required):
    return {"type": "object", "properties": properties, "required": required, "additionalProperties": False}


def _http(settings, path, method="GET", **arguments):
    operation = next(row for row in authority.operations()
                     if row["path"] == path and row["method"] == method
                     and (path != "/nodes" or row["auth"] == "public"))
    response = authority.invoke(settings, operation, arguments)
    if not response["http_ok"]:
        raise ToolError("runtime_authority_refused", "The configured authority refused a runtime workflow operation.")
    return response["result"]


def _config(settings, reference, operation):
    config = settings.node_runtimes.get(reference)
    if config is None:
        raise ToolError("node_not_configured", "Choose a configured node reference.")
    selected = select_authority(settings, config.authority, operation)
    root = config.root_public_key or pinned_root(settings, config.authority)
    key_path = config.node_key_file or config.state_dir / "node.key"
    return config, replace(selected, node_key_file=key_path, invite_token=config.invite_token), root


def _state_path(config: NodeConfig, name: str) -> Path:
    path = config.state_dir / name
    if config.state_dir.resolve() != config.state_dir or path.is_symlink() or path.resolve().parent != config.state_dir:
        raise ToolError("unsafe_node_state", "Configured node state must not escape its directory through symbolic links.")
    return path


def _read_state(settings, config, name):
    path = _state_path(config, name)
    if not path.is_file():
        return None
    if path.stat().st_size > settings.max_output_bytes:
        raise ToolError("node_state_too_large", "Stored node state exceeds the configured byte limit.")
    return strict_loads(path.read_bytes())


def _write_state(settings, config, name, value):
    atomic_json(_state_path(config, name), value, max_bytes=settings.max_output_bytes)


@contextmanager
def _locked_node(config):
    if not config.state_dir.exists():
        private_directory(config.state_dir)
        atomic_json(_state_path(config, "state-owner.json"), {"format": "genesismesh-mcp-node-state-v1"})
    path = _state_path(config, "state.lock")
    with open(path, "a+b") as lock:
        if lock.seek(0, 2) == 0:
            lock.write(b"0")
            lock.flush()
        lock.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise ToolError("node_busy", "Another workflow is updating this node's state.") from None
        try:
            yield
        finally:
            lock.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _node(settings, config, root_pin, *, create=False):
    key_path = settings.node_key_file
    if key_path == config.state_dir / "node.key":
        key_path = _state_path(config, "node.key")
    if key_path is None or not key_path.is_file():
        if not create or config.node_key_file is not None:
            raise ToolError("node_identity_missing", "The configured node identity has not been provisioned.")
        settings.require(frozenset({"provision"}))
        marker = _read_state(settings, config, "state-owner.json")
        if marker != {"format": "genesismesh-mcp-node-state-v1"}:
            raise ToolError("node_storage_unmanaged", "Automatic node provisioning requires a new managed state directory.")
        _state_path(config, "node.pub")
        save_keypair(generate_keypair(), str(config.state_dir / "node"), "node-local")
    try:
        private_key = load_private_key(str(key_path))
    except (OSError, ValueError):
        raise ToolError("node_identity_unavailable", "The configured node identity could not be loaded.") from None
    genesis_data = _read_state(settings, config, "genesis.json")
    if genesis_data is None:
        if not create:
            raise ToolError("node_not_joined", "Run the configured node enrollment workflow first.")
        genesis_data = _http(settings, "/genesis")
    genesis = GenesisBlock.model_validate(genesis_data)
    if genesis.root_public_key != root_pin:
        raise ToolError("root_pin_mismatch", "The node genesis does not match the configured root public key.")
    node = MeshNode(genesis, KeyPair(private_key, private_key.verify_key))
    held_history = _read_state(settings, config, "key-history.json")
    if held_history is not None and not node.adopt_key_history(
        held_history["successions"], held_history.get("vouching_grace_seconds")
    ):
        raise ToolError("invalid_node_key_history", "Stored authority key history failed core verification.")
    if create:
        _write_state(settings, config, "genesis.json", genesis_data)
    return node


def _refresh_history(settings, config, node, *, persist=False):
    data = _http(settings, "/na/key-history")
    if not isinstance(data, dict) or not isinstance(data.get("successions"), list) or not node.adopt_key_history(
        data["successions"], data.get("vouching_grace_seconds")
    ):
        raise ToolError("invalid_authority_history", "The authority key history failed core verification.")
    if persist:
        _write_state(settings, config, "key-history.json", {
            "successions": [s.to_wire() for s in node.key_history.successions],
            "vouching_grace_seconds": int(node.key_history.vouching_grace.total_seconds()),
        })


def _certificate(node, value):
    cert = JoinCertificate.model_validate(value)
    if cert.node_public_key != node.node_keypair.public_key_b64 or not node._verify_join_certificate(cert):
        raise ToolError("invalid_node_certificate", "The certificate is not valid for this configured node identity.")
    node.join_certificate = cert
    node.roles = cert.roles
    return cert


def node_join(settings, args):
    settings.require(frozenset({"read", "node", "local", "write"}))
    config, selected, root_pin = _config(settings, args["node"], JOIN)
    with WorkflowJournal(settings, JOIN, args["operation_id"], args) as journal:
        if journal.completed_result is not None:
            return journal.completed_result
        with _locked_node(config):
            node = _node(selected, config, root_pin, create=True)
            _refresh_history(selected, config, node, persist=True)
            held = _read_state(selected, config, "certificate.json")
            cert = None
            if held is not None:
                try:
                    cert = _certificate(node, held)
                except ToolError:
                    pass
            reused = cert is not None
            certificate_persisted = reused
            if cert is None:
                if not config.invite_token:
                    raise ToolError("invite_required", "A usable certificate or server-configured invite token is required.")

                def enroll():
                    raw = _http(selected, "/join", "POST", body={"validity_hours": args.get("validity_hours", 168)})
                    _certificate(node, raw)
                    return raw

                raw_certificate = journal.step("enroll", enroll, mutation=True)
                cert = _certificate(node, raw_certificate)
            try:
                if not reused:
                    def persist_certificate():
                        _write_state(selected, config, "certificate.json", raw_certificate)
                        return {"certificate_id": cert.cert_id, "persisted": True}

                    # Journal the verified response before a separate local write:
                    # a failed disk write must not lose a consumed single-use invite's certificate.
                    # Atomic replacement of this same validated certificate is safe
                    # to retry under the node lock after a local filesystem failure.
                    journal.step("persist_certificate", persist_certificate)
                    certificate_persisted = True
                raw_policy = _http(selected, "/policy")
                policy = PolicyManifest.model_validate(raw_policy)
                if not node._verify_policy_manifest(policy):
                    raise ToolError("invalid_node_policy", "The policy failed core signature verification.")
                node.policy_manifest = policy
                _write_state(selected, config, "policy.json", raw_policy)
                heartbeat = journal.step("heartbeat", lambda: _http(
                    selected, "/heartbeat", "POST", body={"cert_id": cert.cert_id, "status": "healthy"}
                ), mutation=True)
                if heartbeat.get("ack") is not True:
                    raise ToolError("heartbeat_refused", "The authority did not acknowledge this node's heartbeat.")
            except (ToolError, ValueError, KeyError, TypeError, OSError) as error:
                return {"complete": False, "enrolled": True, "node": args["node"],
                        "certificate_id": cert.cert_id, "certificate_persisted": certificate_persisted,
                        "reused_certificate": reused,
                        "error": error.code if isinstance(error, ToolError) else "node_state_update_failed", "runtime_started": False,
                        "operation": journal.summary()}
            _write_state(selected, config, "node.json", {"node": args["node"], "authority": config.authority,
                         "network": node.genesis_block.network_name, "node_public_key": node.node_keypair.public_key_b64})
            return journal.finish({"complete": True, "enrolled": True, "node": args["node"],
                                   "reused_certificate": reused, "invite_consumed": not reused,
                                   "heartbeat_acknowledged": True, "state_persisted": True,
                                   "runtime_started": False, "status": node.get_status()})


def node_status(settings, args):
    settings.require(frozenset({"read", "local"}))
    config, selected, root_pin = _config(settings, args["node"], STATUS)
    result = {"node": args["node"], "authority": config.authority, "runtime_started": False, "probes": {}}
    for probe in ("healthz", "readyz", "nodes"):
        try:
            result["probes"][probe] = _http(selected, "/" + probe)
        except ToolError as error:
            result["probes"][probe] = {"available": False, "error": error.code}
    try:
        node = _node(selected, config, root_pin)
        _refresh_history(selected, config, node)
        cert = _read_state(selected, config, "certificate.json")
        if cert is not None:
            _certificate(node, cert)
        policy = _read_state(selected, config, "policy.json")
        if policy is not None:
            node.policy_manifest = PolicyManifest.model_validate(policy)
            if not node._verify_policy_manifest(node.policy_manifest):
                raise ToolError("invalid_node_policy", "The held policy failed core signature verification.")
        status = node.get_status()
        if node.join_certificate is not None:
            gossip = _verified_crl(selected, node)
            revoked = gossip.is_certificate_revoked(node.join_certificate.cert_id)
            status.update(certificate_revoked=revoked, revocation_checked=True)
            status["certificate_valid"] = status["certificate_valid"] and not revoked
        else:
            status.update(certificate_revoked=None, revocation_checked=False)
        result.update(local_state_available=True, status=status)
    except (ToolError, ValueError, KeyError) as error:
        result.update(local_state_available=False, error=error.code if isinstance(error, ToolError) else "invalid_node_state")
    return result


class _NoRedirectConnect(connect):
    def process_redirect(self, exc):
        return exc


async def _noop_broadcast(*_):
    return None


def _verified_crl(settings, node):
    """Use the core's signer horizon and timing rules before trusting revocation state."""
    crl = CertificateRevocationList.model_validate(_http(settings, "/crl"))
    now = datetime.now(timezone.utc)
    if not node.verify_na_signed(crl, crl.signatures, crl.issued_at, now=now):
        raise ToolError("invalid_crl", "The current revocation list failed core verification.")
    gossip = CRLGossip(node.node_keypair.public_key_b64, lambda _: None, _noop_broadcast)
    signer = node.signer_of(crl, crl.signatures)
    if signer is None or gossip._timing_refusal(crl, signer.public_key):
        raise ToolError("invalid_crl", "The current revocation list is expired or has invalid timing.")
    gossip.set_crl(crl)
    return gossip


async def _send_peer(settings, config, peer, root_pin, message):
    node = _node(settings, config, root_pin)
    _refresh_history(settings, config, node, persist=True)
    raw_cert = _read_state(settings, config, "certificate.json")
    if raw_cert is None:
        raise ToolError("node_not_joined", "The configured node has no held certificate.")
    cert = _certificate(node, raw_cert)
    gossip = _verified_crl(settings, node)
    if gossip.is_certificate_revoked(cert.cert_id):
        raise ToolError("node_revoked", "The local node certificate is revoked.")
    identity = RuntimePeerIdentity(node, node.node_keypair.public_key_b64, gossip, {}, {})
    transport = None
    # The outer timeout covers handshake and send too, unlike the core CLI's
    # connection-only timeout. No proxy credentials or redirects are inherited.
    async with asyncio.timeout(settings.timeout_seconds):
        async with _NoRedirectConnect(peer.endpoint, proxy=None, compression=None,
                                      open_timeout=settings.timeout_seconds, close_timeout=2,
                                      max_size=min(settings.max_output_bytes, 262144)) as websocket:
            try:
                session, remote_cert, remote_static = await NoiseHandshake().perform_initiator(
                    websocket, identity.noise_keypair(), identity.local_cert_b64()
                )
                transport = WebSocketTransport(websocket, noise_session=session)
                accepted = identity.validate_peer_cert(remote_cert, remote_static)
                if accepted.node_public_key != peer.peer_public_key:
                    raise ToolError("peer_identity_mismatch", "The peer does not match its configured public key.")
                frame = create_data_message(sender_id=node.node_keypair.public_key_b64,
                                            recipient_id=peer.recipient_public_key or peer.peer_public_key,
                                            data=message.encode("utf-8"))
                await transport.send(frame.to_bytes())
                return {"transport_sent": True, "recipient_delivery_confirmed": False,
                        "message_id": frame.message_id, "peer_identity_verified": True,
                        "payload_sha256": hashlib.sha256(message.encode("utf-8")).hexdigest()}
            finally:
                if transport is not None:
                    await transport.close()


def peer_send(settings, args):
    settings.require(frozenset({"read", "local", "node", "write", "execute"}))
    peer = settings.peers.get(args["peer"])
    if peer is None:
        raise ToolError("peer_not_configured", "Choose a configured peer reference.")
    config, selected, root_pin = _config(settings, peer.node, SEND)
    if len(args["message"].encode("utf-8")) > min(65536, settings.max_input_bytes):
        raise ToolError("message_too_large", "The message exceeds the configured payload limit.")
    with WorkflowJournal(settings, SEND, args["operation_id"], args) as journal:
        if journal.completed_result is not None:
            return journal.completed_result
        try:
            with _locked_node(config):
                result = journal.step("send", lambda: asyncio.run(
                    _send_peer(selected, config, peer, root_pin, args["message"])
                ), mutation=True)
        except ToolError:
            raise
        except Exception:
            raise ToolError("peer_send_failed", "Peer transport failed. It was not retried; delivery may be unknown.") from None
        return journal.finish({**result, "peer": args["peer"], "complete": True})


def _guard_exchange(settings: Settings, action: GuardAction, request: ExecutionMediationRequest):
    raw = request.model_dump_json().encode("utf-8")
    # Core's daemon uses a single 65536-byte request read.
    if len(raw) > min(settings.max_input_bytes, 60000):
        raise ToolError("guard_request_too_large", "The signed guard request exceeds the protocol input limit.")
    deadline = monotonic() + settings.timeout_seconds
    with socket.create_connection((action.host, action.port), timeout=settings.timeout_seconds) as sock:
        sock.sendall(raw)
        chunks, size = [], 0
        while True:
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise TimeoutError
            sock.settimeout(remaining)
            chunk = sock.recv(min(65536, settings.max_output_bytes + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > settings.max_output_bytes:
                raise ToolError("guard_output_too_large", "The guard response exceeded its byte limit; execution may have occurred.")
    payload = strict_loads(b"".join(chunks))
    if "receipt_id" not in payload:
        rejection = MediationRejection.model_validate(payload)
        if rejection.request_id != request.request_id:
            raise ToolError("guard_response_mismatch", "The guard rejection does not match this request.")
        return {"accepted": False, "execution_confirmed": False, "execution_may_have_occurred": True,
                "response_authenticated": False, "rejection": json_value(rejection)}
    receipt = MediatedExecutionReceipt.model_validate(payload)
    if (set(payload) - set(MediatedExecutionReceipt.model_fields)
            or receipt.request_id != request.request_id or receipt.agent_sovereign_id != request.agent_sovereign_id
            or receipt.capability != request.requested_capability or receipt.decision_id != request.decision_id
            or receipt.guard_sovereign_id != action.guard_sovereign_id
            or receipt.signature is None or not verify_model_signature(receipt, receipt.signature, action.guard_public_key)):
        raise ToolError("invalid_guard_receipt", "The guard receipt signature or request binding is invalid; execution may have occurred.")
    return {"accepted": True, "execution_confirmed": True, "receipt_signature_verified": True,
            "process_exit_success": receipt.subprocess_exit_code == 0, "receipt": json_value(receipt)}


def guard_request(settings, args):
    settings.require(frozenset({"local", "write", "execute", "sign"}))
    action = settings.guard_actions.get(args["action"])
    if action is None:
        raise ToolError("guard_action_not_configured", "Choose a configured guard action.")
    token = InvocationToken.model_validate(args["token"])
    decision = BoundaryDecision.model_validate(args["decision"])
    if token.bearer_sovereign_id != action.agent_sovereign_id or token.agreement_id != decision.agreement_id:
        raise ToolError("guard_binding_mismatch", "The invocation token does not match the configured agent and decision agreement.")
    key = settings.load_signer(action.signer, GUARD)
    with WorkflowJournal(settings, GUARD, args["operation_id"], args) as journal:
        if journal.completed_result is not None:
            return journal.completed_result
        request = ExecutionMediationRequest(
            request_id=str(uuid.uuid5(uuid.NAMESPACE_URL, GUARD + ":" + args["action"] + ":" + args["operation_id"])),
            agent_sovereign_id=action.agent_sovereign_id, requested_capability=action.capability,
            decision_id=decision.decision_id, token_id=token.token_id, invocation_token=token,
            subprocess_command=list(action.command), allowed_env_vars=list(action.allowed_env),
            requested_at=datetime.now(timezone.utc),
        )
        request.signature = sign_model(request, key, action.agent_sovereign_id)
        try:
            result = journal.step("guard_request", lambda: _guard_exchange(settings, action, request), mutation=True)
        except ToolError:
            raise
        except Exception:
            raise ToolError("guard_unavailable", "The guard request did not yield a verified response. It was not retried; execution may have occurred.") from None
        return journal.finish({**result, "complete": True, "action": args["action"]})


def build_tools(settings):
    guard_schema = _schema({"action": _REF, "operation_id": _OP,
                            "token": InvocationToken.model_json_schema(),
                            "decision": BoundaryDecision.model_json_schema()},
                           ["action", "operation_id", "token", "decision"])
    # Both models share core Signature; lift definitions so their references
    # resolve against the complete tool schema.
    definitions = {}
    for name in ("token", "decision"):
        definitions.update(guard_schema["properties"][name].pop("$defs", {}))
    guard_schema["$defs"] = definitions
    close_models(guard_schema)
    return [
        ToolSpec(JOIN, "Enroll a configured node, verify and persist its identity/policy, reuse a valid held "
                 "certificate and send a heartbeat. A persistent peer daemon is managed separately.",
                 _schema({"node": _REF, "operation_id": _OP,
                          "validity_hours": {"type": "integer", "minimum": 1, "maximum": 8760}},
                         ["node", "operation_id"]), lambda args: node_join(settings, args),
                 frozenset({"read", "node", "local", "write"}), core_targets=("cli:join",), open_world=True),
        ToolSpec(STATUS, "Combine configured authority probes with verified held node-certificate status.",
                 _schema({"node": _REF}, ["node"]), lambda args: node_status(settings, args),
                 frozenset({"read", "local"}), read_only=True, idempotent=True,
                 core_targets=("cli:status",), open_world=True),
        ToolSpec(SEND, "Send a bounded message through a configured Noise-authenticated peer. Confirms transport "
                 "send only; no recipient-delivery receipt is implied. Durable operation IDs prevent silent retries.",
                 _schema({"peer": _REF, "operation_id": _OP, "message": {"type": "string", "maxLength": 65536}},
                         ["peer", "operation_id", "message"]), lambda args: peer_send(settings, args),
                 frozenset({"read", "local", "node", "write", "execute"}),
                 core_targets=("cli:send",), open_world=True),
        ToolSpec(GUARD, "Submit a purpose-signed request for a configured guard action and verify its bound "
                 "execution receipt. Fixed command/environment come from server configuration. A rejection or "
                 "transport error is not evidence that no subprocess started.", guard_schema,
                 lambda args: guard_request(settings, args), frozenset({"local", "write", "execute", "sign"}),
                 destructive=True, core_targets=("cli:trust guard request",), open_world=True),
    ]
