"""Real two-sovereign workflows and recovery after partial network mutations."""

from __future__ import annotations

import threading
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from genesis_mesh.audit import logger as audit_logger
from genesis_mesh.crypto import generate_keypair, save_keypair, sign_model
from genesis_mesh.models import GenesisBlock, NetworkAuthority, PolicyManifestRef
from genesis_mesh.na_service.server import NetworkAuthorityService
from jsonschema import Draft202012Validator
from werkzeug.serving import make_server

from genesismesh_mcp import authority
from genesismesh_mcp.multi_support import Client, Deadline, ReviewSession
from genesismesh_mcp.multi_workflows import (
    build_tools,
    federation_bootstrap,
    federation_preview,
    fleet_mesh,
    fleet_status,
    fleet_verify,
    run_proof,
)
from genesismesh_mcp.settings import Settings
from genesismesh_mcp.types import ToolError
from genesismesh_mcp.workflow_config import AuthorityConfig


@pytest.fixture
def pair(tmp_path, monkeypatch):
    monkeypatch.setattr(audit_logger, "DEFAULT_AUDIT_DIR", tmp_path / "audit")
    definitions = {tool.name for tool in build_tools(Settings())}
    configurations, credentials, servers = {}, {}, []
    now = datetime.now(timezone.utc)
    try:
        for name in ("alpha", "beta"):
            home = tmp_path / name
            home.mkdir()
            keys = {key: generate_keypair() for key in ("root", "na", "operator", "reader", "subject")}
            paths = {key: save_keypair(value, str(home / key))[0] for key, value in keys.items()}
            genesis = GenesisBlock(network_name=name, network_version="1.8.1",
                                   root_public_key=keys["root"].public_key_b64,
                                   network_authority=NetworkAuthority(public_key=keys["na"].public_key_b64,
                                       valid_from=now, valid_to=now + timedelta(days=1)),
                                   policy_manifest=PolicyManifestRef(hash="sha256:test"))
            genesis.signatures.append(sign_model(genesis, keys["root"].private_key, "root"))
            service = NetworkAuthorityService(genesis_block=genesis, na_private_key=keys["na"].private_key,
                        key_id="na", db_path=str(home / "authority.db"),
                        operator_public_keys={"operator": keys["operator"].public_key_b64,
                                              "reader": keys["reader"].public_key_b64},
                        operator_key_tiers={"operator": "privileged", "reader": "read"})
            server = make_server("127.0.0.1", 0, service.app)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            servers.append((server, thread, service))
            configurations[name] = AuthorityConfig(url=f"http://127.0.0.1:{server.server_port}",
                    public_key=keys["na"].public_key_b64, root_public_key=keys["root"].public_key_b64,
                    operator_key_file=paths["operator"], operator_key_id="operator", allowed_tools=frozenset(definitions))
            credentials[name] = (keys, paths)
        yield Settings(authorities=configurations, fleets={"two": ("alpha", "beta")},
                       workflow_state_dir=tmp_path / "state", allow_http_loopback=True,
                       profiles=frozenset({"read", "verify", "operator", "write", "local"}), timeout_seconds=60), credentials
    finally:
        for server, thread, service in reversed(servers):
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            service.db.close()


def bootstrap_args(settings, operation_id="bootstrap", **scope):
    arguments = {"acceptor": "alpha", "issuer": "beta", **scope}
    preview = federation_preview(settings, arguments)
    return {**arguments, "operation_id": operation_id, "preview_digest": preview["preview_digest"]}


def treaties(settings, alias="alpha"):
    client = Client(settings, alias, "gm_workflow_federation_bootstrap", Deadline(settings))
    return client.call("GET", "/recognition-treaties")["recognition_treaties"]


def test_federation_preview_issue_and_completed_replay(pair):
    settings, _ = pair
    arguments = bootstrap_args(settings, roles=["role:client"], claims={"purpose": "integration"})
    assert treaties(settings) == []
    result = federation_bootstrap(settings, arguments)
    assert result["status"] == "completed", result
    assert result["result"]["genesis_signatures_verified"] is True
    assert result["result"]["trust_path"]["trusted"] is True
    assert result["steps"]["complete"] is True
    assert datetime.fromisoformat(result["observed_at"]).tzinfo is not None
    assert len(treaties(settings)) == 1
    assert federation_bootstrap(settings, arguments) == result
    assert len(treaties(settings)) == 1
    with pytest.raises(ToolError, match="different inputs"):
        federation_bootstrap(settings, {**arguments, "roles": ["role:operator"]})


def test_preview_binds_scope_and_does_not_issue_on_mismatch(pair):
    settings, _ = pair
    arguments = bootstrap_args(settings)
    result = federation_bootstrap(settings, {**arguments, "roles": ["role:operator"]})
    assert result["status"] == "partial"
    assert result["error"]["code"] == "preview_mismatch"
    assert treaties(settings) == []


def test_pinned_identity_mismatch_prevents_mutations(pair):
    settings, _ = pair
    arguments = bootstrap_args(settings)
    config = replace(settings.authorities["beta"], public_key=settings.authorities["alpha"].public_key)
    wrong = replace(settings, authorities={**settings.authorities, "beta": config})
    result = federation_bootstrap(wrong, arguments)
    assert result["status"] == "partial"
    assert result["error"]["code"] == "authority_pin_mismatch"
    assert treaties(settings) == []


def test_root_signature_failure_prevents_mutations(pair, monkeypatch):
    settings, _ = pair
    arguments = bootstrap_args(settings)
    original = authority.invoke

    def unsigned(config, operation, args):
        response = original(config, operation, args)
        if operation["path"] == "/genesis":
            response["result"]["signatures"] = []
        return response

    monkeypatch.setattr(authority, "invoke", unsigned)
    result = federation_bootstrap(settings, arguments)
    assert result["error"]["code"] == "genesis_signature_invalid"
    assert treaties(settings) == []


def test_failed_post_issue_check_resumes_without_duplicate_treaty(pair, monkeypatch):
    settings, _ = pair
    arguments = bootstrap_args(settings)
    original = authority.invoke

    def untrusted(config, operation, args):
        response = original(config, operation, args)
        if operation["path"] == "/connectome/trust-path":
            response["result"] = {"trusted": False, "reason": "not-yet-visible"}
        return response

    monkeypatch.setattr(authority, "invoke", untrusted)
    result = federation_bootstrap(settings, arguments)
    assert result["status"] == "partial"
    assert result["error"]["code"] == "trust_path_rejected"
    recorded = result["steps"]["steps"]["bootstrap-issue"]
    assert recorded["status"] == "completed" and recorded["result_identifiers"]["result.treaty_id"]
    assert len(treaties(settings)) == 1
    monkeypatch.setattr(authority, "invoke", original)
    resumed = federation_bootstrap(settings, arguments)
    assert resumed["status"] == "completed", resumed
    assert len(treaties(settings)) == 1


def test_lost_mutation_reply_is_reported_and_never_replayed(pair, monkeypatch):
    settings, _ = pair
    arguments = bootstrap_args(settings)
    original = authority.invoke

    def lost_reply(config, operation, args):
        response = original(config, operation, args)
        if operation["method"] == "POST" and operation["path"] == "/admin/recognition-treaties":
            raise ToolError("authority_unavailable", "The response was lost after the request.")
        return response

    monkeypatch.setattr(authority, "invoke", lost_reply)
    result = federation_bootstrap(settings, arguments)
    assert result["status"] == "partial"
    assert result["steps"]["steps"]["bootstrap-issue"]["status"] == "unknown"
    monkeypatch.setattr(authority, "invoke", original)
    retried = federation_bootstrap(settings, arguments)
    assert retried["status"] == "partial"
    assert retried["error"]["code"] == "outcome_unknown"
    assert len(treaties(settings)) == 1


def test_lower_operator_tier_denial_preserves_response(pair):
    settings, keys = pair
    arguments = bootstrap_args(settings)
    restricted = replace(settings.authorities["alpha"], operator_key_id="reader",
                         operator_key_file=keys["alpha"][1]["reader"])
    result = federation_bootstrap(replace(settings, authorities={**settings.authorities, "alpha": restricted}), arguments)
    assert result["status"] == "partial"
    assert result["error"]["code"] == "authority_rejected"
    assert result["error"]["details"]["http_status"] == 403
    assert treaties(settings) == []


def test_fleet_status_mesh_verify_and_scope_sensitive_skip(pair):
    settings, _ = pair
    status = fleet_status(settings, {"fleet": "two"})
    assert status["healthy"] is True
    assert len(status["authorities"]) == 2
    assert fleet_verify(settings, {"fleet": "two"})["untrusted"] == 2
    result = fleet_mesh(settings, {"fleet": "two", "operation_id": "mesh", "roles": ["role:client"]})
    assert result["status"] == "completed", result
    assert result["created"] == 2
    assert datetime.fromisoformat(result["observed_at"]).tzinfo is not None
    assert fleet_verify(settings, {"fleet": "two"})["untrusted"] == 0
    repeated = fleet_mesh(settings, {"fleet": "two", "operation_id": "mesh-again", "roles": ["role:client"]})
    assert repeated["status"] == "completed", repeated
    assert repeated["created"] == 0 and repeated["skipped"] == 2
    changed = fleet_mesh(settings, {"fleet": "two", "operation_id": "mesh-scope", "roles": ["role:operator"]})
    assert changed["status"] == "completed", changed
    assert changed["created"] == 2 and changed["skipped"] == 0


def test_remote_proof_acceptance_revocation_and_replay(pair):
    settings, credentials = pair
    args = {"acceptor": "alpha", "issuer": "beta", "operation_id": "proof",
            "subject_public_key": credentials["beta"][0]["subject"].public_key_b64}
    result = run_proof(settings, args)
    assert result["status"] == "completed", result
    assert result["inspection"]["valid"] is True
    assert result["result"]["pre_revocation"] == {"accepted": True, "reason": "accepted"}
    assert result["result"]["post_revocation"] == {"accepted": False, "reason": "attestation_locally_revoked"}
    assert result["result"]["operators"]["adoption_proof"] is False
    assert run_proof(settings, args) == result
    assert len(treaties(settings)) == 1


def test_fleet_status_reports_all_members_after_budget_expires(pair, monkeypatch):
    settings, _ = pair
    from genesismesh_mcp import multi_support

    clock = iter(range(100))
    monkeypatch.setattr(multi_support, "monotonic", lambda: next(clock))
    result = fleet_status(replace(settings, timeout_seconds=0.5), {"fleet": "two"})
    assert result["healthy"] is False
    assert len(result["authorities"]) == 2
    assert all(row["healthz"]["error"]["code"] == "workflow_deadline" for row in result["authorities"])


def test_workflow_permissions_profiles_and_registration(pair):
    settings, _ = pair
    disabled = replace(settings, authorities={name: replace(value, allowed_tools=frozenset())
                                             for name, value in settings.authorities.items()})
    with pytest.raises(ToolError, match="not enabled"):
        fleet_status(disabled, {"fleet": "two"})
    with pytest.raises(ToolError):
        fleet_mesh(replace(settings, profiles=frozenset({"read"})), {"fleet": "two", "operation_id": "deny"})
    tools = build_tools(settings)
    assert len(tools) == 6
    for tool in tools:
        Draft202012Validator.check_schema(tool.input_schema)
        assert tool.open_world
        if not tool.read_only:
            assert "local" in tool.profiles


def test_fleet_resume_rechecks_skipped_treaties_after_other_pair_failed(pair, monkeypatch):
    settings, _ = pair
    initial = fleet_mesh(settings, {"fleet": "two", "operation_id": "initial-mesh", "roles": ["role:client"]})
    assert initial["status"] == "completed"
    first = next(row for row in initial["pairs"] if row["from"] == "alpha")
    original = authority.invoke

    def beta_lookup_unavailable(config, operation, args):
        if config.authority_url == settings.authorities["beta"].url and operation["path"] == "/recognition-treaties":
            raise ToolError("authority_unavailable", "The second pair cannot be inspected yet.")
        return original(config, operation, args)

    monkeypatch.setattr(authority, "invoke", beta_lookup_unavailable)
    args = {"fleet": "two", "operation_id": "partial-mesh", "roles": ["role:client"]}
    partial = fleet_mesh(settings, args)
    assert partial["status"] == "partial" and partial["skipped"] == 1
    monkeypatch.setattr(authority, "invoke", original)
    alpha = Client(settings, "alpha", "gm_workflow_fleet_mesh", Deadline(settings))
    alpha.call("POST", "/admin/recognition-treaties/<treaty_id>/revoke",
               parameters={"treaty_id": first["treaty_id"]}, body={"reason": "changed while workflow paused"})
    assert fleet_verify(settings, {"fleet": "two"})["untrusted"] == 1
    resumed = fleet_mesh(settings, args)
    assert resumed["status"] == "completed", resumed
    assert fleet_verify(settings, {"fleet": "two"})["untrusted"] == 0
    assert resumed["created"] == 1 and resumed["skipped"] == 1


def test_bootstrap_resume_checks_its_persisted_treaty_even_with_another_trusted_path(pair, monkeypatch):
    settings, _ = pair
    args = bootstrap_args(settings, operation_id="interrupted-bootstrap")
    original = authority.invoke
    issued = None

    def fail_after_issue(config, operation, arguments):
        nonlocal issued
        if issued and config.authority_url == settings.authorities["alpha"].url and operation["path"] == "/connectome.json":
            raise ToolError("authority_unavailable", "The final summary was unavailable.")
        response = original(config, operation, arguments)
        if operation["path"] == "/admin/recognition-treaties" and operation["method"] == "POST":
            issued = response["result"]
        return response

    monkeypatch.setattr(authority, "invoke", fail_after_issue)
    partial = federation_bootstrap(settings, args)
    assert partial["status"] == "partial" and issued
    monkeypatch.setattr(authority, "invoke", original)
    alpha = Client(settings, "alpha", "gm_workflow_federation_bootstrap", Deadline(settings))
    alpha.call("POST", "/admin/recognition-treaties/<treaty_id>/revoke",
               parameters={"treaty_id": issued["treaty_id"]}, body={"reason": "replaced externally"})
    alpha.call("POST", "/admin/recognition-treaties", expected=201, body={
        "subject_sovereign_id": "beta", "subject_public_keys": [settings.authorities["beta"].public_key],
        "scope": {"allowed_roles": ["role:operator"], "accepted_statuses": ["active"], "claims": {}},
        "validity_hours": 24,
    })
    assert alpha.call("GET", "/connectome/trust-path", query={"from": "alpha", "to": "beta"})["trusted"]
    resumed = federation_bootstrap(settings, args)
    assert resumed["status"] == "partial", resumed
    assert resumed["error"]["code"] == "treaty_no_longer_active"
    assert len(treaties(settings)) == 2


def test_fleet_fresh_skip_detection_cannot_hide_an_unknown_prior_issue(pair, monkeypatch):
    settings, _ = pair
    original = authority.invoke
    attempts = 0

    def lose_alpha_issue_reply(config, operation, arguments):
        nonlocal attempts
        response = original(config, operation, arguments)
        if config.authority_url == settings.authorities["alpha"].url and operation["path"] == "/admin/recognition-treaties":
            attempts += 1
            raise ToolError("authority_unavailable", "Reply lost after commit")
        return response

    monkeypatch.setattr(authority, "invoke", lose_alpha_issue_reply)
    args = {"fleet": "two", "operation_id": "uncertain-mesh", "roles": ["role:client"]}
    partial = fleet_mesh(settings, args)
    assert partial["status"] == "partial" and attempts == 1
    monkeypatch.setattr(authority, "invoke", original)
    resumed = fleet_mesh(settings, args)
    assert resumed["status"] == "partial"
    alpha_row = next(row for row in resumed["pairs"] if row["from"] == "alpha")
    assert alpha_row["status"] == "failed" and alpha_row["error"]["code"] == "outcome_unknown"
    assert len(treaties(settings)) == 1


def test_fleet_enforces_aggregate_response_budget_before_further_requests(pair, monkeypatch):
    settings, _ = pair
    calls = []

    def large_health(config, operation, arguments):
        calls.append(operation["path"])
        return {"http_status": 200, "http_ok": True, "response_format": "json", "result": {"padding": "x" * 700}}

    monkeypatch.setattr(authority, "invoke", large_health)
    result = fleet_status(replace(settings, max_output_bytes=1024), {"fleet": "two"})
    assert calls == ["/healthz"]
    assert result["healthy"] is False and len(result["authorities"]) == 2
    assert result["authorities"][0]["readyz"]["error"]["code"] == "workflow_response_budget"
    assert result["authorities"][1]["healthz"]["error"]["code"] == "workflow_response_budget"


def test_core_review_session_shares_the_response_budget_with_direct_calls(pair, monkeypatch):
    settings, _ = pair
    calls = []

    def large_response(config, operation, arguments):
        calls.append(operation["path"])
        return {"http_status": 200, "http_ok": True, "response_format": "json", "result": {"padding": "x" * 700}}

    monkeypatch.setattr(authority, "invoke", large_response)
    bounded = replace(settings, max_output_bytes=1024)
    client = Client(bounded, "alpha", "gm_workflow_federation_preview", Deadline(bounded))
    session = ReviewSession(client)
    session.get(client.settings.authority_url + "/genesis")
    with pytest.raises(ToolError) as exc:
        client.raw("GET", "/healthz")
    assert exc.value.code == "workflow_response_budget"
    assert calls == ["/genesis"]
