"""Federation, fleet and recognition/revocation proof orchestration."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from genesis_mesh.models import RecognitionTreaty
from genesis_mesh.trust.treaty import verify_recognition_treaty
from genesis_mesh.workflows.federation import (
    _public_review_summary,
    _redacted_treaty_preview,
    _treaty_preview,
)
from genesis_mesh.workflows.proof import inspect_proof_bundle
from genesis_mesh.workflows.trust_bundle import bundle_endpoint, validate_bundle_against_review

from .authority_schemas import obj
from .multi_support import Client, Deadline, WorkflowFailure, checked, digest, distinct_pair, review, safe_error
from .settings import Settings
from .types import ToolError, ToolSpec
from .workflow_support import WorkflowJournal, fleet_members

READ = frozenset({"read"})
WRITE = frozenset({"read", "verify", "operator", "write", "local"})
NAME = {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$"}
TEXT = {"type": "string", "minLength": 1, "maxLength": 1024}
CLAIMS = {"type": "object", "additionalProperties": {"type": "string", "maxLength": 4096}, "maxProperties": 100}
SCOPE = {
    "roles": {"type": "array", "items": TEXT, "maxItems": 100, "uniqueItems": True},
    "accepted_statuses": {"type": "array", "items": {"enum": ["active", "suspended", "revoked"]},
                          "minItems": 1, "maxItems": 3, "uniqueItems": True},
    "claims": CLAIMS,
    "validity_hours": {"type": "integer", "minimum": 1, "maximum": 87600},
}
PAIR = {"acceptor": NAME, "issuer": NAME}


def _scope(args, *, fleet=False):
    return {"roles": args.get("roles", ["role:anchor", "role:bridge", "role:operator", "role:client"] if fleet
                              else ["role:client"]),
            "accepted_statuses": args.get("accepted_statuses", ["active"]),
            "claims": args.get("claims", {}), "validity_hours": args.get("validity_hours", 8760 if fleet else 24)}


def _pair(settings, args, name, deadline):
    return (Client(settings, args["acceptor"], name, deadline), Client(settings, args["issuer"], name, deadline))


def _treaty_body(issuer: Client, issuer_review: dict, scope: dict):
    return _treaty_preview(issuer_id=issuer_review["sovereign_id"],
                          issuer_public_key=issuer_review["network_authority"]["public_key"],
                          issuer_endpoint=issuer.settings.authority_url, **scope)


def _preview(acceptor: Client, issuer: Client, args: dict):
    acceptor_review, issuer_review = review(acceptor), review(issuer)
    distinct_pair(acceptor, issuer, (acceptor_review, issuer_review))
    body = _treaty_body(issuer, issuer_review, _scope(args))
    bundle_report = None
    if args.get("issuer_bundle") is not None:
        bundle = args["issuer_bundle"]
        endpoint = bundle_endpoint(bundle)
        if endpoint and endpoint != issuer.settings.authority_url.rstrip("/"):
            raise ToolError("bundle_endpoint_mismatch", "The issuer bundle names a different configured authority.")
        bundle_report = validate_bundle_against_review(bundle, issuer_review, label="issuer")
    material = {"acceptor": acceptor.identity(), "issuer": issuer.identity(),
                "acceptor_sovereign_id": acceptor_review["sovereign_id"], "treaty": body,
                "issuer_bundle": args.get("issuer_bundle")}
    return {"workflow": "federation-bootstrap", "dry_run": True, "preview_digest": digest(material),
            "acceptor": _public_review_summary(acceptor_review), "issuer": _public_review_summary(issuer_review),
            "genesis_signatures_verified": True, "treaty_preview": _redacted_treaty_preview(body),
            "issuer_bundle_validation": bundle_report}, acceptor_review, issuer_review, body


def _partial(journal, error: Exception, *, extra=None):
    return {"status": "partial", "operation_id": journal.operation_id, "error": safe_error(error),
            "recovery": "Inspect recorded results before retrying; uncertain mutations are never replayed.",
            "steps": journal.summary(), **(extra or {})}


def _complete(journal, result):
    result["steps"] = {**journal.summary(), "complete": True}
    return journal.finish(result)


def _mutation(journal, label, client: Client, path: str, body: dict, *, expected=200, parameters=None):
    # Store a definite HTTP response before assessing application success. A
    # lost/invalid response leaves an uncertain mutation that cannot be replayed.
    response = journal.step(label, lambda: client.raw("POST", path, body=body, parameters=parameters), mutation=True)
    return checked(response, expected)


def _trusted(client: Client, source_id: str, target_id: str):
    result = client.call("GET", "/connectome/trust-path", query={"from": source_id, "to": target_id})
    if result.get("trusted") is not True:
        raise WorkflowFailure("trust_path_rejected", "The persisted relationship did not produce a trusted path.", result)
    return result


def _verified_treaty(treaty: dict, acceptor: Client, acceptor_id: str, issuer_id: str, body: dict):
    parsed = RecognitionTreaty.model_validate(treaty)
    result = verify_recognition_treaty(parsed, [acceptor.settings.authority_public_key],
                                      expected_issuer_sovereign_id=acceptor_id,
                                      expected_subject_sovereign_id=issuer_id)
    if not result.accepted:
        raise ToolError("treaty_verification_failed", "The issued treaty does not verify against the accepting pin.")
    if (parsed.subject_public_keys != body["subject_public_keys"] or parsed.scope.model_dump() != body["scope"]):
        raise ToolError("treaty_scope_mismatch", "The issued treaty differs from the reviewed scope or issuer key.")
    return treaty


def _current_relationship(acceptor: Client, acceptor_review: dict, issuer_review: dict, body: dict,
                          treaty_id: str, *, issued: dict | None = None):
    """Re-read live status; a signed treaty keeps its original status after revoke."""
    row = acceptor.call("GET", "/recognition-treaties/<treaty_id>", parameters={"treaty_id": treaty_id})
    if row.get("status") != "active":
        raise WorkflowFailure("treaty_no_longer_active", "The recorded treaty is no longer active.",
                              {"treaty_id": treaty_id, "status": row.get("status")})
    live = _verified_treaty(row["treaty"], acceptor, acceptor_review["sovereign_id"],
                            issuer_review["sovereign_id"], body)
    if live.get("treaty_id") != treaty_id or (issued is not None and live != issued):
        raise ToolError("persisted_treaty_mismatch", "The persisted treaty differs from the recorded issued treaty.")
    return _trusted(acceptor, acceptor_review["sovereign_id"], issuer_review["sovereign_id"])


def _issue(journal, prefix, acceptor: Client, acceptor_review: dict, issuer_review: dict, body: dict):
    treaty = _mutation(journal, prefix + "issue", acceptor, "/admin/recognition-treaties", body, expected=201)
    _verified_treaty(treaty, acceptor, acceptor_review["sovereign_id"], issuer_review["sovereign_id"], body)
    # Reusing a recorded mutation is safe; reusing its old live-status
    # observations could hide a revocation while another step was interrupted.
    path = _current_relationship(acceptor, acceptor_review, issuer_review, body, treaty["treaty_id"], issued=treaty)
    summary = acceptor.call("GET", "/connectome.json")["summary"]
    return {"treaty_id": treaty["treaty_id"], "treaty_status": treaty["status"], "trust_path": path,
            "verification": {"status": "passed", "reason": path.get("reason")},
            "connectome_summary": summary}


def federation_preview(settings, args):
    settings.require(READ)
    acceptor, issuer = _pair(settings, args, "gm_workflow_federation_preview", Deadline(settings))
    return _preview(acceptor, issuer, args)[0]


def federation_bootstrap(settings, args):
    settings.require(WRITE)
    name = "gm_workflow_federation_bootstrap"
    acceptor, issuer = _pair(settings, args, name, Deadline(settings))
    acceptor.require_operator()
    inputs = {**args, "configured_acceptor": acceptor.identity(), "configured_issuer": issuer.identity()}
    with WorkflowJournal(settings, name, args["operation_id"], inputs) as journal:
        if journal.completed_result is not None:
            return journal.completed_result
        try:
            preview, a, i, body = _preview(acceptor, issuer, args)
            if args["preview_digest"] != preview["preview_digest"]:
                raise ToolError("preview_mismatch", "Review a fresh preview with the same authorities, pins and scope.")
            outcome = _issue(journal, "bootstrap-", acceptor, a, i, body)
            result = {"status": "completed", "operation_id": args["operation_id"],
                      "observed_at": datetime.now(timezone.utc).isoformat(),
                      "result": {**preview, "dry_run": False, **outcome}, "steps": journal.summary()}
            return _complete(journal, result)
        except Exception as exc:
            return _partial(journal, exc)


def fleet_status(settings, args):
    settings.require(READ)
    deadline = Deadline(settings)
    rows = []
    for alias in fleet_members(settings, args["fleet"]):
        client = Client(settings, alias, "gm_workflow_fleet_status", deadline, require_root=False)
        row: dict[str, Any] = {"authority": alias}
        for probe in ("healthz", "readyz"):
            try:
                response = client.raw("GET", "/" + probe)
                row[probe] = {"http_status": response["http_status"], "available": response["http_ok"],
                              "result": response["result"]}
            except Exception as exc:
                row[probe] = {"available": False, "error": safe_error(exc)}
        rows.append(row)
    return {"fleet": args["fleet"], "authorities": rows,
            "healthy": all(row[key]["available"] for row in rows for key in ("healthz", "readyz"))}


def fleet_verify(settings, args):
    settings.require(READ)
    deadline = Deadline(settings)
    aliases = fleet_members(settings, args["fleet"])
    clients = {alias: Client(settings, alias, "gm_workflow_fleet_verify", deadline) for alias in aliases}
    reviews, failures = {}, {}
    for alias, client in clients.items():
        try:
            reviews[alias] = review(client)
        except Exception as exc:
            failures[alias] = safe_error(exc)
    rows = []
    for source in aliases:
        for target in aliases:
            if source == target:
                continue
            row = {"from": source, "to": target, "trusted": False}
            if source in failures or target in failures:
                row["error"] = {"code": "authority_review_failed", "authorities": {
                    alias: failures[alias] for alias in (source, target) if alias in failures}}
            else:
                try:
                    distinct_pair(clients[source], clients[target], (reviews[source], reviews[target]))
                    path = clients[source].call("GET", "/connectome/trust-path", query={
                        "from": reviews[source]["sovereign_id"], "to": reviews[target]["sovereign_id"]})
                    row.update(trusted=path.get("trusted") is True, reason=path.get("reason"), hops=path.get("hop_count"))
                except Exception as exc:
                    row["error"] = safe_error(exc)
            rows.append(row)
    return {"fleet": args["fleet"], "pairs": rows, "untrusted": sum(not row["trusted"] for row in rows)}


def _existing_match(client, acceptor_review, issuer_review, body):
    rows = client.call("GET", "/recognition-treaties", query={"status": "active"}).get("recognition_treaties", [])
    for row in rows:
        if row.get("status") != "active":
            continue
        treaty = row.get("treaty", {})
        try:
            _verified_treaty(treaty, client, acceptor_review["sovereign_id"], issuer_review["sovereign_id"], body)
        except (ToolError, ValueError, TypeError):
            continue
        return treaty["treaty_id"]
    return None


def fleet_mesh(settings, args):
    settings.require(WRITE)
    name = "gm_workflow_fleet_mesh"
    deadline = Deadline(settings)
    aliases = fleet_members(settings, args["fleet"])
    clients = {alias: Client(settings, alias, name, deadline) for alias in aliases}
    for client in clients.values():
        client.require_operator()
    inputs = {**args, "configured_authorities": [client.identity() for client in clients.values()]}
    with WorkflowJournal(settings, name, args["operation_id"], inputs) as journal:
        if journal.completed_result is not None:
            return journal.completed_result
        results = []
        try:
            # Complete identity/custody review before the first mutation.
            reviews = {alias: review(client) for alias, client in clients.items()}
            if len({row["sovereign_id"] for row in reviews.values()}) != len(aliases):
                raise ToolError("distinct_authorities_required", "Fleet members must represent distinct sovereigns.")
            for source_index, source in enumerate(aliases):
                for target_index, target in enumerate(aliases):
                    if source == target:
                        continue
                    row = {"from": source, "to": target}
                    prefix = f"pair-{source_index}-{target_index}-"
                    body = _treaty_body(clients[target], reviews[target], _scope(args, fleet=True))
                    try:
                        # A prior mutation must be reconciled through its own
                        # journal result, especially when its outcome is unknown.
                        # Otherwise inspect existing treaties afresh on every
                        # incomplete retry; cached skip decisions can be revoked.
                        attempted = prefix + "issue" in journal.data["steps"]
                        existing = None if attempted else _existing_match(
                            clients[source], reviews[source], reviews[target], body)
                        if existing:
                            path = _current_relationship(clients[source], reviews[source], reviews[target], body, existing)
                            row.update(status="skipped", treaty_id=existing, trust_path=path)
                        else:
                            result = _issue(journal, prefix, clients[source], reviews[source], reviews[target], body)
                            row.update(status="created", **result)
                    except Exception as exc:
                        row.update(status="failed", error=safe_error(exc))
                    results.append(row)
            # Finish with a current observation of every successful pair,
            # including those created before a different pair interrupted us.
            for row in results:
                if row["status"] == "failed":
                    continue
                source, target = row["from"], row["to"]
                body = _treaty_body(clients[target], reviews[target], _scope(args, fleet=True))
                try:
                    row["trust_path"] = _current_relationship(clients[source], reviews[source], reviews[target],
                                                              body, row["treaty_id"])
                except Exception as exc:
                    row.update(status="failed", error=safe_error(exc))
            result = {"status": "partial" if any(row["status"] == "failed" for row in results) else "completed",
                      "operation_id": args["operation_id"], "fleet": args["fleet"], "pairs": results,
                      "observed_at": datetime.now(timezone.utc).isoformat(),
                      "created": sum(row["status"] == "created" for row in results),
                      "skipped": sum(row["status"] == "skipped" for row in results),
                      "failed": sum(row["status"] == "failed" for row in results), "steps": journal.summary()}
            return _complete(journal, result) if result["status"] == "completed" else result
        except Exception as exc:
            return _partial(journal, exc, extra={"fleet": args["fleet"], "pairs": results})


def _accepted(result, expected: bool, label: str):
    if result.get("accepted") is not expected:
        raise WorkflowFailure("proof_step_rejected", label, result)
    return result


def run_proof(settings, args, tool_name="gm_workflow_proof_remote"):
    """Run core's proof sequence with durable outcomes; also used by canary."""
    settings.require(WRITE)
    acceptor, issuer = _pair(settings, args, tool_name, Deadline(settings))
    acceptor.require_operator()
    issuer.require_operator()
    inputs = {**args, "configured_acceptor": acceptor.identity(), "configured_issuer": issuer.identity()}
    with WorkflowJournal(settings, tool_name, args["operation_id"], inputs) as journal:
        if journal.completed_result is not None:
            return journal.completed_result
        try:
            a, i = review(acceptor), review(issuer)
            distinct_pair(acceptor, issuer, (a, i))
            role = args.get("role", "role:client")
            claims = args.get("claims", {})
            validity = args.get("validity_hours", 24)
            body = {"subject_id": args.get("subject_id", "proof-" + args["operation_id"]),
                    "subject_public_key": args["subject_public_key"], "roles": [role], "claims": claims,
                    "validity_hours": validity}
            attestation = _mutation(journal, "attestation-issue", issuer, "/admin/attestations", body, expected=201)
            treaty_body = _treaty_body(issuer, i, {"roles": [role], "accepted_statuses": ["active"],
                                                 "claims": claims, "validity_hours": validity})
            treaty_body["metadata"] = {"proof": "remote-sovereign-proof", "subject_endpoint": issuer.settings.authority_url}
            treaty = _mutation(journal, "treaty-issue", acceptor, "/admin/recognition-treaties", treaty_body, expected=201)
            _verified_treaty(treaty, acceptor, a["sovereign_id"], i["sovereign_id"], treaty_body)
            verify_body = {"attestation": attestation, "treaty": treaty}
            pre = journal.step("verify-before", lambda: _accepted(acceptor.call("POST", "/attestations/verify-with-treaty",
                    body=verify_body), True, "The attestation was rejected before revocation."))
            _mutation(journal, "attestation-revoke", issuer, "/admin/attestations/<attestation_id>/revoke",
                      {"reason": "remote_sovereign_proof_revocation"}, parameters={"attestation_id": attestation["attestation_id"]})
            feed = journal.step("revocation-feed", lambda: issuer.call("GET", "/sovereign-revocation-feed",
                                                                       query={"issuer_sovereign_id": i["sovereign_id"]}))
            imported = _mutation(journal, "feed-import", acceptor, "/admin/sovereign-revocation-feeds/import",
                                 {"feed": feed, "expected_issuer_sovereign_id": i["sovereign_id"]})
            _accepted(imported, True, "The accepting authority rejected the revocation feed.")
            post = journal.step("verify-after", lambda: _accepted(acceptor.call("POST", "/attestations/verify-with-treaty",
                    body=verify_body), False, "The attestation remained accepted after revocation."))
            connectome = journal.step("connectome", lambda: acceptor.call("GET", "/connectome.json"))
            path = journal.step("trust-path", lambda: _trusted(acceptor, a["sovereign_id"], i["sovereign_id"]))
            bundle = {"proof": "remote-sovereign-recognition-revocation", "created_at": datetime.now(timezone.utc).isoformat(),
                      "operators": {"acceptor": {"operator_label": acceptor.alias, "operator_type": "unknown"},
                                    "issuer": {"operator_label": issuer.alias, "operator_type": "unknown",
                                               "controls_keys": False, "controls_infrastructure": False},
                                    "assistance_notes": [], "adoption_proof": False},
                      "acceptor": {"network_name": a["sovereign_id"], "endpoint": acceptor.settings.authority_url,
                                   "na_public_key_prefix": acceptor.settings.authority_public_key[:24]},
                      "issuer": {"network_name": i["sovereign_id"], "endpoint": issuer.settings.authority_url,
                                 "na_public_key_prefix": issuer.settings.authority_public_key[:24]},
                      "attestation_id": attestation["attestation_id"], "treaty_id": treaty["treaty_id"],
                      "feed_id": feed["feed_id"], "feed_sequence": feed["sequence"],
                      "pre_revocation": {"accepted": pre["accepted"], "reason": pre["reason"]},
                      "post_revocation": {"accepted": post["accepted"], "reason": post["reason"]},
                      "trust_path": path, "connectome_summary": connectome["summary"]}
            inspection = inspect_proof_bundle(bundle, connectome_artifact=connectome)
            if not inspection["valid"]:
                raise WorkflowFailure("proof_inspection_failed", "Core proof inspection rejected the completed summary.", inspection)
            return _complete(journal, {"status": "completed", "operation_id": args["operation_id"], "result": bundle,
                                       "inspection": inspection})
        except Exception as exc:
            return _partial(journal, exc)


def build_tools(settings: Settings) -> list[ToolSpec]:
    federation = {**PAIR, **SCOPE, "issuer_bundle": {"type": "object"}}
    definitions = [
        ("gm_workflow_federation_preview", "Review pinned sovereigns and preview a scoped recognition treaty. "
         "Returns a digest binding the proposed identities and scope; makes no trust mutation.",
         obj(federation, ("acceptor", "issuer")), federation_preview, READ, True, False, "federation bootstrap"),
        ("gm_workflow_federation_bootstrap", "Issue the reviewed recognition treaty, verify its signature and resulting "
         "trust path, and record partial or uncertain outcomes durably. Requires the matching preview digest.",
         obj({**federation, "operation_id": NAME, "preview_digest": TEXT},
             ("acceptor", "issuer", "operation_id", "preview_digest")), federation_bootstrap, WRITE, False, True,
         "federation bootstrap"),
        ("gm_workflow_fleet_status", "Probe health and readiness for every member of a configured fleet, preserving "
         "individual failures within one elapsed-time budget.", obj({"fleet": NAME}, ("fleet",)),
         fleet_status, READ, True, False, "fleet status"),
        ("gm_workflow_fleet_verify", "Verify pinned fleet identities and query every ordered trust path. "
         "An unreachable or untrusted pair remains a failure.", obj({"fleet": NAME}, ("fleet",)),
         fleet_verify, READ, True, False, "fleet verify"),
        ("gm_workflow_fleet_mesh", "Create missing scoped recognition treaties across a configured fleet. "
         "Reuse matching active signed treaties and persist per-pair outcomes without replaying uncertain mutations.",
         obj({"fleet": NAME, "operation_id": NAME, **SCOPE}, ("fleet", "operation_id")),
         fleet_mesh, WRITE, False, True, "fleet mesh"),
        ("gm_workflow_proof_remote", "Run a recognition and revocation proof between two configured authorities. "
         "Issues a real attestation and treaty, revokes the attestation, imports its feed and verifies rejection. "
         "Records durable partial outcomes; does not claim independent adoption.",
         obj({**PAIR, "operation_id": NAME, "role": TEXT, "subject_id": TEXT, "subject_public_key": TEXT,
              "claims": CLAIMS, "validity_hours": SCOPE["validity_hours"]},
             ("acceptor", "issuer", "operation_id", "subject_public_key")),
         run_proof, WRITE, False, True, "proof remote"),
    ]
    return [ToolSpec(name, description, schema, lambda args, function=function: function(settings, args), profiles,
                     read_only=read_only, destructive=destructive, idempotent=read_only,
                     core_targets=("cli:" + target,), open_world=True)
            for name, description, schema, function, profiles, read_only, destructive, target in definitions]
