"""Optional pytest execution receipt; no runtime dependency on pytest."""

from __future__ import annotations

import hashlib
import inspect
import json
import platform
import sys
import threading
from collections import Counter
from contextvars import ContextVar
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from genesismesh_mcp.test_evidence import FORMAT_VERSION, adapter_identity, source_identity
from genesismesh_mcp.tool_evidence import definition_digest, register_observer
from genesismesh_mcp.types import ToolSpec

_CASE = ContextVar("genesismesh_test_case", default=None)


# Exact reviewed result shapes: adverse domain outcomes, not necessarily failed calls.
# Constructors and opaque extracted records do not inherit generic policy flags.
_DOMAIN_OUTCOMES = {
    'gm_offline_atlas_lookup_trust_path': lambda result, arguments: result is None,
    'gm_offline_jose_jwt_to_decision_claims': lambda result, arguments: result is None,
    'gm_offline_spiffe_svid_to_agreement_fields': lambda result, arguments: result is None,
    'gm_offline_w3c_vc_vc_to_trust_evidence_fields': lambda result, arguments: result is None,
    'gm_offline_remediation_rfc3339': lambda result, arguments: result is None,
    'gm_offline_consensus_assess_cascade_risk': lambda result, arguments: isinstance(result, (list, tuple)) and len(result) == 2 and isinstance(result[0], dict) and result[0].get('blocked') is True and result[1] == 'cascade_detected',
    'gm_offline_context_assess_attestation_basis': lambda result, arguments: isinstance(result, dict) and result.get('status_failure') in {'attestation_not_found', 'attestation_invalid', 'attestation_revoked', 'attestation_subject_mismatch'},
    'gm_offline_context_evaluate_context': lambda result, arguments: isinstance(result, dict) and isinstance(result.get('decision'), dict) and result['decision'].get('authorized') is False,
    'gm_offline_context_integrity_scan_for_injection_markers': lambda result, arguments: isinstance(result, list) and bool(result) and all(isinstance(item, str) for item in result),
    'gm_offline_privacy_scan_metadata_fingerprints': lambda result, arguments: isinstance(result, list) and bool(result) and all(isinstance(item, str) for item in result),
    'gm_offline_context_validate_boundary_policy': lambda result, arguments: isinstance(result, dict) and isinstance(result.get('issues'), list) and bool(result['issues']) and all(isinstance(item, dict) and isinstance(item.get('code'), str) and bool(item['code']) for item in result['issues']),
    'gm_offline_evidence_store_check_metadata_only': lambda result, arguments: isinstance(result, str) and bool(result),
    'gm_offline_grants_envelope_secret_problem': lambda result, arguments: isinstance(result, str) and bool(result),
    'gm_offline_grants_use_secret_problem': lambda result, arguments: isinstance(result, str) and bool(result),
    'gm_offline_remediation_request_approval_problem': lambda result, arguments: isinstance(result, str) and bool(result),
    'gm_offline_remediation_review_approval_problem': lambda result, arguments: isinstance(result, str) and bool(result),
    'gm_offline_evidence_store_validate_execution': lambda result, arguments: isinstance(result, dict) and isinstance(result.get('code'), str) and bool(result['code']),
    'gm_offline_out_of_band_check_break_glass': lambda result, arguments: isinstance(result, dict) and isinstance(result.get('code'), str) and bool(result['code']),
    'gm_offline_out_of_band_check_observation': lambda result, arguments: isinstance(result, dict) and isinstance(result.get('code'), str) and bool(result['code']),
    'gm_offline_remediation_check_remediation': lambda result, arguments: isinstance(result, dict) and isinstance(result.get('code'), str) and bool(result['code']),
    'gm_offline_remediation_remediation_record_problem': lambda result, arguments: isinstance(result, (list, tuple)) and len(result) == 2 and isinstance(result[0], dict) and isinstance(result[0].get('code'), str) and bool(result[0]['code']),
    'gm_offline_evidence_store_verify_retention_checkpoint': lambda result, arguments: result is False,
    'gm_offline_remediation_admin_approval_valid': lambda result, arguments: result is False,
    'gm_offline_grants_check_grant': lambda result, arguments: isinstance(result, dict) and isinstance(result.get('problems'), list) and bool(result['problems']) and all(isinstance(item, dict) and isinstance(item.get('reason'), str) and bool(item['reason']) for item in result['problems']),
    'gm_offline_grants_use_problem': lambda result, arguments: isinstance(result, (list, tuple)) and len(result) == 2 and isinstance(result[0], str) and bool(result[0]) and isinstance(result[1], str),
    'gm_offline_key_succession_genesis_refusal': lambda result, arguments: isinstance(result, (list, tuple)) and len(result) == 2 and result[0] in {'genesis_invalid', 'genesis_root_mismatch', 'unknown_field', 'non_canonical_form', 'genesis_invalid_signature'},
    'gm_offline_oversight_evaluate_oversight_policy': lambda result, arguments: isinstance(result, dict) and result.get('result') == 'block',
    'gm_offline_remediation_review_request_problem': lambda result, arguments: isinstance(result, (list, tuple)) and len(result) == 2 and result[0] in ['review_requested_by_actor'] and isinstance(result[1], str),
    'gm_offline_remediation_review_holder_problem': lambda result, arguments: isinstance(result, (list, tuple)) and len(result) == 2 and result[0] in ['review_same_holder_as_requester', 'review_same_holder_as_actor'] and isinstance(result[1], str),
    'gm_offline_remediation_rotation_problem': lambda result, arguments: isinstance(result, (list, tuple)) and len(result) == 2 and result[0] in ['remediation_rotation_other_executor', 'remediation_rotation_before_change', 'remediation_rotation_reused'] and isinstance(result[1], str),
    'gm_offline_remediation_remediation_plan': lambda result, arguments: isinstance(result, dict) and result.get('mode') == 'alert_only' and result.get('steps') == 'none' and result.get('fallback') in ['not_versioned', 'not_rotatable', 'not_reversible', 'indeterminate'],
    'gm_offline_remediation_decision_plan': lambda result, arguments: isinstance(result, dict) and result.get('mode') == 'alert_only' and result.get('steps') == 'none' and result.get('fallback') in ['not_versioned', 'not_rotatable', 'not_reversible', 'not_executed'],
    'gm_offline_remediation_emergency_map': lambda result, arguments: isinstance(result, dict) and not result and isinstance(arguments, dict) and isinstance(arguments.get('policies'), list) and any(isinstance(policy, dict) and isinstance(policy.get('emergency'), dict) and isinstance(policy.get('selector'), dict) and isinstance(policy['selector'].get('capabilities'), list) and len(policy['selector']['capabilities']) == 1 for policy in arguments['policies']),
    'gm_offline_trust_bundle_validate_trust_bundle': lambda result, arguments: isinstance(result, dict) and isinstance(result.get('errors'), list) and bool(result['errors']) and all(isinstance(item, str) and bool(item) for item in result['errors']),
}

def _denial(result, tool_name=None, arguments=None):
    if tool_name in _DOMAIN_OUTCOMES:
        return _DOMAIN_OUTCOMES[tool_name](result, arguments)
    if (isinstance(result, dict) and result.get("http_ok") is True
            and isinstance(result.get("result"), dict)):
        body, status = result["result"], result.get("http_status")
        args = arguments if isinstance(arguments, dict) else {}
        path = args.get("path") if isinstance(args.get("path"), dict) else {}
        request = args.get("body") if isinstance(args.get("body"), dict) else {}
        historical_fields = set()
        if (tool_name == "na_boundary_verify" and status == 200
                and type(body.get("accepted")) is bool and type(body.get("authorized")) is bool
                and all(isinstance(body.get(key), str) and body[key] for key in ("decision_id", "reason"))):
            historical_fields = {"authorized"}  # Signature validity and historical policy outcome are distinct.
        elif (tool_name == "na_out_of_band_propose_holder" and status == 201 and body.get("approved") is False
                and all(isinstance(body.get(key), str) and body[key] for key in ("proposal_id", "key_id", "holder", "proposed_by"))
                and body["key_id"] == path.get("key_id") and body["holder"] == request.get("holder")):
            historical_fields = {"approved"}  # A recorded proposal awaits another holder.
        elif (tool_name in {"na_remediation_get_remediation", "na_remediation_record_notice"} and status == 200
                and body.get("subject_kind") in ("decision", "judgement") and body.get("subject_id") == path.get("subject_id")
                and isinstance(body.get("subject_id"), str) and bool(body["subject_id"])
                and body.get("state") in ("judged_allowed", "matched", "recorded", "remediation_due", "overdue", "remediated", "upheld", "waived")
                and type(body.get("review_pending")) is bool):
            if ((tool_name == "na_remediation_get_remediation" and isinstance(body.get("reviews"), list) and isinstance(body.get("records"), list))
                    or (tool_name == "na_remediation_record_notice" and all(isinstance(body.get(key), str) and body[key] for key in ("notified_at", "notified_by")))):
                historical_fields = {"verdict"}  # Original decision retained in a successfully read/updated state record.
        if historical_fields:
            result = {**result, "result": {key: value for key, value in body.items() if key not in historical_fields}}
        if tool_name == "na_treaties_connectome_trust_path" and body.get("trusted") is False:
            return True
    if result is False:
        return True
    if isinstance(result, dict):
        if (tool_name == "gm_offline_oversight_reject_commitment"
                and result.get("approved") is False and result.get("human_signature")):
            # This named constructor succeeds by producing a signed refusal.
            # Other error flags still apply; verification/evaluation False does not get this exception.
            result = {key: value for key, value in result.items() if key != "approved"}
        return (any(result.get(key) is False for key in ("valid", "verified", "accepted", "http_ok", "authorized", "approved", "completed", "complete",
                                                       "accepted_for_review", "local_state_available"))
                or (type(result.get("evidence_failures")) is int and result["evidence_failures"] > 0)
                or result.get("status") in ("failed", "denied", "rejected", "partial", "unknown")
                or result.get("verdict") in ("deny", "block")
                or ("http_ok" in result and _denial(result.get("result")))
                or (isinstance(result.get("decision"), dict) and _denial(result["decision"])))
    return isinstance(result, (list, tuple)) and bool(result) and result[0] is False


def pytest_addoption(parser):
    parser.addoption("--evidence-report", type=Path, help="Write a source-bound execution receipt")


def pytest_configure(config):
    destination = config.getoption("--evidence-report")
    if destination:
        config.pluginmanager.register(ExecutionReceipt(config, destination), "execution-receipt")


class ExecutionReceipt:
    def __init__(self, config, destination):
        self.root, self.destination = config.rootpath, destination
        self.start = source_identity(self.root)
        self.adapter_start = adapter_identity()
        restricted = any(getattr(config.option, name, False) for name in (
            "keyword", "markexpr", "deselect", "ignore", "ignore_glob", "pyargs", "override_ini",
            "lf", "stepwise", "stepwise_skip", "stepwise_reset", "collectonly", "keepduplicates", "noconftest", "confcutdir",
            "runxfail", "plugins", "inifilename", "rootdir"))
        self.scope = {"args": list(config.args), "restricted": restricted}
        self.plugins = sorted({f"{dist.project_name}=={dist.version}" for _, dist in config.pluginmanager.list_plugin_distinfo()})
        self.coverage_context = None
        self.measurement_config = None
        coverage = sys.modules.get("coverage")
        measurement = coverage.Coverage.current() if coverage is not None else None
        if measurement is not None:
            options = ("run:branch", "run:source", "run:source_pkgs", "run:include", "run:omit", "run:core",
                       "report:exclude_lines", "report:exclude_also", "report:partial_branches")
            self.measurement_config = json.loads(json.dumps({name: measurement.get_option(name) for name in options}))
            self.coverage_context = "genesismesh-source:" + self.start["content_sha256"]
            measurement.switch_context(self.coverage_context)
        self.collected, self.deselected, self.collection_errors = [], [], []
        self.reports = {}
        self.active_test = None
        self.tool_calls = Counter()
        self.call_lock = threading.Lock()
        self.original_init = ToolSpec.__init__
        import requests

        self.transport_identity = (requests.Session, requests.sessions.Session, requests.sessions.Session.request,
                                   requests.sessions.Session.send)

        @wraps(self.original_init)
        def observed_init(tool, *args, **kwargs):
            self.original_init(tool, *args, **kwargs)
            handler = tool.handler
            if not callable(handler):
                return
            definition = definition_digest(tool, self.adapter_start["files"])

            @wraps(handler)
            def observed_call(arguments):
                owner = _CASE.get()
                nodeid, phase = owner if owner is not None else (None, None)
                valid = Draft202012Validator(tool.input_schema, format_checker=FormatChecker()).is_valid(arguments)
                current = (requests.Session, requests.sessions.Session, requests.sessions.Session.request, requests.sessions.Session.send)
                mocked = any(value is not original for value, original in zip(current, self.transport_identity))
                outcome = "returned"
                denial = False
                try:
                    result = handler(arguments)
                    denial = _denial(result, tool.name, arguments)
                    return result
                except BaseException as exc:
                    outcome = type(exc).__name__
                    raise
                finally:
                    if nodeid is not None and self.active_test == nodeid:
                        with self.call_lock:
                            self.tool_calls[nodeid, phase, tool.name, valid, outcome, definition, mocked, denial] += 1

            register_observer(observed_call, handler, self.adapter_start["files"])
            object.__setattr__(tool, "handler", observed_call)

        self.observed_init = observed_init
        ToolSpec.__init__ = observed_init

    def pytest_runtest_logstart(self, nodeid, location):
        self.active_test = nodeid

    def pytest_runtest_setup(self, item):
        _CASE.set((item.nodeid, "setup"))

    @pytest.hookimpl(wrapper=True, tryfirst=True)
    def pytest_runtest_call(self, item):
        original = item.obj
        token = _CASE.set((item.nodeid, "call"))
        if inspect.iscoroutinefunction(original):
            @wraps(original)
            async def contextual(*args, **kwargs):
                task_token = _CASE.set((item.nodeid, "call"))
                try:
                    return await original(*args, **kwargs)
                finally:
                    _CASE.reset(task_token)
            item.obj = contextual
        try:
            return (yield)
        finally:
            item.obj = original
            _CASE.reset(token)

    def pytest_runtest_teardown(self, item, nextitem):
        _CASE.set((item.nodeid, "teardown"))

    def pytest_runtest_logfinish(self, nodeid, location):
        self.active_test = None
        _CASE.set(None)

    def pytest_unconfigure(self, config):
        ToolSpec.__init__ = self.original_init

    def pytest_collection_finish(self, session):
        self.collected = [item.nodeid for item in session.items]

    def pytest_deselected(self, items):
        self.deselected.extend(item.nodeid for item in items)

    def pytest_collectreport(self, report):
        if report.failed:
            self.collection_errors.append(report.nodeid)

    def pytest_runtest_logreport(self, report):
        self.reports.setdefault(report.nodeid, []).append(
            (report.when, report.outcome, getattr(report, "wasxfail", None)))

    def pytest_sessionfinish(self, session, exitstatus):
        outcomes = dict.fromkeys(self.deselected, "deselected")
        for nodeid in self.collected:
            phases = self.reports.get(nodeid, [])
            if any(outcome == "failed" for _, outcome, _ in phases):
                result = "failed"
            elif any(outcome == "skipped" and xfail is not None for _, outcome, xfail in phases):
                result = "xfailed"
            elif any(outcome == "passed" and xfail is not None for _, outcome, xfail in phases):
                result = "xpassed"
            elif any(outcome == "skipped" for _, outcome, _ in phases):
                result = "skipped"
            elif {phase for phase, outcome, _ in phases if outcome == "passed"} == {"setup", "call", "teardown"}:
                result = "passed"
            else:
                result = "not_run"
            outcomes[nodeid] = result
        receipt = {"format_version": FORMAT_VERSION, "created_at": datetime.now(timezone.utc).isoformat(),
                   "python": platform.python_version(), "platform": platform.platform(),
                   "exit_status": int(exitstatus), "source_start": self.start, "source_end": source_identity(self.root),
                   "collected": self.collected + self.deselected, "outcomes": outcomes,
                   "collection_errors": self.collection_errors}
        receipt["coverage_context"] = self.coverage_context
        receipt["measurement_config"] = self.measurement_config
        receipt["measurement_config_sha256"] = hashlib.sha256(
            json.dumps(self.measurement_config, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        receipt["adapter_start"], receipt["adapter_end"] = self.adapter_start, adapter_identity()
        receipt["collection_scope"] = self.scope
        receipt["pytest_version"], receipt["plugins"] = pytest.__version__, self.plugins
        receipt["tool_calls"] = [{"test": nodeid, "phase": phase, "tool": tool, "schema_valid": valid,
                                  "outcome": outcome, "definition": definition, "transport_mocked": mocked,
                                  "domain_denial": denial, "count": count}
                                 for (nodeid, phase, tool, valid, outcome, definition, mocked, denial), count in sorted(self.tool_calls.items())]
        self.destination.parent.mkdir(parents=True, exist_ok=True)
        self.destination.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
