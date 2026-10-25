"""Optional pytest execution receipt; no runtime dependency on pytest."""

from __future__ import annotations

import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

from genesismesh_mcp.test_evidence import FORMAT_VERSION, source_identity


def pytest_addoption(parser):
    parser.addoption("--evidence-report", type=Path, help="Write a source-bound execution receipt")


def pytest_configure(config):
    destination = config.getoption("--evidence-report")
    if destination:
        config.pluginmanager.register(ExecutionReceipt(config.rootpath, destination), "execution-receipt")


class ExecutionReceipt:
    def __init__(self, root, destination):
        self.root, self.destination = root, destination
        self.start = source_identity(root)
        self.coverage_context = None
        coverage = sys.modules.get("coverage")
        measurement = coverage.Coverage.current() if coverage is not None else None
        if measurement is not None:
            self.coverage_context = "genesismesh-source:" + self.start["content_sha256"]
            measurement.switch_context(self.coverage_context)
        self.collected, self.deselected, self.collection_errors = [], [], []
        self.reports = {}

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
            elif any(outcome == "skipped" and xfail for _, outcome, xfail in phases):
                result = "xfailed"
            elif any(outcome == "passed" and xfail for _, outcome, xfail in phases):
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
        self.destination.parent.mkdir(parents=True, exist_ok=True)
        self.destination.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
