"""Validate checkout-only test claims against a pytest execution receipt.

Collection and passing outcomes establish execution, not the meaning of assertions.
Runtime catalog discovery deliberately does not depend on this optional gate.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections import Counter
from pathlib import Path, PurePosixPath

FORMAT_VERSION = 1
OUTCOMES = frozenset({"passed", "failed", "skipped", "xfailed", "xpassed", "not_run", "deselected"})


def file_digest(path: Path) -> str:
    data = path.read_bytes()
    try:
        data = data.decode("utf-8").replace("\r\n", "\n").encode("utf-8")
    except UnicodeDecodeError:
        pass
    return hashlib.sha256(data).hexdigest()


def adapter_identity() -> dict:
    """Inventory the imported adapter, including a noneditable site-packages installation."""
    import genesismesh_mcp

    root = Path(genesismesh_mcp.__file__).resolve().parent
    files = {"src/genesismesh_mcp/" + path.relative_to(root).as_posix(): file_digest(path)
             for path in sorted(root.rglob("*")) if path.is_file() and "__pycache__" not in path.parts
             and path.suffix in {".py", ".json", ".md"}}
    return {"package_root": str(root), "files": files}


def source_identity(root: Path) -> dict:
    """Bind evidence to tracked and nonignored sources, independent of Git CRLF settings."""
    root = root.resolve()

    def git(*args):
        return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.DEVNULL)

    try:
        if Path(git("rev-parse", "--show-toplevel").decode().strip()).resolve() != root:
            raise ValueError("Not the repository root")
        names = git("ls-files", "-z", "--cached", "--others", "--exclude-standard").decode().split("\0")
        revision = git("rev-parse", "HEAD").decode().strip()
        dirty = bool(git("status", "--porcelain"))
    except (OSError, ValueError, subprocess.CalledProcessError):
        names = [p.relative_to(root).as_posix() for folder in ("src", "tests", "scripts")
                 for p in (root / folder).rglob("*") if p.is_file() and "__pycache__" not in p.parts]
        names += [name for name in ("pyproject.toml", "requirements.lock", "conftest.py") if (root / name).is_file()]
        revision, dirty = None, None
    files = {}
    for name in sorted(set(filter(None, names))):
        relative = PurePosixPath(name.replace("\\", "/"))
        path = root.joinpath(*relative.parts)
        if relative.is_absolute() or ".." in relative.parts or path.is_symlink() or not path.is_file():
            continue
        if not path.resolve().is_relative_to(root):
            continue
        files[relative.as_posix()] = file_digest(path)
    digest = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"revision": revision, "dirty": dirty, "content_sha256": digest, "files": files}


def valid_reference(reference: object) -> bool:
    if not isinstance(reference, str) or "::" not in reference or any(c in reference for c in "\\\r\n"):
        return False
    filename, selector = reference.split("::", 1)
    path = PurePosixPath(filename)
    return (bool(path.parts) and not path.is_absolute() and ".." not in path.parts and path.parts[0] == "tests"
            and path.suffix == ".py" and bool(selector) and all(selector.split("::")))


def matching_cases(reference: str, collected: list[str]) -> list[str]:
    return [nodeid for nodeid in collected if nodeid == reference or nodeid.startswith(reference + "[")
            or nodeid.startswith(reference + "::")]


def verify_evidence(root: Path, receipt: dict, coverage: dict, *, require_clean: bool = False) -> tuple[list[str], dict]:
    problems = []
    current = source_identity(root)
    adapter_files = {name: digest for name, digest in current["files"].items()
                     if name.startswith("src/genesismesh_mcp/") and Path(name).suffix in {".py", ".json", ".md"}}
    if receipt.get("format_version") != FORMAT_VERSION:
        problems.append("Unsupported test evidence format")
    for label in ("source_start", "source_end"):
        source = receipt.get(label)
        if not isinstance(source, dict) or any(source.get(key) != current[key]
                                              for key in ("revision", "content_sha256", "files")):
            problems.append(f"Test evidence {label} does not match the current revision and source contents")
        if require_clean and (not isinstance(source, dict) or source.get("dirty") is not False):
            problems.append(f"Test evidence {label} must describe a clean Git checkout")
    if require_clean and (current["dirty"] is not False or not current["revision"]):
        problems.append("Test evidence gate requires a clean Git checkout")
    for label in ("adapter_start", "adapter_end"):
        imported = receipt.get(label)
        if not adapter_files or not isinstance(imported, dict) or imported.get("files") != adapter_files:
            problems.append(f"Test evidence {label} imported adapter does not match the checkout sources")
    if receipt.get("collection_scope") != {"args": ["tests"], "restricted": False}:
        problems.append("Test evidence requires unrestricted tests/ collection; positional subsets and selection overrides are refused")
    if receipt.get("exit_status") != 0 or receipt.get("collection_errors") != []:
        problems.append("Test session did not finish successfully without collection errors")
    collected, outcomes = receipt.get("collected"), receipt.get("outcomes")
    if not isinstance(collected, list) or not collected or any(not isinstance(n, str) for n in collected):
        problems.append("Test evidence has no valid collected test inventory")
        collected = []
    if len(set(collected)) != len(collected):
        problems.append("Test evidence contains duplicate collected IDs")
    if not isinstance(outcomes, dict):
        problems.append("Test evidence has no valid outcomes")
        outcomes = {}
    if set(outcomes) != set(collected) or any(not isinstance(v, str) or v not in OUTCOMES for v in outcomes.values()):
        problems.append("Test outcomes must exactly match the collected inventory with recognized outcomes")
    references, matched, claims = set(), set(), 0
    for row in coverage["rows"]:
        capability = row["id"]
        if row.get("verification_status") == "not_exercised":
            continue
        claims += 1
        refs = row.get("tests")
        if not isinstance(refs, list) or not refs:
            problems.append(f"{capability}: exercised claim has no test references")
            continue
        for reference in refs:
            if not valid_reference(reference):
                problems.append(f"{capability}: invalid test reference {reference!r}")
                continue
            references.add(reference)
            cases = matching_cases(reference, collected)
            if not cases:
                problems.append(f"{capability}: cited test was not collected: {reference}")
            for case in cases:
                matched.add(case)
                if outcomes.get(case) != "passed":
                    problems.append(f"{capability}: cited case did not pass: {case} ({outcomes.get(case, 'missing')})")
    summary = {"claims": claims, "references": len(references), "matched_cases": len(matched),
               "valid": not problems,
               "collected_cases": len(collected), "outcomes": dict(Counter(str(v) for v in outcomes.values())),
               "source_revision": current["revision"], "source_sha256": current["content_sha256"],
               "meaning": "Checks collection and passing outcomes; assertion relevance still requires review."}
    return sorted(set(problems)), summary


def load_receipt(path: Path) -> dict:
    if path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("Test evidence exceeds 16 MiB")
    receipt = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(receipt, dict):
        raise ValueError("Test evidence must be an object")
    return receipt


def verify_branch_coverage(receipt: dict, report: dict, *, root: Path | None = None) -> tuple[list[str], dict]:
    """Reject stale or statement-only measurements; retain the raw report for inspection."""
    problems = []
    source = receipt.get("source_start", {})
    expected = "genesismesh-source:" + source.get("content_sha256", "") if isinstance(source, dict) else None
    context = receipt.get("coverage_context")
    if context != expected or not context:
        problems.append("Test receipt does not identify a source-bound coverage context")
    meta = report.get("meta", {})
    if not isinstance(meta, dict) or meta.get("branch_coverage") is not True or meta.get("show_contexts") is not True:
        problems.append("Coverage report must include branches and measurement contexts")
    files = report.get("files", {})
    contexts = set()
    expected_files = {name: digest for name, digest in source.get("files", {}).items()
                      if name.startswith("src/genesismesh_mcp/") and name.endswith(".py")} if isinstance(source, dict) else {}
    measured_files, tallies = set(), Counter()
    fields = ("num_statements", "covered_lines", "num_branches", "covered_branches")
    if not isinstance(files, dict) or not files:
        problems.append("Coverage report has no measured files")
        files = {}
    for filename, measured in files.items():
        parts = PurePosixPath(filename.replace("\\", "/")).parts
        canonical = "src/" + "/".join(parts[parts.index("genesismesh_mcp"):]) if "genesismesh_mcp" in parts else None
        if canonical not in expected_files or canonical in measured_files:
            problems.append(f"Unexpected or duplicate measured adapter file: {filename}")
        else:
            measured_files.add(canonical)
            actual = Path(filename)
            if not actual.is_absolute():
                actual = (root or Path.cwd()) / actual
            if not actual.is_file() or file_digest(actual) != expected_files[canonical]:
                problems.append(f"Measured adapter file contents do not match the receipt: {filename}")
        per_file = measured.get("summary", {}) if isinstance(measured, dict) else {}
        if (any(type(per_file.get(k)) is not int or per_file[k] < 0 for k in fields)
                or per_file["covered_lines"] > per_file["num_statements"]
                or per_file["covered_branches"] > per_file["num_branches"]):
            problems.append(f"Per-file coverage totals are invalid: {filename}")
        else:
            tallies.update({key: per_file[key] for key in fields})
        line_contexts = measured.get("contexts", {}) if isinstance(measured, dict) else None
        if not isinstance(line_contexts, dict):
            problems.append(f"Coverage contexts are malformed: {filename}")
            continue
        for values in line_contexts.values():
            if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
                problems.append(f"Coverage contexts are malformed: {filename}")
            else:
                contexts.update(values)
    if expected not in contexts or contexts - {"", expected}:
        problems.append("Coverage measurements do not match the test receipt's source context")
    if not expected_files or measured_files != expected_files.keys():
        problems.append("Coverage report must inventory every checkout adapter Python file")
    totals = report.get("totals", {})
    if (not isinstance(totals, dict) or any(type(totals.get(k)) is not int or totals[k] < 0 for k in fields)
            or not totals.get("num_statements") or not totals.get("num_branches")
            or totals["covered_lines"] > totals["num_statements"] or totals["covered_branches"] > totals["num_branches"]):
        problems.append("Coverage totals are missing or invalid")
        totals = {}
    elif any(totals[key] != tallies[key] for key in fields):
        problems.append("Coverage totals do not match per-file measurements")
    summary = {"valid": not problems, "coverage_context": context, "measured_files": len(files),
               **{key: totals.get(key) for key in fields}}
    if totals:
        summary["line_percent"] = round(100 * totals["covered_lines"] / totals["num_statements"], 2)
        summary["branch_percent"] = round(100 * totals["covered_branches"] / totals["num_branches"], 2)
    return sorted(set(problems)), summary
