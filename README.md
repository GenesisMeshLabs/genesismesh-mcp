# Genesis Mesh MCP

A standalone [Model Context Protocol](https://modelcontextprotocol.io/) server for Genesis Mesh: Network Authority operations, offline trust primitives, signing, evidence verification and a complete reference to the core public surface.

**Core compatibility: Genesis Mesh 1.8.1.** This is an unreleased development adapter (`0.1.0.dev0`), not yet a component of the coordinated release train. It reuses the core implementation and the [official MCP Python SDK](https://py.sdk.modelcontextprotocol.io/); it does not implement a second trust protocol.

## Coverage

- Named adapters cover **all 116 public HTTP method/path operations**, plus separate signed node and attestation rosters.
- Offline tools cover agreements, delegation, recognition, tokens, freshness, policy decisions, execution evidence, audit verification, disclosure, consensus, data governance, oversight, risk, privacy, purge, discovery, interoperability, grants and key history.
- The catalog accounts for **782 contract entries**, including every CLI command, public Python symbol, signed artifact, error code, package and behavioral rule. These are overlapping surfaces, not 782 independent features.
- Resources include model schemas, all **137 CLI command references**, compatibility details, configuration capabilities and the current coverage report.
- **284 tools** include configured workflows for federation, fleet generation/mesh/status/verification, remote proofs/canaries/cleanup, audit packs/archives, held anchors, treaty lifecycle, node enrollment/status, peer sends and guard requests.

Coverage accounting, executable adapters and tested behavior are reported separately. The executable-workflow gap count is **zero** against the pinned contract: 119 CLI commands have adapters and 18 describe host/custody operations. Host daemons, general database migration/restore and production root-key custody remain documented boundaries. This is not identical CLI flag/process behavior or proof of production deployment. See [measured coverage](docs/coverage.md), [workflow scope](docs/operational-gaps.md), and [configuration examples](docs/workflows.md).

## Install

Requires Python 3.12 or later. From this repository:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -c requirements.lock ".[dev]"
.\.venv\Scripts\python.exe -m genesismesh_mcp --check
```

On Linux/macOS, use `.venv/bin/python`. The constraints file pins the dependency set verified for this checkout. Development commands work with an editable installation too: replace `".[dev]"` with `-e ".[dev]"`.

`--check` checks compatibility, packaged snapshot integrity, tool registration and coverage. It does not connect to an authority or validate that credentials are usable.

## Connect an MCP host

Use the installed interpreter's absolute path. A typical MCP host configuration is:

```json
{
  "mcpServers": {
    "genesismesh": {
      "command": "C:/path/to/genesismesh-mcp/.venv/Scripts/python.exe",
      "args": ["-m", "genesismesh_mcp"]
    }
  }
}
```

The server runs over **stdio**. stdout carries MCP only. There is no unauthenticated remote HTTP listener. Offline verification works without a Network Authority.

To use an authority, create a gitignored `config.local.json`:

```json
{
  "authority_url": "https://your-authority.example",
  "profiles": ["read", "verify"]
}
```

Append `"--config", "C:/path/to/config.local.json"` to the host's arguments. Configuration paths resolve relative to that file. HTTP is allowed only for explicitly enabled loopback development, using `"allow_http_loopback": true`.

## Enable privileged operations deliberately

Profiles are checked both when listing tools and when invoking them directly:

| Profile | Purpose |
| --- | --- |
| `read` | Public authority reads and public bundle export |
| `verify` | Offline checks and verification endpoints |
| `operator` | Operator-authenticated authority operations; also needs `read` or `write` |
| `node` | Dedicated node identity operations; also needs `write` |
| `write` | Authority mutations and recorded operations |
| `sign` | Offline artifact signing with explicitly permitted signers |
| `local` | Confined artifact reads and configured workflow storage/journals |
| `execute` | Configured peer sends and fixed guard actions; requires their other profiles |
| `provision` | Private fleet or node-key creation in server-configured storage |
| `maintain` | Configured canary audit stores and explicitly disposable proof-database cleanup |

For authority administration, configure `operator_key_file`, `operator_key_id`, and an independently obtained `authority_public_key`. Core operator tiers still apply. Node operations use `node_key_file`; edge enrollment also uses `executor_key_file`. Enrollment's `invite_token` is local configuration, not a model input.

Offline signing requires both a signer reference and an exact tool allowlist:

```json
{
  "profiles": ["verify", "sign"],
  "signer_files": {"issuer": "keys/issuer.key"},
  "signer_permissions": {
    "issuer": ["gm_offline_freshness_issue_freshness_proof"]
  }
}
```

Keys use the core's base64 key-file format. There are no wildcard signer permissions. The model supplies a `signer_ref`, never a private key, key path, signer backend or replacement authority URL. There is no raw arbitrary-signing tool.

An invitation tool intentionally returns its newly issued enrollment token; treat that result as sensitive. Oversight signing does **not** prove that a separate human approved: the host and configured key custodian must control those calls. A policy ALLOW is an assessment, not proof an external action executed.

## Discover and use the core

Read these MCP resources:

- `genesis-mesh://coverage` — implementation, test evidence, disabled profiles, boundaries and gaps.
- `genesis-mesh://compatibility` — core version, immutable revision and contract digest.
- `genesis-mesh://configuration` — enabled profiles and signer permissions; no key paths or secrets.
- `genesis-mesh://schema/<module>:<Model>` — structural JSON schema; not cryptographic verification.
- `genesis-mesh://cli/trust/delegate/verify` — core CLI syntax and option reference.
- `genesis-mesh://errors`, `genesis-mesh://rules`, `genesis-mesh://packages` — preserved core contract semantics.

Examples of requests to an MCP host:

- “Inspect this authority's key history and recognition policy.”
- “Verify this agreement and explain the rejection details.”
- “Validate this trust bundle; distinguish structural consistency from authenticity.”
- “Verify this evidence export against the root key and anchors I hold.”
- “Build an Atlas from this graph and overlay the signed evidence.”
- “Show which core operations this server implements and which still need orchestration.”

Typed tools expose argument schemas through MCP. Binary arguments/results use standard base64. Signed artifacts retain the core's wire representation. HTTP results distinguish `http_ok` from protocol decisions within `result`; a successful HTTP request can still return a trust denial.

## Verify a change

```powershell
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts/snapshot_cli.py --check
.\.venv\Scripts\python.exe scripts/check_coverage.py --core ../genesismesh --require-http --require-no-gaps
.\.venv\Scripts\python.exe scripts/render_coverage.py --check
.\.venv\Scripts\python.exe -m build
```

The source check requires the exact revision in `data/compatibility.json`. New core surfaces, changed signatures, invalid aliases, snapshot drift and missing workflow adapters fail CI. `--require-no-gaps` includes incomplete compositions; schemas, references and documented host boundaries remain separate classifications.

Tests include disposable real HTTP authorities, Noise peers, guard subprocesses, SQLite stores, domain success/denial paths, official MCP clients, real stdio processes, signing isolation and filesystem limits. Recovery tests exercise missing mutation replies, revoked certificates, changed anchors, corrupt readback and key-history rollback. `scripts/smoke_installed.py` must additionally run with a fresh wheel-only virtual environment; an editable-environment stdio test is not clean-wheel evidence. CI runs Windows/Linux and Python 3.12/3.14.

## Limits

`max_input_bytes` and `max_output_bytes` default to 1 MiB and 4 MiB. Oversized artifacts are refused, never silently truncated. HTTP responses are read with bounded streaming and redirects/retries disabled. `timeout_seconds` controls socket inactivity and streamed-body elapsed checks; it is not a hard process or CPU deadline. Known quadratic audit/Atlas workloads have separate complexity limits.

General workspace access remains read-only. Workflow writes use separately configured artifact, node, provisioning and proof-store locations. Private workflow/node/provisioning storage cannot overlap readable workspace or artifact roots. The stdio host user is the security boundary: this is not a multi-user hosted authorization service. No production authority was modified to test this implementation.
