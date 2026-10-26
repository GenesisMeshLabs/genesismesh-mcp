# Working on Genesis Mesh MCP

- Keep protocol rules, canonical serialization, cryptography and trust decisions in the pinned Genesis Mesh dependency. This repository adapts those capabilities to MCP.
- Read `docs/architecture.md` and the packaged coverage catalog before extending a tool. Distinguish executable behavior, support primitives, schemas and operational boundaries.
- Never turn a policy ALLOW, valid signature or submitted record into a claim that an external action executed.
- Add named, typed adapters. Do not add arbitrary URLs, shell commands, Python imports or raw private keys to tool inputs.
- Preserve core signed wire representations. Never silently truncate or normalize signed data before presenting it as original evidence.
- Every new signing adapter requires explicit profile and per-tool signer permission checks. MCP annotations are descriptive, not authorization.
- Recheck source drift with `python scripts/check_coverage.py --core PATH --require-http`; preserve the exact immutable core pin until an intentional compatibility update.
- The core pin lives in `src/genesismesh_mcp/data/compatibility.json` (release, commit, contract digest); `pyproject.toml`, `requirements.lock` and the README name the same release (a test checks it), and CI checks out that commit. When a core release is published, Renovate opens an "Update Genesis Mesh" pull request that moves the pip pins; it fails until the compatibility update is done on its branch: set `compatibility.json` to the release's tag commit, refresh the packaged contract data and the CLI snapshot (`scripts/snapshot_cli.py`), review the request schemas and the coverage (`scripts/check_coverage.py --core PATH`, `scripts/render_coverage.py`), and update the README line.
- Run Ruff, pytest, the CLI snapshot check and a clean wheel stdio smoke before delivery. Windows and Linux are supported; CI owns unrun platforms.
- Keep working plans/review notes under gitignored `temp/`. Never commit configured keys, invite tokens, local configuration or real trust material.
- Use signed personal-identity commits and PRs for shared changes. The Maintainer merges. No AI attribution in commits or PRs.
