# Workflow parity and hosting boundaries

All 10 previously missing workflows and all 7 component-only compositions now have named configured adapters. `--require-no-gaps` passes against Genesis Mesh 1.8.1, commit `9e4d5c01e6ba7a22e73c17388796ec274f73a2fc`. The catalog separately reports registration, test evidence, availability and hosting boundaries.

| Core workflow | MCP adapter | Implemented behavior |
| --- | --- | --- |
| `federation bootstrap` | `gm_workflow_federation_preview`, `gm_workflow_federation_bootstrap` | Review pinned sovereign identities, bind a preview to scope/identities, issue the treaty, verify the persisted relationship and retain partial outcomes. |
| `fleet generate` | `gm_workflow_fleet_generate` | Core root/NA/operator key creation, signed genesis, final-path configurations and manifest, privately staged and atomically published. |
| `fleet mesh` | `gm_workflow_fleet_mesh` | Every ordered pair, scope-aware existing treaty checks, missing treaty issuance and per-pair outcomes. |
| `fleet status` / `fleet verify` | `gm_workflow_fleet_status`, `gm_workflow_fleet_verify` | Bounded health/readiness aggregation and trust-path checks across a configured fleet. |
| `proof remote` | `gm_workflow_proof_remote` | Issue attestation/treaty, verify acceptance, revoke, import the signed revocation feed, verify rejection and inspect the proof summary. |
| `proof canary` | `gm_workflow_proof_canary` | Remote proof, purpose-signed receipt, atomic receipt persistence/readback and an owned core audit-store event. |
| `proof cleanup` | `gm_workflow_proof_cleanup_preview`, `gm_workflow_proof_cleanup` | Review exact whole-table scope, verify an exclusive backup, then delete all rows from the four selected trust tables in an explicitly disposable database. |
| `audit pack` / `audit archive` | `gm_workflow_audit_pack`, `gm_workflow_audit_archive` | Materialize and read back signed pack files; archive verifies the pack against configured root/anchors before recording and optional pruning. |
| `evidence anchors fetch` | `gm_workflow_evidence_anchors_fetch` | Full bounded pagination, comparison against held history, core verification and serialized persistence; anchor refusal remains visible. |
| `treaty renew` / `treaty replace` | `gm_workflow_treaty_renew`, `gm_workflow_treaty_replace` | Preserve linkage metadata, issue first, revoke the old treaty second, retain created IDs if later steps fail. |
| `join` / `status` | `gm_workflow_node_join`, `gm_workflow_node_status` | Verified enrollment/reuse, durable certificate/policy/key-history state, heartbeat, live probes and fresh signed revocation checks. |
| `send` | `gm_workflow_peer_send` | Configured Noise peer transport, pinned peer certificate/static-key binding and bounded payloads; no recipient-delivery claim. |
| `trust guard request` | `gm_workflow_guard_request` | Submit a signed request for a fixed configured action, preserve guard rejection, and verify receipt signature and request/agent/decision/capability binding. |

Read [workflow configuration](workflows.md) before enabling these operations. All mutating workflows use operation identifiers and durable journals. An uncertain request outcome is not silently retried. Completed operation replay returns its historical result; use fresh status/verification tools to establish current state.

## Exact scope limitations

This is executable value/workflow parity for the adapter's pinned public contract, not identical command-line parsing, formatting or every flag. The remaining 18 CLI hosting/custody commands and 6 Python runtime/administrative entry points are explicitly classified as operational boundaries. Schema, reference and low-level helper mappings are not counted as executable behavior.

- NA/guard daemons, persistent peer runtime, deployment and development-stack process supervision remain host-managed. Enrollment reports `runtime_started: false`; peer send opens a bounded connection for that send. Starting a persistent peer daemon is not implied by successful enrollment.
- General database migration/restore and live-host administration remain outside MCP. Canary initialization is limited to an explicitly owned store; an existing incompatible schema is refused.
- Fleet generation creates local private key files and the core's placeholder policy hash. It does not move roots into offline custody, replace the policy hash, configure production hosts, or start NAs. Those steps must precede production use. Overwriting existing fleets is deliberately unsupported.
- Core proof cleanup deletes **all rows** in `imported_sovereign_revocations`, `sovereign_revocation_feeds`, `recognition_treaties`, and `membership_attestations`, including ordinary trust records. The adapter reproduces that scope only for a configured `owned: true`, `disposable: true` store, after preview and backup verification. Other tables remain untouched.
- Configured archive storage is local storage; it does not claim immutable retention or an external storage-service guarantee.
- Network delivery, independent human approval and production readiness are not inferred from registration, signature verification or local integration tests. Tests use disposable authorities, peers, guards and stores.

The existing succession proof, proof-summary inspection and guard receipt verification tools remain available. Summary inspection checks consistency, not proof that the described remote events actually occurred.
