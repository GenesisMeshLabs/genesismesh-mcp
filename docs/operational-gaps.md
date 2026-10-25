# Remaining orchestration work

The MCP catalog accounts for the complete pinned core contract. It does **not** claim that every CLI workflow is executable through MCP. A `gap` means the workflow has not been implemented. `components_available` means some required operations exist, but their ordering, state management, or failure handling is still missing. Reference resources do not change either status.

This assessment uses Genesis Mesh 1.8.1, commit `9e4d5c01e6ba7a22e73c17388796ec274f73a2fc`. Read `genesis-mesh://coverage` for the current registrations and test evidence.

## Gaps that need runtime or configuration support

| Core CLI workflow | Concrete dependencies and effects | Work needed for an MCP implementation |
| --- | --- | --- |
| `federation bootstrap` | Reviews the accepting and issuing sovereigns, optionally reads an issuer trust bundle, previews scope, issues a treaty with the accepting operator's key, then verifies the persisted relationship. A failure after issuance can leave a real treaty in place. | A server-configured authority registry with separate pins/credentials, a structured preview/execute workflow, and explicit partial-success reporting. The single configured authority's HTTP tools do not implement this complete workflow. |
| `fleet generate` | Creates multiple sovereign directories, root/NA/operator/node key material, signed genesis blocks, per-NA configurations, and a fleet manifest. | A deliberate bootstrap/provisioning implementation with key-custody rules and scoped file writes. No generic CLI launcher or private-key-returning tool is supplied. This remains an implementation gap, not completed coverage. |
| `fleet mesh` | Reads a manifest and each member configuration; uses each accepting NA's operator identity; creates recognition treaties for ordered sovereign pairs while skipping already active relationships. | Multiple configured authorities, bounded pair counts, per-authority authorization, idempotent discovery, and a persisted per-pair outcome report. A sequence of arbitrary URL calls is not equivalent. |
| `fleet status` | Reads the fleet manifest and member configurations, then probes every member's `/healthz` and `/readyz`. | A configured fleet registry and a bounded read-only aggregator. The workflow is safe to implement without key generation; it is currently absent because the adapter configuration represents one authority. |
| `fleet verify` | Resolves each member's sovereign identity and checks `/connectome/trust-path` across every ordered pair. | The same configured fleet registry, bounded pair enumeration, per-pair failures, and a complete report. A single trust-path query is only a component. |
| `proof remote` | Uses two authority operator identities to issue an attestation and treaty, test acceptance, revoke the attestation, import its revocation feed, and test rejection. It produces a redacted summary and changes both authorities' state. | A named pair of configured authorities, scoped credentials, explicit proof-run authorization, recoverable step tracking, and reporting of partial mutations. Read-only discovery is not a substitute for this proof. |
| `proof canary` | Runs the remote proof, signs a receipt, atomically writes the receipt file, and records an event in a local NA audit database. | The remote workflow plus a purpose-restricted receipt signer, confined output handling, and a supported audit-store integration. Scheduling or calling individual endpoints does not reproduce this workflow. |
| `proof cleanup` | Backs up a SQLite database and deletes the selected cross-sovereign proof rows. | A typed maintenance operation with database ownership checks, backup verification, exact selection, explicit destructive-action authorization, and recovery behavior. No database mutation tool is exposed. |
| `send` | Loads a local node key, held join certificate and genesis configuration; opens a Noise-authenticated WebSocket connection to a reachable peer and transmits a recipient-addressed data message. | A peer-transport adapter with server-configured peer destinations and node state, bounded payloads, lifecycle handling, and a precise distinction between transport send and recipient delivery. NA HTTP enrollment tools do not provide peer messaging. |
| `trust guard request` | Builds and signs an execution request containing a full invocation token and boundary decision, connects to a running GenesisGuard daemon, and can cause an allowlisted subprocess to execute. | A configured guard connection, named server-side actions, purpose-restricted agent signing, token/decision binding, host execution authorization, and receipt/rejection handling. Offline request assessment and receipt verification do not execute the action. |

Source anchors: [federation](https://github.com/GenesisMeshLabs/genesismesh/blob/9e4d5c01e6ba7a22e73c17388796ec274f73a2fc/genesis_mesh/workflows/federation.py#L30), [fleet](https://github.com/GenesisMeshLabs/genesismesh/blob/9e4d5c01e6ba7a22e73c17388796ec274f73a2fc/genesis_mesh/cli/fleet_ops.py#L135), [remote proof and canary](https://github.com/GenesisMeshLabs/genesismesh/blob/9e4d5c01e6ba7a22e73c17388796ec274f73a2fc/genesis_mesh/workflows/proof.py#L23), [proof cleanup](https://github.com/GenesisMeshLabs/genesismesh/blob/9e4d5c01e6ba7a22e73c17388796ec274f73a2fc/genesis_mesh/workflows/proof.py#L408), [peer send](https://github.com/GenesisMeshLabs/genesismesh/blob/9e4d5c01e6ba7a22e73c17388796ec274f73a2fc/genesis_mesh/cli/ops.py#L622), [guard request](https://github.com/GenesisMeshLabs/genesismesh/blob/9e4d5c01e6ba7a22e73c17388796ec274f73a2fc/genesis_mesh/cli/mediation_ops.py#L39).

## Workflows whose components already exist

The coverage catalog also lists these incomplete compositions:

- `audit pack` and `audit archive`: authority creation/archive operations and local pack verification exist; the CLI's complete fetch, verification, local artifact and archive sequence is not reproduced by one workflow.
- `evidence anchors fetch`: the authority anchor endpoint exists; maintaining a held anchor file under the CLI's rules is not implemented as a workflow.
- `join`: enrollment, policy fetch and heartbeat operations exist. Local certificate/key/config persistence, existing-certificate reuse and the optional persistent peer runtime are not orchestrated.
- `status`: authority probes exist. The CLI's combined local configuration and held-certificate view is absent.
- `treaty renew` and `treaty replace`: read, issue and revoke operations exist. Their ordered linkage metadata and partial-failure handling need dedicated compositions.

These are ordinary product workflows with remaining implementation work. They are not counted as complete merely because their component tools can be called individually.

## Safe gaps closed during implementation

`gm_offline_key_succession_prove_succession` implements the value operation behind `na succession prove`. It accepts a typed `KeySuccessionRecord` and a server-configured signer reference, verifies that the signer's public key is exactly `record.new_public_key`, and delegates signing to core `sign_succession` using `record.new_key_id`. Its signer must be explicitly authorized for this tool. It returns the core wire form, preserving omitted fields. It does not use a root key, submit the succession, approve its root authorization, or activate the new key.

`gm_offline_proof_inspect_proof_bundle` implements `proof inspect` on structured inputs, including the optional Connectome cross-check. It reports `verification_scope: summary_consistency_only` and `signatures_verified: false`. A valid summary is not evidence that the described live actions occurred.

`gm_offline_mediation_verify_guard_receipt` implements receipt signature verification behind `trust guard verify`. It never starts a subprocess or connects to a guard.

## Completing the remaining work

Add explicit services for configured fleets, peer transport, and guard execution rather than a generic subprocess or arbitrary-URL fallback. Give each workflow a defined state model, bounded operation count, typed inputs/results, and tests against temporary local authorities or daemons. Keep partial success and actual execution separate from verification. Update the coverage row only after the complete behavior is registered and tested.
