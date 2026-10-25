# Configured workflows

The server operator configures destinations, identity files and storage. MCP requests use their names. They cannot supply authority URLs, key paths, output directories, arbitrary Python imports or shell commands. Configuration paths resolve relative to the configuration file.

## Authorities, fleets and artifacts

This example enables a small set of workflows. Replace the public-key placeholders with independently obtained pins. Add the exact tool names needed for other workflows to each relevant authority's `allowed_tools`; wildcards are refused. An authority's operator tier still limits what its key can do.

```json
{
  "profiles": ["read", "verify", "operator", "write", "local"],
  "workflow_state_dir": "private/workflow-state",
  "workspace": "artifacts",
  "artifact_roots": {"audit": "artifacts/audit"},
  "authorities": {
    "acceptor": {
      "url": "https://acceptor.example",
      "public_key": "ACCEPTOR_NA_PUBLIC_KEY",
      "root_public_key": "ACCEPTOR_ROOT_PUBLIC_KEY",
      "operator_key_file": "private/acceptor-operator.key",
      "operator_key_id": "operator",
      "allowed_tools": [
        "gm_workflow_federation_preview", "gm_workflow_federation_bootstrap",
        "gm_workflow_fleet_status", "gm_workflow_fleet_verify", "gm_workflow_fleet_mesh",
        "gm_workflow_audit_pack", "gm_workflow_audit_archive", "gm_workflow_evidence_anchors_fetch"
      ]
    },
    "issuer": {
      "url": "https://issuer.example",
      "public_key": "ISSUER_NA_PUBLIC_KEY",
      "root_public_key": "ISSUER_ROOT_PUBLIC_KEY",
      "operator_key_file": "private/issuer-operator.key",
      "operator_key_id": "operator",
      "allowed_tools": [
        "gm_workflow_federation_preview", "gm_workflow_federation_bootstrap",
        "gm_workflow_fleet_status", "gm_workflow_fleet_verify", "gm_workflow_fleet_mesh"
      ]
    }
  },
  "fleets": {"pair": ["acceptor", "issuer"]}
}
```

HTTPS is required except when `allow_http_loopback: true` explicitly permits local HTTP development. Fleets contain at most 16 distinct configured authorities, yielding at most 240 ordered pairs. Multi-authority workflows share an elapsed-time budget and an aggregate response budget of `max_output_bytes`, including core review reads. Exhaustion produces bounded failures/partial outcomes without truncating signed content. Federation, fleet verification and proofs verify genesis signatures against root pins and compare live NA identities with the configured pins. Key changes require deliberate configuration updates.

Call `gm_workflow_federation_preview` with:

```json
{"acceptor":"acceptor","issuer":"issuer","roles":["role:client"],"validity_hours":24}
```

Review the returned scope and identities. Call `gm_workflow_federation_bootstrap` with the same fields plus the returned `preview_digest` and a new `operation_id`, such as `recognition-001`. Changing the reviewed scope invalidates the digest. Fleet tools accept `{"fleet":"pair"}`; mesh also requires `operation_id` and accepts scope parameters documented in its MCP schema.

An audit archive request is:

```json
{"authority":"acceptor","artifact_store":"audit","operation_id":"archive-001","prune":false}
```

Pack files are created without overwrite and read back against their manifest. Archive independently verifies signed pack contents against the configured root, served anchors and executor keys before recording the archive; pruning is optional and follows successful recording. Anchor synchronization verifies complete served history against held copies before appending. Storage remains local, without an immutability guarantee.

## Durable operations and recovery

Mutation tools require an `operation_id`. The journal binds it to the workflow, inputs, configuration and configured credential contents. Reusing an ID with different inputs or changed configuration is refused. Concurrent requests for the same operation cannot execute twice. Resource locks also serialize shared node, provisioning, proof-store and anchor storage.

The journal persists intent before dispatch. A successfully recorded step is reused. Read-only checks can run again when later work needs fresh state. If a mutation loses its reply or the process stops before recording the outcome, the journal marks it uncertain and refuses blind replay. The operation may already have taken effect.

Inspect an operation with:

```json
{"workflow":"gm_workflow_federation_bootstrap","operation_id":"recognition-001"}
```

Pass that to `gm_workflow_operation_status`. It returns bounded step status, result digests and created identifiers, not private request bodies. Its profile checks include the original workflow's requirements. Reconcile uncertain effects with the authority, guard or local store before choosing a new operation ID. There is no tool that clears an uncertain mutation flag. An unfinished operation older than 24 hours refuses new steps.

Completed replay returns the historical result. It does not claim the relationship, certificate or authority is still healthy. Use current status/verification tools for that assessment. A partial workflow result is an MCP error result with its structured progress retained.

## Private fleet provisioning

Enable `local`, `write`, and `provision`, then configure:

```json
{"provisioning":{"lab":{"root":"private/fleets","host":"127.0.0.1","base_port":8443,"max_members":16}}}
```

Call `gm_workflow_fleet_generate` with `{"provisioning":"lab","operation_id":"fleet-001","names":["north","south"]}`. It uses core's scaffold, privately stages keys and signed genesis, rewrites configurations to their final paths, and atomically publishes the fleet directory. Only public metadata and relative artifact references are returned. Names must be portable and unique ignoring case; existing output is never overwritten.

The core scaffold uses a placeholder policy hash and stores root keys beside NA keys. Replace the policy hash and move roots into offline custody before managed deployment. No server is started. New private directories use owner-only permissions on POSIX and current-user/SYSTEM access on Windows.

## Nodes and peers

Extend an authority's permissions with `gm_workflow_node_join`, `gm_workflow_node_status`, and `gm_workflow_peer_send`, then configure:

```json
{
  "node_runtimes": {
    "client": {
      "authority": "acceptor",
      "state_dir": "private/client-state",
      "node_key_file": "private/client.key",
      "invite_token": "CONFIGURE_LOCALLY"
    }
  },
  "peers": {
    "bridge": {
      "node": "client",
      "endpoint": "wss://peer.example/",
      "peer_public_key": "BASE64_PEER_PUBLIC_KEY",
      "recipient_public_key": "BASE64_RECIPIENT_PUBLIC_KEY"
    }
  }
}
```

Join requires `read`, `node`, `local`, `write`; generating a node key when `node_key_file` is absent additionally requires `provision`. A valid held certificate is reused. Newly enrolled certificates are journaled before atomic persistence, so a disk failure need not consume another invite. Join checks certificate identity, genesis/root trust, key history and policy, sends a heartbeat, and reports `runtime_started: false`. Status and peer send additionally fetch and verify fresh signed CRL state.

Peer send additionally requires `execute`. Its input is `{"peer":"bridge","operation_id":"send-001","message":"hello"}`. The adapter validates the Noise peer certificate and static-key binding, retains verified key history, and bounds transport work. The result confirms transport send, without claiming recipient delivery. Persistent peer hosting remains a separate core runtime operation.

## Fixed guard actions

Enable `local`, `write`, `execute`, `sign`; authorize a signer specifically for `gm_workflow_guard_request`. A guard action supplies a literal loopback host, port, pinned guard identity, agent identity, signer reference, capability, fixed command argument list and allowed environment-variable names:

```json
{
  "signer_files": {"agent":"private/agent.key"},
  "signer_permissions": {"agent":["gm_workflow_guard_request"]},
  "guard_actions": {
    "check": {
      "host":"127.0.0.1", "port":8765,
      "guard_public_key":"BASE64_GUARD_PUBLIC_KEY",
      "guard_sovereign_id":"guard", "agent_sovereign_id":"agent",
      "signer":"agent", "capability":"capability:check",
      "command":["/opt/example/check"], "allowed_env":[]
    }
  }
}
```

The guard daemon must already run with its own allowed capabilities, stored decisions and token trust. The MCP request contains the action reference, operation ID, complete invocation token and boundary decision. The guard verifies authorization; the adapter verifies the returned signed receipt and its binding to this request. The model cannot change the configured executable, arguments or destination. A timeout or rejection can occur after a subprocess started; the adapter preserves that uncertainty.

## Canary and disposable proof maintenance

Canary requires `read`, `verify`, `operator`, `write`, `local`, `maintain`, `sign`, authority permission for `gm_workflow_proof_canary` on both parties, and a receipt signer permitted for that exact tool. Configure a named store:

```json
{
  "proof_stores": {
    "canary": {
      "db_path":"private/canary/audit.db", "backup_dir":"private/canary-backups",
      "receipt_dir":"private/canary-receipts", "receipt_signer":"receipt",
      "owned":true, "disposable":false, "allowed_tools":["gm_workflow_proof_canary"]
    }
  }
}
```

Input is `{"store":"canary","acceptor":"acceptor","issuer":"issuer","operation_id":"cycle-001"}`. The proof must finish before a completion receipt is signed. The exact receipt is persisted/read back before the core audit event. Existing databases must already use the pinned schema; only a new explicitly owned store is initialized.

Cleanup is separately enabled by `owned: true`, `disposable: true`, permissions for `gm_workflow_proof_cleanup_preview` and `gm_workflow_proof_cleanup`, and the `maintain` profile. Preview shows **all rows** in four core trust tables, including non-proof records. Execute requires its digest and a new operation ID. A write transaction prevents scope changes, an exclusive SQLite backup is checked for integrity and matching rows, then deletion commits. Other tables remain untouched. Maintenance is limited to 64 MiB stores and 50,000 rows per selected table.
