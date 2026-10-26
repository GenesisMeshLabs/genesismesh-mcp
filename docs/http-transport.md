# Serving over HTTP with OAuth

`genesismesh-mcp` runs over stdio for a local MCP host. `genesismesh-mcp-http` serves the same tools over [Streamable HTTP](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#streamable-http) at `<issuer>/mcp`, for hosts that connect by URL (claude.ai connectors, Claude Desktop, Claude Code, agent runtimes).

Every HTTP request needs an OAuth access token. The server is its own authorization server:

- **Clients register themselves** (RFC 7591 dynamic client registration) and use the authorization code flow with PKCE. Registration grants nothing.
- **An approval code authorizes a client.** Someone with access to the server host issues a single-use code with `genesismesh-mcp-admin issue-code`, and types it into the consent page the client opens. The code expires (15 minutes by default) and names the scopes it allows. Five wrong codes end the request.
- **Autonomous agents get a token directly.** `genesismesh-mcp-admin create-agent` prints a scoped access token, valid for a number of days, that the agent sends as `Authorization: Bearer ...`.
- **Tokens are short-lived and stored as SHA-256 digests.** Access tokens last an hour; refresh tokens rotate on every use and last 30 days. Every token is bound to this server's `/mcp` resource (RFC 8707). `genesismesh-mcp-admin revoke <client_id>` revokes a client or agent and every token issued to it.

## Scopes

A scope grants a configuration profile. A request lists and calls only the tools whose profiles are both configured on the server and granted by its token.

| Scope | Profiles |
| --- | --- |
| `gm:read`, `gm:verify`, `gm:operator`, `gm:write`, `gm:node`, `gm:sign`, `gm:local`, `gm:execute`, `gm:provision`, `gm:maintain` | The profile of the same name |
| `gm:admin` | Every profile |

The approval code caps a grant: a client that asks for more receives only what the code allows, and a refresh never widens a grant. A tool outside the grant is refused with `scope_required`.

**An admin token can do whatever the configured operator key can.** Grant `gm:admin`, `gm:operator` or `gm:write` only to clients you would give the operator key to, and revoke them when no longer needed. Tool results come from the authority and from client-supplied artifacts: a model acting on them can be steered by their contents, so keep the operator key's core tier no higher than the work needs.

## Configure

The tool settings file is the same as for stdio (see the [README](../README.md)). The transport has its own file:

```json
{
  "issuer_url": "https://mcp.example.org",
  "state_db": "state/oauth.db",
  "host": "0.0.0.0",
  "port": 8765
}
```

| Setting | Default | Meaning |
| --- | --- | --- |
| `issuer_url` | required | The public origin clients use; HTTPS except on a loopback development host. The MCP endpoint is `<issuer_url>/mcp`. |
| `state_db` | required | SQLite file for clients, codes and token digests, relative to this file. Created `0600` on POSIX. |
| `host`, `port` | `127.0.0.1`, `8765` | The listener. Put a TLS-terminating reverse proxy in front of it. |
| `allowed_hosts` | the issuer's host | `Host` headers accepted (DNS rebinding protection). |
| `access_token_seconds` | 3600 | Access token lifetime. |
| `refresh_token_seconds` | 2592000 | Refresh token lifetime. |
| `approval_code_seconds` | 900 | Default approval code lifetime. |

Run it:

```sh
genesismesh-mcp-http --config settings.json --remote remote.json
```

The tool settings' `timeout_seconds` (15 by default, at most 300) bounds each authority request. Raise it for an authority with a large evidence store: verifying 11,700 entries takes about 20 seconds on a one-vCPU VM. Audit packs must end at an anchor; on a store whose executor keys predate registry records, pass the authority's executor keys to `gm_local_audit_verify` as `executor_keys`.

## Connect a client

1. Issue an approval code on the server host:

   ```sh
   genesismesh-mcp-admin --remote remote.json issue-code --scopes gm:read,gm:verify
   ```

2. Add the server by URL, `https://mcp.example.org/mcp`, in the client (for example a claude.ai custom connector, or `claude mcp add --transport http genesismesh https://mcp.example.org/mcp`).
3. The client opens the consent page. Enter the code and approve.

For an autonomous agent:

```sh
genesismesh-mcp-admin --remote remote.json create-agent --label nightly-ops --scopes gm:admin --days 30
```

Store the printed token in the agent's secret store; it is not shown again. `genesismesh-mcp-admin --remote remote.json list` shows clients and agents with live tokens; `revoke <client_id>` ends one.

## Container

The repository's `Dockerfile` builds an image that runs `genesismesh-mcp-http` as an unprivileged user (uid 10001) with `/config/settings.json` and `/config/remote.json`. Mount the configuration and the private key files read-only, owned by uid 10001 and mode `0600`, and keep `state_db` on a writable volume.

## What this does not do

- It is one operator's server, not a multi-tenant service: every client acts with the same configured keys, limited by its scopes.
- There is no rate limiting beyond the approval-code attempt limit; put the server behind a proxy that limits request rates if it is exposed widely.
- Approval codes are typed by a person; there is no single sign-on or identity provider integration.
