# deploys-app MCP server

A local [MCP](https://modelcontextprotocol.io) server (stdio) that exposes the
**deploys.app** API to Claude. It wraps the official Go client in this repo
(`github.com/deploys-app/api/client`), so every request is the exact typed
contract — validation (`Valid()`), error mapping, and JSON shapes all come for
free.

## Design

The API has ~88 user-facing actions across 18 resources. Listing each as its own
tool would flood the model's context window, so this server uses the
**search + execute** pattern with just two tools:

| Tool | Purpose |
|---|---|
| `deploys_search_actions` | Find actions by intent/keyword. Returns matching action ids, descriptions, `readOnly`/`destructive` flags, and the JSON **input schema** for each (auto-derived from the request structs). Empty query browses the whole catalogue. |
| `deploys_execute_action` | Run an action by id with a `params` object matching its input schema. Returns the API's JSON result. |

The full catalogue lives in `catalog.go`. The privileged `Collector` and
`Deployer` interfaces are intentionally excluded, as are the two multipart
upload methods (`me.uploadKYCDocument`, `billing.uploadTransferSlip`) that the
JSON client cannot express.

## Build

This is a nested Go module (its own `go.mod` with a `replace` to the parent), so
the MCP SDK and jsonschema dependencies stay out of the `github.com/deploys-app/api`
library.

```bash
cd mcp
go build -o deploys-mcp .
```

## Configure

A service account authenticates with **HTTP Basic auth**: username = the
service-account email, password = a key secret.

| Env var | Required | Default | Notes |
|---|---|---|---|
| `DEPLOYS_SA_EMAIL` | yes* | — | Service-account email (Basic-auth username). |
| `DEPLOYS_SA_SECRET` | yes* | — | Service-account key secret (Basic-auth password). |
| `DEPLOYS_API_KEY` | yes* | — | Alternative single-var form: `"<email>:<secret>"`. |
| `DEPLOYS_ENDPOINT` | no | `https://api.deploys.app/` | Override the API base URL. |

\* Provide either the `DEPLOYS_SA_EMAIL` + `DEPLOYS_SA_SECRET` pair **or**
`DEPLOYS_API_KEY`. The server sends `Authorization: Basic base64(email:secret)`.

## Register with Claude

**Claude Code:**

```bash
claude mcp add deploys \
  -e DEPLOYS_SA_EMAIL=sa@deploys.app -e DEPLOYS_SA_SECRET=xxx \
  -- /absolute/path/to/mcp/deploys-mcp
```

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "deploys": {
      "command": "/absolute/path/to/mcp/deploys-mcp",
      "env": {
        "DEPLOYS_SA_EMAIL": "sa@deploys.app",
        "DEPLOYS_SA_SECRET": "xxx"
      }
    }
  }
}
```

## How Claude uses it

1. Claude calls `deploys_search_actions` with an intent like `"list deployments"`.
2. It reads back the matching action id (e.g. `deployment.list`) and its input schema.
3. It calls `deploys_execute_action` with `{"action":"deployment.list","params":{...}}`.

## Remote HTTP mode (OAuth-protected)

The same binary can run as a **remote HTTP MCP resource server** instead of a
local stdio server. Set `DEPLOYS_MCP_HTTP_ADDR` to a listen address to select
this mode. Here there is no single service account: each caller authenticates
with their own **deploys.app OAuth 2.1 bearer token** (the token issued by the
[`auth`](../../auth) service), and the server forwards that token to the API so
the caller acts as themselves.

It implements the OAuth 2.0 protected-resource contract the `auth` server expects:

- Unauthenticated/invalid requests get `401` + a `WWW-Authenticate: Bearer …`
  header carrying `resource_metadata`.
- `GET /.well-known/oauth-protected-resource` serves the resource metadata
  (RFC 9728), pointing clients at the `auth` authorization server.
- Incoming bearer tokens are validated via auth's `POST /introspect`
  (RFC 7662), guarded by the shared `INTROSPECTION_TOKEN`.

| Env var | Required | Default | Notes |
|---|---|---|---|
| `DEPLOYS_MCP_HTTP_ADDR` | yes | — | Listen address, e.g. `:8080`. Presence selects HTTP mode. |
| `DEPLOYS_MCP_BASE_URL` | yes | — | Public base URL of this server; the protected-resource identifier. |
| `DEPLOYS_AUTH_URL` | yes | — | `auth` server base URL, e.g. `https://auth.deploys.app`. |
| `INTROSPECTION_TOKEN` | yes | — | Shared secret presented to auth's `/introspect`. |
| `DEPLOYS_ENDPOINT` | no | `https://api.deploys.app/` | Override the upstream API base URL. |

```bash
DEPLOYS_MCP_HTTP_ADDR=:8080 \
DEPLOYS_MCP_BASE_URL=https://mcp.deploys.app \
DEPLOYS_AUTH_URL=https://auth.deploys.app \
INTROSPECTION_TOKEN=xxx \
  ./deploys-mcp

# register with Claude Code
claude mcp add --transport http deploys https://mcp.deploys.app/
```

## Distribution

The local stdio binary is the personal/team option; to distribute it without
requiring Go, package it as an [MCPB](https://modelcontextprotocol.io) bundle.
The **remote HTTP mode** above is what the Anthropic connector directory
requires — a remote HTTP server with OAuth, since the directory does not accept
user-pasted bearer tokens. Dynamic client registration (DCR) is served by the
`auth` server's `/register` endpoint.
