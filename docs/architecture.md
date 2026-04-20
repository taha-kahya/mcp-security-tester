# Architecture

The tool is a transparent MCP proxy. It sits between the agent and real MCP servers, intercepting every message in both directions without modifying the protocol.

---

## Proxy model

```
Agent (Cursor / Claude Desktop / Copilot)
              ↓  MCP protocol (stdio)
    ┌─────────────────────────┐
    │    mcp-security-proxy   │
    │                         │
    │  manifest_watcher       │  ← diffs manifest on every re-fetch
    │  output_scanner         │  ← scans responses before agent sees them
    │  call_logger            │  ← logs every call with full context
    │  anomaly_detector       │  ← flags suspicious sequences
    └─────────────────────────┘
              ↓  MCP protocol (stdio, subprocess)
      Real MCP Server
```

The proxy is simultaneously an MCP server (facing the agent) and an MCP client (facing the real server). The agent's MCP config points to the proxy command instead of the real server command.

---

## Components

### `proxy/server.py` — core bridge

Runs two MCP sessions in the same asyncio event loop:
- **Downstream** (to agent): MCP server using `stdio_server()`, capturing the process's stdin/stdout
- **Upstream** (to real server): MCP client using `stdio_client()`, spawning the real server as a subprocess

Every `list_tools` and `call_tool` request is intercepted, passed through the watchers/scanners, then forwarded.

### `proxy/manifest_watcher.py` — rug pull detection

On the first `list_tools` call, snapshots the full manifest (SHA-256 hash per tool: name + description + schema + annotations). On every subsequent `list_tools`, diffs against the snapshot. Any change — description text, parameter types, enum values — triggers a Finding before the agent sees the updated manifest.

Severity escalation:
- New permission scope or new sensitive path added → CRITICAL
- Description or schema changed → HIGH
- Annotation or metadata changed → MEDIUM

### `proxy/output_scanner.py` — injection and credential detection

Runs on every tool response before it reaches the agent. Extracts all strings from the MCP content payload and runs two passes:

1. **Injection scanner** — reuses `static_analyzer` detectors (secrecy directives, imperative verbs in unusual context, hidden Unicode, cross-tool references)
2. **Credential scanner** — regex patterns for API keys, tokens, private key headers, AWS key formats

Findings are logged and alerted. The response is passed through unmodified (observe-only mode by default).

### `call_logger/logger.py` — structured call log

Every tool call is recorded as a `ToolCall` entry:
- Timestamp, tool name, arguments, response content
- Duration (ms)
- Findings from the output scanner
- Whether the call was expected (flagged by anomaly detector)

Written to `mcp-security.jsonl` (newline-delimited JSON, appendable).

### `anomaly_detector/` — behavioral pattern detection

Checks the recent call history against known suspicious sequences:
- Destructive sequence: `read_file` immediately followed by an outbound call (`send_email`, `http_request`, `create_message`) without an explicit user instruction in between
- Rapid repetition: same tool called more than N times in M seconds (potential loop injection)
- Unexpected tool: a tool that was never in the approved manifest gets called

Patterns live in `anomaly_detector/patterns.py` as a declarative list — easy to extend.

### `static_analyzer/` — reused at runtime

The same detectors built for pre-connect manifest scanning are reused:
1. At connect time: scan the full manifest for poisoning signals
2. At runtime: `output_scanner` uses these detectors on every tool response string

---

## Data flow

```
Agent sends call_tool("read_file", {"path": "..."})
        ↓
proxy/server.py receives it
        ↓
forwards to upstream server, awaits response
        ↓
proxy/output_scanner.py scans the response content
        ↓
call_logger records the full call + any findings
        ↓
anomaly_detector checks call history for suspicious sequences
        ↓
any findings → alert to stderr + log file
        ↓
response returned to agent (unmodified)
```

---

## Configuration

The user adds one entry to their MCP client config per server they want to monitor:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcp-tester",
      "args": ["monitor", "--name", "filesystem", "--server", "npx -y @modelcontextprotocol/server-filesystem ."]
    }
  }
}
```

The proxy starts when the agent connects, spawns the real server, and runs until the agent disconnects.

---

## Alert format

Alerts are written to stderr (so they don't interfere with the MCP protocol on stdout) and to the log file:

```json
{"level": "CRITICAL", "signal": "rug_pull", "tool": "read_file", "detail": "description changed after approval", "timestamp": "..."}
{"level": "HIGH", "signal": "output_injection", "tool": "fetch_issue", "detail": "secrecy directive found in response", "timestamp": "..."}
```
