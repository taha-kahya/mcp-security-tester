# MCP Security Proxy

A transparent security proxy that sits between your AI agent and MCP servers — watching every tool call, scanning every response, and alerting when something goes wrong.

---

## The problem

MCP servers can behave maliciously in ways that are invisible to the user:
- A server changes its tool definitions after you approved it (**rug pull**)
- A tool returns a response containing hidden instructions that hijack the agent (**prompt injection**)
- A passive tool description silently alters how the agent uses another server (**tool shadowing**)
- An agent starts calling tools it was never asked to call (**behavioral anomaly**)

None of these are detectable by reading the manifest once at install time. They require continuous runtime observation.

---

## How it works

The proxy sits transparently in the MCP communication path:

```
Agent (Cursor / Claude Desktop / Copilot)
              ↓
    mcp-security-proxy          ← intercepts every message
              ↓
      Real MCP Server(s)
```

The agent thinks it's talking directly to the real server. Every tool call flows through the proxy, which:

1. **Snapshots the manifest** on connect — diffs on every re-fetch to detect rug pulls
2. **Scans every tool output** before the agent sees it — detects injection payloads and credential leakage
3. **Logs every tool call** with full context — tool name, arguments, response, timing
4. **Flags anomalous sequences** — agent calling tools it shouldn't given the conversation context

---

## Quick start

### 1. Install

```bash
pip install -e ".[dev]"
```

### 2. Find the full path to `mcp-tester`

```bash
which mcp-tester
# e.g. /opt/anaconda3/bin/mcp-tester
```

Claude Desktop does not inherit your shell PATH, so you must use the absolute path in the config.

### 3. Configure Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (create it if it doesn't exist):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/opt/anaconda3/bin/mcp-tester",
      "args": [
        "monitor",
        "--name", "filesystem",
        "--server", "npx -y @modelcontextprotocol/server-filesystem /path/to/your/directory",
        "--log", "/path/to/mcp-security.jsonl"
      ]
    }
  }
}
```

Replace `/opt/anaconda3/bin/mcp-tester` with your actual path from step 2, and set the directory and log paths to wherever you want.

### 4. Restart Claude Desktop

Quit and reopen Claude Desktop. The proxy starts automatically when Claude connects to the filesystem server.

Alerts stream to stderr in real time. Tool calls are logged to the path you set with `--log`.

---

## Attack coverage

| Attack | How it's caught |
|--------|----------------|
| Tool poisoning | Static scan of manifest at connect time |
| Rug pull | Manifest diff on every re-fetch |
| Indirect prompt injection | Output scanner on every tool response |
| Tool shadowing | Cross-tool reference detection in manifest |
| Behavioral anomaly | Suspicious tool call sequence detection |

See [docs/attacks.md](docs/attacks.md) for payloads and detection logic.

---

## Project structure

```
mcp_security_tester/
├── proxy/                  # core proxy — bridges agent ↔ real server
│   ├── server.py           # MCP server + client bridge
│   ├── manifest_watcher.py # snapshot manifest, diff on re-fetch
│   └── output_scanner.py   # scan tool responses before agent sees them
├── call_logger/            # structured log of every tool call
├── anomaly_detector/       # flag suspicious tool call sequences
├── static_analyzer/        # poisoning signal detectors (used at runtime)
└── reports/                # Finding + Report dataclasses, JSON output
```

See [docs/architecture.md](docs/architecture.md) for detail.
