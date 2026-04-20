# Implementation Plan

## Repository layout

```
mcp_security_tester/
├── proxy/
│   ├── __init__.py
│   ├── server.py             # MCP server+client bridge — core proxy loop
│   ├── manifest_watcher.py   # snapshot manifest on connect, diff on re-fetch
│   └── output_scanner.py     # scan tool responses for injection + credentials
│
├── call_logger/
│   ├── __init__.py
│   └── logger.py             # ToolCall dataclass + JSONL writer
│
├── anomaly_detector/
│   ├── __init__.py
│   ├── patterns.py           # declarative suspicious sequence definitions
│   └── detector.py           # check call history against patterns
│
├── static_analyzer/          # poisoning signal detectors — reused at runtime
│   ├── signals.py
│   ├── detectors.py
│   └── analyzer.py
│
├── reports/
│   ├── models.py             # Finding + Report dataclasses
│   └── json_reporter.py
│
└── cli.py                    # mcp-tester monitor command

corpus/manifests/             # saved real-world manifests for offline analysis
tests/
  fixtures/
  unit/
```

---

## Module interfaces

### `proxy/server.py`

```python
class MCPSecurityProxy:
    def __init__(self, upstream_command: list[str], server_name: str): ...
    async def run(self) -> None:
        """Start downstream MCP server (to agent) + upstream client (to real server)."""
```

The proxy registers `list_tools` and `call_tool` handlers that intercept, scan, log, then forward.

### `proxy/manifest_watcher.py`

```python
class ManifestWatcher:
    def watch(self, tools: list[dict]) -> list[Finding]:
        """First call: snapshot. Subsequent calls: diff and return rug pull findings."""
    def _hash_tool(self, tool: dict) -> str:
        """SHA-256 of canonical JSON representation of the tool."""
```

### `proxy/output_scanner.py`

```python
class OutputScanner:
    def scan(self, tool_name: str, content: list) -> list[Finding]:
        """Extract strings from MCP content, run injection + credential detectors."""
```

Credential patterns to cover: GitHub tokens (`ghp_`), OpenAI keys (`sk-`), AWS access keys (`AKIA`), private key PEM headers, generic high-entropy strings.

### `call_logger/logger.py`

```python
@dataclass
class ToolCall:
    timestamp: str
    tool_name: str
    arguments: dict
    response_text: str        # extracted text content for readability
    duration_ms: float
    findings: list[Finding]

class CallLogger:
    def log(self, call: ToolCall) -> None: ...
    def recent(self, n: int = 10) -> list[ToolCall]: ...
    def export_jsonl(self, path: str) -> None: ...
```

### `anomaly_detector/patterns.py`

Declarative sequence rules:

```python
@dataclass
class SequencePattern:
    name: str
    description: str
    trigger_tool: str          # tool that starts the sequence (glob-style, e.g. "read_*")
    following_tool: str        # tool that follows and makes it suspicious
    max_gap_calls: int = 3     # how many calls between trigger and following counts
    severity: str = "HIGH"

PATTERNS: list[SequencePattern] = [
    SequencePattern("read_then_exfiltrate", ..., trigger_tool="read_*", following_tool="send_*"),
    SequencePattern("rapid_repeat", ...),
    ...
]
```

### `cli.py`

```
mcp-tester monitor --server "npx -y @modelcontextprotocol/server-filesystem ." --name filesystem
mcp-tester monitor --server "..." --log mcp-security.jsonl
mcp-tester replay --log mcp-security.jsonl     # offline analysis of a captured session
```

---

## Technology choices

| Component | Choice | Reason |
|-----------|--------|--------|
| Language | Python 3.11+ | MCP SDK is Python-first |
| MCP proxy | `mcp` official SDK — `Server` + `ClientSession` | Both run in same asyncio loop |
| LLM (future) | Anthropic SDK `claude-sonnet-4-6` | Semantic anomaly explanation |
| Log format | JSONL | Appendable, streamable, easy to replay |
| Alert output | stderr | Doesn't interfere with MCP protocol on stdout |

---

## Proxy wiring — key technical detail

The proxy runs two MCP sessions in one asyncio event loop:

```python
async with stdio_client(upstream_params) as (upstream_read, upstream_write):
    async with ClientSession(upstream_read, upstream_write) as upstream:
        await upstream.initialize()

        app = Server("mcp-security-proxy")

        @app.list_tools()
        async def handle_list_tools():
            result = await upstream.list_tools()
            findings = manifest_watcher.watch([t.model_dump() for t in result.tools])
            # alert on findings
            return result.tools

        @app.call_tool()
        async def handle_call_tool(name, arguments):
            result = await upstream.call_tool(name, arguments)
            findings = output_scanner.scan(name, result.content)
            call_logger.log(...)
            anomaly_detector.check(call_logger.recent())
            return result.content

        async with stdio_server() as (read, write):
            await app.run(read, write, app.create_initialization_options())
```

`stdio_client` spawns the real server as a subprocess (separate stdin/stdout). `stdio_server` uses the proxy process's own stdin/stdout to talk to the agent. No conflicts.
