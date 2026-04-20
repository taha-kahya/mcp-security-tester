"""
Known public MCP server targets for manifest collection.
'command' is the argv list to spawn the server via stdio transport.
Servers requiring env vars (e.g. GITHUB_TOKEN) are noted in 'env_required'.
"""

SOURCES: list[dict] = [
    # Anthropic official servers (highest priority — these have known CVEs)
    {
        "name": "mcp-server-filesystem",
        "command": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "."],
        "env_required": [],
        "notes": "Official filesystem server. CVE-2025-68143 class (path traversal).",
    },
    {
        "name": "mcp-server-github",
        "command": ["npx", "-y", "@modelcontextprotocol/server-github"],
        "env_required": ["GITHUB_TOKEN"],
        "notes": "Official GitHub server. Used in May 2025 data breach.",
    },
    {
        "name": "mcp-server-git",
        "command": ["uvx", "mcp-server-git", "--repository", "."],
        "env_required": [],
        "notes": "Official Git server. CVE-2025-68143/44/45.",
    },
    {
        "name": "mcp-server-postgres",
        "command": ["npx", "-y", "@modelcontextprotocol/server-postgres"],
        "env_required": ["POSTGRES_CONNECTION_STRING"],
        "notes": "Official Postgres server.",
    },
    {
        "name": "mcp-server-slack",
        "command": ["npx", "-y", "@modelcontextprotocol/server-slack"],
        "env_required": ["SLACK_BOT_TOKEN"],
        "notes": "Official Slack server.",
    },

    # Popular community servers (from awesome-mcp-servers)
    {
        "name": "mcp-server-brave-search",
        "command": ["npx", "-y", "@modelcontextprotocol/server-brave-search"],
        "env_required": ["BRAVE_API_KEY"],
        "notes": "Brave search integration.",
    },
    {
        "name": "mcp-server-puppeteer",
        "command": ["npx", "-y", "@modelcontextprotocol/server-puppeteer"],
        "env_required": [],
        "notes": "Browser automation — high-risk tool surface.",
    },
    {
        "name": "mcp-server-everything",
        "command": ["npx", "-y", "@modelcontextprotocol/server-everything"],
        "env_required": [],
        "notes": "Reference server with all MCP primitives — good baseline.",
    },
]
