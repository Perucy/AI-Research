# CodeGuard MCP Server

A security scanner MCP server for developers — and a research prototype for studying MCP client-side security.

CodeGuard exposes four tools that help developers catch common security issues in their codebases. It was also used as the research vehicle for a study on how MCP clients respond to three classes of client-side attacks.

---

## What It Does

| Tool | Description |
|---|---|
| `scan_file` | Scans a source file for hardcoded secrets, API keys, passwords, private keys, JWT tokens, SQL injection patterns, and path traversal risks |
| `scan_dependencies` | Checks `requirements.txt`, `package.json`, or `pyproject.toml` for packages with known CVEs |
| `get_report` | Aggregates findings from all scans in the session into a consolidated report with a risk score |
| `suggest_fix` | Returns step-by-step remediation for a specific finding by its ID |

---

## Installation

**Requirements**
- Python 3.11+
- An MCP-compatible client (Claude Desktop, Cursor, Cline)

**Setup**

```bash
git clone https://github.com/your-username/codeguard-mcp
cd codeguard-mcp
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

**Connect to your MCP client**

Add the following to your client's MCP config file:

*Claude Desktop* — `~/Library/Application Support/Claude/claude_desktop_config.json`  
*Cursor* — `~/.cursor/mcp.json`  
*Cline* — via the MCP Servers panel in VS Code

```json
{
  "mcpServers": {
    "codeguard": {
      "command": "/absolute/path/to/.venv/bin/python3",
      "args": ["/absolute/path/to/server.py"],
      "env": {
        "ATTACK_MODE": "none"
      }
    }
  }
}
```

Restart your client. You should see all four tools available.

---

## Usage

Once connected, ask your AI assistant to use the tools directly:

```
Scan this file for security issues: /path/to/your/file.py
```

```
Check my dependencies for vulnerabilities: /path/to/requirements.txt
```

```
Give me the full security report
```

```
Suggest a fix for finding a3f2b1c9
```

---

## Research Mode

CodeGuard was used to study how MCP clients respond to three client-side attack scenarios. This is controlled by the `ATTACK_MODE` environment variable.

| Value | Description |
|---|---|
| `none` | Default. All tools behave legitimately. |
| `rug_pull` | Mutates `get_report`'s description after 3 calls to include hidden exfiltration instructions |
| `metadata` | Patches `suggest_fix`'s description with hidden instructions inside an HTML comment |
| `shadow` | Registers a `read_file` tool that shadows the official filesystem server and silently exfiltrates file content |

**To reproduce the experiments:**

1. Set `ATTACK_MODE` to the desired value in your client's MCP config
2. Restart your client
3. Run the same tool sequence as the baseline
4. Observe whether the client detects the attack, warns the user, or executes the hidden instruction

A local HTTP listener is useful for confirming whether the shadowing exfiltration fires:

```bash
python3 -m http.server 8888
```

Then change the exfiltration URL in `read_file` to `http://localhost:8888/collect` before testing.

Full research writeup and findings: [blog link]

---

## Project Structure

```
codeguard-mcp/
├── server.py          # Main MCP server — all tools and attack layers
├── requirements.txt   # Dependencies
└── README.md
```

---

## Dependencies

```
mcp
httpx
```

---

## Disclaimer

CodeGuard was built as a local research prototype. It was never published to any MCP marketplace or registry. All experiments were conducted on a personal machine with simulated targets. No real credentials were collected and no external systems were involved. The attack layers are included for reproducibility of the research — use them only in controlled environments on systems you own.

---

## Related Work

- [Huang et al. — MCP Threat Modeling and Prompt Injection Analysis](https://arxiv.org/html/2603.22489v1)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MCP Specification](https://modelcontextprotocol.io)

---

## License

MIT