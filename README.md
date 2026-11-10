# Enterprise Read-Only SQL & Telemetry MCP Server (`mcp-sql-guard`)

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![MCP SDK](https://img.shields.io/badge/MCP-FastMCP%20v1.6+-8A2BE2.svg)](https://modelcontextprotocol.io/)
[![Pydantic v2](https://img.shields.io/badge/Pydantic-v2.7+-E92063.svg)](https://docs.pydantic.dev/)
[![Tests](https://img.shields.io/badge/pytest-36%20passed%20%7C%20100%25-brightgreen.svg)](https://github.com/Christianlamas062/enterprise-sql-mcp-guard/actions)
[![Security](https://img.shields.io/badge/Defense-Defense--in--Depth%20(AST%20%2B%20mode=ro)-orange.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A production-grade, asynchronous **Model Context Protocol (MCP)** tool server built with `FastMCP`, `aiosqlite`, and `Pydantic v2`. 

`mcp-sql-guard` safely exposes analytical SQLite databases to AI Agents (**Claude Desktop**, **OpenCode**, **Cursor**, **Windsurf**) under strict deterministic security constraints, microsecond execution telemetry, and automatic LLM context-window protection.

---

## 🛡️ Problem Statement & Zero-Trust Defense

When AI Agents are given direct database tools, standard prompt instructions like *"only execute SELECT queries"* fail against prompt injections, hallucinated DDL (`DROP TABLE`), obfuscated comments, and stacked statements (`SELECT 1; DELETE FROM users;`).

`mcp-sql-guard` implements a **two-layer deterministic defense-in-depth model**:

1. **AST & Regex Sanitization Layer:** Pre-execution parser strips comments, rejects stacked queries, mandates `SELECT`/`WITH`/`EXPLAIN QUERY PLAN` statement roots, and regex-blocks 12+ mutating tokens (`INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `CREATE`, `REPLACE`, `TRUNCATE`, `ATTACH`, `DETACH`, `PRAGMA`, `VACUUM`).
2. **OS & Driver-Level URI Enforcement (`?mode=ro`):** All connections are opened in strict read-only mode (`file:path?mode=ro` + `PRAGMA query_only = ON`). Even if an injection bypassed parsing, the SQLite engine deterministically denies write operations at the C driver level.
3. **Context Window Starvation Protection:** Responses are automatically row-bounded (`MAX_ROWS = 100`) and payload-size truncated (`MAX_PAYLOAD_BYTES = 64KB`) to protect LLM context windows and prevent token exhaustion denial-of-service.

---

## 📐 Architecture & JSON-RPC 2.0 Flow

```mermaid
sequenceDiagram
    autonumber
    actor Agent as AI Agent (Claude / Cursor / OpenCode)
    participant Server as FastMCP Server (JSON-RPC 2.0)
    participant Guard as AST & Regex Security Guard
    participant Engine as SQLite Engine (URI ?mode=ro)

    Note over Agent, Server: Attack Attempt: Destructive DDL Injection
    Agent->>Server: call_tool("execute_readonly_query", {"sql": "DROP TABLE billing_ledgers;"})
    Server->>Guard: validate_select_only(sql)
    Guard-->>Server: Raise SecurityViolationError (Forbidden DDL Token: DROP)
    Server-->>Agent: JSON-RPC Response [status: BLOCKED, latency: 0.05ms]

    Note over Agent, Engine: Valid Analytical Query Execution
    Agent->>Server: call_tool("execute_readonly_query", {"sql": "SELECT tier, SUM(mrr) FROM institutional_clients GROUP BY 1", "max_rows": 50})
    Server->>Guard: validate_select_only(sql)
    Guard-->>Server: Validation PASSED (Normalized SELECT)
    Server->>Engine: Async Execute (Timeout: 3.0s, Limit: 50)
    Engine-->>Server: Rows + Execution Telemetry (~1.8ms)
    Server-->>Agent: JSON-RPC Response [Payloads + Metadata Audit]
```

---

## 🗂️ Project Structure

```text
enterprise-sql-mcp-guard/
├── pyproject.toml              # Build specs, dependencies & pytest configuration
├── claude_desktop_config.json  # Plug-and-play MCP client integration config
├── README.md                   # System documentation & architectural reference
├── src/
│   └── mcp_sql_guard/
│       ├── __init__.py         # Package exports & versioning
│       ├── config.py           # Environment variables, timeouts, and row/payload bounds
│       ├── schemas.py          # Strict Pydantic v2 input/output models (extra='forbid')
│       ├── security.py         # Deterministic AST/Regex validator (Read-Only + Anti-Injection)
│       ├── db_engine.py        # aiosqlite async engine + URI ?mode=ro + high-precision telemetry
│       └── server.py           # FastMCP server exposing Tools, Resources, and Prompts
├── scripts/
│   ├── seed_enterprise_db.py   # Generates enterprise_analytics.db with 1,800+ deterministic rows
│   └── demo_cli_audit.py       # Simulates 15 JSON-RPC agent calls & prints Rich CLI dashboard
└── tests/
    ├── __init__.py
    ├── test_security_guard.py  # Unit tests for SQLSecurityGuard (mutations, stacked queries, comments)
    └── test_mcp_tools.py       # Async integration tests for tools, truncation, timeouts, and mode=ro
```

---

## 🛠️ MCP Tools, Resources & Prompts

| Type | Name | Description |
| :--- | :--- | :--- |
| **Tool** | `execute_readonly_query(sql, max_rows)` | Executes a validated analytical SQL query against the read-only database. |
| **Tool** | `inspect_schema()` | Returns DDL, column data types, indexes, and row counts for all database tables. |
| **Tool** | `get_server_telemetry()` | Returns cumulative server statistics (queries executed, blocked attacks, average latency). |
| **Resource** | `sqlguard://schema` | Complete markdown-formatted DDL catalog of the analytical database. |
| **Prompt** | `safe_analytical_sql_prompt` | Pre-engineered system prompt directing agents to emit strictly read-only queries. |

---

## 🚀 Quickstart & Setup

### 1. Installation

```bash
git clone https://github.com/Christianlamas062/enterprise-sql-mcp-guard.git
cd enterprise-sql-mcp-guard

# Install dependencies
pip install -e .
```

### 2. Seed the Enterprise Analytics Database

Generates a deterministic B2B SaaS database (`enterprise_analytics.db`) with **1,800+ records** across 3 tables (`institutional_clients`, `api_usage_logs`, `billing_ledgers`):

```bash
python scripts/seed_enterprise_db.py
```

### 3. Run the CLI Audit Simulation

Simulates 15 realistic agent tool interactions (aggregations, joins, CTEs, and 4 adversarial injection attacks):

```bash
python scripts/demo_cli_audit.py
```

### 4. Run the Test Suite

```bash
pytest -v
```

---

## 🤖 Claude Desktop & Cursor Integration

Add `mcp-sql-guard` to your `claude_desktop_config.json` (or `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "enterprise-sql-guard": {
      "command": "python",
      "args": [
        "-m",
        "mcp_sql_guard.server"
      ],
      "env": {
        "PYTHONPATH": "C:/path/to/enterprise-sql-mcp-guard/src",
        "MCP_SQL_GUARD_DB_PATH": "C:/path/to/enterprise-sql-mcp-guard/enterprise_analytics.db",
        "MCP_SQL_GUARD_DEFAULT_MAX_ROWS": "50",
        "MCP_SQL_GUARD_HARD_MAX_ROWS": "100",
        "MCP_SQL_GUARD_TIMEOUT_SEC": "3.0"
      }
    }
  }
}
```

---

## 📊 Verification & Test Matrix

The test suite covers **36 test cases** with a **100% pass rate**:

* **SQL Injection & AST Bypass Tests:** `DROP TABLE`, `; UPDATE`, stacked `SELECT 1; SELECT 2`, comment obfuscation (`/* ... */`, `--`), unclosed block comments, token splitting (`DR/**/OP`), and unauthorized CTE bodies.
* **Row & Byte Bounds Tests:** Enforcing custom `max_rows`, hard limits (`MAX_ROWS = 100`), and JSON payload byte thresholds.
* **Driver-Level Mode Tests:** Verifying `sqlite3.OperationalError: attempt to write a readonly database` when executing directly on the connection.
* **Timeout Protections:** Validating `asyncio.wait_for` bounds against recursive Cartesian queries.

---

## 📄 License

MIT License. Designed for enterprise production environments and sovereign AI agent deployments.
