# Enterprise Read-Only SQL & Telemetry MCP Server (`mcp-sql-guard`)

Production-grade, asynchronous Model Context Protocol (MCP) tool server built with `FastMCP`, `aiosqlite`, and `Pydantic v2`. Exposes analytical SQLite databases to AI Agents (Claude Desktop, OpenCode, Cursor) under strict deterministic security constraints.

## Key Capabilities

- **Zero-Trust Read-Only Enforcement:** Hard block on all mutating SQL statements (`INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `TRUNCATE`, `ATTACH`, `PRAGMA` write modes) at both the AST/Regex validation layer and the SQLite URI connection level (`?mode=ro`).
- **Context Window Protection:** Automatic row bounding (`MAX_ROWS = 100` default cap, configurable up to `200`) and payload size truncation (`MAX_PAYLOAD_BYTES`) to prevent LLM token exhaustion.
- **Execution Telemetry:** Microsecond query latency tracking via `time.perf_counter()`, row counters, SHA-256 query fingerprinting, and structured JSON-RPC audit logging with `asyncio.Lock` concurrency safety.

## Architecture

```text
enterprise-sql-mcp-guard/
├── pyproject.toml
├── README.md
├── src/
│   └── mcp_sql_guard/
│       ├── __init__.py
│       ├── config.py          # Environment variables, timeouts, and row/payload limits
│       ├── schemas.py         # Strict Pydantic v2 input/output models
│       ├── security.py        # Deterministic AST/Regex validator (Read-Only + Anti-Injection)
│       ├── db_engine.py       # Async read-only connection engine (aiosqlite) + Telemetry
│       └── server.py          # FastMCP server exposing Tools, Resources, and Prompts
├── scripts/
│   ├── seed_enterprise_db.py  # Generates enterprise_analytics.db with 1,500+ deterministic rows
│   └── demo_cli_audit.py      # Simulates 15 JSON-RPC agent calls & prints Rich CLI dashboard
└── tests/
    ├── __init__.py
    ├── test_security_guard.py # Unit tests for SQLSecurityGuard (mutations, stacked queries, comments)
    └── test_mcp_tools.py      # Async integration tests for tools, truncation, timeouts, and URI mode=ro
```

## Quickstart

```bash
# 1. Seed the deterministic enterprise database (1,500+ rows)
python scripts/seed_enterprise_db.py

# 2. Run the test suite
pytest -v

# 3. Run the CLI Audit Dashboard simulation
python scripts/demo_cli_audit.py
```

