"""FastMCP Server implementation for Enterprise Read-Only SQL & Telemetry (`mcp-sql-guard`)."""

from __future__ import annotations

import asyncio
import warnings
from pathlib import Path
from typing import Any

warnings.filterwarnings("ignore", message=".*Field 'lifespan' has an incomplete definition.*")

from mcp.server.fastmcp import FastMCP

from mcp_sql_guard.config import DEFAULT_CONFIG
from mcp_sql_guard.db_engine import AsyncReadOnlyDB
from mcp_sql_guard.schemas import QueryMetadata, QueryResponse
from mcp_sql_guard.security import SecurityViolationError, SQLSecurityGuard

mcp: FastMCP = FastMCP("Enterprise-SQL-Guard")


class _EngineRegistry:
    """Concurrency-safe registry managing the active AsyncReadOnlyDB instance."""

    def __init__(self) -> None:
        self._lock: asyncio.Lock = asyncio.Lock()
        self._engine: AsyncReadOnlyDB = AsyncReadOnlyDB(config=DEFAULT_CONFIG)

    async def get_engine(self) -> AsyncReadOnlyDB:
        """Retrieve the current `AsyncReadOnlyDB` engine under lock protection."""
        async with self._lock:
            return self._engine

    async def configure_engine(
        self,
        db_path: str | Path,
        timeout_seconds: float | None = None,
        max_payload_bytes: int | None = None,
    ) -> AsyncReadOnlyDB:
        """Reconfigure and replace the active `AsyncReadOnlyDB` engine safely."""
        async with self._lock:
            self._engine = AsyncReadOnlyDB(
                db_path=db_path,
                config=DEFAULT_CONFIG,
                timeout_seconds=timeout_seconds,
                max_payload_bytes=max_payload_bytes,
            )
            return self._engine


_REGISTRY: _EngineRegistry = _EngineRegistry()


async def configure_server_db(
    db_path: str | Path,
    timeout_seconds: float | None = None,
    max_payload_bytes: int | None = None,
) -> AsyncReadOnlyDB:
    """Configure the database path and execution bounds for the MCP server tools."""
    return await _REGISTRY.configure_engine(
        db_path=db_path,
        timeout_seconds=timeout_seconds,
        max_payload_bytes=max_payload_bytes,
    )


async def get_active_db() -> AsyncReadOnlyDB:
    """Return the active `AsyncReadOnlyDB` instance."""
    return await _REGISTRY.get_engine()


@mcp.tool()
async def execute_readonly_query(
    sql: str,
    max_rows: int = 50,
    raise_on_block: bool = False,
) -> dict[str, Any]:
    """Execute a validated read-only SQL query against the enterprise SQLite database.

    Runs `SQLSecurityGuard.validate_select_only`, executes against `AsyncReadOnlyDB`
    with `?mode=ro` URI enforcement and timeout protection, and returns the serialized
    `QueryResponse` dictionary.

    Args:
        sql: The SELECT, WITH (CTE), or EXPLAIN QUERY PLAN statement to execute.
        max_rows: Maximum rows to return (1 to 200, hard-capped at MAX_ROWS=100 by default).
        raise_on_block: When True, re-raises `SecurityViolationError` instead of returning
            a structured `BLOCKED` `QueryResponse` payload.
    """
    engine = await _REGISTRY.get_engine()
    try:
        # Run SQLSecurityGuard validation explicitly as required by contract
        SQLSecurityGuard.validate_select_only(sql)
        response = await engine.execute_query(sql=sql, max_rows=max_rows)
        payload = response.model_dump()
        payload["error"] = None
        return payload
    except SecurityViolationError as exc:
        # Ensure telemetry records the blocked attempt if validate_select_only raised before engine.execute_query
        await engine.record_blocked_attempt(
            sql=sql,
            reason=exc.reason,
            latency_ms=0.05,
            query_hash=exc.sql_hash or SQLSecurityGuard.compute_query_hash(sql),
        )
        if raise_on_block:
            raise
        blocked_response = QueryResponse(
            columns=[],
            rows=[],
            metadata=QueryMetadata(
                execution_time_ms=0.05,
                row_count=0,
                truncated=False,
                security_status="BLOCKED",
                query_hash=exc.sql_hash or SQLSecurityGuard.compute_query_hash(sql),
            ),
        )
        payload = blocked_response.model_dump()
        payload["error"] = exc.reason
        return payload


@mcp.tool()
async def inspect_schema() -> list[dict[str, Any]]:
    """Return full DDL metadata, column types, indexes, and row counts for all tables."""
    engine = await _REGISTRY.get_engine()
    schemas = await engine.inspect_schema()
    return [schema.model_dump() for schema in schemas]


@mcp.tool()
async def get_server_telemetry() -> dict[str, Any]:
    """Return cumulative audit statistics (total queries, blocked attempts, avg latency ms)."""
    engine = await _REGISTRY.get_engine()
    return await engine.get_telemetry_snapshot()


@mcp.resource("sqlguard://schema")
async def resource_database_schema() -> str:
    """Expose the full database schema as a read-only MCP resource."""
    schemas = await inspect_schema()
    lines: list[str] = ["# Enterprise Analytics Database Schema (Read-Only)\n"]
    for table in schemas:
        lines.append(f"## Table: `{table['table_name']}` (Rows: {table['row_estimate']})")
        lines.append("```sql")
        lines.append(table.get("ddl", ""))
        lines.append("```\n")
    return "\n".join(lines)


@mcp.prompt()
def safe_analytical_sql_prompt(business_question: str) -> str:
    """Generate a strict read-only SQL generation prompt for AI agents."""
    return (
        "You are querying an Enterprise Read-Only SQLite Database protected by `mcp-sql-guard`.\n"
        "Constraints:\n"
        "1. Write ONLY a single `SELECT` or `WITH ... SELECT` statement.\n"
        "2. Never emit `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `PRAGMA`, or stacked `;` statements.\n"
        "3. First call `inspect_schema` if you need column names or types.\n\n"
        f"Business Question: {business_question}"
    )


def main() -> None:
    """Entrypoint for running the FastMCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
