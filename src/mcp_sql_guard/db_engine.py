"""Asynchronous Read-Only SQLite Execution Engine with High-Precision Telemetry."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import aiosqlite

from mcp_sql_guard.config import DEFAULT_CONFIG, MAX_ROWS, GuardConfig
from mcp_sql_guard.schemas import (
    QueryMetadata,
    QueryRequest,
    QueryResponse,
    TableSchema,
)
from mcp_sql_guard.security import SecurityViolationError, SQLSecurityGuard


@dataclass
class TelemetryState:
    """Thread/async-safe telemetry state container protected by an asyncio.Lock."""

    total_queries_executed: int = 0
    successful_queries: int = 0
    blocked_attempts: int = 0
    timeout_errors: int = 0
    truncated_responses: int = 0
    total_rows_returned: int = 0
    cumulative_latency_ms: float = 0.0
    audit_log: list[dict[str, Any]] = field(default_factory=list)


class AsyncReadOnlyDB:
    """Zero-Trust Asynchronous SQLite engine enforcing URI `?mode=ro`, timeouts, and row bounds."""

    def __init__(
        self,
        db_path: str | Path | None = None,
        config: GuardConfig = DEFAULT_CONFIG,
        timeout_seconds: float | None = None,
        max_payload_bytes: int | None = None,
    ) -> None:
        self._config: GuardConfig = config
        resolved_path = Path(db_path) if db_path is not None else config.db_path
        self._db_path: Path = resolved_path.resolve()
        self._timeout_seconds: float = (
            timeout_seconds if timeout_seconds is not None else config.query_timeout_seconds
        )
        self._max_payload_bytes: int = (
            max_payload_bytes if max_payload_bytes is not None else config.max_payload_bytes
        )
        self._telemetry_lock: asyncio.Lock = asyncio.Lock()
        self._telemetry: TelemetryState = TelemetryState()

    @property
    def db_path(self) -> Path:
        """Return the resolved path to the SQLite database file."""
        return self._db_path

    @property
    def read_only_uri(self) -> str:
        """Construct a cross-platform SQLite URI with `?mode=ro` enforcement."""
        posix_path = self._db_path.as_posix()
        return f"file:{posix_path}?mode=ro"

    async def _record_telemetry(
        self,
        *,
        sql: str,
        query_hash: str,
        status: str,
        latency_ms: float,
        row_count: int = 0,
        truncated: bool = False,
        reason: str | None = None,
    ) -> None:
        """Record query execution metrics under an async lock (zero unlocked mutable state)."""
        async with self._telemetry_lock:
            self._telemetry.total_queries_executed += 1
            self._telemetry.cumulative_latency_ms += latency_ms
            if status == "PASSED":
                self._telemetry.successful_queries += 1
                self._telemetry.total_rows_returned += row_count
                if truncated:
                    self._telemetry.truncated_responses += 1
            elif status == "BLOCKED":
                self._telemetry.blocked_attempts += 1
            elif status == "TIMEOUT":
                self._telemetry.timeout_errors += 1

            self._telemetry.audit_log.append(
                {
                    "query_hash": query_hash,
                    "status": status,
                    "execution_time_ms": round(latency_ms, 3),
                    "row_count": row_count,
                    "truncated": truncated,
                    "reason": reason or "OK",
                    "sql_preview": (sql.strip()[:120] + "...")
                    if len(sql.strip()) > 120
                    else sql.strip(),
                }
            )
            # Keep last 250 audit records in memory
            if len(self._telemetry.audit_log) > 250:
                self._telemetry.audit_log.pop(0)

    async def record_blocked_attempt(
        self,
        sql: str,
        reason: str,
        latency_ms: float,
        query_hash: str | None = None,
    ) -> None:
        """Public helper to record a security violation blocked prior to DB execution."""
        computed_hash = query_hash or SQLSecurityGuard.compute_query_hash(sql)
        await self._record_telemetry(
            sql=sql,
            query_hash=computed_hash,
            status="BLOCKED",
            latency_ms=latency_ms,
            row_count=0,
            truncated=False,
            reason=reason,
        )

    async def execute_query(
        self,
        sql: str,
        max_rows: int = 50,
        params: dict[str, Any] | None = None,
        enforce_hard_cap: bool = True,
    ) -> QueryResponse:
        """Validate and execute a read-only SQL query with timeout and context-window protection.

        Args:
            sql: Raw SQL query string.
            max_rows: Requested row limit (validated via `QueryRequest` [1..200] and capped at `MAX_ROWS` if `enforce_hard_cap` is True).
            params: Optional dictionary of bind parameters.
            enforce_hard_cap: When True, caps effective rows at `MAX_ROWS` (100) if `max_rows` exceeds it,
                or honors `max_rows` up to 200 while flagging truncation whenever more rows exist.

        Returns:
            Validated `QueryResponse` Pydantic model with columns, rows, and `QueryMetadata`.

        Raises:
            SecurityViolationError: If the SQL fails `SQLSecurityGuard.validate_select_only` or triggers a SQLite read-only error.
            TimeoutError: If query execution exceeds `self._timeout_seconds`.
        """
        start_ns = time.perf_counter()
        query_hash = SQLSecurityGuard.compute_query_hash(sql or "")

        # 1. AST / Regex Security Gate
        try:
            validated_sql = SQLSecurityGuard.validate_select_only(sql)
        except SecurityViolationError as exc:
            elapsed_ms = (time.perf_counter() - start_ns) * 1000.0
            await self.record_blocked_attempt(
                sql=sql,
                reason=exc.reason,
                latency_ms=elapsed_ms,
                query_hash=exc.sql_hash or query_hash,
            )
            raise

        # 2. Validate request parameters via Pydantic v2 QueryRequest
        request_model = QueryRequest(sql=validated_sql, max_rows=max_rows, params=params)
        effective_max_rows = (
            min(request_model.max_rows, MAX_ROWS)
            if enforce_hard_cap and request_model.max_rows > MAX_ROWS
            else request_model.max_rows
        )
        capped_by_hard_limit = enforce_hard_cap and request_model.max_rows > MAX_ROWS

        async def _run_db_operation() -> tuple[list[str], list[dict[str, Any]], bool]:
            async with aiosqlite.connect(self.read_only_uri, uri=True) as conn:
                conn.row_factory = aiosqlite.Row
                # Reinforce read-only mode at connection level
                await conn.execute("PRAGMA query_only = ON;")

                cursor = await conn.execute(
                    request_model.sql,
                    request_model.params or {},
                )
                try:
                    description = cursor.description or ()
                    columns = [ str(col[0]) for col in description ]

                    # Fetch one extra row to deterministically detect if result set exceeds effective_max_rows
                    fetched_rows = await cursor.fetchmany(effective_max_rows + 1)
                    is_truncated = len(fetched_rows) > effective_max_rows or capped_by_hard_limit
                    bounded_rows = fetched_rows[:effective_max_rows]

                    rows_out: list[dict[str, Any]] = []
                    running_bytes = 0

                    for raw_row in bounded_rows:
                        row_dict = {col: raw_row[idx] for idx, col in enumerate(columns)}
                        serialized_row = json.dumps(row_dict, default=str)
                        row_bytes = len(serialized_row.encode("utf-8"))

                        if (
                            rows_out
                            and (running_bytes + row_bytes) > self._max_payload_bytes
                        ):
                            is_truncated = True
                            break

                        running_bytes += row_bytes
                        rows_out.append(row_dict)

                    return columns, rows_out, is_truncated
                finally:
                    await cursor.close()

        try:
            columns, rows, truncated = await asyncio.wait_for(
                _run_db_operation(),
                timeout=self._timeout_seconds,
            )
        except asyncio.TimeoutError as exc:
            elapsed_ms = (time.perf_counter() - start_ns) * 1000.0
            await self._record_telemetry(
                sql=validated_sql,
                query_hash=query_hash,
                status="TIMEOUT",
                latency_ms=elapsed_ms,
                reason=f"Query exceeded {self._timeout_seconds:.2f}s execution timeout.",
            )
            raise TimeoutError(
                f"TIMEOUT_ERROR: Query execution exceeded {self._timeout_seconds:.2f}s limit."
            ) from exc
        except sqlite3.OperationalError as exc:
            elapsed_ms = (time.perf_counter() - start_ns) * 1000.0
            err_msg = str(exc)
            if "readonly" in err_msg.lower() or "query_only" in err_msg.lower():
                sec_err = SecurityViolationError(
                    f"SECURITY_BLOCK: SQLite URI `?mode=ro` engine blocked write operation: {err_msg}",
                    sql_hash=query_hash,
                )
                await self.record_blocked_attempt(
                    sql=validated_sql,
                    reason=sec_err.reason,
                    latency_ms=elapsed_ms,
                    query_hash=query_hash,
                )
                raise sec_err from exc
            raise

        elapsed_ms = round((time.perf_counter() - start_ns) * 1000.0, 4)
        await self._record_telemetry(
            sql=validated_sql,
            query_hash=query_hash,
            status="PASSED",
            latency_ms=elapsed_ms,
            row_count=len(rows),
            truncated=truncated,
        )

        metadata = QueryMetadata(
            execution_time_ms=elapsed_ms,
            row_count=len(rows),
            truncated=truncated,
            security_status="PASSED",
            query_hash=query_hash,
        )
        return QueryResponse(columns=columns, rows=rows, metadata=metadata)

    async def execute_raw_on_readonly_connection(self, raw_sql: str) -> None:
        """Directly execute a statement against the `?mode=ro` SQLite URI connection.

        Used by security verification suites to prove that even if the regex layer were bypassed,
        the underlying SQLite file URI (`?mode=ro`) deterministically rejects writes.
        """
        async with aiosqlite.connect(self.read_only_uri, uri=True) as conn:
            await conn.execute(raw_sql)
            await conn.commit()

    async def inspect_schema(self) -> list[TableSchema]:
        """Inspect full DDL metadata, column types, indexes, and row counts for all tables."""
        async def _fetch_schemas() -> list[TableSchema]:
            async with aiosqlite.connect(self.read_only_uri, uri=True) as conn:
                conn.row_factory = aiosqlite.Row
                cursor = await conn.execute(
                    """
                    SELECT name, sql
                    FROM sqlite_master
                    WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                    ORDER BY name ASC;
                    """
                )
                tables = await cursor.fetchall()
                await cursor.close()

                schemas: list[TableSchema] = []
                for tbl in tables:
                    table_name = str(tbl["name"])
                    ddl_sql = str(tbl["sql"] or "")

                    # Safe identifier quoting for PRAGMA and COUNT
                    escaped_ident = table_name.replace('"', '""')

                    col_cursor = await conn.execute(f'PRAGMA table_info("{escaped_ident}");')
                    col_rows = await col_cursor.fetchall()
                    await col_cursor.close()

                    columns_meta: list[dict[str, str]] = [
                        {
                            "name": str(col["name"]),
                            "type": str(col["type"] or "ANY"),
                            "notnull": str(bool(col["notnull"])),
                            "default": str(col["dflt_value"])
                            if col["dflt_value"] is not None
                            else "",
                            "primary_key": str(bool(col["pk"])),
                        }
                        for col in col_rows
                    ]

                    idx_cursor = await conn.execute(f'PRAGMA index_list("{escaped_ident}");')
                    idx_rows = await idx_cursor.fetchall()
                    await idx_cursor.close()

                    indexes_meta: list[dict[str, str]] = [
                        {
                            "name": str(idx["name"]),
                            "unique": str(bool(idx["unique"])),
                            "origin": str(idx["origin"]),
                        }
                        for idx in idx_rows
                    ]

                    cnt_cursor = await conn.execute(
                        f'SELECT COUNT(*) AS cnt FROM "{escaped_ident}";'
                    )
                    cnt_row = await cnt_cursor.fetchone()
                    await cnt_cursor.close()
                    row_estimate = int(cnt_row["cnt"]) if cnt_row is not None else 0

                    schemas.append(
                        TableSchema(
                            table_name=table_name,
                            columns=columns_meta,
                            row_estimate=row_estimate,
                            ddl=ddl_sql,
                            indexes=indexes_meta,
                        )
                    )
                return schemas

        return await asyncio.wait_for(_fetch_schemas(), timeout=self._timeout_seconds)

    async def get_telemetry_snapshot(self) -> dict[str, Any]:
        """Return cumulative audit statistics under async lock protection."""
        async with self._telemetry_lock:
            total = self._telemetry.total_queries_executed
            avg_latency = (
                round(self._telemetry.cumulative_latency_ms / total, 4)
                if total > 0
                else 0.0
            )
            return {
                "server_name": "Enterprise-SQL-Guard",
                "database_uri_mode": "ro",
                "database_path": str(self._db_path),
                "total_queries_executed": total,
                "successful_queries": self._telemetry.successful_queries,
                "blocked_attempts": self._telemetry.blocked_attempts,
                "timeout_errors": self._telemetry.timeout_errors,
                "truncated_responses": self._telemetry.truncated_responses,
                "total_rows_returned": self._telemetry.total_rows_returned,
                "average_execution_latency_ms": avg_latency,
                "recent_audit_events": list(self._telemetry.audit_log[-25:]),
            }

