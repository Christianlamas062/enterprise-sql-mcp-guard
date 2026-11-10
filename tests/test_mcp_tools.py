"""Async integration tests for `AsyncReadOnlyDB` and FastMCP Tools (`execute_readonly_query`, `inspect_schema`, `get_server_telemetry`)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from mcp_sql_guard.db_engine import AsyncReadOnlyDB
from mcp_sql_guard.schemas import QueryRequest
from mcp_sql_guard.security import SecurityViolationError
from mcp_sql_guard.server import (
    configure_server_db,
    execute_readonly_query,
    get_server_telemetry,
    inspect_schema,
)
from scripts.seed_enterprise_db import seed_database


@pytest.fixture(scope="module")
def seeded_db_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Create a deterministic seeded enterprise SQLite database for the test module."""
    db_dir = tmp_path_factory.mktemp("enterprise_db")
    db_file = db_dir / "enterprise_analytics_test.db"
    counts = seed_database(db_file)
    assert counts["total_rows"] >= 1500
    return db_file


@pytest.fixture(autouse=True)
async def _bind_server_to_test_db(seeded_db_path: Path) -> None:
    """Reconfigure the MCP server registry before each test for isolated telemetry."""
    await configure_server_db(seeded_db_path)


class TestMCPToolsAndEngine:
    """Verify MCP tools, row truncation, payload protection, timeouts, and URI `?mode=ro`."""

    async def test_execute_readonly_query_valid_select(self) -> None:
        res = await execute_readonly_query(
            sql="SELECT client_id, tier, mrr_usd FROM institutional_clients WHERE tier = 'SOVEREIGN_DESK' ORDER BY client_id ASC",
            max_rows=10,
        )
        assert res["error"] is None
        assert res["columns"] == ["client_id", "tier", "mrr_usd"]
        assert len(res["rows"]) == 10
        assert res["metadata"]["security_status"] == "PASSED"
        assert res["metadata"]["row_count"] == 10
        assert res["metadata"]["truncated"] is True
        assert res["metadata"]["execution_time_ms"] >= 0.0

    async def test_execute_readonly_query_with_cte_not_truncated(self) -> None:
        res = await execute_readonly_query(
            sql="""
            WITH tier_totals AS (
                SELECT tier, COUNT(*) AS cnt, ROUND(SUM(mrr_usd), 2) AS sum_mrr
                FROM institutional_clients
                GROUP BY tier
            )
            SELECT * FROM tier_totals ORDER BY sum_mrr DESC
            """,
            max_rows=50,
        )
        assert res["error"] is None
        assert res["metadata"]["security_status"] == "PASSED"
        assert res["metadata"]["row_count"] == 4
        assert res["metadata"]["truncated"] is False

    async def test_row_truncation_enforced_at_custom_max_rows(self) -> None:
        res = await execute_readonly_query(
            sql="SELECT log_id, request_id, endpoint FROM api_usage_logs ORDER BY log_id ASC",
            max_rows=15,
        )
        assert res["metadata"]["row_count"] == 15
        assert res["metadata"]["truncated"] is True
        assert len(res["rows"]) == 15

    async def test_hard_max_rows_cap_of_100_enforced(self) -> None:
        # Even if caller requests 180 rows (within QueryRequest le=200), hard cap MAX_ROWS=100 bounds output
        res = await execute_readonly_query(
            sql="SELECT log_id, request_id FROM api_usage_logs ORDER BY log_id ASC",
            max_rows=180,
        )
        assert res["metadata"]["row_count"] == 100
        assert res["metadata"]["truncated"] is True

    async def test_payload_byte_size_truncation(self, seeded_db_path: Path) -> None:
        # Configure a very small max_payload_bytes (350 bytes) to trigger byte-level context protection
        small_engine = AsyncReadOnlyDB(
            db_path=seeded_db_path,
            max_payload_bytes=350,
        )
        response = await small_engine.execute_query(
            sql="SELECT * FROM institutional_clients ORDER BY client_id ASC",
            max_rows=50,
        )
        assert response.metadata.truncated is True
        assert 1 <= response.metadata.row_count < 10

    async def test_blocked_query_returns_structured_blocked_metadata(self) -> None:
        res = await execute_readonly_query(
            sql="DROP TABLE institutional_clients;",
            max_rows=10,
        )
        assert res["metadata"]["security_status"] == "BLOCKED"
        assert res["metadata"]["row_count"] == 0
        assert res["rows"] == []
        assert "DROP" in res["error"]

    async def test_blocked_query_raises_when_requested(self) -> None:
        with pytest.raises(SecurityViolationError):
            await execute_readonly_query(
                sql="DELETE FROM billing_ledgers;",
                max_rows=10,
                raise_on_block=True,
            )

    async def test_inspect_schema_returns_all_tables_and_counts(self) -> None:
        schemas = await inspect_schema()
        table_map = {item["table_name"]: item for item in schemas}
        assert set(table_map.keys()) == {
            "institutional_clients",
            "api_usage_logs",
            "billing_ledgers",
        }
        assert table_map["institutional_clients"]["row_estimate"] == 120
        assert table_map["api_usage_logs"]["row_estimate"] == 1200
        assert table_map["billing_ledgers"]["row_estimate"] == 480
        assert len(table_map["institutional_clients"]["columns"]) == 9
        assert len(table_map["institutional_clients"]["indexes"]) >= 2

    async def test_sqlite_uri_mode_ro_blocks_writes_at_driver_level(
        self, seeded_db_path: Path
    ) -> None:
        engine = AsyncReadOnlyDB(db_path=seeded_db_path)
        assert engine.read_only_uri.endswith("?mode=ro")
        with pytest.raises(sqlite3.OperationalError) as exc_info:
            await engine.execute_raw_on_readonly_connection(
                "DELETE FROM institutional_clients WHERE client_id = 'CLI-0001';"
            )
        assert "readonly" in str(exc_info.value).lower()

    async def test_query_timeout_enforcement(self, seeded_db_path: Path) -> None:
        # Use a tight timeout (0.015s) and a heavy recursive Cartesian query to trigger asyncio.wait_for timeout
        fast_timeout_engine = AsyncReadOnlyDB(
            db_path=seeded_db_path,
            timeout_seconds=0.015,
        )
        heavy_recursive_sql = """
        WITH RECURSIVE spin(n) AS (
            SELECT 1
            UNION ALL
            SELECT n + 1 FROM spin WHERE n < 5000000
        )
        SELECT COUNT(*) FROM spin a CROSS JOIN institutional_clients b
        """
        with pytest.raises(TimeoutError) as exc_info:
            await fast_timeout_engine.execute_query(heavy_recursive_sql, max_rows=10)
        assert "TIMEOUT_ERROR" in str(exc_info.value)

    async def test_server_telemetry_tracks_passed_and_blocked_calls(self) -> None:
        await execute_readonly_query(
            sql="SELECT COUNT(*) AS cnt FROM institutional_clients", max_rows=5
        )
        await execute_readonly_query(
            sql="UPDATE institutional_clients SET mrr_usd = 999999", max_rows=5
        )
        telemetry = await get_server_telemetry()
        assert telemetry["total_queries_executed"] == 2
        assert telemetry["successful_queries"] == 1
        assert telemetry["blocked_attempts"] == 1
        assert telemetry["average_execution_latency_ms"] >= 0.0
        assert len(telemetry["recent_audit_events"]) == 2

    def test_pydantic_query_request_bounds_validation(self) -> None:
        req = QueryRequest(sql="SELECT 1", max_rows=200)
        assert req.max_rows == 200
        with pytest.raises(ValueError):
            QueryRequest(sql="SELECT 1", max_rows=0)
        with pytest.raises(ValueError):
            QueryRequest(sql="SELECT 1", max_rows=201)

