"""Enterprise Read-Only SQL & Telemetry MCP Server (mcp-sql-guard)."""

from mcp_sql_guard.config import GuardConfig
from mcp_sql_guard.db_engine import AsyncReadOnlyDB
from mcp_sql_guard.schemas import (
    QueryMetadata,
    QueryRequest,
    QueryResponse,
    TableSchema,
)
from mcp_sql_guard.security import SecurityViolationError, SQLSecurityGuard

__all__ = [
    "AsyncReadOnlyDB",
    "GuardConfig",
    "QueryMetadata",
    "QueryRequest",
    "QueryResponse",
    "SQLSecurityGuard",
    "SecurityViolationError",
    "TableSchema",
]
__version__ = "1.0.0"

