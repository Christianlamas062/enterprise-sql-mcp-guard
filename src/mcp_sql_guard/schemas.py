"""Strict Pydantic v2 schemas for Enterprise Read-Only SQL & Telemetry MCP Server."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class QueryRequest(BaseModel):
    """Input validation contract for read-only analytical SQL queries."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sql: str = Field(..., min_length=1, description="Read-only SQL statement to execute.")
    max_rows: int = Field(
        default=50,
        ge=1,
        le=200,
        description="Maximum rows to return for context window protection.",
    )
    params: dict[str, Any] | None = Field(
        default=None,
        description="Optional named parameters for parameterized SQL queries.",
    )


class QueryMetadata(BaseModel):
    """Execution telemetry and security audit metadata for a SQL query."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    execution_time_ms: float = Field(
        ...,
        ge=0.0,
        description="High-precision query execution latency in milliseconds.",
    )
    row_count: int = Field(
        ...,
        ge=0,
        description="Number of rows returned in the payload.",
    )
    truncated: bool = Field(
        ...,
        description="True if results were capped by max_rows or payload byte limits.",
    )
    security_status: Literal["PASSED", "BLOCKED"] = Field(
        ...,
        description="Deterministic security validation status.",
    )
    query_hash: str = Field(
        ...,
        min_length=8,
        description="SHA-256 fingerprint of the normalized SQL query.",
    )


class QueryResponse(BaseModel):
    """Structured output returned by read-only SQL execution."""

    model_config = ConfigDict(extra="forbid")

    columns: list[str] = Field(
        default_factory=list,
        description="Ordered column names from the query cursor.",
    )
    rows: list[dict[str, Any]] = Field(
        default_factory=list,
        description="List of row dictionaries mapping column names to values.",
    )
    metadata: QueryMetadata = Field(
        ...,
        description="Execution telemetry and security status.",
    )


class TableSchema(BaseModel):
    """Schema metadata for a single database table."""

    model_config = ConfigDict(extra="forbid")

    table_name: str = Field(..., description="Name of the SQLite table.")
    columns: list[dict[str, str]] = Field(
        default_factory=list,
        description="List of column metadata dictionaries (name, type, notnull, pk, default).",
    )
    row_estimate: int = Field(
        ...,
        ge=0,
        description="Exact or estimated row count for the table.",
    )
    ddl: str = Field(
        default="",
        description="Original CREATE TABLE DDL statement from sqlite_master.",
    )
    indexes: list[dict[str, str]] = Field(
        default_factory=list,
        description="List of indexes associated with the table.",
    )

