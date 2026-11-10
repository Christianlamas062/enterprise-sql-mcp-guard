"""Configuration settings for Enterprise Read-Only SQL & Telemetry MCP Server."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class GuardConfig:
    """Immutable configuration parameters for SQL guardrails and execution bounds."""

    db_path: Path = Path(
        os.getenv(
            "MCP_SQL_GUARD_DB_PATH",
            str(Path(__file__).resolve().parents[2] / "enterprise_analytics.db"),
        )
    )
    default_max_rows: int = int(os.getenv("MCP_SQL_GUARD_DEFAULT_MAX_ROWS", "50"))
    hard_max_rows: int = int(os.getenv("MCP_SQL_GUARD_HARD_MAX_ROWS", "100"))
    schema_max_rows: int = 200
    query_timeout_seconds: float = float(os.getenv("MCP_SQL_GUARD_TIMEOUT_SEC", "3.0"))
    max_payload_bytes: int = int(os.getenv("MCP_SQL_GUARD_MAX_PAYLOAD_BYTES", "65536"))


DEFAULT_CONFIG: GuardConfig = GuardConfig()
MAX_ROWS: int = DEFAULT_CONFIG.hard_max_rows

