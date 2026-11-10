"""Simulated Agent JSON-RPC Audit & Telemetry CLI Dashboard for `mcp-sql-guard`."""

from __future__ import annotations

import asyncio
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.box import DOUBLE_EDGE, ROUNDED
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from mcp_sql_guard.server import (
    configure_server_db,
    execute_readonly_query,
    get_server_telemetry,
    inspect_schema,
)
from scripts.seed_enterprise_db import DEFAULT_DB_PATH, seed_database


@dataclass(frozen=True)
class SimulatedAgentCall:
    """Represents a single JSON-RPC 2.0 MCP tool call issued by an AI Agent."""

    rpc_id: int
    agent_persona: str
    tool_name: str
    arguments: dict[str, Any]
    description: str


SIMULATED_CALLS: list[SimulatedAgentCall] = [
    SimulatedAgentCall(
        rpc_id=101,
        agent_persona="Claude-Desktop",
        tool_name="inspect_schema",
        arguments={},
        description="Discover enterprise tables, column types, indexes, and row estimates",
    ),
    SimulatedAgentCall(
        rpc_id=102,
        agent_persona="Claude-Desktop",
        tool_name="execute_readonly_query",
        arguments={
            "sql": (
                "SELECT tier, region, COUNT(*) AS client_count, "
                "ROUND(SUM(mrr_usd), 2) AS total_mrr_usd, ROUND(AVG(risk_score), 2) AS avg_risk "
                "FROM institutional_clients WHERE account_status = 'ACTIVE' "
                "GROUP BY tier, region ORDER BY total_mrr_usd DESC"
            ),
            "max_rows": 25,
        },
        description="Aggregate active MRR and average risk score by institutional tier & region",
    ),
    SimulatedAgentCall(
        rpc_id=103,
        agent_persona="Cursor-Agent",
        tool_name="execute_readonly_query",
        arguments={
            "sql": (
                "WITH endpoint_stats AS ("
                "  SELECT endpoint, COUNT(*) AS reqs, ROUND(AVG(latency_ms), 2) AS avg_lat_ms, "
                "  SUM(tokens_consumed) AS total_tokens, ROUND(SUM(compute_cost_usd), 4) AS cost_usd "
                "  FROM api_usage_logs GROUP BY endpoint"
                ") SELECT * FROM endpoint_stats ORDER BY cost_usd DESC"
            ),
            "max_rows": 20,
        },
        description="CTE aggregation of API endpoint latency, token volume, and compute cost",
    ),
    SimulatedAgentCall(
        rpc_id=104,
        agent_persona="Rogue-Prompt-Inj",
        tool_name="execute_readonly_query",
        arguments={
            "sql": "DROP TABLE billing_ledgers;",
            "max_rows": 10,
        },
        description="[ATTACK #1] Direct destructive DDL DROP TABLE attempt",
    ),
    SimulatedAgentCall(
        rpc_id=105,
        agent_persona="OpenCode-Analyst",
        tool_name="execute_readonly_query",
        arguments={
            "sql": (
                "SELECT payment_status, billing_period, COUNT(*) AS invoices, "
                "ROUND(SUM(total_usd), 2) AS gross_volume_usd "
                "FROM billing_ledgers GROUP BY payment_status, billing_period "
                "ORDER BY billing_period ASC, gross_volume_usd DESC"
            ),
            "max_rows": 50,
        },
        description="Quarterly billing settlement vs. overdue exposure matrix",
    ),
    SimulatedAgentCall(
        rpc_id=106,
        agent_persona="Rogue-Prompt-Inj",
        tool_name="execute_readonly_query",
        arguments={
            "sql": (
                "SELECT client_id, mrr_usd FROM institutional_clients WHERE tier = 'SOVEREIGN_DESK'; "
                "UPDATE billing_ledgers SET payment_status = 'SETTLED' WHERE payment_status = 'OVERDUE';"
            ),
            "max_rows": 10,
        },
        description="[ATTACK #2] Stacked SQL injection piggybacking UPDATE on a valid SELECT",
    ),
    SimulatedAgentCall(
        rpc_id=107,
        agent_persona="Claude-Desktop",
        tool_name="execute_readonly_query",
        arguments={
            "sql": (
                "SELECT c.client_id, c.organization_name, c.tier, b.invoice_id, b.total_usd, b.payment_status "
                "FROM billing_ledgers b JOIN institutional_clients c ON b.client_id = c.client_id "
                "WHERE b.payment_status IN ('OVERDUE', 'DISPUTED') "
                "ORDER BY b.total_usd DESC LIMIT 10"
            ),
            "max_rows": 10,
        },
        description="Top 10 largest overdue/disputed institutional invoices with client join",
    ),
    SimulatedAgentCall(
        rpc_id=108,
        agent_persona="Cursor-Agent",
        tool_name="execute_readonly_query",
        arguments={
            "sql": "SELECT log_id, request_id, client_id, endpoint, latency_ms FROM api_usage_logs ORDER BY log_id ASC",
            "max_rows": 40,
        },
        description="Context window protection test: 1,200 table rows automatically truncated to max_rows=40",
    ),
    SimulatedAgentCall(
        rpc_id=109,
        agent_persona="Rogue-Prompt-Inj",
        tool_name="execute_readonly_query",
        arguments={
            "sql": "/* Bypass guard */ PRAGMA writable_schema = ON;",
            "max_rows": 5,
        },
        description="[ATTACK #3] Comment-obfuscated PRAGMA writable_schema escalation attempt",
    ),
    SimulatedAgentCall(
        rpc_id=110,
        agent_persona="OpenCode-Analyst",
        tool_name="execute_readonly_query",
        arguments={
            "sql": (
                "EXPLAIN QUERY PLAN SELECT * FROM api_usage_logs "
                "WHERE client_id = 'CLI-0001' AND recorded_at > '2026-01-02'"
            ),
            "max_rows": 10,
        },
        description="Verify composite B-Tree index utilization via EXPLAIN QUERY PLAN",
    ),
    SimulatedAgentCall(
        rpc_id=111,
        agent_persona="Claude-Desktop",
        tool_name="execute_readonly_query",
        arguments={
            "sql": (
                "SELECT endpoint, COUNT(*) AS error_events, ROUND(AVG(latency_ms), 2) AS avg_error_latency_ms "
                "FROM api_usage_logs WHERE http_status >= 400 "
                "GROUP BY endpoint ORDER BY error_events DESC"
            ),
            "max_rows": 15,
        },
        description="HTTP 4xx/5xx anomaly breakdown across quantitative API endpoints",
    ),
    SimulatedAgentCall(
        rpc_id=112,
        agent_persona="Rogue-Prompt-Inj",
        tool_name="execute_readonly_query",
        arguments={
            "sql": "-- benign header\nDELETE FROM api_usage_logs WHERE http_status >= 500",
            "max_rows": 10,
        },
        description="[ATTACK #4] Line-comment obfuscated DELETE audit log tampering attempt",
    ),
    SimulatedAgentCall(
        rpc_id=113,
        agent_persona="Cursor-Agent",
        tool_name="execute_readonly_query",
        arguments={
            "sql": (
                "WITH client_spend AS ("
                "  SELECT client_id, SUM(compute_cost_usd) AS api_spend, SUM(tokens_consumed) AS tokens "
                "  FROM api_usage_logs GROUP BY client_id"
                ") "
                "SELECT c.client_id, c.organization_name, c.tier, c.mrr_usd, "
                "ROUND(s.api_spend, 4) AS total_api_spend, s.tokens "
                "FROM client_spend s JOIN institutional_clients c ON s.client_id = c.client_id "
                "ORDER BY s.api_spend DESC LIMIT 8"
            ),
            "max_rows": 8,
        },
        description="Multi-table CTE ranking highest LLM token & compute consumers against MRR",
    ),
    SimulatedAgentCall(
        rpc_id=114,
        agent_persona="OpenCode-Analyst",
        tool_name="execute_readonly_query",
        arguments={
            "sql": (
                "SELECT region, account_status, COUNT(*) AS accounts, "
                "ROUND(AVG(contract_arr_usd), 2) AS avg_arr_usd "
                "FROM institutional_clients GROUP BY region, account_status ORDER BY region, accounts DESC"
            ),
            "max_rows": 25,
        },
        description="Regional ARR distribution and account audit-hold / churn cohort analysis",
    ),
    SimulatedAgentCall(
        rpc_id=115,
        agent_persona="SecOps-Auditor",
        tool_name="get_server_telemetry",
        arguments={},
        description="Fetch cumulative server telemetry, average execution latency, and blocked audit log",
    ),
]


async def run_audit_simulation() -> None:
    """Seed the enterprise database, execute 15 simulated MCP calls, and print a Rich dashboard."""
    console = Console()

    if not DEFAULT_DB_PATH.exists():
        seed_database(DEFAULT_DB_PATH)
    else:
        # Ensure fresh deterministic state
        seed_database(DEFAULT_DB_PATH)

    await configure_server_db(DEFAULT_DB_PATH)

    console.print()
    console.print(
        Panel.fit(
            "[bold cyan]ENTERPRISE READ-ONLY SQL & TELEMETRY MCP SERVER (`mcp-sql-guard`)[/bold cyan]\n"
            "[white]Zero-Trust AST/Regex Validation  |  SQLite URI `?mode=ro`  |  Context Window Truncation  |  JSON-RPC 2.0 Audit[/white]",
            border_style="bright_blue",
            box=DOUBLE_EDGE,
            padding=(1, 4),
        )
    )

    audit_table = Table(
        title="[bold white]JSON-RPC 2.0 Agent Tool Execution Ledger (15 Simulated Calls)[/bold white]",
        box=ROUNDED,
        header_style="bold bright_cyan",
        show_lines=True,
        expand=True,
    )
    audit_table.add_column("RPC ID", justify="center", style="bold white", width=7, no_wrap=True)
    audit_table.add_column("Agent Persona", style="cyan", width=17, no_wrap=True)
    audit_table.add_column("MCP Tool", style="bright_yellow", width=23, no_wrap=True)
    audit_table.add_column("Description / SQL Payload Summary", style="white", ratio=1)
    audit_table.add_column("Rows", justify="right", width=7, no_wrap=True)
    audit_table.add_column("Trunc", justify="center", width=6, no_wrap=True)
    audit_table.add_column("Latency", justify="right", width=9, no_wrap=True)
    audit_table.add_column("Security Gate", justify="center", width=13, no_wrap=True)

    sample_jsonrpc_traces: list[dict[str, Any]] = []

    for call in SIMULATED_CALLS:
        jsonrpc_request = {
            "jsonrpc": "2.0",
            "id": call.rpc_id,
            "method": "tools/call",
            "params": {
                "name": call.tool_name,
                "arguments": call.arguments,
            },
        }

        t0 = time.perf_counter()
        if call.tool_name == "inspect_schema":
            result_payload = await inspect_schema()
            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            row_count_str = f"{len(result_payload)} tbls"
            trunc_str = "[dim]NO[/dim]"
            sec_badge = Text("PASSED (RO)", style="bold green")
        elif call.tool_name == "get_server_telemetry":
            result_payload = await get_server_telemetry()
            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            row_count_str = "STATS"
            trunc_str = "[dim]NO[/dim]"
            sec_badge = Text("PASSED (RO)", style="bold green")
        else:
            result_payload = await execute_readonly_query(
                sql=call.arguments["sql"],
                max_rows=call.arguments.get("max_rows", 50),
            )
            meta = result_payload["metadata"]
            elapsed_ms = meta["execution_time_ms"]
            row_count_str = str(meta["row_count"])
            trunc_str = (
                "[bold yellow]YES[/bold yellow]"
                if meta["truncated"]
                else "[dim]NO[/dim]"
            )
            if meta["security_status"] == "PASSED":
                sec_badge = Text("PASSED", style="bold green")
            else:
                sec_badge = Text("BLOCKED", style="bold white on red")

        jsonrpc_response = {
            "jsonrpc": "2.0",
            "id": call.rpc_id,
            "result": result_payload,
        }

        if call.rpc_id in (102, 104, 106, 108):
            sample_jsonrpc_traces.append(
                {
                    "request": jsonrpc_request,
                    "response": jsonrpc_response,
                }
            )

        desc_text = call.description
        if "sql" in call.arguments:
            sql_snippet = call.arguments["sql"]
            if len(sql_snippet) > 88:
                sql_snippet = sql_snippet[:85] + "..."
            desc_text = f"[bold]{call.description}[/bold]\n[dim]{sql_snippet}[/dim]"
            if isinstance(result_payload, dict) and result_payload.get("error"):
                desc_text += f"\n[bold red]-> {result_payload['error']}[/bold red]"

        audit_table.add_row(
            f"#{call.rpc_id}",
            call.agent_persona,
            call.tool_name,
            desc_text,
            row_count_str,
            trunc_str,
            f"{elapsed_ms:.2f} ms",
            sec_badge,
        )

    console.print(audit_table)
    console.print()

    # Print sample JSON-RPC Request/Response Payloads
    console.print(
        Panel(
            "[bold bright_yellow]Sample JSON-RPC 2.0 Wire Payloads (Valid Analytical Query vs. Blocked SQL Injection)[/bold bright_yellow]",
            border_style="yellow",
        )
    )
    for trace in sample_jsonrpc_traces[:3]:
        req_id = trace["request"]["id"]
        resp_copy = json.loads(json.dumps(trace["response"]))
        if (
            isinstance(resp_copy.get("result"), dict)
            and "rows" in resp_copy["result"]
            and len(resp_copy["result"]["rows"]) > 2
        ):
            resp_copy["result"]["rows"] = resp_copy["result"]["rows"][:2] + [
                {"_note": "... remaining rows omitted in CLI preview ..."}
            ]
        formatted_json = json.dumps(
            {"request": trace["request"], "response": resp_copy},
            indent=2,
        )
        console.print(
            Panel(
                formatted_json,
                title=f"[bold cyan]JSON-RPC Trace #{req_id}[/bold cyan]",
                border_style="cyan"
                if trace["response"]["result"]["metadata"]["security_status"] == "PASSED"
                else "red",
            )
        )

    # Final Server Telemetry Summary Panel
    final_telemetry = await get_server_telemetry()
    summary_table = Table(
        title="[bold bright_green]Cumulative MCP Server Telemetry Snapshot[/bold bright_green]",
        box=ROUNDED,
        header_style="bold green",
    )
    summary_table.add_column("Metric", style="bold white")
    summary_table.add_column("Value", justify="right", style="bright_cyan")

    summary_table.add_row("MCP Server Instance", str(final_telemetry["server_name"]))
    summary_table.add_row("SQLite URI Enforcement Mode", f"?mode={final_telemetry['database_uri_mode']} + PRAGMA query_only=ON")
    summary_table.add_row("Total Queries Evaluated", str(final_telemetry["total_queries_executed"]))
    summary_table.add_row("Successful Read-Only Queries", f"[green]{final_telemetry['successful_queries']}[/green]")
    summary_table.add_row("Blocked Mutation / Injection Attempts", f"[bold red]{final_telemetry['blocked_attempts']}[/bold red]")
    summary_table.add_row("Context-Window Truncated Responses", f"[yellow]{final_telemetry['truncated_responses']}[/yellow]")
    summary_table.add_row("Total Rows Streamed to Agents", str(final_telemetry["total_rows_returned"]))
    summary_table.add_row("Average Query Execution Latency", f"{final_telemetry['average_execution_latency_ms']:.3f} ms")

    console.print(summary_table)
    console.print()


if __name__ == "__main__":
    asyncio.run(run_audit_simulation())
