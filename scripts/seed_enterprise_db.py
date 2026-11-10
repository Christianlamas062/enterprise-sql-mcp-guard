"""Seed script for generating a deterministic B2B SaaS / Quantitative SQLite database (`enterprise_analytics.db`)."""

from __future__ import annotations

import hashlib
import random
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEFAULT_DB_PATH: Path = (
    Path(__file__).resolve().parents[1] / "enterprise_analytics.db"
)


def _deterministic_hash(seed_str: str) -> str:
    """Return a short deterministic hex digest for invoice and request IDs."""
    return hashlib.sha256(seed_str.encode("utf-8")).hexdigest()[:12].upper()


def seed_database(db_path: str | Path = DEFAULT_DB_PATH) -> dict[str, int]:
    """Create and populate `enterprise_analytics.db` with 1,800+ deterministic rows across 3 tables.

    Tables created:
    1. `institutional_clients` (120 rows)
    2. `api_usage_logs` (1,200 rows)
    3. `billing_ledgers` (480 rows)
    """
    target_path = Path(db_path).resolve()
    target_path.parent.mkdir(parents=True, exist_ok=True)
    if target_path.exists():
        target_path.unlink()

    rng = random.Random(42069)
    base_time = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    conn = sqlite3.connect(str(target_path))
    try:
        cur = conn.cursor()
        cur.executescript(
            """
            PRAGMA journal_mode = DELETE;
            PRAGMA foreign_keys = ON;

            CREATE TABLE institutional_clients (
                client_id TEXT PRIMARY KEY,
                organization_name TEXT NOT NULL,
                tier TEXT NOT NULL CHECK(tier IN ('ENTERPRISE_QUANT', 'INSTITUTIONAL_PRIME', 'GROWTH_CORP', 'SOVEREIGN_DESK')),
                region TEXT NOT NULL CHECK(region IN ('US-EAST', 'EU-CENTRAL', 'AP-NORTHEAST', 'UK-LON')),
                mrr_usd REAL NOT NULL,
                contract_arr_usd REAL NOT NULL,
                risk_score REAL NOT NULL,
                account_status TEXT NOT NULL CHECK(account_status IN ('ACTIVE', 'AUDIT_HOLD', 'CHURNED')),
                onboarded_at TEXT NOT NULL
            );

            CREATE INDEX idx_clients_tier_region ON institutional_clients(tier, region);
            CREATE INDEX idx_clients_status ON institutional_clients(account_status);

            CREATE TABLE api_usage_logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL UNIQUE,
                client_id TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                http_status INTEGER NOT NULL,
                latency_ms REAL NOT NULL,
                tokens_consumed INTEGER NOT NULL,
                compute_cost_usd REAL NOT NULL,
                recorded_at TEXT NOT NULL,
                FOREIGN KEY (client_id) REFERENCES institutional_clients(client_id)
            );

            CREATE INDEX idx_usage_client_time ON api_usage_logs(client_id, recorded_at);
            CREATE INDEX idx_usage_endpoint ON api_usage_logs(endpoint);

            CREATE TABLE billing_ledgers (
                invoice_id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                billing_period TEXT NOT NULL,
                subtotal_usd REAL NOT NULL,
                tax_usd REAL NOT NULL,
                total_usd REAL NOT NULL,
                payment_status TEXT NOT NULL CHECK(payment_status IN ('SETTLED', 'PENDING_WIRE', 'OVERDUE', 'DISPUTED')),
                settled_at TEXT,
                ledger_hash TEXT NOT NULL,
                FOREIGN KEY (client_id) REFERENCES institutional_clients(client_id)
            );

            CREATE INDEX idx_billing_client_period ON billing_ledgers(client_id, billing_period);
            CREATE INDEX idx_billing_status ON billing_ledgers(payment_status);
            """
        )

        # 1. Populate institutional_clients (120 rows)
        prefixes = [
            "Citadel", "Vanguard", "BlackRock", "Renaissance", "TwoSigma",
            "Bridgewater", "Millennium", "Point72", "JaneStreet", "AQR",
            "Apollo", "KKR", "Carlyle", "Brookfield", "Fidelity",
            "StateStreet", "Schroders", "Nomura", "Macquarie", "UBS",
        ]
        suffixes = [
            "Alpha Desk", "Quant Strategies", "Global Macro", "Fixed Income",
            "Systematic Equities", "Treasury Ops", "Digital Assets", "Risk Analytics",
        ]
        tiers = ["ENTERPRISE_QUANT", "INSTITUTIONAL_PRIME", "GROWTH_CORP", "SOVEREIGN_DESK"]
        regions = ["US-EAST", "EU-CENTRAL", "AP-NORTHEAST", "UK-LON"]
        statuses = ["ACTIVE", "ACTIVE", "ACTIVE", "ACTIVE", "AUDIT_HOLD", "CHURNED"]

        clients_data: list[tuple[str, str, str, str, float, float, float, str, str]] = []
        client_ids: list[str] = []

        for idx in range(1, 121):
            c_id = f"CLI-{idx:04d}"
            client_ids.append(c_id)
            org_name = f"{prefixes[idx % len(prefixes)]} {suffixes[idx % len(suffixes)]} #{idx:03d}"
            tier = tiers[idx % len(tiers)]
            region = regions[(idx * 3) % len(regions)]

            base_mrr = {
                "SOVEREIGN_DESK": 48000.0,
                "ENTERPRISE_QUANT": 32000.0,
                "INSTITUTIONAL_PRIME": 18500.0,
                "GROWTH_CORP": 6500.0,
            }[tier]
            mrr = round(base_mrr + rng.uniform(-1500.0, 4500.0), 2)
            arr = round(mrr * 12.0, 2)
            risk_score = round(rng.uniform(5.0, 92.5), 2)
            status = statuses[idx % len(statuses)]
            onboard_dt = (base_time - timedelta(days=rng.randint(30, 720))).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            clients_data.append(
                (c_id, org_name, tier, region, mrr, arr, risk_score, status, onboard_dt)
            )

        cur.executemany(
            """
            INSERT INTO institutional_clients (
                client_id, organization_name, tier, region,
                mrr_usd, contract_arr_usd, risk_score, account_status, onboarded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            clients_data,
        )

        # 2. Populate api_usage_logs (1,200 rows)
        endpoints = [
            "/v2/quant/orderbook-snapshot",
            "/v2/quant/volatility-surface",
            "/v2/risk/var-monte-carlo",
            "/v2/llm/alpha-sentiment-rag",
            "/v2/execution/smart-router-quote",
            "/v2/compliance/aml-screen",
        ]
        http_codes = [200, 200, 200, 200, 200, 200, 201, 429, 500, 503]

        usage_data: list[tuple[str, str, str, int, float, int, float, str]] = []
        for log_idx in range(1, 1201):
            req_id = f"REQ-{_deterministic_hash(f'log-{log_idx}')}"
            c_id = client_ids[rng.randint(0, len(client_ids) - 1)]
            endpoint = endpoints[log_idx % len(endpoints)]
            status_code = http_codes[rng.randint(0, len(http_codes) - 1)]
            latency = round(rng.uniform(4.2, 340.8), 3)
            tokens = rng.randint(120, 16384)
            cost_usd = round(tokens * 0.000015, 6)
            rec_dt = (
                base_time + timedelta(minutes=log_idx * 12, seconds=rng.randint(0, 59))
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            usage_data.append(
                (req_id, c_id, endpoint, status_code, latency, tokens, cost_usd, rec_dt)
            )

        cur.executemany(
            """
            INSERT INTO api_usage_logs (
                request_id, client_id, endpoint, http_status,
                latency_ms, tokens_consumed, compute_cost_usd, recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            usage_data,
        )

        # 3. Populate billing_ledgers (480 rows: 4 quarters x 120 clients)
        periods = ["2026-Q1", "2026-Q2", "2026-Q3", "2026-Q4"]
        pay_statuses = ["SETTLED", "SETTLED", "SETTLED", "PENDING_WIRE", "OVERDUE", "DISPUTED"]

        billing_data: list[tuple[str, str, str, float, float, float, str, str | None, str]] = []
        inv_counter = 1
        for c_id, _, _, _, mrr, _, _, _, _ in clients_data:
            for period in periods:
                inv_id = f"INV-2026-{inv_counter:05d}"
                inv_counter += 1
                subtotal = round(mrr * 3.0 + rng.uniform(0.0, 2500.0), 2)
                tax = round(subtotal * 0.0825, 2)
                total = round(subtotal + tax, 2)
                p_status = pay_statuses[(inv_counter + rng.randint(0, 5)) % len(pay_statuses)]
                settled_at = (
                    (base_time + timedelta(days=rng.randint(15, 300))).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    )
                    if p_status == "SETTLED"
                    else None
                )
                l_hash = _deterministic_hash(f"{inv_id}:{c_id}:{total}:{period}")
                billing_data.append(
                    (inv_id, c_id, period, subtotal, tax, total, p_status, settled_at, l_hash)
                )

        cur.executemany(
            """
            INSERT INTO billing_ledgers (
                invoice_id, client_id, billing_period, subtotal_usd,
                tax_usd, total_usd, payment_status, settled_at, ledger_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            billing_data,
        )

        conn.commit()
    finally:
        conn.close()

    counts = {
        "institutional_clients": len(clients_data),
        "api_usage_logs": len(usage_data),
        "billing_ledgers": len(billing_data),
        "total_rows": len(clients_data) + len(usage_data) + len(billing_data),
    }
    return counts


if __name__ == "__main__":
    summary = seed_database()
    print(
        f"[SEED COMPLETE] Database generated at {DEFAULT_DB_PATH}\n"
        f"  - institutional_clients: {summary['institutional_clients']} rows\n"
        f"  - api_usage_logs:        {summary['api_usage_logs']} rows\n"
        f"  - billing_ledgers:       {summary['billing_ledgers']} rows\n"
        f"  - TOTAL DETERMINISTIC ROWS: {summary['total_rows']}"
    )

