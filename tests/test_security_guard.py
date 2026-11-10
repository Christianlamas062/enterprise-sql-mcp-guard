"""Unit tests for `SQLSecurityGuard` zero-trust AST/Regex validation layer."""

from __future__ import annotations

import pytest

from mcp_sql_guard.security import SecurityViolationError, SQLSecurityGuard


class TestSQLSecurityGuardValidQueries:
    """Verify valid read-only queries pass normalization and comment stripping."""

    def test_valid_simple_select_with_trailing_semicolon(self) -> None:
        sql = "  SELECT client_id, mrr_usd FROM institutional_clients WHERE account_status = 'ACTIVE';  "
        cleaned = SQLSecurityGuard.validate_select_only(sql)
        assert cleaned == "SELECT client_id, mrr_usd FROM institutional_clients WHERE account_status = 'ACTIVE'"

    def test_valid_with_cte_aggregation(self) -> None:
        sql = """
        WITH regional_mrr AS (
            SELECT region, SUM(mrr_usd) AS total_mrr
            FROM institutional_clients
            GROUP BY region
        )
        SELECT * FROM regional_mrr ORDER BY total_mrr DESC;
        """
        cleaned = SQLSecurityGuard.validate_select_only(sql)
        assert cleaned.startswith("WITH regional_mrr AS")
        assert "SELECT * FROM regional_mrr" in cleaned

    def test_valid_explain_query_plan(self) -> None:
        sql = "EXPLAIN QUERY PLAN SELECT * FROM api_usage_logs WHERE client_id = 'CLI-0001'"
        cleaned = SQLSecurityGuard.validate_select_only(sql)
        assert cleaned.startswith("EXPLAIN QUERY PLAN SELECT")

    def test_valid_select_strips_inline_and_block_comments(self) -> None:
        sql = """
        /* Header audit comment */
        SELECT client_id, -- inline comment
               organization_name
        FROM institutional_clients /* trailing block comment */
        """
        cleaned = SQLSecurityGuard.validate_select_only(sql)
        assert "/*" not in cleaned
        assert "--" not in cleaned
        assert cleaned == "SELECT client_id, organization_name FROM institutional_clients"

    def test_semicolon_inside_string_literal_is_allowed(self) -> None:
        sql = "SELECT client_id FROM institutional_clients WHERE organization_name = 'Alpha;Beta Corp'"
        cleaned = SQLSecurityGuard.validate_select_only(sql)
        assert "'Alpha;Beta Corp'" in cleaned


class TestSQLSecurityGuardBlockedViolations:
    """Verify mutating keywords, stacked injections, and comment obfuscation are deterministically blocked."""

    @pytest.mark.parametrize(
        ("malicious_sql", "expected_keyword"),
        [
            ("DROP TABLE institutional_clients", "DROP"),
            ("DELETE FROM billing_ledgers WHERE payment_status = 'OVERDUE'", "DELETE"),
            ("UPDATE institutional_clients SET mrr_usd = 0 WHERE client_id = 'CLI-0001'", "UPDATE"),
            ("INSERT INTO institutional_clients VALUES ('CLI-9999', 'Evil', 'GROWTH_CORP', 'US-EAST', 1, 12, 0, 'ACTIVE', '2026-01-01')", "INSERT"),
            ("ALTER TABLE institutional_clients ADD COLUMN backdoor TEXT", "ALTER"),
            ("TRUNCATE TABLE api_usage_logs", "TRUNCATE"),
            ("CREATE TABLE pwned (id INT)", "CREATE"),
            ("REPLACE INTO institutional_clients VALUES ('CLI-0001', 'X', 'GROWTH_CORP', 'US-EAST', 1, 12, 0, 'ACTIVE', '2026-01-01')", "REPLACE"),
            ("ATTACH DATABASE 'evil.db' AS evil", "ATTACH"),
            ("DETACH DATABASE evil", "DETACH"),
            ("PRAGMA writable_schema = ON", "PRAGMA"),
            ("VACUUM", "VACUUM"),
        ],
    )
    def test_blocked_mutating_keywords(self, malicious_sql: str, expected_keyword: str) -> None:
        with pytest.raises(SecurityViolationError) as exc_info:
            SQLSecurityGuard.validate_select_only(malicious_sql)
        assert expected_keyword in exc_info.value.reason
        assert len(exc_info.value.sql_hash) == 16

    def test_blocked_stacked_query_injection(self) -> None:
        stacked_sql = "SELECT * FROM institutional_clients; DROP TABLE institutional_clients;"
        with pytest.raises(SecurityViolationError) as exc_info:
            SQLSecurityGuard.validate_select_only(stacked_sql)
        assert "Stacked SQL statements separated by ';'" in exc_info.value.reason

    def test_blocked_stacked_select_statements(self) -> None:
        stacked_selects = "SELECT 1; SELECT 2"
        with pytest.raises(SecurityViolationError) as exc_info:
            SQLSecurityGuard.validate_select_only(stacked_selects)
        assert "Stacked SQL statements" in exc_info.value.reason

    def test_blocked_comment_obfuscated_mutation(self) -> None:
        obfuscated = "/* harmless comment */\n-- another comment\nDELETE /* inline */ FROM api_usage_logs"
        with pytest.raises(SecurityViolationError) as exc_info:
            SQLSecurityGuard.validate_select_only(obfuscated)
        assert "DELETE" in exc_info.value.reason

    def test_blocked_unclosed_block_comment_obfuscation(self) -> None:
        unclosed = "SELECT * FROM institutional_clients /* unclosed comment DROP TABLE"
        with pytest.raises(SecurityViolationError) as exc_info:
            SQLSecurityGuard.validate_select_only(unclosed)
        assert "Unclosed block comment" in exc_info.value.reason

    def test_blocked_token_splitting_via_block_comment(self) -> None:
        split_keyword = "DR/**/OP TABLE institutional_clients"
        with pytest.raises(SecurityViolationError) as exc_info:
            SQLSecurityGuard.validate_select_only(split_keyword)
        assert "SECURITY_BLOCK" in exc_info.value.reason

    def test_blocked_cte_with_mutating_body(self) -> None:
        cte_delete = "WITH target AS (SELECT client_id FROM institutional_clients) DELETE FROM institutional_clients WHERE client_id IN (SELECT client_id FROM target)"
        with pytest.raises(SecurityViolationError) as exc_info:
            SQLSecurityGuard.validate_select_only(cte_delete)
        assert "DELETE" in exc_info.value.reason

    def test_blocked_empty_or_comment_only_query(self) -> None:
        with pytest.raises(SecurityViolationError):
            SQLSecurityGuard.validate_select_only("   ")
        with pytest.raises(SecurityViolationError):
            SQLSecurityGuard.validate_select_only("/* only a comment */ -- and line comment")

