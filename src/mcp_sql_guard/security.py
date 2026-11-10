"""Zero-Trust SQL security validator enforcing read-only execution and anti-injection."""

from __future__ import annotations

import hashlib
import re
from typing import Final


class SecurityViolationError(Exception):
    """Raised when a SQL statement violates read-only or anti-injection constraints."""

    def __init__(self, reason: str, sql_hash: str = "") -> None:
        super().__init__(reason)
        self.reason: str = reason
        self.sql_hash: str = sql_hash


class SQLSecurityGuard:
    """Deterministic AST/Regex SQL validator preventing mutations and stacked injections."""

    _FORBIDDEN_KEYWORDS_PATTERN: Final[re.Pattern[str]] = re.compile(
        r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|REPLACE|TRUNCATE|ATTACH|DETACH|PRAGMA|VACUUM|REINDEX|SAVEPOINT|RELEASE|ROLLBACK|BEGIN|COMMIT|LOAD_EXTENSION)\b",
        re.IGNORECASE,
    )

    _ALLOWED_PREFIX_PATTERN: Final[re.Pattern[str]] = re.compile(
        r"^(SELECT\b|WITH\b|EXPLAIN\s+QUERY\s+PLAN\b)",
        re.IGNORECASE,
    )

    _BLOCK_COMMENT_PATTERN: Final[re.Pattern[str]] = re.compile(
        r"/\*[\s\S]*?\*/",
        re.MULTILINE,
    )

    _LINE_COMMENT_PATTERN: Final[re.Pattern[str]] = re.compile(
        r"--[^\r\n]*",
    )

    _STRING_LITERAL_PATTERN: Final[re.Pattern[str]] = re.compile(
        r"'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"",
    )

    @classmethod
    def compute_query_hash(cls, sql: str) -> str:
        """Compute a deterministic 16-character SHA-256 fingerprint of a SQL string."""
        normalized = " ".join(sql.strip().split()).upper()
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]

    @classmethod
    def _strip_comments_and_mask_strings(cls, sql: str) -> tuple[str, str]:
        """Strip SQL comments (`--` and `/* */`) while preserving string literals.

        Returns:
            A tuple of `(cleaned_sql, masked_sql)` where `cleaned_sql` has comments
            removed (preserving string literals) and `masked_sql` additionally replaces
            string literal contents with placeholders for structural token analysis.
        """
        if "/*" in sql:
            # Check for unclosed block comments used to obfuscate payloads
            open_count = sql.count("/*")
            close_count = sql.count("*/")
            if open_count > close_count:
                raise SecurityViolationError(
                    "SECURITY_BLOCK: Unclosed block comment '/*' detected (comment obfuscation attempt).",
                    sql_hash=cls.compute_query_hash(sql),
                )

        # Tokenize string literals and comments in a single pass so comments inside strings
        # are preserved and comments outside strings are stripped.
        token_pattern = re.compile(
            r"('(?:''|[^'])*'|\"(?:\"\"|[^\"])*\")|(/\*[\s\S]*?\*/)|(--[^\r\n]*)",
            re.MULTILINE,
        )

        cleaned_parts: list[str] = []
        masked_parts: list[str] = []
        last_idx = 0

        for match in token_pattern.finditer(sql):
            start, end = match.span()
            if start > last_idx:
                segment = sql[last_idx:start]
                cleaned_parts.append(segment)
                masked_parts.append(segment)

            string_lit, block_comment, line_comment = match.groups()
            if string_lit is not None:
                cleaned_parts.append(string_lit)
                masked_parts.append("'__STR__'")
            elif block_comment is not None or line_comment is not None:
                # Replace comments with a single space to prevent token concatenation bypass
                # e.g., DR/**/OP -> DR OP (or SE/**/LECT)
                cleaned_parts.append(" ")
                masked_parts.append(" ")

            last_idx = end

        if last_idx < len(sql):
            tail = sql[last_idx:]
            cleaned_parts.append(tail)
            masked_parts.append(tail)

        cleaned_sql = "".join(cleaned_parts).strip()
        masked_sql = "".join(masked_parts).strip()
        return cleaned_sql, masked_sql

    @classmethod
    def validate_select_only(cls, sql: str) -> str:
        """Validate that a SQL statement is strictly read-only and single-statement.

        Steps:
        1. Strip SQL comments (`--` and `/* */`).
        2. Reject multiple statements separated by `;` (prevent stacked query injection).
        3. Enforce that the normalized statement starts strictly with `SELECT`, `WITH`,
           or `EXPLAIN QUERY PLAN`.
        4. Reject forbidden tokens via word-boundary regex:
           `\\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|REPLACE|TRUNCATE|ATTACH|DETACH|PRAGMA|VACUUM)\\b`.
        5. Raise `SecurityViolationError` with an explicit audit reason if any check fails.

        Args:
            sql: Raw SQL query string provided by the caller/agent.

        Returns:
            Normalized, comment-stripped single SQL statement ready for execution.

        Raises:
            SecurityViolationError: If the statement violates any security constraint.
        """
        query_hash = cls.compute_query_hash(sql or "")
        if not sql or not sql.strip():
            raise SecurityViolationError(
                "SECURITY_BLOCK: Empty or whitespace-only SQL statement.",
                sql_hash=query_hash,
            )

        cleaned_sql, masked_sql = cls._strip_comments_and_mask_strings(sql)
        if not cleaned_sql:
            raise SecurityViolationError(
                "SECURITY_BLOCK: SQL statement contains only comments (comment-only payload rejected).",
                sql_hash=query_hash,
            )

        # Allow at most one trailing semicolon; strip it before checking for stacked semicolons
        while cleaned_sql.endswith(";"):
            cleaned_sql = cleaned_sql[:-1].rstrip()
        while masked_sql.endswith(";"):
            masked_sql = masked_sql[:-1].rstrip()

        if not cleaned_sql:
            raise SecurityViolationError(
                "SECURITY_BLOCK: Empty SQL statement after stripping trailing semicolon.",
                sql_hash=query_hash,
            )

        # 2. Reject multiple statements separated by `;`
        if ";" in masked_sql:
            raise SecurityViolationError(
                "SECURITY_BLOCK: Stacked SQL statements separated by ';' are strictly forbidden (SQL injection mitigation).",
                sql_hash=query_hash,
            )

        # Normalize internal whitespace for prefix and keyword checks
        normalized_masked = " ".join(masked_sql.split())
        normalized_cleaned = " ".join(cleaned_sql.split())

        # 4. Reject forbidden tokens via word-boundary regex (checked on both masked and raw to catch any keyword)
        forbidden_match = cls._FORBIDDEN_KEYWORDS_PATTERN.search(normalized_masked)
        if forbidden_match is None:
            # Also check cleaned_sql in case an attacker embedded forbidden keywords
            forbidden_match = cls._FORBIDDEN_KEYWORDS_PATTERN.search(normalized_cleaned)

        if forbidden_match is not None:
            keyword = forbidden_match.group(1).upper()
            raise SecurityViolationError(
                f"SECURITY_BLOCK: Forbidden mutating or administrative keyword '{keyword}' detected.",
                sql_hash=query_hash,
            )

        # 3. Enforce that the normalized statement starts strictly with SELECT, WITH, or EXPLAIN QUERY PLAN
        if not cls._ALLOWED_PREFIX_PATTERN.match(normalized_masked):
            first_token = normalized_masked.split(" ", 1)[0].upper()
            raise SecurityViolationError(
                f"SECURITY_BLOCK: Statement must begin with SELECT, WITH, or EXPLAIN QUERY PLAN (got '{first_token}').",
                sql_hash=query_hash,
            )

        # If it starts with WITH (CTE), ensure a SELECT is present in the statement
        if normalized_masked.upper().startswith("WITH") and not re.search(
            r"\bSELECT\b", normalized_masked, re.IGNORECASE
        ):
            raise SecurityViolationError(
                "SECURITY_BLOCK: WITH (CTE) clause must resolve to a SELECT query.",
                sql_hash=query_hash,
            )

        return normalized_cleaned

