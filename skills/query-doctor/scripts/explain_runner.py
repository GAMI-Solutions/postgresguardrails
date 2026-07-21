#!/usr/bin/env python3
"""
explain_runner.py — run EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) against a
real Postgres database and print the resulting plan as JSON.

Safety:
  - A hard statement_timeout (default 30s) is set with SET LOCAL inside a
    transaction, so a runaway query can't hang the session.
  - EXPLAIN ANALYZE actually *executes* the query, including any side
    effects of an UPDATE/DELETE/INSERT it contains. To make this safe by
    default, everything runs inside a transaction that is ALWAYS rolled
    back, never committed — regardless of query type or outcome. Nothing
    this script runs is ever persisted to the database.
  - The query text itself is embedded directly into the EXPLAIN statement
    (there is no way around this — EXPLAIN's argument is a full SQL
    statement, not a bindable value). This tool trusts the SQL you hand it
    the same way `psql -f query.sql` would; it does not accept untrusted
    input from anywhere else.

Requires: psycopg (v3) — `pip install "psycopg[binary]"`.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

try:
    import psycopg
except ImportError:  # reported clearly at call time, not at import time
    psycopg = None


DEFAULT_TIMEOUT_MS = 30_000


class ExplainError(RuntimeError):
    """Raised for usage/config errors, as opposed to psycopg/DB errors."""


def _read_sql(args: argparse.Namespace) -> str:
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                return f.read().strip()
        except OSError as exc:
            raise ExplainError(f"could not read {args.file}: {exc}") from exc
    if args.query:
        return args.query.strip()
    raise ExplainError("one of --file or --query is required")


def _resolve_conninfo(args: argparse.Namespace) -> str:
    conninfo = args.conn or os.environ.get("DATABASE_URL")
    if not conninfo:
        raise ExplainError(
            "no connection string: pass --conn, or set the DATABASE_URL environment variable"
        )
    return conninfo


def run_explain(conninfo: str, sql: str, analyze: bool = True, timeout_ms: int = DEFAULT_TIMEOUT_MS) -> dict:
    """Run EXPLAIN against `sql` and return
    {"sql": sql, "analyze": analyze, "plan": <raw Postgres EXPLAIN JSON>}.

    `plan` is exactly what Postgres returns for EXPLAIN (FORMAT JSON): a
    list containing one dict with a "Plan" key (plus "Planning Time" and,
    if analyze=True, "Execution Time").

    Always runs inside a transaction that is rolled back at the end, even
    on success — this function never commits anything. Importable and
    reused by index_advisor.py for its own EXPLAIN calls.
    """
    if psycopg is None:
        raise ExplainError('psycopg is not installed. Run: pip install "psycopg[binary]"')

    try:
        timeout_ms = int(timeout_ms)
    except (TypeError, ValueError) as exc:
        raise ExplainError(f"timeout_ms must be an integer, got {timeout_ms!r}") from exc
    if timeout_ms <= 0:
        raise ExplainError("timeout_ms must be positive")

    # BUFFERS requires ANALYZE on Postgres < 17, so only ask for it when we
    # are actually analyzing (keeps this working across PG 13-17).
    options = "ANALYZE, BUFFERS, FORMAT JSON" if analyze else "FORMAT JSON"
    explain_sql = f"EXPLAIN ({options}) {sql}"

    with psycopg.connect(conninfo, autocommit=False) as conn:
        try:
            with conn.cursor() as cur:
                # statement_timeout is a GUC set via a utility statement,
                # not a bindable query parameter. timeout_ms is validated
                # as a plain int above, so f-string interpolation here
                # carries no injection risk.
                cur.execute(f"SET LOCAL statement_timeout = {timeout_ms}")
                cur.execute(explain_sql)
                row = cur.fetchone()
                if row is None:
                    raise ExplainError("EXPLAIN returned no rows")
                raw = row[0]
        finally:
            conn.rollback()  # never persist anything EXPLAIN ANALYZE did

    plan = json.loads(raw) if isinstance(raw, str) else raw
    return {"sql": sql, "analyze": analyze, "plan": plan}


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="explain_runner.py",
        description=(
            "Run EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) against a real "
            "Postgres database, inside a transaction that is always rolled "
            "back, with a hard statement_timeout. Prints the plan as JSON."
        ),
        epilog=(
            "Examples:\n"
            "  explain_runner.py --conn \"$DATABASE_URL\" -q \"SELECT * FROM orders WHERE customer_id = 42\"\n"
            "  explain_runner.py --conn \"$DATABASE_URL\" -f slow_query.sql -o plan.json\n"
            "  explain_runner.py --conn \"$DATABASE_URL\" -f slow_query.sql --no-analyze   # planner estimates only, zero execution risk\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--conn", metavar="DSN",
        help="Postgres connection string / DSN. Falls back to the DATABASE_URL env var.",
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", "-f", metavar="PATH", help="path to a .sql file containing the query")
    src.add_argument("--query", "-q", metavar="SQL", help="the query itself, inline")
    parser.add_argument(
        "--no-analyze", action="store_true",
        help=(
            "run EXPLAIN without ANALYZE (planner estimates only — does not "
            "execute the query, so no actual timing/row/buffer data, but "
            "zero execution risk even for DML)"
        ),
    )
    parser.add_argument(
        "--timeout-ms", type=int, default=DEFAULT_TIMEOUT_MS,
        help=f"statement_timeout in milliseconds (default: {DEFAULT_TIMEOUT_MS})",
    )
    parser.add_argument(
        "--output", "-o", metavar="PATH",
        help="write the plan JSON to this file instead of stdout",
    )
    args = parser.parse_args()

    try:
        sql = _read_sql(args)
        conninfo = _resolve_conninfo(args)
        result = run_explain(conninfo, sql, analyze=not args.no_analyze, timeout_ms=args.timeout_ms)
    except ExplainError as exc:
        print(f"explain_runner: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # psycopg connection/execution errors, etc.
        print(f"explain_runner: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    text = json.dumps(result, indent=2, default=str)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
