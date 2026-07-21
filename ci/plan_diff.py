#!/usr/bin/env python3
"""
ci/plan_diff.py — compare a query's EXPLAIN plan cost between two git refs
(typically a PR's base and head) against the SAME live database, and flag
a regression if the planner's Total Cost went up by more than a threshold.

This diffs the *query text* across git history, not the schema — it
answers "did this PR's edit to this query make the planner think it's
more expensive?". Both versions run with EXPLAIN (FORMAT JSON) only,
never ANALYZE: this is meant to run unattended on every pull request
against a shared staging database, so it must never execute PR-authored
SQL — only ask the planner to cost it.

Requires: psycopg (v3) - `pip install "psycopg[binary]"` - and to be run
from inside a git checkout where both refs are reachable (a full/unshallow
clone, or at least `git fetch` of the base ref).

Standalone usage:
    plan_diff.py queries/top_customers.sql --base origin/main --head HEAD --conn "$DATABASE_URL"
    plan_diff.py a.sql b.sql --base origin/main --head HEAD --json
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import subprocess
import sys
from typing import Optional

try:
    import psycopg
except ImportError:
    psycopg = None


DEFAULT_TIMEOUT_MS = 30_000
DEFAULT_THRESHOLD_PCT = 20.0


class PlanDiffError(RuntimeError):
    pass


@dataclasses.dataclass
class DiffResult:
    file: str
    base_ref: str
    head_ref: str
    base_cost: Optional[float] = None
    head_cost: Optional[float] = None
    delta_pct: Optional[float] = None
    is_regression: bool = False
    note: Optional[str] = None
    error: Optional[str] = None


def _git_show(ref: str, path: str) -> Optional[str]:
    """Return the file's content at `ref`, or None if it doesn't exist
    there (new file, or a typo'd path)."""
    proc = subprocess.run(
        ["git", "show", f"{ref}:{path}"],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return None
    return proc.stdout


def _explain_total_cost(conninfo: str, sql: str, timeout_ms: int) -> float:
    """Planner-estimated Total Cost for `sql`, via EXPLAIN (FORMAT JSON)
    only — never ANALYZE, so this never executes the query. Always rolls
    back; nothing here can persist a change even by accident."""
    if psycopg is None:
        raise PlanDiffError('psycopg is not installed. Run: pip install "psycopg[binary]"')

    try:
        timeout_ms = int(timeout_ms)
    except (TypeError, ValueError) as exc:
        raise PlanDiffError(f"timeout_ms must be an integer, got {timeout_ms!r}") from exc

    with psycopg.connect(conninfo, autocommit=False) as conn:
        try:
            with conn.cursor() as cur:
                # statement_timeout is a GUC set via a utility statement, not a
                # bindable parameter; timeout_ms is validated as a plain int
                # above, so this f-string carries no injection risk.
                cur.execute(f"SET LOCAL statement_timeout = {timeout_ms}")
                cur.execute(f"EXPLAIN (FORMAT JSON) {sql}")
                row = cur.fetchone()
                if row is None:
                    raise PlanDiffError("EXPLAIN returned no rows")
                raw = row[0]
        finally:
            conn.rollback()

    plan = json.loads(raw) if isinstance(raw, str) else raw
    top = plan[0] if isinstance(plan, list) else plan
    return top["Plan"].get("Total Cost", 0.0)


def diff_file(conninfo: str, path: str, base_ref: str, head_ref: str, timeout_ms: int, threshold_pct: float) -> DiffResult:
    result = DiffResult(file=path, base_ref=base_ref, head_ref=head_ref)

    head_sql = _git_show(head_ref, path)
    if head_sql is None:
        result.error = f"{path} not found at {head_ref}"
        return result

    base_sql = _git_show(base_ref, path)
    if base_sql is None:
        result.note = f"new file, no baseline at {base_ref}"
        try:
            result.head_cost = _explain_total_cost(conninfo, head_sql, timeout_ms)
        except Exception as exc:
            result.error = f"EXPLAIN failed at {head_ref}: {exc}"
        return result

    try:
        result.base_cost = _explain_total_cost(conninfo, base_sql, timeout_ms)
    except Exception as exc:
        result.error = f"EXPLAIN failed at {base_ref}: {exc}"
        return result

    try:
        result.head_cost = _explain_total_cost(conninfo, head_sql, timeout_ms)
    except Exception as exc:
        result.error = f"EXPLAIN failed at {head_ref}: {exc}"
        return result

    if result.base_cost and result.base_cost > 0:
        result.delta_pct = round((result.head_cost - result.base_cost) / result.base_cost * 100, 1)
        result.is_regression = result.delta_pct > threshold_pct
    return result


def _print_human(results: list, threshold_pct: float) -> None:
    for r in results:
        print(f"== {r.file} ({r.base_ref} -> {r.head_ref}) ==")
        if r.error:
            print(f"  ERROR: {r.error}")
        elif r.note:
            cost = f"{r.head_cost:.2f}" if r.head_cost is not None else "n/a"
            print(f"  {r.note} (head cost: {cost})")
        else:
            flag = "  <-- REGRESSION" if r.is_regression else ""
            print(f"  base cost {r.base_cost:.2f} -> head cost {r.head_cost:.2f}  ({r.delta_pct:+.1f}%){flag}")
        print()

    regressions = [r for r in results if r.is_regression]
    if regressions:
        plural = "y" if len(regressions) == 1 else "ies"
        print(f"{len(regressions)} quer{plural} regressed by more than {threshold_pct:.0f}% total cost.")
    else:
        print(f"No regressions above the {threshold_pct:.0f}% threshold.")


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="plan_diff.py",
        description=(
            "Compare EXPLAIN plan cost for one or more queries between two git "
            "refs against the same live database, and flag a regression if "
            "planner cost increased by more than a threshold."
        ),
        epilog=(
            "Examples:\n"
            "  plan_diff.py queries/top_customers.sql --base origin/main --head HEAD --conn \"$DATABASE_URL\"\n"
            "  plan_diff.py a.sql b.sql --base origin/main --head HEAD --json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("files", nargs="+", help="query .sql file path(s), relative to the git repo root")
    parser.add_argument("--base", required=True, help="base git ref (e.g. origin/main, or a commit SHA)")
    parser.add_argument("--head", required=True, help="head git ref (e.g. HEAD, or a commit SHA)")
    parser.add_argument("--conn", metavar="DSN", help="Postgres connection string. Falls back to DATABASE_URL.")
    parser.add_argument(
        "--threshold-pct", type=float, default=DEFAULT_THRESHOLD_PCT,
        help=f"flag as a regression if head cost exceeds base cost by more than this percent (default: {DEFAULT_THRESHOLD_PCT})",
    )
    parser.add_argument("--timeout-ms", type=int, default=DEFAULT_TIMEOUT_MS, help=f"statement_timeout in milliseconds (default: {DEFAULT_TIMEOUT_MS})")
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON instead of a human-readable summary")
    args = parser.parse_args()

    conninfo = args.conn or os.environ.get("DATABASE_URL")
    if not conninfo:
        print("plan_diff: no connection string: pass --conn or set the DATABASE_URL environment variable", file=sys.stderr)
        return 2

    results = [
        diff_file(conninfo, f, args.base, args.head, args.timeout_ms, args.threshold_pct)
        for f in args.files
    ]

    if args.json:
        print(json.dumps([dataclasses.asdict(r) for r in results], indent=2))
    else:
        _print_human(results, args.threshold_pct)

    if any(r.is_regression for r in results):
        return 1
    if any(r.error for r in results):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
