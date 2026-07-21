#!/usr/bin/env python3
"""
index_advisor.py — propose candidate indexes for a slow query, and, if the
hypopg extension is installed in the target database, test each candidate
as a *hypothetical* index and report the before/after planner cost.

This never creates a real index. hypopg's hypothetical indexes cost zero
disk/CPU/lock to create, are only visible to the planner's cost estimator
in the current backend, and are never written to disk — but on top of
that, every hypopg session here still runs inside a transaction that is
always rolled back, as a second safety net.

Candidates are derived from the EXPLAIN plan tree itself (Filter, Index
Cond, Sort Key, Group Key, Hash Cond, Merge Cond) — not by parsing the raw
SQL — so join columns are picked up correctly and the columns Postgres
itself already identified as relevant are trusted directly.

Standalone usage:
    # from a saved explain_runner.py output file
    index_advisor.py --plan plan.json --conn "$DATABASE_URL"

    # or let it generate its own baseline (EXPLAIN without ANALYZE — never
    # executes the query, so this is safe even for DML)
    index_advisor.py --query "SELECT ..." --conn "$DATABASE_URL"

    # no DB access at all — just print candidates derived from a plan file
    index_advisor.py --plan plan.json --no-hypopg
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
import explain_runner  # noqa: E402

try:
    import psycopg
except ImportError:
    psycopg = None


MAX_INDEX_COLUMNS = 3  # cap composite index proposals at this many columns

_SQL_KEYWORDS = {
    "AND", "OR", "NOT", "NULL", "IS", "ANY", "ALL", "TRUE", "FALSE",
    "ARRAY", "SOME", "IN", "LIKE", "BETWEEN",
}
_COND_COL_RE = re.compile(
    r"\(?\s*([A-Za-z_][A-Za-z0-9_.]*)\s*(?:=|<>|!=|<=|>=|<|>|~~?\*?|\bIN\b|\bLIKE\b)",
    re.IGNORECASE,
)
_JOIN_COND_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)"
)


class IndexAdvisorError(RuntimeError):
    pass


# --------------------------------------------------------------------------
# Candidate column extraction from the plan tree
# --------------------------------------------------------------------------

def _cols_from_cond(cond_text: Optional[str]) -> list:
    if not cond_text:
        return []
    cols = []
    for clause in re.split(r"\bAND\b|\bOR\b", cond_text, flags=re.IGNORECASE):
        m = _COND_COL_RE.match(clause.strip())
        if m:
            col = m.group(1).split(".")[-1]
            if col.upper() not in _SQL_KEYWORDS:
                cols.append(col)
    return cols


def _add_join_cond_cols(cond_text: Optional[str], acc: dict) -> None:
    if not cond_text:
        return
    for m in _JOIN_COND_RE.finditer(cond_text):
        t1, c1, t2, c2 = m.groups()
        for table, col in ((t1, c1), (t2, c2)):
            bucket = acc.setdefault(table, [])
            if col not in bucket:
                bucket.append(col)


def _collect_relations(node: dict) -> set:
    """All Relation Name/Alias values anywhere under this node."""
    rels = set()
    rel = node.get("Relation Name") or node.get("Alias")
    if rel:
        rels.add(rel)
    for child in node.get("Plans", []):
        rels |= _collect_relations(child)
    return rels


def _add_sort_or_group_cols(value: Any, acc: dict, fallback_rel: Optional[str]) -> None:
    """Sort Key / Group Key entries are sometimes qualified ("orders.id")
    and sometimes bare ("id"). Qualified entries go straight to their own
    table; bare entries are only attributed if `fallback_rel` is known
    (i.e. there's exactly one relation under this subtree) — guessing
    wrong is worse than skipping."""
    if not isinstance(value, list):
        return
    for item in value:
        item = str(item)
        if not re.match(r"^[\w.]+$", item):
            continue
        if "." in item:
            table, col = item.rsplit(".", 1)
        elif fallback_rel:
            table, col = fallback_rel, item
        else:
            continue
        bucket = acc.setdefault(table, [])
        if col not in bucket:
            bucket.append(col)


def extract_candidate_columns(plan_root: dict) -> dict:
    """Walk the plan tree and return {relation_name: [col, col, ...]},
    columns ordered equality-first (Filter/Index Cond/join conditions
    before Sort/Group Key), deduplicated per relation.

    Two passes on purpose: equality/join columns are collected across the
    *whole* tree before any Sort/Group Key columns are appended, so the
    ordering reflects the standard composite-index rule of thumb
    (equality columns first, then columns used for ordering) regardless
    of where each node happens to sit in the plan tree."""
    acc: dict = {}

    def _walk_equality(node: dict) -> None:
        rel = node.get("Relation Name") or node.get("Alias")
        if rel:
            cols = []
            cols += _cols_from_cond(node.get("Filter"))
            cols += _cols_from_cond(node.get("Index Cond"))
            cols += _cols_from_cond(node.get("Recheck Cond"))
            if cols:
                bucket = acc.setdefault(rel, [])
                for c in cols:
                    if c not in bucket:
                        bucket.append(c)
        _add_join_cond_cols(node.get("Hash Cond"), acc)
        _add_join_cond_cols(node.get("Merge Cond"), acc)
        for child in node.get("Plans", []):
            _walk_equality(child)

    def _walk_sort_group(node: dict) -> None:
        rel = node.get("Relation Name") or node.get("Alias")
        sort_or_group = node.get("Sort Key") or node.get("Group Key")
        if sort_or_group:
            # Sort/Aggregate nodes don't own a relation themselves; if this
            # node has exactly one relation among its descendants,
            # unqualified keys can be safely attributed to it.
            fallback_rel = rel
            if fallback_rel is None:
                descendants = _collect_relations(node)
                fallback_rel = next(iter(descendants)) if len(descendants) == 1 else None
            _add_sort_or_group_cols(sort_or_group, acc, fallback_rel)
        for child in node.get("Plans", []):
            _walk_sort_group(child)

    _walk_equality(plan_root)
    _walk_sort_group(plan_root)
    return acc


def build_candidates(plan_root: dict) -> list:
    """Return [{"table":, "columns":, "ddl":, "hypopg_ddl":}, ...],
    at most MAX_INDEX_COLUMNS columns each."""
    candidates = []
    for table, cols in extract_candidate_columns(plan_root).items():
        cols = cols[:MAX_INDEX_COLUMNS]
        if not cols:
            continue
        idx_name = f"idx_{table}_{'_'.join(cols)}"[:63]  # Postgres identifier length limit
        candidates.append({
            "table": table,
            "columns": cols,
            "ddl": f"CREATE INDEX CONCURRENTLY {idx_name} ON {table} ({', '.join(cols)});",
            # hypopg ignores the index name and CONCURRENTLY anyway; keep a
            # plain variant for the calls we actually send it.
            "hypopg_ddl": f"CREATE INDEX ON {table} ({', '.join(cols)})",
        })
    return candidates


# --------------------------------------------------------------------------
# hypopg testing — EXPLAIN only, never ANALYZE (hypothetical indexes only
# affect planning, never execution — see the hypopg docs).
# --------------------------------------------------------------------------

def _plan_root(raw_plan: Any) -> dict:
    top = raw_plan[0] if isinstance(raw_plan, list) else raw_plan
    return top["Plan"]


def _total_cost(raw_plan: Any) -> float:
    return _plan_root(raw_plan).get("Total Cost", 0.0)


def _plan_uses_index_name(raw_plan: Any, index_name: str) -> bool:
    def _walk(node: dict) -> bool:
        if node.get("Index Name") == index_name:
            return True
        return any(_walk(c) for c in node.get("Plans", []))

    return _walk(_plan_root(raw_plan))


def _run_explain_raw(cur: Any, sql: str) -> Any:
    cur.execute(f"EXPLAIN (FORMAT JSON) {sql}")
    row = cur.fetchone()
    raw = row[0]
    return json.loads(raw) if isinstance(raw, str) else raw


def test_candidates_with_hypopg(conninfo: str, sql: str, candidates: list, timeout_ms: int) -> Optional[list]:
    """Returns a list of result dicts, or None if the hypopg extension is
    not installed in the target database. Never runs CREATE INDEX (real);
    only hypopg_create_index (hypothetical, zero-cost, backend-local).
    Always rolls back."""
    if psycopg is None:
        raise IndexAdvisorError('psycopg is not installed. Run: pip install "psycopg[binary]"')

    timeout_ms = int(timeout_ms)
    results = []

    with psycopg.connect(conninfo, autocommit=False) as conn:
        try:
            with conn.cursor() as cur:
                cur.execute(f"SET LOCAL statement_timeout = {timeout_ms}")
                cur.execute("SELECT 1 FROM pg_extension WHERE extname = 'hypopg'")
                if cur.fetchone() is None:
                    return None

                baseline_raw = _run_explain_raw(cur, sql)
                baseline_cost = _total_cost(baseline_raw)

                for candidate in candidates:
                    cur.execute("SELECT * FROM hypopg_create_index(%s)", (candidate["hypopg_ddl"],))
                    _indexrelid, indexname = cur.fetchone()
                    new_raw = _run_explain_raw(cur, sql)
                    new_cost = _total_cost(new_raw)
                    improvement = round((1 - new_cost / baseline_cost) * 100, 1) if baseline_cost else None
                    results.append({
                        "table": candidate["table"],
                        "columns": candidate["columns"],
                        "ddl": candidate["ddl"],
                        "baseline_cost": round(baseline_cost, 2),
                        "estimated_cost_with_index": round(new_cost, 2),
                        "estimated_improvement_pct": improvement,
                        "planner_would_use_index": _plan_uses_index_name(new_raw, indexname),
                    })
                    cur.execute("SELECT hypopg_reset()")  # isolate each candidate's test from the next
        finally:
            conn.rollback()

    results.sort(key=lambda r: (r["estimated_improvement_pct"] is None, -(r["estimated_improvement_pct"] or 0)))
    return results


# --------------------------------------------------------------------------
# Loading the baseline plan (from a saved file, or by generating our own)
# --------------------------------------------------------------------------

def _load_from_plan_file(path: str) -> tuple:
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    if not isinstance(doc, dict) or "plan" not in doc:
        raise IndexAdvisorError(
            f'{path} doesn\'t look like an explain_runner.py output file (expected a JSON object with a "plan" key)'
        )
    sql = doc.get("sql")
    if not sql:
        raise IndexAdvisorError(
            f'{path} has no "sql" field — pass --query/--file instead so index_advisor knows '
            "what to re-run for the hypopg before/after comparison"
        )
    return sql, doc["plan"]


def _read_sql_arg(args: argparse.Namespace) -> str:
    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            return f.read().strip()
    return args.query.strip()


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _print_human(candidates: list, hypopg_results: Optional[list]) -> None:
    if not candidates:
        print("No candidate columns found in this plan (no Filter / Index Cond / Sort Key / join condition to work from).")
        return

    if hypopg_results is None:
        print("Candidate indexes (hypopg not available in this database — no before/after cost shown):\n")
        for c in candidates:
            print(f"  {c['ddl']}")
        print("\nAsk your DBA to run `CREATE EXTENSION hypopg;` in this database to enable before/after cost estimates.")
        return

    print("Candidate indexes, tested as hypothetical indexes via hypopg (nothing was actually created):\n")
    for r in hypopg_results:
        used = "planner WOULD use it" if r["planner_would_use_index"] else "planner would NOT use it"
        pct = f"{r['estimated_improvement_pct']:+.1f}%" if r["estimated_improvement_pct"] is not None else "n/a"
        print(f"  {r['ddl']}")
        print(f"    baseline cost {r['baseline_cost']} -> with index {r['estimated_cost_with_index']} ({pct} cost change), {used}")
        print()


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="index_advisor.py",
        description=(
            "Propose candidate indexes for a query and, if hypopg is "
            "installed in the target database, test them as hypothetical "
            "indexes to show before/after planner cost. Never creates a "
            "real index."
        ),
        epilog=(
            "Examples:\n"
            "  index_advisor.py --plan plan.json --conn \"$DATABASE_URL\"\n"
            "  index_advisor.py --query \"SELECT ...\" --conn \"$DATABASE_URL\"\n"
            "  index_advisor.py --plan plan.json --no-hypopg\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--conn", metavar="DSN", help="Postgres connection string. Falls back to DATABASE_URL.")
    parser.add_argument("--plan", metavar="PATH", help="path to a plan JSON file produced by explain_runner.py")
    src = parser.add_mutually_exclusive_group()
    src.add_argument("--file", "-f", metavar="PATH", help="path to a .sql file containing the query")
    src.add_argument("--query", "-q", metavar="SQL", help="the query itself, inline")
    parser.add_argument("--no-hypopg", action="store_true", help="skip hypopg testing entirely (no DB connection needed)")
    parser.add_argument(
        "--timeout-ms", type=int, default=explain_runner.DEFAULT_TIMEOUT_MS,
        help=f"statement_timeout for the EXPLAIN calls used while testing candidates (default: {explain_runner.DEFAULT_TIMEOUT_MS})",
    )
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON instead of a human-readable summary")
    args = parser.parse_args()

    try:
        if args.plan:
            sql, baseline_plan = _load_from_plan_file(args.plan)
        elif args.file or args.query:
            sql = _read_sql_arg(args)
            conninfo = args.conn or os.environ.get("DATABASE_URL")
            if not conninfo:
                raise IndexAdvisorError("no connection string: pass --conn or set DATABASE_URL (needed to generate a baseline plan)")
            baseline_plan = explain_runner.run_explain(conninfo, sql, analyze=False, timeout_ms=args.timeout_ms)["plan"]
        else:
            raise IndexAdvisorError("pass --plan, or --query/--file, to say what to analyze")

        candidates = build_candidates(_plan_root(baseline_plan))

        hypopg_results = None
        if candidates and not args.no_hypopg:
            conninfo = args.conn or os.environ.get("DATABASE_URL")
            if not conninfo:
                print("index_advisor: no --conn/DATABASE_URL — skipping hypopg testing, showing candidates only", file=sys.stderr)
            else:
                hypopg_results = test_candidates_with_hypopg(conninfo, sql, candidates, args.timeout_ms)
    except (IndexAdvisorError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"index_advisor: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"index_advisor: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps({"candidates": candidates, "hypopg_results": hypopg_results}, indent=2))
    else:
        _print_human(candidates, hypopg_results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
