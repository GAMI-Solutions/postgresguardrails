#!/usr/bin/env python3
"""
plan_analyzer.py — parse an EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) plan
(as produced by explain_runner.py) and flag common performance problems:

  - Seq Scans touching a large number of rows
  - Row-count estimates far off from what actually happened (needs ANALYZE)
  - Sorts/hashes that spilled to disk (work_mem exceeded)
  - Nested Loop joins whose inner side executed a huge number of times
  - Index/Bitmap scans that throw away most of what they fetch via a Filter

Each finding has a severity (HIGH/MEDIUM/LOW), the plan node it came from,
a message, and a one-line fix suggestion.

Standalone usage:
    explain_runner.py --conn "$DATABASE_URL" -q "SELECT ..." | plan_analyzer.py
    plan_analyzer.py plan.json
    plan_analyzer.py plan.json --json
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from typing import Optional


# --------------------------------------------------------------------------
# Tunable thresholds — plain config constants, easy to adjust.
# --------------------------------------------------------------------------

SEQ_SCAN_ROW_THRESHOLD = 10_000
SEQ_SCAN_HIGH_ROW_THRESHOLD = 100_000

ESTIMATE_RATIO_THRESHOLD = 10.0
ESTIMATE_RATIO_HIGH_THRESHOLD = 100.0

NESTED_LOOP_LOOP_THRESHOLD = 1_000
NESTED_LOOP_LOOP_HIGH_THRESHOLD = 10_000

FILTER_REMOVAL_RATIO_THRESHOLD = 0.5
FILTER_REMOVAL_RATIO_HIGH_THRESHOLD = 0.9

SEQ_SCAN_NODE_TYPES = {"Seq Scan"}
INDEX_SCAN_NODE_TYPES = {"Index Scan", "Index Only Scan", "Bitmap Heap Scan", "Bitmap Index Scan"}


@dataclasses.dataclass(frozen=True)
class Finding:
    severity: str  # "HIGH" | "MEDIUM" | "LOW"
    rule: str
    node_type: str
    relation: Optional[str]
    message: str
    fix: str


def _node_label(node: dict) -> str:
    label = node.get("Node Type", "?")
    rel = node.get("Relation Name") or node.get("Alias")
    if rel:
        label += f" on {rel}"
    idx = node.get("Index Name")
    if idx:
        label += f" (using {idx})"
    return label


def _fmt(n: float) -> str:
    return f"{n:,.0f}" if float(n).is_integer() else f"{n:,.1f}"


# --------------------------------------------------------------------------
# Per-node checks. Each takes one plan node dict and returns a Finding (or
# None / [] if it doesn't apply).
# --------------------------------------------------------------------------

def _check_seq_scan(node: dict) -> Optional[Finding]:
    if node.get("Node Type") not in SEQ_SCAN_NODE_TYPES:
        return None
    if "Actual Rows" in node:
        scanned = node["Actual Rows"] + node.get("Rows Removed by Filter", 0)
    else:
        scanned = node.get("Plan Rows", 0)
    if scanned <= SEQ_SCAN_ROW_THRESHOLD:
        return None
    severity = "HIGH" if scanned > SEQ_SCAN_HIGH_ROW_THRESHOLD else "MEDIUM"
    rel = node.get("Relation Name", "<table>")
    return Finding(
        severity=severity,
        rule="seq_scan_large_table",
        node_type=node["Node Type"],
        relation=node.get("Relation Name"),
        message=f"{_node_label(node)} scanned ~{_fmt(scanned)} rows with no index",
        fix=f"Add an index on {rel}'s filtered/joined column(s) with CREATE INDEX CONCURRENTLY, then confirm the planner switches to an Index Scan.",
    )


def _check_row_estimate(node: dict) -> Optional[Finding]:
    if "Actual Rows" not in node or "Plan Rows" not in node:
        return None  # only meaningful with ANALYZE data
    actual = node["Actual Rows"]
    planned = node["Plan Rows"]
    if actual == 0 and planned == 0:
        return None
    ratio = (actual + 1) / (planned + 1)  # +1 smoothing: avoids div-by-zero and infinite ratios
    off_by = ratio if ratio >= 1 else 1 / ratio
    if off_by <= ESTIMATE_RATIO_THRESHOLD:
        return None
    severity = "HIGH" if off_by > ESTIMATE_RATIO_HIGH_THRESHOLD else "MEDIUM"
    direction = "under" if actual > planned else "over"
    rel = node.get("Relation Name") or node.get("Alias") or "<table>"
    return Finding(
        severity=severity,
        rule="row_estimate_mismatch",
        node_type=node["Node Type"],
        relation=node.get("Relation Name") or node.get("Alias"),
        message=(
            f"{_node_label(node)}: planner {direction}estimated rows by "
            f"~{off_by:.1f}x (planned {_fmt(planned)}, actual {_fmt(actual)})"
        ),
        fix=f"Run ANALYZE {rel}; if the mismatch persists, raise the statistics target on the relevant column(s) (ALTER TABLE ... ALTER COLUMN ... SET STATISTICS ...).",
    )


def _check_disk_spill(node: dict) -> Optional[Finding]:
    node_type = node.get("Node Type")

    if node_type == "Sort":
        method = (node.get("Sort Method") or "").lower()
        space_type = (node.get("Sort Space Type") or "").lower()
        if "external" in method or space_type == "disk":
            space = node.get("Sort Space Used")
            space_str = f", used {space} kB" if space else ""
            return Finding(
                severity="HIGH",
                rule="disk_spill",
                node_type=node_type,
                relation=node.get("Relation Name"),
                message=f"{_node_label(node)} spilled to disk ({node.get('Sort Method', 'external sort')}{space_str})",
                fix="Increase work_mem for this query/session, or reduce the row width being sorted (select fewer columns before ORDER BY).",
            )

    if node_type == "Hash":
        batches = node.get("Hash Batches")
        if batches and batches > 1:
            return Finding(
                severity="HIGH",
                rule="disk_spill",
                node_type=node_type,
                relation=node.get("Relation Name"),
                message=f"{_node_label(node)} split into {batches} batches (spilled to disk — work_mem was exceeded)",
                fix="Increase work_mem for this query/session, or reduce the size of the hashed side (filter earlier, or make sure the smaller table is hashed).",
            )

    return None


def _check_nested_loop(node: dict) -> list:
    if node.get("Node Type") != "Nested Loop":
        return []
    findings = []
    for child in node.get("Plans", []):
        loops = child.get("Actual Loops")
        if not loops or loops <= NESTED_LOOP_LOOP_THRESHOLD:
            continue
        severity = "HIGH" if loops > NESTED_LOOP_LOOP_HIGH_THRESHOLD else "MEDIUM"
        findings.append(Finding(
            severity=severity,
            rule="nested_loop_high_loop_count",
            node_type="Nested Loop",
            relation=child.get("Relation Name") or child.get("Alias"),
            message=f"Nested Loop executed its inner side ({_node_label(child)}) {_fmt(loops)} times",
            fix="Make sure the inner side has an index on the join column; if it already does, check the row estimate findings above for why the planner chose Nested Loop anyway.",
        ))
    return findings


def _check_index_filter_removal(node: dict) -> Optional[Finding]:
    if node.get("Node Type") not in INDEX_SCAN_NODE_TYPES:
        return None
    removed = node.get("Rows Removed by Filter", 0)
    if not removed:
        return None
    actual = node.get("Actual Rows", 0)
    total = actual + removed
    if total == 0:
        return None
    ratio = removed / total
    if ratio <= FILTER_REMOVAL_RATIO_THRESHOLD:
        return None
    severity = "HIGH" if ratio > FILTER_REMOVAL_RATIO_HIGH_THRESHOLD else "MEDIUM"
    return Finding(
        severity=severity,
        rule="index_scan_low_selectivity",
        node_type=node["Node Type"],
        relation=node.get("Relation Name"),
        message=(
            f"{_node_label(node)} fetched {_fmt(total)} rows via the index, but a Filter "
            f"discarded {_fmt(removed)} of them ({ratio * 100:.0f}%)"
        ),
        fix="The index isn't selective enough for this WHERE clause — consider a composite index that also covers the filtered column(s), or a partial index matching this predicate.",
    )


_PER_NODE_CHECKS = (
    _check_seq_scan,
    _check_row_estimate,
    _check_disk_spill,
    _check_index_filter_removal,
)


def analyze_plan(plan_json) -> list:
    """plan_json is the raw Postgres EXPLAIN (FORMAT JSON) result: either a
    list containing one {"Plan": {...}, ...} dict (what Postgres actually
    returns), or that inner dict directly."""
    top = plan_json[0] if isinstance(plan_json, list) else plan_json
    root = top.get("Plan") if isinstance(top, dict) else None
    if root is None:
        raise ValueError("plan JSON doesn't look like an EXPLAIN (FORMAT JSON) result (no \"Plan\" key found)")

    findings: list = []

    def _walk(node: dict) -> None:
        for check in _PER_NODE_CHECKS:
            finding = check(node)
            if finding:
                findings.append(finding)
        findings.extend(_check_nested_loop(node))
        for child in node.get("Plans", []):
            _walk(child)

    _walk(root)

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda f: order.get(f.severity, 9))
    return findings


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _load_plan_document(path: Optional[str]) -> dict:
    text = sys.stdin.read() if path is None else open(path, "r", encoding="utf-8").read()
    doc = json.loads(text)
    # Accept either explain_runner.py's wrapper {"sql":.., "plan":..} or a
    # bare Postgres EXPLAIN (FORMAT JSON) result passed directly.
    if isinstance(doc, dict) and "plan" in doc:
        return doc
    return {"sql": None, "analyze": None, "plan": doc}


def _print_human(doc: dict, findings: list) -> None:
    plan_list = doc["plan"] if isinstance(doc["plan"], list) else [doc["plan"]]
    top = plan_list[0] if plan_list else {}

    if doc.get("sql"):
        print(f"Query: {doc['sql'].strip()}")
    if "Planning Time" in top:
        print(f"Planning time: {top['Planning Time']:.2f} ms")
    if "Execution Time" in top:
        print(f"Execution time: {top['Execution Time']:.2f} ms")
    print()

    if not findings:
        print("No issues found by Query Doctor's heuristics.")
        return

    counts: dict = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    summary = ", ".join(f"{v} {k}" for k, v in sorted(counts.items(), key=lambda kv: order.get(kv[0], 9)))
    print(f"{len(findings)} finding(s): {summary}\n")

    for f in findings:
        print(f"[{f.severity}] {f.message}")
        print(f"  Fix: {f.fix}")
        print()


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="plan_analyzer.py",
        description="Parse an EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) plan and flag common performance problems.",
        epilog=(
            "Examples:\n"
            "  explain_runner.py --conn \"$DATABASE_URL\" -q \"SELECT ...\" | plan_analyzer.py\n"
            "  plan_analyzer.py plan.json\n"
            "  plan_analyzer.py plan.json --json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "plan_file", nargs="?", default=None,
        help="path to a plan JSON file (as produced by explain_runner.py); reads stdin if omitted",
    )
    parser.add_argument("--json", action="store_true", help="print findings as JSON instead of human-readable text")
    args = parser.parse_args()

    try:
        doc = _load_plan_document(args.plan_file)
        findings = analyze_plan(doc["plan"])
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"plan_analyzer: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps([dataclasses.asdict(f) for f in findings], indent=2))
    else:
        _print_human(doc, findings)
    return 0


if __name__ == "__main__":
    sys.exit(main())
