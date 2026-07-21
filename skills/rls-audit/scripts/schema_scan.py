#!/usr/bin/env python3
"""
schema_scan.py — parse a Postgres schema-only SQL dump and output
structured JSON: every table, its columns, whether Row Level Security is
enabled/forced, its existing policies, and a tenant-column guess with a
confidence score.

This is a read-only, offline parser — it never connects to a database.
Feed it the output of `pg_dump --schema-only`, or any hand-written schema
.sql file.

Parses statement-by-statement with pglast (the real Postgres grammar) when
importable, so schema-qualified names, `ALTER TABLE ... ROW LEVEL
SECURITY`, and `CREATE POLICY` are all understood correctly regardless of
formatting. If an individual statement fails to parse (e.g. some
extension-specific DDL pglast doesn't support), that one statement falls
back to a lighter regex scan (or is skipped if it's irrelevant to RLS,
like a GRANT or COMMENT) rather than aborting the whole scan — one bad
statement in a multi-thousand-line dump shouldn't take down the rest.

Standalone usage:
    pg_dump --schema-only "$DATABASE_URL" > schema.sql
    python3 schema_scan.py schema.sql
    python3 schema_scan.py schema.sql --min-confidence 0.3
    python3 schema_scan.py schema.sql --missing-rls-only
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import re
import sys
from typing import Any, Optional

try:
    import pglast
    import pglast.enums as pg_enums
    HAS_PGLAST = True
except ImportError:
    HAS_PGLAST = False
    pg_enums = None


# --------------------------------------------------------------------------
# Tenant-column heuristics — config constants, easy to extend.
# --------------------------------------------------------------------------

EXACT_TENANT_COLUMN_NAMES = {
    "tenant_id", "org_id", "organization_id", "account_id", "workspace_id", "company_id",
}
FUZZY_NAME_SUBSTRINGS = ("tenant", "org", "account", "workspace", "company")
TENANT_TABLE_NAME_PATTERNS = {
    "tenant", "tenants", "organization", "organizations", "org", "orgs",
    "account", "accounts", "workspace", "workspaces", "company", "companies",
}

EXACT_MATCH_SCORE = 0.7
FUZZY_MATCH_SCORE = 0.3
FK_TO_TENANT_TABLE_SCORE = 0.4


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

@dataclasses.dataclass
class ColumnInfo:
    name: str
    data_type: str
    not_null: bool = False
    is_primary_key: bool = False
    is_foreign_key: bool = False
    fk_table: Optional[str] = None


@dataclasses.dataclass
class PolicyInfo:
    name: str
    command: str  # "select" | "insert" | "update" | "delete" | "all"
    permissive: bool
    roles: list
    using_expr: Optional[str]
    with_check_expr: Optional[str]
    raw_sql: str


@dataclasses.dataclass
class TableInfo:
    schema: str
    name: str
    columns: list
    rls_enabled: bool = False
    rls_forced: bool = False
    policies: list = dataclasses.field(default_factory=list)
    tenant_column_guess: Optional[str] = None
    tenant_column_confidence: float = 0.0
    tenant_column_confidence_label: str = "NONE"
    tenant_column_reasons: list = dataclasses.field(default_factory=list)

    @property
    def qualified_name(self) -> str:
        return f"{self.schema}.{self.name}"


# --------------------------------------------------------------------------
# Statement splitting — semicolon/quote/dollar-quote/comment aware, so
# function bodies (`AS $$ ... ; ... $$`) and string literals don't get cut
# in the middle. This only finds statement *boundaries*; each statement's
# meaning is then extracted by pglast (or the regex fallback) separately.
# --------------------------------------------------------------------------

_DOLLAR_TAG_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)?\$")


def _split_statements(sql: str) -> list:
    """Return [(start_line, statement_text), ...]."""
    statements = []
    buf = []
    line = 1
    start_line = 1
    in_squote = False
    in_dquote = False
    dollar_tag: Optional[str] = None
    i, n = 0, len(sql)

    while i < n:
        ch = sql[i]

        if dollar_tag is not None:
            m = _DOLLAR_TAG_RE.match(sql, i)
            if m and m.group(1) == dollar_tag:
                buf.append(sql[i:m.end()])
                line += sql.count("\n", i, m.end())
                i = m.end()
                dollar_tag = None
                continue
            if ch == "\n":
                line += 1
            buf.append(ch)
            i += 1
            continue

        if in_squote:
            if ch == "\n":
                line += 1
            buf.append(ch)
            if ch == "'":
                in_squote = False
            i += 1
            continue

        if in_dquote:
            if ch == "\n":
                line += 1
            buf.append(ch)
            if ch == '"':
                in_dquote = False
            i += 1
            continue

        if ch == "\n":
            line += 1

        if sql[i:i + 2] == "--":
            end = sql.find("\n", i)
            end = end if end != -1 else n
            buf.append(sql[i:end])
            i = end
            continue

        if sql[i:i + 2] == "/*":
            end = sql.find("*/", i)
            end = end + 2 if end != -1 else n
            buf.append(sql[i:end])
            line += sql.count("\n", i, end)
            i = end
            continue

        if ch == "'":
            in_squote = True
            buf.append(ch)
            i += 1
            continue

        if ch == '"':
            in_dquote = True
            buf.append(ch)
            i += 1
            continue

        if ch == "$":
            m = _DOLLAR_TAG_RE.match(sql, i)
            if m:
                dollar_tag = m.group(1) or ""
                buf.append(sql[i:m.end()])
                i = m.end()
                continue

        if ch == ";":
            buf.append(ch)
            text = "".join(buf).strip()
            if text and text != ";":
                statements.append((start_line, text))
            buf = []
            i += 1
            start_line = line
            continue

        buf.append(ch)
        i += 1

    tail = "".join(buf).strip()
    if tail:
        statements.append((start_line, tail))
    return statements


# --------------------------------------------------------------------------
# Small generic helpers reused by the regex fallback path.
# --------------------------------------------------------------------------

def _extract_balanced(text: str, open_paren_pos: int) -> str:
    depth = 0
    i = open_paren_pos
    n = len(text)
    in_str = None
    start = open_paren_pos + 1
    while i < n:
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
            i += 1
            continue
        if ch in ("'", '"'):
            in_str = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[start:i]
        i += 1
    return text[start:]


def _split_top_level(text: str) -> list:
    parts, buf, depth, in_str = [], [], 0, None
    for ch in text:
        if in_str:
            buf.append(ch)
            if ch == in_str:
                in_str = None
            continue
        if ch in ("'", '"'):
            in_str = ch
            buf.append(ch)
        elif ch in "([{":
            depth += 1
            buf.append(ch)
        elif ch in ")]}":
            depth -= 1
            buf.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if buf:
        parts.append("".join(buf))
    return [p.strip() for p in parts]


def _extract_paren_clause(text: str, keyword_pattern: str) -> Optional[str]:
    m = re.search(keyword_pattern, text, re.IGNORECASE)
    if not m:
        return None
    paren_start = text.find("(", m.end())
    if paren_start == -1:
        return None
    closing = _find_matching_paren(text, paren_start)
    if closing is None:
        return None
    return text[paren_start + 1:closing].strip()


def _find_matching_paren(text: str, open_pos: int) -> Optional[int]:
    depth = 0
    for i in range(open_pos, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return None


def _using_and_check(raw_sql: str) -> tuple:
    return (
        _extract_paren_clause(raw_sql, r"\bUSING\s*"),
        _extract_paren_clause(raw_sql, r"\bWITH\s+CHECK\s*"),
    )


def _split_qualified(name: str) -> tuple:
    name = name.replace('"', "")
    parts = name.split(".")
    if len(parts) == 2:
        return parts[0], parts[1]
    return "public", parts[-1]


# --------------------------------------------------------------------------
# pglast-based extraction
# --------------------------------------------------------------------------

_TYPE_NAME_MAP = {
    "int8": "bigint", "int4": "integer", "int2": "smallint", "bool": "boolean",
    "varchar": "character varying", "bpchar": "character",
    "timestamptz": "timestamp with time zone", "timetz": "time with time zone",
    "float4": "real", "float8": "double precision",
}


def _type_name(type_name_node: Any) -> str:
    names = [n.sval for n in type_name_node.names]
    if names and names[0] == "pg_catalog":
        names = names[1:]
    base = _TYPE_NAME_MAP.get(".".join(names), ".".join(names))
    typmods = type_name_node.typmods
    if typmods:
        mods = [str(getattr(m.val, "ival", "")) for m in typmods if hasattr(m, "val")]
        mods = [m for m in mods if m]
        if mods:
            base += f"({','.join(mods)})"
    return base


def _rel_name(range_var: Any) -> tuple:
    return (range_var.schemaname or "public", range_var.relname)


def _apply_constraint(constraint: Any, info: TableInfo) -> None:
    if constraint is None:
        return
    if constraint.contype == pg_enums.ConstrType.CONSTR_PRIMARY:
        keys = constraint.keys if hasattr(constraint, "keys") and constraint.keys else None
        colnames = [k.sval for k in keys] if keys else None
        for col in info.columns:
            if colnames is None or col.name in colnames:
                col.is_primary_key = True
                col.not_null = True
                if colnames is None:
                    break  # inline single-column constraint: applies to this ColumnDef only
    elif constraint.contype == pg_enums.ConstrType.CONSTR_NOTNULL:
        pass  # handled per-column at call site
    elif constraint.contype == pg_enums.ConstrType.CONSTR_FOREIGN:
        fk_table = constraint.pktable.relname if constraint.pktable else None
        fk_attrs = constraint.fk_attrs or ()
        if fk_attrs:
            colnames = [a.sval for a in fk_attrs]
            for col in info.columns:
                if col.name in colnames:
                    col.is_foreign_key = True
                    col.fk_table = fk_table


def _columns_from_create_stmt(stmt: Any, info: TableInfo) -> None:
    for elt in stmt.tableElts or ():
        if isinstance(elt, pglast.ast.ColumnDef):
            col = ColumnInfo(name=elt.colname, data_type=_type_name(elt.typeName))
            info.columns.append(col)
            for constraint in elt.constraints or ():
                if constraint.contype == pg_enums.ConstrType.CONSTR_NOTNULL:
                    col.not_null = True
                elif constraint.contype == pg_enums.ConstrType.CONSTR_PRIMARY:
                    col.not_null = True
                    col.is_primary_key = True
                elif constraint.contype == pg_enums.ConstrType.CONSTR_FOREIGN:
                    col.is_foreign_key = True
                    col.fk_table = constraint.pktable.relname if constraint.pktable else None
        elif isinstance(elt, pglast.ast.Constraint):
            # table-level constraint declared inside CREATE TABLE (...), e.g.
            # PRIMARY KEY (a, b) or FOREIGN KEY (a) REFERENCES other(id)
            _apply_constraint(elt, info)


def _roles_to_list(roles: Any) -> list:
    result = []
    for r in roles or ():
        if getattr(r, "roletype", None) == pg_enums.RoleSpecType.ROLESPEC_PUBLIC:
            result.append("PUBLIC")
        else:
            result.append(getattr(r, "rolename", None) or "PUBLIC")
    return result or ["PUBLIC"]


def _try_parse_one(text: str) -> Optional[Any]:
    if not HAS_PGLAST:
        return None
    try:
        parsed = pglast.parse_sql(text)
    except Exception:
        return None
    return parsed[0].stmt if parsed else None


def _handle_parsed_statement(node: Any, raw_text: str, tables: dict, order: list) -> None:
    if isinstance(node, pglast.ast.CreateStmt):
        schema, name = _rel_name(node.relation)
        info = tables.setdefault((schema, name), TableInfo(schema=schema, name=name, columns=[]))
        if (schema, name) not in order:
            order.append((schema, name))
        _columns_from_create_stmt(node, info)

    elif isinstance(node, pglast.ast.AlterTableStmt):
        schema, name = _rel_name(node.relation)
        info = tables.get((schema, name)) or tables.get(("public", name))
        if info is None:
            return
        for cmd in node.cmds or ():
            if cmd.subtype == pg_enums.AlterTableType.AT_EnableRowSecurity:
                info.rls_enabled = True
            elif cmd.subtype == pg_enums.AlterTableType.AT_DisableRowSecurity:
                info.rls_enabled = False
            elif cmd.subtype == pg_enums.AlterTableType.AT_ForceRowSecurity:
                info.rls_forced = True
            elif cmd.subtype == pg_enums.AlterTableType.AT_AddConstraint:
                _apply_constraint(cmd.def_, info)

    elif isinstance(node, pglast.ast.CreatePolicyStmt):
        schema, name = _rel_name(node.table)
        info = tables.get((schema, name)) or tables.get(("public", name))
        using_expr, check_expr = _using_and_check(raw_text)
        policy = PolicyInfo(
            name=node.policy_name,
            command=(node.cmd_name or "all"),
            permissive=bool(node.permissive),
            roles=_roles_to_list(node.roles),
            using_expr=using_expr,
            with_check_expr=check_expr,
            raw_sql=raw_text.strip(),
        )
        if info is not None:
            info.policies.append(policy)


# --------------------------------------------------------------------------
# Regex fallback — used per-statement when pglast is unavailable, or when
# a specific statement fails to parse. Anything that isn't recognizably a
# CREATE TABLE / ALTER TABLE ROW LEVEL SECURITY / CREATE POLICY / ADD
# CONSTRAINT statement is silently ignored (GRANT, COMMENT, SEQUENCE,
# function bodies, etc. — irrelevant to an RLS audit).
# --------------------------------------------------------------------------

_RE_CREATE_TABLE = re.compile(r'\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:ONLY\s+)?([\w".]+)\s*\(', re.IGNORECASE)
_RE_ALTER_RLS = re.compile(r'\bALTER\s+TABLE\s+(?:ONLY\s+)?([\w".]+)\s+(ENABLE|DISABLE|FORCE)\s+ROW\s+LEVEL\s+SECURITY', re.IGNORECASE)
_RE_CREATE_POLICY = re.compile(r'\bCREATE\s+POLICY\s+([\w"]+)\s+ON\s+([\w".]+)', re.IGNORECASE)
_RE_ADD_CONSTRAINT = re.compile(r'\bALTER\s+TABLE\s+(?:ONLY\s+)?([\w".]+)\s+ADD\s+CONSTRAINT\s+\S+\s+(PRIMARY\s+KEY|FOREIGN\s+KEY)', re.IGNORECASE)


def _handle_unparsed_statement(text: str, tables: dict, order: list) -> None:
    m = _RE_CREATE_TABLE.search(text)
    if m:
        schema, name = _split_qualified(m.group(1))
        open_paren = text.find("(", m.end() - 1)
        cols_text = _extract_balanced(text, open_paren) if open_paren != -1 else ""
        columns = []
        for col_def in _split_top_level(cols_text):
            col_def = col_def.strip()
            if not col_def or re.match(r"^(PRIMARY|FOREIGN|UNIQUE|CHECK|CONSTRAINT|EXCLUDE)\b", col_def, re.IGNORECASE):
                continue  # table-level constraint clause, not a column (best effort in fallback mode)
            parts = col_def.split(None, 1)
            if not parts:
                continue
            colname = parts[0].strip('"')
            rest = parts[1] if len(parts) > 1 else ""
            col = ColumnInfo(name=colname, data_type=(rest.split(",")[0][:40].strip() or "unknown"))
            col.not_null = bool(re.search(r"\bNOT\s+NULL\b|\bPRIMARY\s+KEY\b", col_def, re.IGNORECASE))
            col.is_primary_key = bool(re.search(r"\bPRIMARY\s+KEY\b", col_def, re.IGNORECASE))
            fk_m = re.search(r'\bREFERENCES\s+"?([\w.]+)"?', col_def, re.IGNORECASE)
            if fk_m:
                col.is_foreign_key = True
                col.fk_table = fk_m.group(1).split(".")[-1]
            columns.append(col)
        info = tables.setdefault((schema, name), TableInfo(schema=schema, name=name, columns=[]))
        info.columns.extend(columns)
        if (schema, name) not in order:
            order.append((schema, name))
        return

    m = _RE_ALTER_RLS.search(text)
    if m:
        schema, name = _split_qualified(m.group(1))
        info = tables.get((schema, name)) or tables.get(("public", name))
        if info:
            action = m.group(2).upper()
            if action == "ENABLE":
                info.rls_enabled = True
            elif action == "DISABLE":
                info.rls_enabled = False
            elif action == "FORCE":
                info.rls_forced = True
        return

    m = _RE_CREATE_POLICY.search(text)
    if m:
        policy_name = m.group(1).strip('"')
        schema, name = _split_qualified(m.group(2))
        info = tables.get((schema, name)) or tables.get(("public", name))
        using_expr, check_expr = _using_and_check(text)
        cmd_m = re.search(r"\bFOR\s+(SELECT|INSERT|UPDATE|DELETE|ALL)\b", text, re.IGNORECASE)
        policy = PolicyInfo(
            name=policy_name,
            command=(cmd_m.group(1).lower() if cmd_m else "all"),
            permissive="RESTRICTIVE" not in text.upper(),
            roles=["PUBLIC"],
            using_expr=using_expr,
            with_check_expr=check_expr,
            raw_sql=text.strip(),
        )
        if info:
            info.policies.append(policy)
        return

    m = _RE_ADD_CONSTRAINT.search(text)
    if m:
        schema, name = _split_qualified(m.group(1))
        info = tables.get((schema, name)) or tables.get(("public", name))
        if info:
            if "FOREIGN" in m.group(2).upper():
                cols_m = re.search(r'FOREIGN\s+KEY\s*\(([^)]+)\)\s*REFERENCES\s+"?([\w.]+)"?', text, re.IGNORECASE)
                if cols_m:
                    fk_table = cols_m.group(2).split(".")[-1]
                    colnames = [c.strip().strip('"') for c in cols_m.group(1).split(",")]
                    for col in info.columns:
                        if col.name in colnames:
                            col.is_foreign_key = True
                            col.fk_table = fk_table
            else:
                cols_m = re.search(r"PRIMARY\s+KEY\s*\(([^)]+)\)", text, re.IGNORECASE)
                if cols_m:
                    colnames = [c.strip().strip('"') for c in cols_m.group(1).split(",")]
                    for col in info.columns:
                        if col.name in colnames:
                            col.is_primary_key = True
                            col.not_null = True
        return
    # anything else (GRANT, COMMENT, SEQUENCE, function bodies, ...) is
    # irrelevant to an RLS audit — silently ignored.


# --------------------------------------------------------------------------
# Tenant-column guessing
# --------------------------------------------------------------------------

def _confidence_label(score: float) -> str:
    if score >= 0.7:
        return "HIGH"
    if score >= 0.3:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def _guess_tenant_column(info: TableInfo) -> None:
    best_col, best_score, best_reasons = None, 0.0, []
    for col in info.columns:
        score, reasons = 0.0, []
        name_lower = col.name.lower()
        if name_lower in EXACT_TENANT_COLUMN_NAMES:
            score += EXACT_MATCH_SCORE
            reasons.append(f"column name '{col.name}' matches a known tenant-id naming convention")
        elif any(sub in name_lower for sub in FUZZY_NAME_SUBSTRINGS):
            score += FUZZY_MATCH_SCORE
            reasons.append(f"column name '{col.name}' loosely resembles a tenant-id naming convention")
        if col.is_foreign_key and col.fk_table and col.fk_table.lower() in TENANT_TABLE_NAME_PATTERNS:
            score += FK_TO_TENANT_TABLE_SCORE
            reasons.append(f"foreign key references '{col.fk_table}', which looks like a tenant/org table")
        score = min(score, 1.0)
        if score > best_score:
            best_col, best_score, best_reasons = col.name, score, reasons
    info.tenant_column_guess = best_col
    info.tenant_column_confidence = round(best_score, 2)
    info.tenant_column_confidence_label = _confidence_label(best_score)
    info.tenant_column_reasons = best_reasons


# --------------------------------------------------------------------------
# Top-level entry point
# --------------------------------------------------------------------------

def scan_schema(sql: str) -> list:
    """Returns a list of TableInfo, one per CREATE TABLE found, in the
    order they first appeared in the dump."""
    tables: dict = {}
    order: list = []

    for _line, text in _split_statements(sql):
        node = _try_parse_one(text)
        if node is not None:
            _handle_parsed_statement(node, text, tables, order)
        else:
            _handle_unparsed_statement(text, tables, order)

    for info in tables.values():
        _guess_tenant_column(info)

    return [tables[key] for key in order]


def _table_to_dict(t: TableInfo) -> dict:
    d = dataclasses.asdict(t)
    d["qualified_name"] = t.qualified_name
    return d


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="schema_scan.py",
        description=(
            "Parse a Postgres schema-only SQL dump and output structured JSON per "
            "table: columns, RLS status, existing policies, and a tenant-column "
            "guess with confidence."
        ),
        epilog=(
            "Examples:\n"
            "  pg_dump --schema-only \"$DATABASE_URL\" > schema.sql\n"
            "  schema_scan.py schema.sql\n"
            "  schema_scan.py schema.sql --min-confidence 0.3\n"
            "  schema_scan.py schema.sql --missing-rls-only\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("schema_file", nargs="?", default=None, help="path to a schema-only SQL dump; reads stdin if omitted")
    parser.add_argument("--min-confidence", type=float, default=0.0, help="only include tables whose tenant-column confidence is >= this (0.0-1.0)")
    parser.add_argument("--missing-rls-only", action="store_true", help="only include tables that look multi-tenant (confidence > 0) but don't have RLS enabled")
    args = parser.parse_args()

    try:
        text = sys.stdin.read() if args.schema_file is None else open(args.schema_file, "r", encoding="utf-8").read()
    except OSError as exc:
        print(f"schema_scan: could not read {args.schema_file}: {exc}", file=sys.stderr)
        return 1

    try:
        tables = scan_schema(text)
    except Exception as exc:
        print(f"schema_scan: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    if args.min_confidence > 0:
        tables = [t for t in tables if t.tenant_column_confidence >= args.min_confidence]
    if args.missing_rls_only:
        tables = [t for t in tables if t.tenant_column_confidence > 0 and not t.rls_enabled]

    print(json.dumps([_table_to_dict(t) for t in tables], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
