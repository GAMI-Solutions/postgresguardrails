#!/usr/bin/env python3
"""
DDL rules engine for the postgres-guardrails Migration Firewall.

check_sql(sql) is the entry point: it splits the input into statements,
classifies each against the 7 known lock-hazard patterns, and returns a
list of Finding objects (rule id, severity, line, matched snippet, and the
safe multi-step rewrite to use instead).

Detection strategy, per rule:
  1. If pglast is importable and the SQL parses cleanly, use the parsed AST
     to make the hazard/safe decision (accurate: distinguishes e.g. a
     constant DEFAULT from a volatile function-call DEFAULT).
  2. Regex is always used to locate/format the matched snippet, and is the
     *sole* decision mechanism whenever pglast is unavailable or the SQL
     fails to parse (e.g. dialect-specific syntax from Prisma/Django/Rails
     migration files that isn't valid standalone SQL).

Fails safe: this module never raises on malformed/unparseable input. A
parse failure just means every rule falls back to its regex heuristic.
"""
from __future__ import annotations

import dataclasses
import enum
import json
import re
import sys
from typing import Any, Callable, Optional

try:
    import pglast
    import pglast.enums as pg_enums
    HAS_PGLAST = True
except ImportError:  # pragma: no cover - exercised in environments without pglast
    HAS_PGLAST = False
    pg_enums = None  # type: ignore


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

class Severity(str, enum.Enum):
    BLOCK = "BLOCK"
    WARN = "WARN"


@dataclasses.dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    line: int
    snippet: str
    message: str
    safe_rewrite: str


@dataclasses.dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    title: str
    description: str
    # detect(text, node) -> True (hazard), False (confirmed safe), or None
    # (rule not applicable to this statement / node type).
    detect: Callable[[str, Optional[Any]], Optional[bool]]
    safe_pattern: str


@dataclasses.dataclass
class _Stmt:
    text: str          # raw source text of the statement (no trailing ';')
    line: int           # 1-based line number where the statement starts
    node: Optional[Any]  # parsed pglast AST node, or None if unavailable


# --------------------------------------------------------------------------
# Shared regex helpers
# --------------------------------------------------------------------------

_COMMENT_RE = re.compile(r"--[^\n]*|/\*.*?\*/", re.DOTALL)

_RE_ALTER_TABLE = re.compile(r"\bALTER\s+TABLE\b", re.IGNORECASE)


def _strip_comments(sql: str) -> str:
    return _COMMENT_RE.sub(lambda m: "\n" * m.group(0).count("\n"), sql)


def _snippet(text: str, start: int = 0, length: int = 100) -> str:
    seg = text[start : start + length]
    seg = re.sub(r"\s+", " ", seg).strip()
    if start + length < len(text):
        seg += " ..."
    return seg


def _locate(text: str, patterns: list) -> tuple:
    """Try each compiled regex in order; return (offset, snippet) for the
    first hit, or (0, whole-statement snippet) if none match."""
    for pattern in patterns:
        m = pattern.search(text)
        if m:
            return m.start(), _snippet(text, m.start())
    return 0, _snippet(text, 0)


def _split_statements_regex(sql: str) -> list:
    """Fallback statement splitter: semicolons outside quotes, with
    accurate line tracking. Used when pglast is unavailable or parsing
    fails."""
    clean = _strip_comments(sql)
    statements = []
    buf = []
    line = 1
    start_line = 1
    in_squote = False
    in_dquote = False
    for ch in clean:
        if ch == "\n":
            line += 1
        if ch == "'" and not in_dquote:
            in_squote = not in_squote
        elif ch == '"' and not in_squote:
            in_dquote = not in_dquote
        if ch == ";" and not in_squote and not in_dquote:
            text = "".join(buf)
            if text.strip():
                statements.append(_Stmt(text=text, line=start_line, node=None))
            buf = []
            start_line = line
        else:
            buf.append(ch)
    tail = "".join(buf)
    if tail.strip():
        statements.append(_Stmt(text=tail, line=start_line, node=None))
    return statements


def _split_statements(sql: str) -> list:
    """Preferred splitter: use pglast to get exact statement boundaries and
    parsed AST nodes. Falls back to the regex splitter on any parse error."""
    if HAS_PGLAST:
        try:
            raw_stmts = pglast.parse_sql(sql)
        except Exception:
            raw_stmts = None
        if raw_stmts is not None:
            statements = []
            for raw in raw_stmts:
                loc = raw.stmt_location or 0
                ln = raw.stmt_len if raw.stmt_len else (len(sql) - loc)
                text = sql[loc : loc + ln]
                line = sql.count("\n", 0, loc) + 1
                statements.append(_Stmt(text=text, line=line, node=raw.stmt))
            return statements
    return _split_statements_regex(sql)


# ==========================================================================
# Rule 1 — CREATE INDEX without CONCURRENTLY
# ==========================================================================

_RE_CREATE_INDEX = re.compile(r"\bCREATE\s+(?:UNIQUE\s+)?INDEX\b", re.IGNORECASE)
_RE_CONCURRENTLY = re.compile(r"\bCONCURRENTLY\b", re.IGNORECASE)


def _detect_index_concurrently(text: str, node: Optional[Any]) -> Optional[bool]:
    if HAS_PGLAST and isinstance(node, pglast.ast.IndexStmt):
        return not bool(node.concurrent)
    if node is not None:
        return None  # a parsed node exists but it isn't a CREATE INDEX
    if not _RE_CREATE_INDEX.search(text):
        return None
    return not _RE_CONCURRENTLY.search(text)


RULE_INDEX_CONCURRENTLY = Rule(
    id="index_no_concurrently",
    severity=Severity.BLOCK,
    title="CREATE INDEX without CONCURRENTLY",
    description=(
        "A plain CREATE INDEX takes a SHARE lock on the table for the "
        "duration of the build, blocking all writes. On a hot table this "
        "can stall production traffic for the entire build time."
    ),
    detect=_detect_index_concurrently,
    safe_pattern=(
        "Use CREATE INDEX CONCURRENTLY instead, outside of a transaction "
        "block:\n"
        "  1) SET statement_timeout = 0; -- concurrent builds can be slow\n"
        "  2) CREATE INDEX CONCURRENTLY IF NOT EXISTS <idx_name> ON "
        "<table> (<cols>);\n"
        "  3) If it fails partway, DROP INDEX CONCURRENTLY <idx_name>; and retry."
    ),
)


# ==========================================================================
# Rule 2 — ADD COLUMN with a volatile DEFAULT
# ==========================================================================

_RE_ADD_COLUMN_DEFAULT = re.compile(
    r"\bADD\s+COLUMN\b\s+(?:IF\s+NOT\s+EXISTS\s+)?\"?[\w]+\"?\s+[\w\[\]\"\.]+"
    r"(?:\([^)]*\))?\s*(?:[A-Z ]*?)\bDEFAULT\s+(?P<default>.+?)"
    r"(?=,\s*(?:ADD|ALTER|DROP)\b|\s+NOT\s+NULL\b|\s+NULL\b|\s+CHECK\b|"
    r"\s+REFERENCES\b|\s+UNIQUE\b|\s+PRIMARY\b|$)",
    re.IGNORECASE | re.DOTALL,
)
_RE_STRING_LITERAL = re.compile(r"^'(?:[^']|'')*'(::[\w\s\[\]\.\"]+)?$")
_RE_NUMERIC_LITERAL = re.compile(r"^[-+]?\d+(\.\d+)?(::[\w\s\[\]\.\"]+)?$")
_RE_BOOL_NULL_LITERAL = re.compile(r"^(TRUE|FALSE|NULL)(::[\w\s\[\]\.\"]+)?$", re.IGNORECASE)
_RE_FUNC_CALL = re.compile(r"^[a-zA-Z_][\w]*\s*\(")


def _is_volatile_default_text(expr: str) -> bool:
    expr = expr.strip().rstrip(",")
    if (
        _RE_STRING_LITERAL.match(expr)
        or _RE_NUMERIC_LITERAL.match(expr)
        or _RE_BOOL_NULL_LITERAL.match(expr)
    ):
        return False
    # Strip a trailing ::cast and re-check the inner expression (e.g.
    # now()::timestamptz is still volatile; 'x'::text is still constant).
    cast_stripped = re.sub(r"::[\w\s\[\]\.\"]+$", "", expr).strip()
    if cast_stripped != expr:
        return _is_volatile_default_text(cast_stripped)
    if _RE_FUNC_CALL.match(expr):
        return True
    # Unrecognized shape (arithmetic, param, etc.) - be conservative.
    return True


def _unwrap_default_expr(node: Any) -> Any:
    while HAS_PGLAST and isinstance(node, (pglast.ast.TypeCast, pglast.ast.CollateClause)):
        node = node.arg
    return node


def _detect_volatile_default(text: str, node: Optional[Any]) -> Optional[bool]:
    if HAS_PGLAST and isinstance(node, pglast.ast.AlterTableStmt):
        hazard = False
        found_add_column = False
        for cmd in node.cmds or ():
            if cmd.subtype != pg_enums.AlterTableType.AT_AddColumn:
                continue
            col_def = cmd.def_
            if not col_def or not col_def.constraints:
                continue
            for constraint in col_def.constraints:
                if constraint.contype != pg_enums.ConstrType.CONSTR_DEFAULT:
                    continue
                found_add_column = True
                expr = _unwrap_default_expr(constraint.raw_expr)
                if isinstance(expr, pglast.ast.FuncCall):
                    hazard = True
                elif isinstance(expr, pglast.ast.A_Const):
                    pass  # constant literal: safe
                else:
                    hazard = True  # unrecognized shape: be conservative
        if found_add_column:
            return hazard
        return False if isinstance(node, pglast.ast.AlterTableStmt) else None
    if node is not None:
        return None  # parsed node exists but isn't an ALTER TABLE
    if not _RE_ALTER_TABLE.search(text):
        return None
    m = _RE_ADD_COLUMN_DEFAULT.search(text)
    if not m:
        return False
    return _is_volatile_default_text(m.group("default"))


RULE_VOLATILE_DEFAULT = Rule(
    id="add_column_volatile_default",
    severity=Severity.BLOCK,
    title="ADD COLUMN with a volatile DEFAULT",
    description=(
        "Since PG11, ADD COLUMN with a *constant* DEFAULT is a fast "
        "metadata-only change. A volatile default (now(), random(), "
        "nextval(), gen_random_uuid(), etc.) cannot be stored as one value "
        "for all existing rows, so Postgres still rewrites the whole table "
        "under an ACCESS EXCLUSIVE lock."
    ),
    detect=_detect_volatile_default,
    safe_pattern=(
        "Split into steps so only new rows pay the cost:\n"
        "  1) ALTER TABLE <table> ADD COLUMN <col> <type>; -- nullable, no default\n"
        "  2) Backfill in batches from application code or a script "
        "(UPDATE ... WHERE <col> IS NULL LIMIT N, looped).\n"
        "  3) ALTER TABLE <table> ALTER COLUMN <col> SET DEFAULT <expr>; "
        "-- applies only to future inserts\n"
        "  4) Optionally add NOT NULL later via the NOT VALID CHECK pattern "
        "once fully backfilled."
    ),
)


# ==========================================================================
# Rule 3 — SET NOT NULL / column TYPE change
# ==========================================================================

_RE_SET_NOT_NULL = re.compile(
    r"\bALTER\s+(?:COLUMN\s+)?\"?[\w]+\"?\s+SET\s+NOT\s+NULL\b", re.IGNORECASE
)
_RE_ALTER_TYPE_COL = re.compile(
    r"\bALTER\s+(?:COLUMN\s+)?\"?[\w]+\"?\s+TYPE\s+", re.IGNORECASE
)


def _detect_unsafe_alter_column(text: str, node: Optional[Any]) -> Optional[bool]:
    if HAS_PGLAST and isinstance(node, pglast.ast.AlterTableStmt):
        hazardous_subtypes = {
            pg_enums.AlterTableType.AT_SetNotNull,
            pg_enums.AlterTableType.AT_AlterColumnType,
        }
        return any(cmd.subtype in hazardous_subtypes for cmd in (node.cmds or ()))
    if node is not None:
        return None
    if not _RE_ALTER_TABLE.search(text):
        return None
    return bool(_RE_SET_NOT_NULL.search(text) or _RE_ALTER_TYPE_COL.search(text))


RULE_UNSAFE_ALTER_COLUMN = Rule(
    id="unsafe_alter_column",
    severity=Severity.BLOCK,
    title="SET NOT NULL or column TYPE change without a validated path",
    description=(
        "A direct SET NOT NULL or ALTER COLUMN ... TYPE forces a full "
        "table scan (TYPE changes also rewrite the table) under an "
        "ACCESS EXCLUSIVE lock, blocking all reads and writes for the "
        "duration."
    ),
    detect=_detect_unsafe_alter_column,
    safe_pattern=(
        "For NOT NULL (PG12+):\n"
        "  1) ALTER TABLE <table> ADD CONSTRAINT <name>_not_null "
        "CHECK (<col> IS NOT NULL) NOT VALID;\n"
        "  2) ALTER TABLE <table> VALIDATE CONSTRAINT <name>_not_null; "
        "-- scans without ACCESS EXCLUSIVE\n"
        "  3) ALTER TABLE <table> ALTER COLUMN <col> SET NOT NULL; "
        "-- now fast, planner reuses the validated check\n"
        "  4) ALTER TABLE <table> DROP CONSTRAINT <name>_not_null;\n"
        "For TYPE changes: add a new column of the new type, backfill in "
        "batches, swap references, then drop the old column."
    ),
)


# ==========================================================================
# Rule 4 — FOREIGN KEY without NOT VALID + separate VALIDATE CONSTRAINT
# ==========================================================================

_RE_ADD_FK = re.compile(
    r"\bADD\s+(?:CONSTRAINT\s+\"?[\w]+\"?\s+)?FOREIGN\s+KEY\b", re.IGNORECASE
)
_RE_NOT_VALID = re.compile(r"\bNOT\s+VALID\b", re.IGNORECASE)


def _detect_fk_not_valid(text: str, node: Optional[Any]) -> Optional[bool]:
    if HAS_PGLAST and isinstance(node, pglast.ast.AlterTableStmt):
        found_fk = False
        hazard = False
        for cmd in node.cmds or ():
            if cmd.subtype != pg_enums.AlterTableType.AT_AddConstraint:
                continue
            constraint = cmd.def_
            if not constraint or constraint.contype != pg_enums.ConstrType.CONSTR_FOREIGN:
                continue
            found_fk = True
            if not constraint.skip_validation:
                hazard = True
        if found_fk:
            return hazard
        return False
    if node is not None:
        return None
    if not _RE_ALTER_TABLE.search(text):
        return None
    if not _RE_ADD_FK.search(text):
        return False
    return not _RE_NOT_VALID.search(text)


RULE_FK_NOT_VALID = Rule(
    id="fk_without_not_valid",
    severity=Severity.BLOCK,
    title="FOREIGN KEY added without NOT VALID",
    description=(
        "Adding a foreign key normally scans and locks both tables "
        "(SHARE ROW EXCLUSIVE) to validate every existing row before the "
        "constraint is live, which can stall writes on both sides for a "
        "long time on large tables."
    ),
    detect=_detect_fk_not_valid,
    safe_pattern=(
        "Split creation from validation:\n"
        "  1) ALTER TABLE <table> ADD CONSTRAINT <name> FOREIGN KEY (<col>) "
        "REFERENCES <ref_table> (<ref_col>) NOT VALID; -- fast, no scan\n"
        "  2) ALTER TABLE <table> VALIDATE CONSTRAINT <name>; -- scans "
        "with a much lighter lock, run separately/off-peak."
    ),
)


# ==========================================================================
# Rule 5 — ALTER TYPE ... ADD VALUE inside a transaction
# ==========================================================================

_RE_BEGIN = re.compile(r"\bBEGIN\b", re.IGNORECASE)
_RE_COMMIT_ROLLBACK = re.compile(r"\b(COMMIT|ROLLBACK|END)\b", re.IGNORECASE)
_RE_ALTER_TYPE_ADD_VALUE = re.compile(
    r"\bALTER\s+TYPE\b.*?\bADD\s+VALUE\b", re.IGNORECASE | re.DOTALL
)


def _detect_alter_type_in_txn(statements: list, sql: str) -> list:
    """Whole-file rule: flag ALTER TYPE ... ADD VALUE statements that occur
    inside an explicit BEGIN ... COMMIT/ROLLBACK block."""
    findings = []
    if HAS_PGLAST and statements and all(s.node is not None for s in statements):
        in_txn = False
        for stmt in statements:
            node = stmt.node
            if isinstance(node, pglast.ast.TransactionStmt):
                kind = node.kind
                if kind == pg_enums.TransactionStmtKind.TRANS_STMT_BEGIN:
                    in_txn = True
                elif kind in (
                    pg_enums.TransactionStmtKind.TRANS_STMT_COMMIT,
                    pg_enums.TransactionStmtKind.TRANS_STMT_ROLLBACK,
                ):
                    in_txn = False
                continue
            if isinstance(node, pglast.ast.AlterEnumStmt) and getattr(node, "newVal", None) and in_txn:
                findings.append((stmt.line, _snippet(stmt.text)))
        return findings
    # Regex fallback: scan the raw text for BEGIN ... ALTER TYPE ADD VALUE ... COMMIT/ROLLBACK
    clean = _strip_comments(sql)
    begins = [m.start() for m in _RE_BEGIN.finditer(clean)]
    closes = sorted(m.start() for m in _RE_COMMIT_ROLLBACK.finditer(clean))
    for m in _RE_ALTER_TYPE_ADD_VALUE.finditer(clean):
        pos = m.start()
        enclosing_begin = max((b for b in begins if b < pos), default=None)
        if enclosing_begin is None:
            continue
        next_close = next((c for c in closes if c > enclosing_begin), None)
        if next_close is None or pos < next_close:
            line = clean.count("\n", 0, pos) + 1
            findings.append((line, _snippet(clean, pos)))
    return findings


RULE_ALTER_TYPE_ADD_VALUE_IN_TXN = Rule(
    id="alter_type_add_value_in_txn",
    severity=Severity.BLOCK,
    title="ALTER TYPE ... ADD VALUE inside a transaction block",
    description=(
        "Before PG12, ALTER TYPE ... ADD VALUE cannot run inside a "
        "transaction block at all. On PG12+ it's allowed, but the new "
        "value can't be used in the same transaction that added it, and "
        "an error mid-migration leaves the enum change uncommitted "
        "alongside whatever else was in that transaction."
    ),
    detect=lambda text, node: None,  # handled specially in check_sql (whole-file scope)
    safe_pattern=(
        "Run it as its own top-level statement, outside any BEGIN/COMMIT "
        "the migration tool wraps around other DDL:\n"
        "  1) ALTER TYPE <enum> ADD VALUE 'new_value'; -- own implicit "
        "transaction, committed immediately\n"
        "  2) In a later, separate migration/deploy, reference the new "
        "value in queries or constraints."
    ),
)


# ==========================================================================
# Rule 6 — DROP COLUMN / RENAME without a deprecation step
# ==========================================================================

_RE_DROP_COLUMN = re.compile(r"\bDROP\s+COLUMN\b", re.IGNORECASE)
_RE_RENAME = re.compile(
    r"\bRENAME\s+(?:COLUMN\s+)?\"?[\w]+\"?\s+TO\b|\bRENAME\s+TO\b", re.IGNORECASE
)


def _detect_drop_or_rename(text: str, node: Optional[Any]) -> Optional[bool]:
    if HAS_PGLAST and isinstance(node, pglast.ast.AlterTableStmt):
        return any(
            cmd.subtype == pg_enums.AlterTableType.AT_DropColumn
            for cmd in (node.cmds or ())
        )
    if HAS_PGLAST and isinstance(node, pglast.ast.RenameStmt):
        return node.renameType in (
            pg_enums.ObjectType.OBJECT_COLUMN,
            pg_enums.ObjectType.OBJECT_TABLE,
        )
    if node is not None:
        return None
    if not _RE_ALTER_TABLE.search(text) and "RENAME" not in text.upper():
        return None
    return bool(_RE_DROP_COLUMN.search(text) or _RE_RENAME.search(text))


RULE_DROP_RENAME = Rule(
    id="drop_or_rename_without_deprecation",
    severity=Severity.BLOCK,
    title="DROP COLUMN / RENAME without a deprecation step",
    description=(
        "Dropping or renaming a column/table that's still referenced by "
        "running application code breaks it immediately on deploy - there "
        "is no grace period, even though the DDL itself takes only a "
        "brief lock."
    ),
    detect=_detect_drop_or_rename,
    safe_pattern=(
        "Deprecate before removing:\n"
        "  1) Stop reading/writing the column in application code first, "
        "and ship that deploy.\n"
        "  2) Wait for all old app instances to roll off (a release cycle "
        "or more).\n"
        "  3) Only then: ALTER TABLE <table> DROP COLUMN <col>; (or "
        "RENAME, following the same expand/contract pattern with a new "
        "column + dual-write period instead of an in-place rename)."
    ),
)


# ==========================================================================
# Rule 7 — Missing lock_timeout / statement_timeout guard
# ==========================================================================

_RE_SET_TIMEOUT = re.compile(
    r"\bSET\s+(?:LOCAL\s+)?(?:lock_timeout|statement_timeout)\s*(?:=|\bTO\b)",
    re.IGNORECASE,
)
_RE_RISKY_DDL = re.compile(
    r"\bALTER\s+TABLE\b|\bCREATE\s+(?:UNIQUE\s+)?INDEX\b", re.IGNORECASE
)


def _detect_missing_timeout_guard(statements: list, sql: str) -> list:
    """Whole-file rule: WARN if the script contains ALTER TABLE / CREATE
    INDEX DDL but never sets lock_timeout or statement_timeout anywhere."""
    clean = _strip_comments(sql)
    if _RE_SET_TIMEOUT.search(clean):
        return []
    m = _RE_RISKY_DDL.search(clean)
    if not m:
        return []
    line = clean.count("\n", 0, m.start()) + 1
    return [(line, _snippet(clean, m.start()))]


RULE_MISSING_TIMEOUT_GUARD = Rule(
    id="missing_timeout_guard",
    severity=Severity.WARN,
    title="No lock_timeout / statement_timeout guard around DDL",
    description=(
        "Without a lock_timeout, a DDL statement that's waiting on a lock "
        "can queue behind it indefinitely and pile up other blocked "
        "queries behind that. Setting a timeout turns an indefinite stall "
        "into a fast, safe failure that can be retried."
    ),
    detect=lambda text, node: None,  # handled specially in check_sql (whole-file scope)
    safe_pattern=(
        "Guard the migration session:\n"
        "  SET lock_timeout = '2s';\n"
        "  SET statement_timeout = '30s'; -- adjust for CONCURRENTLY steps, which need it raised/disabled\n"
        "  -- ... your DDL here ..."
    ),
)


# --------------------------------------------------------------------------
# Rule registry
# --------------------------------------------------------------------------

PER_STATEMENT_RULES = (
    RULE_INDEX_CONCURRENTLY,
    RULE_VOLATILE_DEFAULT,
    RULE_UNSAFE_ALTER_COLUMN,
    RULE_FK_NOT_VALID,
    RULE_DROP_RENAME,
)

WHOLE_FILE_RULES = (
    RULE_ALTER_TYPE_ADD_VALUE_IN_TXN,
    RULE_MISSING_TIMEOUT_GUARD,
)

RULES = PER_STATEMENT_RULES + WHOLE_FILE_RULES

# Patterns used only to locate a readable snippet within a statement once a
# rule has already decided it's a hazard (display concern, not detection).
_LOCATOR_PATTERNS = {
    RULE_INDEX_CONCURRENTLY.id: [_RE_CREATE_INDEX],
    RULE_VOLATILE_DEFAULT.id: [_RE_ADD_COLUMN_DEFAULT],
    RULE_UNSAFE_ALTER_COLUMN.id: [_RE_SET_NOT_NULL, _RE_ALTER_TYPE_COL],
    RULE_FK_NOT_VALID.id: [_RE_ADD_FK],
    RULE_DROP_RENAME.id: [_RE_DROP_COLUMN, _RE_RENAME],
}


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def check_sql(sql: str) -> list:
    """Check a SQL migration string against all DDL hazard rules.

    Never raises: unparseable input just falls back to regex-only
    detection for every rule.
    """
    findings = []
    try:
        statements = _split_statements(sql)
    except Exception:
        statements = _split_statements_regex(sql)

    for stmt in statements:
        for rule in PER_STATEMENT_RULES:
            try:
                is_hazard = rule.detect(stmt.text, stmt.node)
            except Exception:
                is_hazard = None
            if not is_hazard:
                continue
            offset, snippet = _locate(stmt.text, _LOCATOR_PATTERNS.get(rule.id, []))
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity.value,
                    line=stmt.line + stmt.text.count("\n", 0, offset),
                    snippet=snippet,
                    message=rule.title,
                    safe_rewrite=rule.safe_pattern,
                )
            )

    for line, snippet in _detect_alter_type_in_txn(statements, sql):
        findings.append(
            Finding(
                rule_id=RULE_ALTER_TYPE_ADD_VALUE_IN_TXN.id,
                severity=RULE_ALTER_TYPE_ADD_VALUE_IN_TXN.severity.value,
                line=line,
                snippet=snippet,
                message=RULE_ALTER_TYPE_ADD_VALUE_IN_TXN.title,
                safe_rewrite=RULE_ALTER_TYPE_ADD_VALUE_IN_TXN.safe_pattern,
            )
        )

    for line, snippet in _detect_missing_timeout_guard(statements, sql):
        findings.append(
            Finding(
                rule_id=RULE_MISSING_TIMEOUT_GUARD.id,
                severity=RULE_MISSING_TIMEOUT_GUARD.severity.value,
                line=line,
                snippet=snippet,
                message=RULE_MISSING_TIMEOUT_GUARD.title,
                safe_rewrite=RULE_MISSING_TIMEOUT_GUARD.safe_pattern,
            )
        )

    findings.sort(key=lambda f: f.line)
    return findings


def _finding_to_dict(finding: Finding) -> dict:
    return dataclasses.asdict(finding)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: ddl_rules.py <path-to-sql-file>", file=sys.stderr)
        sys.exit(1)

    path = sys.argv[1]
    try:
        with open(path, "r", encoding="utf-8") as f:
            sql_text = f.read()
    except OSError as exc:
        print(json.dumps({"error": f"could not read {path}: {exc}"}))
        sys.exit(1)

    results = check_sql(sql_text)
    print(json.dumps([_finding_to_dict(f) for f in results], indent=2))
