#!/usr/bin/env python3
"""
Migration Firewall — PreToolUse hook for postgres-guardrails.

Wired via hooks/hooks.json to fire on every Write/Edit tool call (see the
matcher there). Reads the Claude Code PreToolUse hook payload from stdin,
and for files that look like migrations, checks the (would-be) SQL against
the DDL hazard rules in hooks/lib/ddl_rules.py:

  - Plain .sql migration files are checked directly.
  - Rails (.rb) and Django/Alembic (.py) migration files don't contain SQL
    directly, so we (a) heuristically extract embedded SQL from
    execute("...")/op.execute("...") calls and run it through the same
    rules, and (b) separately pattern-match known framework DSL calls
    (add_index, add_column, op.create_index, op.alter_column, etc.) and map
    them onto the equivalent DDL hazard rule.

On a BLOCK finding, the tool call is denied via the PreToolUse
hookSpecificOutput JSON, with a reason string listing every finding and its
exact safe multi-step rewrite, so Claude can regenerate the migration
correctly on the next turn. On WARN-only findings, the call is allowed but
the warnings are surfaced in the same way. Everything else (wrong tool,
non-migration file, no findings) is a silent allow.

Fails safe: any exception anywhere in this script is caught, logged to
stderr, and the process still exits 0 (allow) — a bug in this hook must
never block a legitimate write.
"""
from __future__ import annotations

import json
import re
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))

import ddl_rules  # noqa: E402
from ddl_rules import Finding, check_sql  # noqa: E402


# --------------------------------------------------------------------------
# Config: which files count as migrations. Add a glob here to extend.
# Supports "**" (any number of path segments), "*" (anything but "/"), "?".
# --------------------------------------------------------------------------

MIGRATION_FILE_PATTERNS = (
    "**/migrations/**/*.sql",
    "**/migrate/**/*.sql",
    "db/migrate/**/*.rb",       # Rails
    "**/migrations/*.py",       # Django / Alembic
    "prisma/migrations/**/*.sql",
)


def _glob_to_regex(pattern: str) -> "re.Pattern[str]":
    pattern = pattern.replace("\\", "/")
    parts = []
    i, n = 0, len(pattern)
    while i < n:
        if pattern[i : i + 3] == "**/":
            parts.append(r"(?:.*/)?")
            i += 3
        elif pattern[i : i + 2] == "**":
            parts.append(r".*")
            i += 2
        elif pattern[i] == "*":
            parts.append(r"[^/]*")
            i += 1
        elif pattern[i] == "?":
            parts.append(r"[^/]")
            i += 1
        else:
            parts.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(parts) + r"$")


_COMPILED_MIGRATION_PATTERNS = tuple(_glob_to_regex(p) for p in MIGRATION_FILE_PATTERNS)


def _matches_migration_pattern(file_path: str) -> bool:
    normalized = file_path.replace("\\", "/")
    return any(p.search(normalized) for p in _COMPILED_MIGRATION_PATTERNS)


# --------------------------------------------------------------------------
# Generic call-parsing helpers, shared by the Ruby and Python DSL detectors.
# ("balanced" means nested parens/quotes inside the call are respected, so
# multi-line calls like `sa.Column(..., server_default=sa.text("now()"))`
# are handled correctly rather than truncated at the first ')'.)
# --------------------------------------------------------------------------

def _extract_balanced_call(text: str, open_paren_pos: int) -> str:
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
    return text[start:]  # unterminated call: best effort


def _find_calls(text: str, name: str):
    """Yield (start_offset, args_text) for every top-level occurrence of
    `name(...)` in text, e.g. name="add_index" or name="op.execute".

    Ruby migration DSLs are commonly called without parens at all (e.g.
    `add_index :users, :email`), so if no '(' immediately follows the
    name, the args are taken to be the rest of the line instead."""
    pattern = re.compile(r"\b" + re.escape(name) + r"\b")
    for m in pattern.finditer(text):
        j = m.end()
        while j < len(text) and text[j] in " \t":
            j += 1
        if j < len(text) and text[j] == "(":
            yield m.start(), _extract_balanced_call(text, j)
        else:
            end = text.find("\n", j)
            if end == -1:
                end = len(text)
            yield m.start(), text[j:end]


def _split_top_level(args: str) -> list:
    """Split call arguments on commas that are not inside nested
    parens/brackets/braces/quotes."""
    parts = []
    depth = 0
    in_str = None
    buf = []
    i, n = 0, len(args)
    while i < n:
        ch = args[i]
        if in_str:
            buf.append(ch)
            if ch == "\\" and i + 1 < n:
                buf.append(args[i + 1])
                i += 2
                continue
            if ch == in_str:
                in_str = None
            i += 1
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
        i += 1
    if buf:
        parts.append("".join(buf))
    return [p.strip() for p in parts]


def _get_kwarg_value(parts: list, key: str, ruby: bool) -> "str | None":
    sep = ":" if ruby else "="
    pat = re.compile(rf"^{re.escape(key)}\s*{re.escape(sep)}\s*(.+)$", re.DOTALL)
    for p in parts:
        m = pat.match(p.strip())
        if m:
            return m.group(1).strip()
    return None


def _snippet_line(content: str, pos: int, length: int = 120) -> str:
    end = content.find("\n", pos)
    if end == -1:
        end = len(content)
    seg = content[pos : min(end, pos + length)]
    seg = re.sub(r"\s+", " ", seg).strip()
    return seg


def _line_of(content: str, pos: int) -> int:
    return content.count("\n", 0, pos) + 1


def _finding_from_rule(rule: ddl_rules.Rule, line: int, snippet: str, source_label: str) -> Finding:
    return Finding(
        rule_id=rule.id,
        severity=rule.severity.value,
        line=line,
        snippet=snippet,
        message=f"{rule.title} [{source_label}]",
        safe_rewrite=rule.safe_pattern,
    )


def _offset_finding(f: Finding, base_line: int, source_label: str) -> Finding:
    """Re-anchor a Finding produced by check_sql() on an *extracted* SQL
    fragment back onto the full file's line numbers."""
    return Finding(
        rule_id=f.rule_id,
        severity=f.severity,
        line=base_line + (f.line - 1),
        snippet=f.snippet,
        message=f"{f.message} [{source_label}]",
        safe_rewrite=f.safe_rewrite,
    )


# --------------------------------------------------------------------------
# Volatile-default heuristics for framework DSLs (mirrors the SQL-literal
# classifier in ddl_rules, but for Ruby/Python expression syntax).
# --------------------------------------------------------------------------

_RE_QUOTED = re.compile(r"^(['\"]).*\1$", re.DOTALL)
_RE_NUMBER = re.compile(r"^-?\d+(\.\d+)?$")


def _is_volatile_ruby_default(expr: str) -> bool:
    expr = expr.strip()
    if expr.startswith("->") or expr.startswith("proc") or expr.startswith("lambda"):
        return True  # deferred/callable default, evaluated per row
    if _RE_QUOTED.match(expr) or _RE_NUMBER.match(expr) or expr.lower() in ("true", "false", "nil"):
        return False
    if re.match(r"^[\w:]+(\.[\w!?]+)+", expr) or re.match(r"^[a-zA-Z_]\w*\s*\(", expr):
        return True  # e.g. SecureRandom.uuid, Time.current, some_call(...)
    return True  # unrecognized shape: be conservative


def _is_volatile_python_default(expr: str) -> bool:
    expr = expr.strip()
    m = re.match(r"^sa\.text\(\s*(['\"])(.*)\1\s*\)$", expr, re.DOTALL)
    if m:
        return ddl_rules._is_volatile_default_text(m.group(2))
    if _RE_QUOTED.match(expr) or _RE_NUMBER.match(expr) or expr in ("True", "False", "None"):
        return False
    if re.match(r"^[\w\.]+\(", expr):
        return True  # e.g. func.now(), some.call(...)
    return True  # unrecognized shape: be conservative


# --------------------------------------------------------------------------
# Embedded-SQL extraction: raw SQL wrapped in execute(...) / op.execute(...)
# --------------------------------------------------------------------------

_RE_RUBY_EXECUTE_STR = re.compile(r"execute\(\s*(['\"])((?:\\.|(?!\1).)*)\1\s*\)", re.DOTALL)
_RE_RUBY_EXECUTE_HEREDOC = re.compile(
    r"execute\(\s*<<[-~]?(['\"]?)(\w+)\1\s*\n(.*?)\n[ \t]*\2\b", re.DOTALL
)


def _findings_from_embedded_sql_ruby(content: str) -> list:
    findings = []
    for m in _RE_RUBY_EXECUTE_STR.finditer(content):
        base_line = _line_of(content, m.start())
        for f in check_sql(m.group(2)):
            findings.append(_offset_finding(f, base_line, "embedded SQL: execute(...)"))
    for m in _RE_RUBY_EXECUTE_HEREDOC.finditer(content):
        base_line = _line_of(content, m.start())
        for f in check_sql(m.group(3)):
            findings.append(_offset_finding(f, base_line, "embedded SQL: execute(<<~SQL)"))
    return findings


_RE_PY_EXECUTE_TRIPLE = re.compile(r'op\.execute\(\s*("""|\'\'\')(.*?)\1\s*\)', re.DOTALL)
_RE_PY_EXECUTE_STR = re.compile(r"op\.execute\(\s*(['\"])((?:\\.|(?!\1).)*)\1\s*\)", re.DOTALL)


def _findings_from_embedded_sql_python(content: str) -> list:
    findings = []
    consumed = []
    for m in _RE_PY_EXECUTE_TRIPLE.finditer(content):
        consumed.append((m.start(), m.end()))
        base_line = _line_of(content, m.start())
        for f in check_sql(m.group(2)):
            findings.append(_offset_finding(f, base_line, "embedded SQL: op.execute(...)"))
    for m in _RE_PY_EXECUTE_STR.finditer(content):
        if any(s <= m.start() < e for s, e in consumed):
            continue
        base_line = _line_of(content, m.start())
        for f in check_sql(m.group(2)):
            findings.append(_offset_finding(f, base_line, "embedded SQL: op.execute(...)"))
    return findings


# --------------------------------------------------------------------------
# Framework DSL mapping: Rails (ActiveRecord migrations)
# --------------------------------------------------------------------------

def _findings_from_rails_dsl(content: str) -> list:
    findings = []

    for pos, args in _find_calls(content, "add_index"):
        parts = _split_top_level(args)
        algo = _get_kwarg_value(parts, "algorithm", ruby=True)
        if not (algo and "concurrently" in algo.lower()):
            findings.append(_finding_from_rule(
                ddl_rules.RULE_INDEX_CONCURRENTLY, _line_of(content, pos),
                _snippet_line(content, pos), "Rails DSL: add_index",
            ))

    for pos, args in _find_calls(content, "add_column"):
        parts = _split_top_level(args)
        default = _get_kwarg_value(parts, "default", ruby=True)
        if default and _is_volatile_ruby_default(default):
            findings.append(_finding_from_rule(
                ddl_rules.RULE_VOLATILE_DEFAULT, _line_of(content, pos),
                _snippet_line(content, pos), "Rails DSL: add_column default",
            ))

    for pos, args in _find_calls(content, "add_foreign_key"):
        parts = _split_top_level(args)
        validate = _get_kwarg_value(parts, "validate", ruby=True)
        if not (validate and validate.strip().lower() == "false"):
            findings.append(_finding_from_rule(
                ddl_rules.RULE_FK_NOT_VALID, _line_of(content, pos),
                _snippet_line(content, pos), "Rails DSL: add_foreign_key",
            ))

    for pos, args in _find_calls(content, "change_column_null"):
        parts = _split_top_level(args)
        if len(parts) >= 3 and parts[2].strip().lower() == "false":
            findings.append(_finding_from_rule(
                ddl_rules.RULE_UNSAFE_ALTER_COLUMN, _line_of(content, pos),
                _snippet_line(content, pos), "Rails DSL: change_column_null",
            ))

    for pos, _args in _find_calls(content, "change_column"):
        findings.append(_finding_from_rule(
            ddl_rules.RULE_UNSAFE_ALTER_COLUMN, _line_of(content, pos),
            _snippet_line(content, pos), "Rails DSL: change_column",
        ))

    for name in ("remove_column", "rename_column", "rename_table"):
        for pos, _args in _find_calls(content, name):
            findings.append(_finding_from_rule(
                ddl_rules.RULE_DROP_RENAME, _line_of(content, pos),
                _snippet_line(content, pos), f"Rails DSL: {name}",
            ))

    return findings


# --------------------------------------------------------------------------
# Framework DSL mapping: Django / Alembic
# --------------------------------------------------------------------------

def _findings_from_python_dsl(content: str) -> list:
    findings = []

    for pos, args in _find_calls(content, "op.create_index"):
        parts = _split_top_level(args)
        conc = _get_kwarg_value(parts, "postgresql_concurrently", ruby=False)
        if not (conc and conc.strip() == "True"):
            findings.append(_finding_from_rule(
                ddl_rules.RULE_INDEX_CONCURRENTLY, _line_of(content, pos),
                _snippet_line(content, pos), "Alembic DSL: op.create_index",
            ))

    for m in re.finditer(r"\bAddIndex\s*\(", content):
        findings.append(_finding_from_rule(
            ddl_rules.RULE_INDEX_CONCURRENTLY, _line_of(content, m.start()),
            _snippet_line(content, m.start()), "Django DSL: AddIndex (use AddIndexConcurrently)",
        ))

    for pos, args in _find_calls(content, "op.add_column"):
        parts = _split_top_level(args)
        server_default = _get_kwarg_value(parts, "server_default", ruby=False)
        if server_default and _is_volatile_python_default(server_default):
            findings.append(_finding_from_rule(
                ddl_rules.RULE_VOLATILE_DEFAULT, _line_of(content, pos),
                _snippet_line(content, pos), "Alembic DSL: op.add_column server_default",
            ))

    for pos, args in _find_calls(content, "op.alter_column"):
        parts = _split_top_level(args)
        nullable = _get_kwarg_value(parts, "nullable", ruby=False)
        type_ = _get_kwarg_value(parts, "type_", ruby=False)
        if (nullable and nullable.strip() == "False") or type_:
            findings.append(_finding_from_rule(
                ddl_rules.RULE_UNSAFE_ALTER_COLUMN, _line_of(content, pos),
                _snippet_line(content, pos), "Alembic DSL: op.alter_column",
            ))

    for name, label in (
        ("op.drop_column", "Alembic DSL: op.drop_column"),
        ("op.rename_table", "Alembic DSL: op.rename_table"),
        ("migrations.RenameField", "Django DSL: RenameField"),
        ("migrations.RenameModel", "Django DSL: RenameModel"),
        ("migrations.RemoveField", "Django DSL: RemoveField"),
    ):
        for pos, _args in _find_calls(content, name):
            findings.append(_finding_from_rule(
                ddl_rules.RULE_DROP_RENAME, _line_of(content, pos),
                _snippet_line(content, pos), label,
            ))

    return findings


# --------------------------------------------------------------------------
# Dispatch by file type
# --------------------------------------------------------------------------

def _findings_for_file(file_path: str, content: str) -> list:
    suffix = Path(file_path).suffix.lower()
    if suffix == ".sql":
        return check_sql(content)
    if suffix == ".rb":
        return _findings_from_embedded_sql_ruby(content) + _findings_from_rails_dsl(content)
    if suffix == ".py":
        return _findings_from_embedded_sql_python(content) + _findings_from_python_dsl(content)
    return []


# --------------------------------------------------------------------------
# Reconstructing the would-be file content for Write vs. Edit tool calls
# --------------------------------------------------------------------------

def _resolve_content(tool_name: str, tool_input: dict) -> str:
    if tool_name == "Write":
        return tool_input.get("content") or ""

    # Edit: tool_input has file_path/old_string/new_string/replace_all, not
    # a full "content" field. Reconstruct the post-edit file so rules that
    # depend on surrounding context (e.g. whole-file timeout/txn scans)
    # still see the real picture.
    file_path = tool_input.get("file_path") or ""
    old_string = tool_input.get("old_string", "")
    new_string = tool_input.get("new_string", "")
    replace_all = bool(tool_input.get("replace_all", False))
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            original = f.read()
    except OSError:
        # File not readable (new/renamed/permissions) — fall back to
        # checking just the text being inserted, in isolation.
        return new_string

    if old_string and old_string in original:
        return original.replace(old_string, new_string, -1 if replace_all else 1)
    # old_string not found verbatim - unusual, but don't silently skip the
    # check: fail toward detecting rather than missing a hazard.
    return original + "\n" + new_string


# --------------------------------------------------------------------------
# Response formatting
# --------------------------------------------------------------------------

def _indent(text: str, prefix: str = "      ") -> str:
    return "\n".join(prefix + line for line in text.splitlines())


def _format_reason(findings: list) -> str:
    blocks = [f for f in findings if f.severity == "BLOCK"]
    warns = [f for f in findings if f.severity == "WARN"]
    lines = []

    if blocks:
        lines.append(
            f"Migration Firewall BLOCKED this write: {len(blocks)} "
            f"lock-hazardous DDL pattern(s) found. Rewrite using the safe "
            f"pattern for each finding below, then retry.\n"
        )
        for f in blocks:
            lines.append(f"- [{f.rule_id}] line {f.line}: {f.message}")
            lines.append(f"  Found: {f.snippet}")
            lines.append("  Safe rewrite:")
            lines.append(_indent(f.safe_rewrite))
            lines.append("")

    if warns:
        if blocks:
            lines.append(f"Additionally, {len(warns)} warning(s) (non-blocking):")
        else:
            lines.append(f"Migration Firewall: {len(warns)} warning(s) (write allowed):")
        for f in warns:
            lines.append(f"- [{f.rule_id}] line {f.line}: {f.message} — {f.snippet}")

    return "\n".join(lines)


def _emit(permission_decision: str, reason: str) -> None:
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": permission_decision,
            "permissionDecisionReason": reason,
        }
    }))


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main() -> None:
    raw = sys.stdin.read()
    data = json.loads(raw)

    tool_name = data.get("tool_name")
    if tool_name not in ("Write", "Edit"):
        return  # not a file-writing tool: nothing to check

    tool_input = data.get("tool_input") or {}
    file_path = tool_input.get("file_path") or ""
    if not _matches_migration_pattern(file_path):
        return  # not a migration file: allow silently

    content = _resolve_content(tool_name, tool_input)
    findings = _findings_for_file(file_path, content)
    if not findings:
        return  # clean: allow silently

    blocks = [f for f in findings if f.severity == "BLOCK"]
    if blocks:
        _emit("deny", _format_reason(findings))
        return

    _emit("allow", _format_reason(findings))


if __name__ == "__main__":
    try:
        main()
    except Exception:  # fail safe: never block on our own bug
        print(
            "migration_firewall: internal error, failing open (allowing "
            f"the write).\n{traceback.format_exc()}",
            file=sys.stderr,
        )
    sys.exit(0)
