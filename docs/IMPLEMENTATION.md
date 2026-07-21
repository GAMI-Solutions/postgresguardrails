# Implementation

Internal documentation for contributors and reviewers. Covers how the five
components actually work, the data contracts between them, and the
reasoning behind the design decisions that aren't obvious from the code
alone. If you're looking for what this plugin does and why, see
`README.md`; this document is about how.

## 1. Architecture overview

The component that matters most for correctness is the Migration Firewall,
because it's the only piece that runs unattended, on every write, with no
opportunity for a human to review first. Everything else is invoked
on-demand (a skill Claude reaches for, a subagent you delegate to, a slash
command you type).

The firewall's flow, for a single Write or Edit tool call:

```
 Claude decides to write/edit a file
            |
            v
 +----------------------------+
 | Claude Code PreToolUse     |   matcher: "Write|Edit"  (hooks/hooks.json)
 | hook dispatch              |
 +--------------+-------------+
                |  JSON on stdin: {tool_name, tool_input, ...}
                v
 +----------------------------------------------------+
 | hooks/migration_firewall.py                        |
 |                                                      |
 |  1. tool_name in (Write, Edit)?  -- else: exit silently, allow
 |  2. file_path matches a migration glob?  -- else: exit silently, allow
 |  3. resolve the would-be file content:              |
 |       Write -> tool_input.content                   |
 |       Edit  -> read file from disk, apply            |
 |                old_string -> new_string              |
 |  4. dispatch by file suffix:                         |
 |       .sql -> ddl_rules.check_sql(content)           |
 |       .rb  -> embedded-SQL extraction + Rails DSL map |
 |       .py  -> embedded-SQL extraction + Alembic/Django DSL map |
 +--------------------------+---------------------------+
                            |  list[Finding]
                            v
                 +----------------------+
                 | any severity==BLOCK? |
                 +----------+-----------+
                   yes |         | no
                       v         v
              permissionDecision   any findings at all?
                = "deny"              yes -> "allow" + warnings in reason
                                       no  -> exit silently (default allow)
                       |
                       v
              JSON on stdout: {hookSpecificOutput: {...}}
                       |
                       v
         +---------------------------------------+
         | Claude Code: tool call denied.         |
         | permissionDecisionReason is surfaced    |
         | to Claude as the reason the write failed |
         +--------------------+--------------------+
                              |
                              v
              Claude reads the reason (which rule fired,
              the exact line, and the safe multi-step
              rewrite for that rule) and regenerates the
              migration on its next turn using the safe
              pattern -- then the same hook runs again on
              the retry.
```

The loop closes itself: the firewall doesn't just say no, it hands back
the specific rewrite Claude needs to try next, in the same response that
denies the call. In practice this means Claude self-corrects within the
same conversation without a human needing to explain *why* the write
failed.

Everything downstream of "did this file match a migration pattern" is
`hooks/lib/ddl_rules.py` — the firewall script itself is just: read stdin,
figure out what file changed and what its new content would be, hand the
SQL (or extracted/mapped SQL-equivalent) to the rules engine, format the
result. All the actual hazard detection lives in one file so it can be
unit-tested and reused (the CI prompt shells out to the exact same
`migration_firewall.py`, not a reimplementation — see section 4).

## 2. Component deep dive

### 2.1 `hooks/lib/ddl_rules.py` — the rules engine

**Responsibility:** given a string of SQL, return every lock-hazard it
contains, each with a severity, a location, and the exact safe rewrite.
Pure function, no I/O beyond the `__main__` CLI wrapper. This file has no
knowledge of Claude Code, hooks, or file paths — it just knows SQL.

**Key functions:**

- `_split_statements(sql) -> list[_Stmt]` — the entry point for turning raw
  SQL into individually-checkable statements. Tries `pglast.parse_sql`
  first; on any exception, falls back to `_split_statements_regex`, a
  hand-written quote-aware scanner that splits on `;` outside of `'...'`
  and `"..."`. Both paths track line numbers, but only the pglast path
  gives an AST node per statement — `_Stmt.node` is `None` in the fallback
  path, and every rule's `detect()` function is written to treat `node is
  None` as "fall back to regex for this statement."
- `check_sql(sql) -> list[Finding]` — runs every per-statement rule
  against every statement, then runs the two whole-file rules once against
  the full text, sorts everything by line, and returns it. Never raises:
  each rule's `detect()` call is individually wrapped in try/except, so
  one rule's bug (or one statement's unexpected AST shape) degrades to "no
  opinion" for that rule/statement rather than aborting the whole check.
- Seven `Rule` objects, each a `detect(text, node) -> Optional[bool]`
  function. The three-value return matters: `True` means hazard found,
  `False` means the rule looked and confirmed this specific statement is
  safe, `None` means "not applicable" (wrong statement type entirely,
  distinct from "applicable and safe"). This distinction lets
  `_LOCATOR_PATTERNS` skip snippet-location work for statements a rule has
  no opinion on.

**Data contract — `Finding`:**

```python
Finding(
    rule_id: str,        # e.g. "index_no_concurrently"
    severity: str,       # "BLOCK" | "WARN"
    line: int,           # 1-based, within the file/SQL string passed in
    snippet: str,        # ~100 chars of matched source, whitespace-collapsed
    message: str,        # the Rule's title, e.g. "CREATE INDEX without CONCURRENTLY"
    safe_rewrite: str,   # the Rule's safe_pattern — the exact rewrite to hand back
)
```

`check_sql()`'s CLI entry point (`__main__`) serializes a list of these
via `dataclasses.asdict` to JSON — this is also the shape `hooks/tests`
and the CI prompt both expect on stdout when they invoke this module
directly.

### 2.2 `hooks/migration_firewall.py` — the PreToolUse hook

**Responsibility:** everything ddl_rules.py doesn't do — recognizing
migration files, reconstructing an Edit's post-write content, extracting
SQL from framework migration files that aren't SQL themselves, and
formatting/emitting the Claude Code hook response.

**Hook stdin contract** (what Claude Code sends, per its PreToolUse hook
spec):

```json
{
  "session_id": "...",
  "transcript_path": "...",
  "cwd": "...",
  "hook_event_name": "PreToolUse",
  "tool_name": "Write",
  "tool_input": {
    "file_path": "/abs/path/to/migration.sql",
    "content": "..."
  }
}
```

For `Edit`, `tool_input` has `file_path`, `old_string`, `new_string`, and
optionally `replace_all`, instead of `content`. `_resolve_content()`
handles both shapes: for `Write` it's a direct field read; for `Edit` it
reads the current file off disk and applies the same replacement Claude
Code itself is about to apply, so whole-file rules (the timeout guard and
the transaction-scoped enum check) see accurate surrounding context, not
just the new fragment in isolation. If the file can't be read (new file,
permissions), it falls back to checking `new_string` alone rather than
skipping the check.

**Hook stdout contract** (what this hook emits — only on BLOCK or WARN
findings; silent/no-stdout otherwise, which Claude Code treats as a
default allow):

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Migration Firewall BLOCKED this write: 1 lock-hazardous DDL pattern(s) found. ...\n- [index_no_concurrently] line 1: CREATE INDEX without CONCURRENTLY\n  Found: CREATE INDEX idx_orders_customer ON orders (customer_id);\n  Safe rewrite:\n      Use CREATE INDEX CONCURRENTLY instead, ..."
  }
}
```

`permissionDecision` is `"deny"` if any finding is BLOCK severity, `
"allow"` (explicit, with warnings in the reason) if there are only WARN
findings, and the process prints nothing at all if there are zero
findings — an explicit `"allow"` and a silent allow are behaviorally
identical to Claude Code, so the silent path is preferred whenever there's
nothing worth saying.

**File-type dispatch** (`_findings_for_file`):

| Suffix | Path |
| :-- | :-- |
| `.sql` | `ddl_rules.check_sql(content)` directly |
| `.rb` | `_findings_from_embedded_sql_ruby` (regex-extracts `execute("...")` and heredoc `execute(<<~SQL...)` bodies, runs each through `check_sql`) + `_findings_from_rails_dsl` (pattern-matches `add_index`, `add_column`, `add_foreign_key`, `change_column_null`, `change_column`, `remove_column`, `rename_column`, `rename_table` calls and maps each to the equivalent `ddl_rules.Rule`) |
| `.py` | `_findings_from_embedded_sql_python` (regex-extracts `op.execute("""...""")` / `op.execute("...")`) + `_findings_from_python_dsl` (maps `op.create_index`, Django `AddIndex`, `op.add_column`, `op.alter_column`, `op.drop_column`, `op.rename_table`, `migrations.RenameField`/`RenameModel`/`RemoveField`) |

The DSL mappers don't re-derive hazard logic — they parse just enough of
the call (which kwarg is present, what value it holds) to decide *whether*
a given `ddl_rules.Rule` applies, then construct a `Finding` carrying that
rule's existing `id`/`severity`/`safe_rewrite`, tagged with a
`[source label]` suffix on the message (e.g. `"... [Rails DSL:
add_index]"`) so the BLOCK reason makes clear which line of *framework*
code triggered a *SQL-level* hazard. This is why there's only one set of
seven safe rewrites in the whole project instead of three (SQL, Rails,
Alembic) — the DSL layer is a translation layer, not a second rule set.

**Call parsing:** `_find_calls(text, name)` yields `(offset, args_text)`
for each occurrence of `name(...)` or, for Ruby's paren-less call syntax
(`add_index :users, :email`), `name <rest of line>`. `_extract_balanced_call`
respects nested parens and quotes so multi-line calls aren't truncated
early. `_split_top_level` and `_get_kwarg_value` then pull out individual
keyword arguments (`algorithm: :concurrently`, `default: -> { ... }`,
`server_default=sa.text("now()")`) for the volatile-default and
concurrently checks.

### 2.3 Query Doctor (`skills/query-doctor/`)

**Responsibility:** connect to a real database, run a real `EXPLAIN`, and
turn the plan into a diagnosis a human can act on — this is the one
component that touches a live database interactively (always read-only in
effect, via rollback; see section 4 on why).

**`explain_runner.py`** — `run_explain(conninfo, sql, analyze, timeout_ms)
-> dict`. Output contract:

```json
{ "sql": "<original query text>", "analyze": true, "plan": [ { "Plan": {...}, "Planning Time": 0.12, "Execution Time": 4.3 } ] }
```

`plan` is exactly what Postgres's `EXPLAIN (FORMAT JSON)` returns — a
one-element list containing the plan tree plus timing metadata — passed
through unmodified so downstream tools work whether they got their input
from this script or straight from `psql`.

**`plan_analyzer.py`** — `analyze_plan(plan_json) -> list[Finding]`
(a distinct `Finding` dataclass from `ddl_rules.Finding` — same name,
different shape, don't confuse them):

```python
Finding(severity: str, rule: str, node_type: str, relation: Optional[str], message: str, fix: str)
```

Walks the plan tree once, running four per-node checks
(`_check_seq_scan`, `_check_row_estimate`, `_check_disk_spill`,
`_check_index_filter_removal`) plus one check that inspects a node's
children (`_check_nested_loop`, since the hazard is about the *inner*
side's loop count, which lives one level down from the `Nested Loop` node
itself). Every threshold is a top-of-file constant
(`SEQ_SCAN_ROW_THRESHOLD`, `ESTIMATE_RATIO_THRESHOLD`, etc.) rather than
inline in a function — the intent is that these get tuned per-deployment
without touching logic.

**`index_advisor.py`** — derives index candidates from the plan tree
itself (`Filter`, `Index Cond`, `Recheck Cond`, `Hash Cond`, `Merge Cond`,
`Sort Key`, `Group Key`), not by parsing the query's SQL text. Two
tree-walks on purpose (`_walk_equality` before `_walk_sort_group`) so
equality/join columns always precede sort columns in a composite
candidate, matching the standard "equality columns first" indexing
convention regardless of where each node sits in the tree — see section 4
for why a single walk got this wrong. If `hypopg` is present
(`SELECT 1 FROM pg_extension WHERE extname='hypopg'`), each candidate is
tested via `hypopg_create_index` and a second `EXPLAIN (FORMAT JSON)` —
never `ANALYZE` — to compare `Total Cost` before/after, then
`hypopg_reset()` before the next candidate.

### 2.4 RLS Tenant Auditor (`agents/rls-auditor.md` + `skills/rls-audit/`)

**Responsibility:** find multi-tenant tables without correct Row Level
Security, and produce a patch + tests a human applies — never applies
anything itself except inside a container it started and will tear down.

**`schema_scan.py`** — offline parser, never connects to a database (it
consumes the *output* of `pg_dump --schema-only`, run by the subagent, not
by this script). `scan_schema(sql) -> list[TableInfo]`:

```python
TableInfo(
    schema: str, name: str, columns: list[ColumnInfo],
    rls_enabled: bool, rls_forced: bool, policies: list[PolicyInfo],
    tenant_column_guess: Optional[str],
    tenant_column_confidence: float,             # 0.0-1.0
    tenant_column_confidence_label: str,          # HIGH / MEDIUM / LOW / NONE
    tenant_column_reasons: list[str],
)
```

Parses one statement at a time — a deliberate difference from
`ddl_rules.py`'s all-or-nothing `_split_statements`. A multi-thousand-line
`pg_dump` is far more likely to contain one statement pglast can't parse
(some extension-specific DDL) than a hand-written migration is, so
`_try_parse_one` isolates failures to the single statement they occur in;
the rest of the scan proceeds normally. `_guess_tenant_column` scores each
column against `EXACT_TENANT_COLUMN_NAMES` (0.7), `FUZZY_NAME_SUBSTRINGS`
(0.3), and a bonus (0.4) if the column is a foreign key into a table whose
name matches `TENANT_TABLE_NAME_PATTERNS` — these three signals can stack
(a column can be both an exact name match and an FK into a tenants table),
so scores are additive up to 1.0.

**`isolation_test.sql`** — a pgTAP template, not a script; the subagent
fills in its twelve `{{PLACEHOLDER}}` tokens per table and writes one
instantiated file per audited table. It asserts, in order: RLS is enabled,
RLS is forced, tenant A can read its own row, tenant A cannot read tenant
B's row, tenant A cannot write/relabel a row into tenant B, tenant B's
symmetric checks, and that a session with no tenant context set fails
closed rather than defaulting to "see everything."

**`agents/rls-auditor.md`** ties these together as a six-step subagent
workflow (get schema → scan → classify each flagged table into one of four
gap categories → generate the patch → generate tests → offer to verify in
a `docker run --rm` Postgres container, always torn down after). The
"never touches production" rule is enforced entirely by instruction, not
by code — this subagent has `Bash` access and could technically run
anything. That's a deliberate trust boundary; see section 4.

### 2.5 Slash commands (`commands/pg/`)

Thin, stateless wrappers with no logic of their own:

- `/pg:check-migration <file>` — pipes the target file through a
  synthetic hook payload straight into `migration_firewall.py`, reusing
  the exact same script the live hook runs (not a reimplementation).
- `/pg:doctor <query-or-file>` — points at `skills/query-doctor/SKILL.md`'s
  workflow.
- `/pg:audit-rls` — delegates to the `rls-auditor` subagent.
- `/pg:upgrade-check <from> <to>` — the one command with its own
  investigation logic (there's no standalone "upgrade checker" component);
  it references `ddl_rules.py`'s migration path patterns and
  `rls-auditor.md`'s schema-dump step to scope its scan, then writes
  `upgrade_runbook_<from>_to_<to>.md`.

### 2.6 CI (`ci/`, `.github/workflows/postgres-guardrails.yml`)

**`plan_diff.py`** — `diff_file(conninfo, path, base_ref, head_ref,
timeout_ms, threshold_pct) -> DiffResult`. Reads the query file's content
at two git refs via `git show <ref>:<path>` (not by checking out either
ref — this is a read of git object storage, so it needs the ref to be
*reachable*, typically via `fetch-depth: 0` or an explicit `git fetch` of
the base branch in CI, but does not need a working-tree checkout of it).
Runs `EXPLAIN (FORMAT JSON)` — deliberately never `ANALYZE` — against both
versions on the *same* live connection, and flags `is_regression = True`
if `(head_cost - base_cost) / base_cost * 100 > threshold_pct` (default
20%). A new file at the head ref (no baseline) is reported as a note, not
an error or a regression.

**`ci/prompt.txt` + `postgres-guardrails.yml`** — the workflow checks out
both the PR and the plugin itself (as `.postgres-guardrails/`, a separate
checkout step so this workflow file is portable to any adopting repo),
then runs `claude -p "$(cat .postgres-guardrails/ci/prompt.txt)" --tools
"Bash,Read"` headless. The prompt instructs Claude to run the *same*
`migration_firewall.py` invocation `/pg:check-migration` uses (via the
synthetic-stdin-payload trick) against every changed migration file, and
`plan_diff.py` against every changed non-migration `.sql` file if
`DATABASE_URL` is set, then write a PR comment ending in exactly
`POSTGRES_GUARDRAILS_RESULT: BLOCK` or `...: PASS`. The workflow's final
step greps for that literal marker to set the job's exit code — the
marker string is the entire data contract between the LLM's free-form
comment and the YAML's pass/fail logic.

## 3. Rules catalogue

All seven rules live in `hooks/lib/ddl_rules.py`. "Lock" is the lock
Postgres takes on the affected table for the hazardous operation, not
necessarily the lightest lock the statement ever takes.

| Rule ID | Severity | Detects | Why it's dangerous | Safe pattern | PG version notes |
| :-- | :-- | :-- | :-- | :-- | :-- |
| `index_no_concurrently` | BLOCK | `CREATE INDEX` (or `CREATE UNIQUE INDEX`) without `CONCURRENTLY` | Plain `CREATE INDEX` takes a `SHARE` lock for the whole build, blocking all writes to the table until it finishes. | `CREATE INDEX CONCURRENTLY IF NOT EXISTS ...`, run outside a transaction block, with `statement_timeout` raised/disabled since concurrent builds can be slow; `DROP INDEX CONCURRENTLY` + retry if it fails partway. | `CONCURRENTLY` cannot run inside a transaction block on any supported version — this is why the safe rewrite is a standalone statement, not a step inside the same `BEGIN...COMMIT` as other DDL. |
| `add_column_volatile_default` | BLOCK | `ADD COLUMN ... DEFAULT <expr>` where `<expr>` is a function call, or any shape that isn't a recognized constant literal | A *constant* default is metadata-only since PG11. A *volatile* default (`now()`, `random()`, `gen_random_uuid()`, `nextval(...)`) can't be stored as a single value for all existing rows, so Postgres still rewrites the entire table under `ACCESS EXCLUSIVE`. | Add the column nullable with no default; backfill in batches; `ALTER COLUMN ... SET DEFAULT` afterward (applies to future inserts only); optionally add `NOT NULL` later via the `NOT VALID` pattern. | Safe-by-default behavior for *constant* defaults requires PG11+. The rule's AST path distinguishes `FuncCall` (hazard) from `A_Const` (safe) directly; the regex path classifies by shape (string/numeric/bool/NULL literal = safe, anything matching a function-call pattern or unrecognized = hazard, conservatively). |
| `unsafe_alter_column` | BLOCK | `ALTER COLUMN ... SET NOT NULL` or `ALTER COLUMN ... TYPE ...` | Both force a full table scan under `ACCESS EXCLUSIVE` (a `TYPE` change also rewrites the table), blocking all reads and writes for the duration. | For `NOT NULL`: add a `CHECK (<col> IS NOT NULL) NOT VALID` constraint, `VALIDATE CONSTRAINT` separately (lighter lock, scans without blocking writes), then `SET NOT NULL` (fast — the planner reuses the validated check), then drop the now-redundant check constraint. For `TYPE`: add a new column of the new type, backfill in batches, swap references, drop the old column. | The `NOT VALID` check-constraint trick for `NOT NULL` depends on the planner being able to reuse an already-validated `CHECK` to make a subsequent `SET NOT NULL` skip its own table scan — behavior present from PG12 onward. This is the PG12+ dependency called out in the README's "what this does not do" section. |
| `fk_without_not_valid` | BLOCK | `ADD CONSTRAINT ... FOREIGN KEY` without `NOT VALID` | Validating a new FK against every existing row takes a lock on both tables (`SHARE ROW EXCLUSIVE`) for as long as the scan takes, stalling writes on both sides on large tables. | `ADD CONSTRAINT ... FOREIGN KEY (...) REFERENCES ... NOT VALID` (fast, no scan, constraint enforced for all *new* writes immediately) then `VALIDATE CONSTRAINT` as a separate statement (scans with a much lighter lock, can be run off-peak). | No version dependency; `NOT VALID` FKs have worked this way since their introduction (PG9.1). |
| `alter_type_add_value_in_txn` | BLOCK | `ALTER TYPE ... ADD VALUE` occurring inside an explicit `BEGIN...COMMIT`/`ROLLBACK` block | Before PG12 this simply isn't allowed. On PG12+ it's allowed, but the new value can't be *used* in the same transaction that added it, and if anything else in that transaction later errors, the enum addition rolls back too, along with whatever else was bundled in. | Run `ALTER TYPE <enum> ADD VALUE 'x'` as its own top-level statement (own implicit transaction, committed immediately, outside any transaction wrapper a migration tool applies); reference the new value from a separate, later migration/deploy. | This is a whole-file rule, not per-statement — the hazard depends on transactional context surrounding the statement, which a single-statement `detect()` can't see. Implemented via `_detect_alter_type_in_txn`, which walks parsed `TransactionStmt`/`AlterEnumStmt` nodes tracking BEGIN/COMMIT state (AST path), or scans raw text for the nearest enclosing `BEGIN`/`COMMIT` pair (regex fallback). |
| `drop_or_rename_without_deprecation` | BLOCK | `DROP COLUMN`, or `RENAME COLUMN`/`RENAME TABLE` | The DDL itself takes only a brief lock, but if application code is still reading/writing the dropped/renamed thing, it breaks immediately on deploy — there's no grace period, unlike the other rules where the *lock* is the danger. | Stop reading/writing the column in app code first and ship that deploy; wait a full release cycle for old instances to roll off; only then run the `DROP`/`RENAME` — or better, expand/contract with a new column and a dual-write period instead of an in-place rename. | No version dependency. This is the one rule where the danger is a correctness/deploy-ordering hazard rather than a lock/performance hazard — included because it's just as capable of taking production down as the lock hazards are. |
| `missing_timeout_guard` | WARN | A file containing `ALTER TABLE` or `CREATE INDEX` DDL that never sets `lock_timeout` or `statement_timeout` anywhere in the file | Without a `lock_timeout`, a DDL statement waiting on a lock held by ordinary traffic queues indefinitely, and other queries pile up waiting behind *it* — an indefinite stall instead of a fast, retryable failure. | `SET lock_timeout = '2s'; SET statement_timeout = '30s';` before the DDL (raise/disable `statement_timeout` specifically around a `CONCURRENTLY` step, which can legitimately run long). | No version dependency. WARN, not BLOCK, because a missing timeout guard doesn't guarantee a bad outcome the way the other six patterns do — it's a "you should probably also do this" rather than a "this will definitely hurt." Also a whole-file rule (`_detect_missing_timeout_guard`), since the guard and the risky DDL can be in different statements within the same file. |

## 4. Design decisions and trade-offs

**Why fail-open, everywhere.** Every script in this plugin that can block
something — the hook, the rules engine, the CLI tools — is written so
that its own internal bugs degrade to "allow" or "no opinion," never to a
hard failure that blocks a legitimate action. `migration_firewall.py`'s
`__main__` wraps `main()` in a bare `except Exception`, logs the full
traceback to stderr, and unconditionally exits 0. `ddl_rules.check_sql`
wraps each individual rule's `detect()` call the same way. The reasoning:
a false positive that blocks a legitimate migration is an immediate,
visible, blocking problem for a developer trying to ship something; a
false negative (a hazard the firewall misses) is caught later — by
`/pg:check-migration` on demand, by the CI gate on the PR, by a human
reviewing the diff, or worst case by monitoring after deploy. A hook
that's more certain of its own correctness than that trade-off implies is
a worse hook, not a better one — the plugin should never be the reason a
routine deploy is stuck.

**Why regex baseline with optional pglast AST, not AST-only.** Requiring
pglast would mean the firewall stops working entirely — silently, or with
an install-time error most users wouldn't debug quickly — the moment it
encounters SQL that isn't valid standalone SQL, which is *routine* for
this plugin's actual inputs: Rails, Django, and Alembic migration files
contain framework DSL and embedded string literals, not bare SQL, and even
plain `.sql` files sometimes contain dialect quirks pglast's grammar
doesn't cover. Regex detection is deliberately kept as a fully independent
decision path (not just a snippet-locator) so the tool degrades gracefully
to "less precise but still functional" rather than "nonfunctional" when
pglast can't parse something or isn't installed. In practice this was
verified to produce identical `check_sql()` results with `pglast`
installed and with `ddl_rules.HAS_PGLAST` forced to `False` on every test
snippet used to build the rules — the AST path exists for precision
(e.g., telling a constant `DEFAULT 'active'` apart from a volatile
`DEFAULT now()` by inspecting the parsed expression node rather than
pattern-matching the source text), not to change *what* gets caught.

**Why the RLS auditor never touches production.** This is the one
component with `Bash` access and the broadest blast radius if it went
wrong — a bad `CREATE POLICY` applied directly to production could either
lock everyone out of a table or, worse, silently fail to isolate tenants
while looking like it worked. Every other component in this plugin either
never executes anything against a real database (`ddl_rules.py`,
`schema_scan.py`) or executes only read-only/rolled-back operations
(`explain_runner.py`, `plan_diff.py`, the hypopg testing in
`index_advisor.py`). The RLS auditor is the exception specifically because
its job — proving isolation actually holds — requires writes (enabling
RLS, creating policies, inserting test rows) to verify anything at all. So
instead of narrowing what it does, the design narrows *where* it's allowed
to do it: only a container it started itself with `--rm`, or a connection
string the user has explicitly confirmed is a test/scratch database. This
is an instruction-level boundary in `agents/rls-auditor.md`'s system
prompt, not a code-level sandboxing mechanism — the subagent could
technically run anything its `Bash` tool access permits. That's a
conscious choice: sandboxing "don't touch a database that looks like
production" in code would mean encoding a heuristic for "looks like
production" that's easier to get wrong than trusting an explicit
instruction plus the subagent's own judgment, and this is the same trust
model Claude Code's tool-use permissions already rely on everywhere else.

**Why hypothetical indexes via hypopg, not real ones.** The whole point of
Query Doctor is to let someone evaluate an index *before* paying its
build cost and lock footprint (however small with `CONCURRENTLY`) on a
real table. `hypopg_create_index` creates an index that's visible only to
the planner's cost estimator, only within the current backend session,
never written to disk — so testing five candidate indexes costs nothing
and leaves nothing behind even if the script crashes mid-run. As a second,
independent safety net (not because the first one is expected to fail),
every hypopg session in `index_advisor.py` still runs inside a transaction
that's unconditionally rolled back in a `finally` block, and every
`EXPLAIN` involved is `FORMAT JSON` only, never `ANALYZE` — so even the
*query itself* is never executed, only costed.

**Why one shared `Finding`-producing rules engine instead of three
(SQL/Rails/Alembic).** The framework DSL mappers in
`migration_firewall.py` translate a framework-specific call shape into "is
rule X's hazard present," then reuse rule X's existing `id`,
`severity.value`, and `safe_pattern` from `ddl_rules.py` to build the
`Finding`. This means there's exactly one authoritative safe-rewrite text
per hazard, maintained in one place — adding a Rails-specific rewrite that
drifted from the SQL one would be a bug, not a feature, since the
underlying Postgres-level hazard and fix are identical regardless of which
migration tool generated the DDL.

## 5. How to add a new rule

Worked example: suppose you want to catch `CREATE TABLE ... PARTITION OF
...` statements that don't specify a `FOR VALUES` bound matching an
existing partition strategy — call it `partition_bound_mismatch`,
WARN-severity, whole-file scope (it needs to see the parent table's
existing partitions elsewhere in the file, so a single statement isn't
enough context). The same steps apply for a simpler per-statement,
BLOCK-severity rule; skip the "whole-file" specific parts if yours is
per-statement.

1. **Write the regex fallback first**, even if you plan to use pglast for
   the real decision — it's what every other rule falls back to, and
   writing it first forces you to state the hazard in plain pattern terms
   before reaching for the AST. Add compiled patterns near the top of
   `ddl_rules.py`, following the existing naming convention
   (`_RE_<THING>`).

2. **Write the `detect(text, node) -> Optional[bool]` function** (for a
   per-statement rule) or a `_detect_<name>(statements, sql) -> list[tuple[int,
   str]]` function (for a whole-file rule, matching the signature of
   `_detect_alter_type_in_txn`/`_detect_missing_timeout_guard`). Structure
   it exactly like the existing rules: check `HAS_PGLAST and
   isinstance(node, <ExpectedNodeType>)` first for the precise AST-based
   decision; if `node is not None` but isn't the expected type, `return
   None` (not applicable — don't let one rule's "not this" get read as
   another rule's "safe"); if `node is None`, fall through to the regex
   check and return `True`/`False`/`None` from that instead.

3. **Write the `Rule(...)` object** — `id` (a short, unique, snake_case
   string used as the finding's key everywhere downstream, including the
   CI marker-grepping and every test assertion, so don't rename one later
   without checking for references), `severity`, a `title` short enough to
   read on one line in a denial message, a `description` explaining the
   *lock or correctness* mechanism (not just "this is bad" — see how every
   existing rule's `description` names the specific lock type or failure
   mode), and a `safe_pattern` written as a **numbered, literally
   copy-pasteable rewrite**, not prose advice — this text gets surfaced
   directly to Claude as the thing to try next, so vague advice here
   produces a vague retry.

4. **Register it.** Append to `PER_STATEMENT_RULES` (checked automatically
   per-statement by `check_sql`) or `WHOLE_FILE_RULES` plus a manual
   `_finding_to_dict`-style block in `check_sql()`'s body (see how
   `_detect_alter_type_in_txn` and `_detect_missing_timeout_guard` are
   invoked explicitly after the per-statement loop — whole-file rules
   aren't in a generic loop because their function signature differs).
   Add an entry to `_LOCATOR_PATTERNS` if you want a specific
   snippet-locating regex distinct from your detection regex (usually the
   same pattern works for both).

5. **If the hazard is also expressible via a Rails/Django/Alembic DSL
   call** (not every rule needs this — e.g. `alter_type_add_value_in_txn`
   has no natural DSL equivalent), add a mapping in
   `_findings_from_rails_dsl` / `_findings_from_python_dsl` in
   `migration_firewall.py`: find or extract the relevant call with
   `_find_calls`, inspect its arguments with `_split_top_level` +
   `_get_kwarg_value`, and if the hazardous shape is present, build a
   `Finding` via `_finding_from_rule(ddl_rules.RULE_YOUR_NEW_RULE, ...)`
   with a `source_label` describing the DSL call (e.g. `"Rails DSL:
   your_call"`) so the denial message is traceable back to the actual line
   a developer wrote.

6. **Write test snippets — one that must block, one equivalent that must
   pass** — and add them to `hooks/tests/test_firewall.py` (integration,
   via subprocess, following the existing pattern of building a synthetic
   stdin payload with `make_payload()` and asserting on
   `get_hook_output()`) or as a standalone `check_sql()` unit test if
   you're testing the rules engine in isolation. Run both with `HAS_PGLAST`
   left as-is and — temporarily, locally — monkeypatched to `False`, to
   confirm your regex fallback alone produces the same block/pass verdict
   pglast-assisted detection does. This is the same verification approach
   used to build all seven existing rules, and it's the fastest way to
   catch a rule that only works when the AST path happens to be available.

7. **Update the rules catalogue table in this document** (section 3)
   with the new row — README contributors are explicitly asked (see
   README's "License and contributing") to include a blocking + passing
   test pair with any new rule; this document's table is the other half
   of that expectation.

## 6. Testing strategy

**Unit tests per rule** live implicitly inside `check_sql()`'s test
snippets (the 5-block/5-pass pairs produced alongside `ddl_rules.py`) —
each rule was verified against a hazardous and a safe SQL snippet, with
`HAS_PGLAST` both left on and forced off, confirming the regex fallback
alone reaches the same verdict as AST-assisted detection. These aren't
currently checked into a `pytest` file under `hooks/lib/` — the durable,
checked-in test coverage for the rules engine's actual decisions comes
through the integration layer described next, which exercises `ddl_rules`
indirectly via the hook. Contributors adding a new rule should add a
direct `check_sql()`-level unit test alongside their catalogue-table entry
if the hazard is subtle enough that a hook-level integration test doesn't
clearly isolate which rule fired.

**Hook integration tests** (`hooks/tests/test_firewall.py`, run via
`pytest hooks/tests/test_firewall.py -v`) invoke `migration_firewall.py`
as a real subprocess via `subprocess.run`, piping in the exact JSON
payload shape Claude Code sends on stdin, and asserting on the exact JSON
it prints on stdout — this is deliberately not a suite of imports against
the module's internal functions, because the actual contract this plugin
depends on is the stdin/stdout behavior of the script as a subprocess,
which is what Claude Code actually invokes. Current coverage: a blocked
raw-SQL migration (asserting both the rule id and that the safe rewrite
text is present in the denial reason — not just that *a* denial
happened), an allowed safe migration, a blocked and an allowed Rails
`add_index` call (with and without `algorithm: :concurrently`), a
non-migration file being ignored (silent, empty stdout, even though the
file contains an obviously dangerous `DROP TABLE` — proving the pattern
gate, not the rules engine, is what's being exercised there), a
non-Write/Edit tool being ignored, malformed JSON on stdin (asserts exit
code 0, empty stdout, and a non-empty stderr — the fail-safe path has to
both *not block* and *not go silent about the bug*), missing `tool_input`
entirely, an `Edit`-tool call verified against the reconstructed
post-edit content rather than just the inserted fragment, and a combined
Alembic file with two independent findings (`op.create_index` without
`postgresql_concurrently=True`, plus an embedded `op.execute(...)` string
containing a raw `SET NOT NULL`) to confirm the DSL-mapping path and the
embedded-SQL-extraction path both run and both surface findings from the
same file.

**Docker-based end-to-end test.** This exists as a *procedure*, not a
checked-in automated test, because the sandbox this plugin was built in
has no Docker or live Postgres available — `agents/rls-auditor.md`'s Step
6 describes it as the subagent's own responsibility to run per-audit:
start a disposable `docker run --rm postgres:16`, load the scanned schema
plus the generated patch, install pgTAP (ships in the standard image's
contrib), create the non-superuser role the policies assume, run the
generated tests with `pg_prove`, report actual pass/fail output, and tear
the container down regardless of outcome. Treat this as the acceptance
test for any change to `schema_scan.py`'s tenant-detection heuristics or
`isolation_test.sql`'s template: if you change either, run this procedure
against a schema with a deliberately-broken policy (missing `WITH CHECK`,
missing `FORCE`, etc.) and confirm the corresponding pgTAP assertion
actually fails before your fix and passes after.

**What's verified without a live database.** `explain_runner.py`,
`plan_analyzer.py`, and `index_advisor.py` were validated against
hand-built `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` JSON fixtures
constructed to match real Postgres output shapes exactly (verified against
`psycopg`'s actual API and hypopg's real function signatures rather than
assumed) — sufficient to exercise every per-node check and the
equality-then-sort column-ordering logic in `index_advisor.py`, but not a
substitute for running against a real planner on real data before trusting
a specific threshold constant in production. `ci/plan_diff.py`'s git-based
logic (base/head file extraction, new-file handling, error paths) was
verified against a real scratch git repository with two commits, without
needing a database at all, since that logic is independent of the
`EXPLAIN` call it wraps.

## 7. Known limitations and roadmap ideas

**Known limitations:**

- The DDL checks are pattern-matching (regex or AST-shape matching), not a
  full semantic understanding of the query planner — a hazardous
  statement written in a sufficiently unusual way could slip through
  (false negative), and unusual-but-safe SQL could occasionally be
  flagged (false positive). A clean firewall pass means "no known hazard
  matched," not a formal safety proof.
- Coverage of framework DSLs is heuristic and necessarily incomplete —
  `_find_calls`'s regex-based call parser handles idiomatic Ruby/Python
  call syntax but not every metaprogramming pattern (e.g. a migration that
  builds its column list from a loop or a shared helper method won't be
  caught, since there's no `add_column(...)` literal in the source text
  for the regex to find).
- `schema_scan.py`'s tenant-column detection is a heuristic scoring
  system, not ground truth — it will miss genuinely unusual naming
  (`client_ref`, `biz_id`) unless a human reviews the low/NONE-confidence
  tail the way `agents/rls-auditor.md` instructs.
- Targets Postgres 13–17; the `NOT NULL` safe-rewrite pattern specifically
  depends on PG12+ behavior and hasn't been tested against anything older.
- Nothing in this plugin substitutes for an actual staging environment or
  a DBA review on anything genuinely high-stakes (a true zero-downtime
  migration on a very large or very hot table often needs more than seven
  generic patterns can express).

**Roadmap ideas:**

- **Partitioning advisor** — detect when a table's growth pattern or
  query shapes (seen via `plan_analyzer.py`'s own seq-scan findings over
  time) suggest it's a partitioning candidate, and generate the
  declarative-partitioning migration path.
- **Bloat / autovacuum tuner** — a skill parallel to Query Doctor that
  reads `pg_stat_user_tables`, flags tables with high dead-tuple ratios or
  autovacuum falling behind, and proposes per-table `autovacuum_*` storage
  parameter overrides.
- **More ORM dialects** — Sequelize, TypeORM, and Go's `golang-migrate`/
  `goose` are the most requested gaps; each would follow the same
  extraction-plus-DSL-mapping pattern `migration_firewall.py` already uses
  for Rails and Alembic/Django, so most of the work is enumerating each
  framework's specific call shapes rather than new architecture.
- **A `pytest`-native unit-test file for `ddl_rules.py` directly** (see
  section 6) — the rule-level test snippets exist and were used to build
  every rule, but aren't yet checked in as an automated suite independent
  of the hook integration tests.
