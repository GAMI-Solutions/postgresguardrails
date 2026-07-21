# postgres-guardrails

A Claude Code plugin for PostgreSQL production safety. It makes it physically
impossible for Claude to write dangerous Postgres migrations, and gives
developers executable tools to diagnose queries and audit security — not just
advice.

**Status:** scaffold only, no logic implemented yet.

## Components

1. **Migration Firewall** — a `PreToolUse` hook that intercepts any Write/Edit
   of migration files (raw SQL, Prisma, Django, Rails, Alembic) and blocks
   lock-hazardous DDL, forcing a rewrite using safe multi-step patterns.
2. **Query Doctor** — a skill with bundled Python scripts that run
   `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` against a real database, parse
   the plan, flag problems, and test hypothetical indexes with hypopg.
3. **RLS Tenant Auditor** — a subagent that scans a schema for multi-tenant
   tables missing Row Level Security, generates policies and pgTAP tests, and
   verifies them against a throwaway Postgres instance.
4. **Slash commands** — `/pg:check-migration`, `/pg:doctor`, `/pg:audit-rls`,
   `/pg:upgrade-check`.
5. **CI mode** — a GitHub Action running Claude Code headless (`claude -p`)
   to re-check migrations and diff EXPLAIN plans on pull requests.

## DDL hazards the firewall catches

- `CREATE INDEX` without `CONCURRENTLY`
- `ALTER TABLE ... ADD COLUMN` with a volatile `DEFAULT`
- `SET NOT NULL` or column type changes (full table rewrite / `ACCESS EXCLUSIVE` lock)
- Adding a `FOREIGN KEY` without `NOT VALID` + separate `VALIDATE CONSTRAINT`
- `ALTER TYPE ... ADD VALUE` inside a transaction
- `DROP COLUMN` / `RENAME` on hot tables without a deprecation step
- Missing `lock_timeout` / `statement_timeout` guards

## Folder structure

```
postgresguardrails/
├── .claude-plugin/
│   └── plugin.json              # plugin manifest: metadata + component registration
├── hooks/
│   ├── hooks.json               # wires the Migration Firewall to PreToolUse (Write|Edit)
│   └── migration_firewall.py    # the firewall hook script
├── skills/
│   └── query-doctor/
│       ├── SKILL.md             # Query Doctor skill definition
│       └── scripts/
│           ├── explain_doctor.py    # runs and parses EXPLAIN plans
│           └── hypopg_advisor.py    # tests hypothetical indexes via hypopg
├── agents/
│   └── rls-auditor.md           # RLS Tenant Auditor subagent definition
├── commands/
│   └── pg/
│       ├── check-migration.md   # /pg:check-migration
│       ├── doctor.md            # /pg:doctor
│       ├── audit-rls.md         # /pg:audit-rls
│       └── upgrade-check.md     # /pg:upgrade-check
├── .github/
│   └── workflows/
│       └── pg-guardrails-ci.yml # CI mode: headless Claude Code check on PRs
└── README.md
```

## Tech constraints

- Hook scripts: Python 3.11+, stdlib only where possible (pglast or sqlglot
  allowed for SQL parsing).
- Follows the official Claude Code plugin structure.
- Fails safe: if a hook can't parse a file, it warns but does not block.
- Targets Postgres 13–17.
