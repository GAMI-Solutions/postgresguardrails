---
description: Scan the codebase and schema for breaking changes between two Postgres major versions and produce an upgrade runbook.
argument-hint: [from-version] [to-version]
---

Assess a Postgres upgrade from $1 to $2 and produce a runbook file — don't just describe it in chat.

1. If `$1` or `$2` is missing, ask for both major versions (e.g. 13, 16) before doing anything else.
2. Look up what changed across every major version in the ($1, $2] range — deprecated/removed syntax, removed features, changed defaults, extension compatibility — from the official release notes for each intermediate version; don't rely on memory alone for version-specific claims.
3. Scan this codebase for anything touching the affected surface: migrations (start from wherever `hooks/lib/ddl_rules.py` looks, i.e. `**/migrations/**`, `db/migrate/**`, `prisma/migrations/**`), ORM usage, `CREATE EXTENSION` statements, and any version-dependent code.
4. Get the schema — ask for a dump/connection, or reuse the dump step from `agents/rls-auditor.md` — and check it for version-sensitive usage: deprecated types, removed operators, extensions with a known version ceiling.
5. Write the runbook to `upgrade_runbook_$1_to_$2.md`: findings specific to this codebase (not a generic changelog dump), a pre-upgrade checklist, recommended upgrade path (`pg_upgrade` vs. dump/restore vs. logical replication, with a call for this setup if you can tell), a rollback plan, and a post-upgrade validation checklist (re-run `/pg:doctor` on hot queries, `/pg:audit-rls` if RLS is in use, `ANALYZE` guidance).
6. Mark anything you couldn't verify confidently (e.g. a specific extension's compatibility) as a TODO for the user to confirm rather than guessing.
