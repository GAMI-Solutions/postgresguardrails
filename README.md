# postgres-guardrails

A large share of database migrations are now written by AI agents, not
humans typing DDL by hand. That's mostly fine. The problem is that agents
write the version of a migration you'd find in a textbook: correct SQL,
wrong for a live production table. `CREATE INDEX` without `CONCURRENTLY`.
`ADD COLUMN` with a default that rewrites the whole table. A foreign key
added the slow way. Each one is confidently correct and each one can lock
a table for the length of a coffee break. postgres-guardrails is a Claude
Code plugin that makes Claude physically unable to write that version. It
intercepts the write, blocks the dangerous statement, and hands back the
safe multi-step rewrite instead — before the file ever hits disk.

## The problem, in ten lines

This is what Claude writes by default when you ask for an index:

```sql
CREATE INDEX idx_orders_customer_id ON orders (customer_id);
```

Textbook-correct. On a table with real traffic, this takes a lock that
blocks every write to `orders` until the build finishes — could be
seconds, could be twenty minutes, depending on table size.

This is what the firewall forces instead:

```sql
SET statement_timeout = 0;
CREATE INDEX CONCURRENTLY IF NOT EXISTS
    idx_orders_customer_id ON orders (customer_id);
```

Same index. No blocked writes. That's the whole idea, repeated across
seven categories of DDL hazard.

## What's inside

**Migration Firewall.** A `PreToolUse` hook that runs on every Write or
Edit to a file that looks like a migration — raw SQL, Rails, Django,
Alembic, Prisma. It parses the DDL (with `pglast` when it's installed,
regex as a fallback), checks it against seven known lock hazards, and
blocks the write if it finds one, returning the exact safe rewrite in the
same response so Claude can just fix it and move on. It's a linter with
a lock on the door, not a linter with an opinion.

**Query Doctor.** A skill for when a query is slow and you want a real
answer instead of a guess. It connects to a database you give it, runs
`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` inside a transaction that's
always rolled back, and flags sequential scans, bad row estimates,
disk-spilling sorts, and nested loops gone wrong — each with a plain
explanation and a one-line fix. If you want index suggestions, it can
test them as hypothetical indexes via `hypopg` first, so you see the
before/after cost before you build anything real.

**RLS Tenant Auditor.** A subagent that reads your schema and looks for
multi-tenant tables that don't have Row Level Security, or have it
enabled without a policy, or have a policy with a gap in it. It writes a
patch and a set of pgTAP tests that try to make tenant A read tenant B's
data — and it never runs either against a real database unless you tell
it to, and even then only against something disposable. This is the
component we'd most encourage you to actually run, because "we have RLS"
and "we've verified RLS holds" are very different claims.

**Slash commands.** `/pg:check-migration`, `/pg:doctor`, `/pg:audit-rls`,
and `/pg:upgrade-check` — thin, on-demand wrappers around the three
components above, plus an upgrade-compatibility scan across Postgres
major versions. They don't add new logic; they just let you invoke this
outside of Claude naturally reaching for it.

**CI gate.** A GitHub Action that runs the Migration Firewall against
every changed migration in a pull request, and — if you give it a
staging database — diffs `EXPLAIN` cost for changed queries between base
and head. It posts one comment per run and fails the check on a BLOCK
finding. It does not fail the check on a plan regression alone; that's
still a judgment call for a person.

## Where you'd use this

- You're a small team on Supabase, RDS, or Neon, and you've let Claude
  Code start touching your schema. You'd like it to keep doing that
  without eventually taking your database down.
- You're rolling out AI agents more broadly and "give it write access to
  the database" is the step that's making everyone nervous. This is the
  guardrail that makes that step less nervous.
- You're on a platform team and you want migration safety enforced as
  policy, in CI, not as a wiki page nobody reads before merging.
- You run multi-tenant Postgres, you're fairly sure RLS is set up right,
  and you've never actually tried to prove it by having one tenant read
  another's data. Most teams in this position are wrong about at least
  one table.

## Installation

This plugin isn't published to a marketplace yet, so today you'd load it
straight from a checkout:

```bash
git clone https://github.com/your-org/postgres-guardrails.git
claude --plugin-dir ./postgres-guardrails
```

Once it's published to a marketplace you or your org control, the normal
path is:

```
/plugin marketplace add your-org/postgres-guardrails
/plugin install postgres-guardrails@your-org
```

(or, non-interactively: `claude plugin install postgres-guardrails@your-org`)

### Sixty-second quickstart

1. Load the plugin (above) in a repo that has Postgres migrations.
2. Ask Claude to write one: "add an index on `orders.customer_id`." Watch
   it get blocked, and watch it fix its own mistake using the rewrite the
   firewall hands back.
3. Run `/pg:doctor` against your slowest known query, with a connection
   string to a real (ideally non-production) database.
4. Run `/pg:audit-rls` if you have multi-tenant tables. Read the pgTAP
   tests it generates before you run them against anything.
5. Copy `.github/workflows/postgres-guardrails.yml` into your repo and
   follow `docs/ci-setup.md` if you want this enforced on every PR.

## What this does not do

It is not a replacement for backups, a staging environment, or a DBA. It
catches known-bad DDL patterns and known-bad plan shapes; it has no idea
whether your backups are current or whether last night's snapshot
restores cleanly, and it won't stop you from doing something unwise that
just doesn't happen to match one of its rules.

The DDL checks are regex/AST-based pattern matching, not a query planner.
They can have false negatives — a hazardous statement written in an
unusual way might slip through — and, less often, false positives on
genuinely unusual but safe SQL. Treat a clean firewall pass as "no known
hazard found," not as a formal proof of safety.

It targets Postgres 13 through 17. Older versions aren't tested and
some of the safe rewrites (the `NOT NULL` constraint trick, in
particular) depend on behavior introduced in PG12.

## License and contributing

MIT. See `LICENSE`.

Issues and PRs are welcome, especially new DDL hazard rules with a real
production war story attached. If you're adding a rule to the firewall,
include a test snippet that should block and one that should pass —
we've found that's the fastest way to agree on what a rule is actually
supposed to catch.
