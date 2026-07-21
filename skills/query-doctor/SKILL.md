---
name: query-doctor
description: Diagnoses slow PostgreSQL queries using real EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) plans, not guesswork. Use whenever the user asks why a query is slow, asks to review or explain a query plan, mentions EXPLAIN/EXPLAIN ANALYZE, asks about missing or unused indexes, asks what index to add, or wants a query optimized against a real Postgres database. Also use for "should I add an index on X" and "is this query going to lock/scan the whole table" questions.
---

# Query Doctor

Diagnoses a slow query against a **real** database connection — this is
not a guess-from-the-SQL-text skill. Every finding here comes from an
actual `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` plan.

## Workflow

1. **Get a connection.** Ask the user for a Postgres connection string, or
   check if `DATABASE_URL` is already set in their environment. Don't
   guess or fabricate one. If they don't have one handy, ask them to run
   `echo $DATABASE_URL` or paste their connection details.

2. **Get the query.** Either the user pastes it, or points you to a
   `.sql` file.

3. **Run the plan.**
   ```
   python3 scripts/explain_runner.py --conn "$DATABASE_URL" -q "<query>" -o /tmp/plan.json
   ```
   - This runs inside a transaction that is **always rolled back** — safe
     to run even if the query contains an UPDATE/DELETE/INSERT.
   - A 30s `statement_timeout` is enforced automatically.
   - If the user is nervous about executing the query at all (e.g. it's a
     write query and they don't want it to actually run, even in a rolled
     back transaction), add `--no-analyze` — this gets planner estimates
     only, with zero execution.

4. **Analyze the plan.**
   ```
   python3 scripts/plan_analyzer.py /tmp/plan.json
   ```
   This prints findings with a severity (HIGH/MEDIUM/LOW) and a one-line
   fix for each: large sequential scans, row-estimate mismatches, sorts
   or hashes spilling to disk, nested loops with huge inner loop counts,
   and index scans that throw away most of what they fetch via a filter.

5. **Discuss the findings with the user** in plain language before
   changing anything — explain *why* each flagged node is slow, not just
   that it's flagged.

6. **Optionally, propose indexes.**
   ```
   python3 scripts/index_advisor.py --plan /tmp/plan.json --conn "$DATABASE_URL"
   ```
   This derives candidate indexes straight from the plan's Filter/Index
   Cond/Sort Key/join conditions. If the `hypopg` extension is installed
   in the target database, it tests each candidate as a **hypothetical**
   index and reports the before/after planner cost — otherwise it just
   lists the candidates. This step **never creates a real index**; say so
   explicitly if the user asks whether it's safe to run.

## Rules

- Never fabricate a connection string, table name, or plan — if you don't
  have a live connection, say so and ask for one.
- Never run `CREATE INDEX` (without `CONCURRENTLY`, or at all) on the
  user's behalf as part of this skill. Recommending DDL is as far as this
  goes; if the user wants it applied, that's a separate, explicit action
  they take (and the Migration Firewall hook will check it if it goes
  through a migration file).
- All three scripts are standalone and support `--help` — use `--json` on
  `plan_analyzer.py` / `index_advisor.py` if you need to parse their
  output programmatically rather than read it yourself.
