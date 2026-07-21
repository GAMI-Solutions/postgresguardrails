---
description: Diagnose a slow query against a real database using the Query Doctor workflow.
argument-hint: [query or .sql file]
---

Diagnose this against a real database, following the workflow in `skills/query-doctor/SKILL.md` exactly (get a connection -> run `explain_runner.py` -> run `plan_analyzer.py` -> discuss findings -> optionally `index_advisor.py`), for:

$ARGUMENTS

1. Read `skills/query-doctor/SKILL.md` now if you haven't already this session, and follow its steps in order — don't skip to index suggestions before showing the EXPLAIN findings.
2. If `$ARGUMENTS` is a path to an existing `.sql` file, use its contents as the query; otherwise treat `$ARGUMENTS` as the query text directly.
3. If no `DATABASE_URL` is set and the user hasn't given a connection string, ask for one before running anything — never fabricate a connection.
