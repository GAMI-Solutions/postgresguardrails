---
name: query-doctor
description: Runs EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) against a real Postgres database, parses the plan, flags problems, and tests hypothetical indexes with hypopg. Use when the user asks to diagnose a slow query, review a query plan, or suggests indexes.
---

# Query Doctor

<!-- TODO: describe workflow — run EXPLAIN, parse JSON plan, flag seq scans/bad
row estimates/spills, invoke scripts/ for hypopg-based index hypotheses. -->
