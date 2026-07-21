# CI setup

`.github/workflows/postgres-guardrails.yml` re-checks migrations on every
pull request using headless Claude Code, and (optionally) diffs EXPLAIN
plan costs for any query files the PR changed. It posts one PR comment
per run and fails the check if the Migration Firewall finds a BLOCK-level
issue.

## What it needs

**Required secret:**

| Secret | What it's for |
| :-- | :-- |
| `ANTHROPIC_API_KEY` | Lets `claude -p` run headless in the CI runner. Get one from the [Claude Console](https://console.anthropic.com/). |

**Optional secret:**

| Secret | What it's for |
| :-- | :-- |
| `DATABASE_URL` | A **staging or scratch** Postgres connection string. Used only for `EXPLAIN (FORMAT JSON)` — never `ANALYZE`, never a mutating statement, never applied against anything you'd call production. Without this secret, the workflow still runs and still checks migrations; it just skips the plan-diff step entirely. |

If you add `DATABASE_URL`, point it at a database whose schema is
reasonably close to production (so planner cost estimates mean something)
but that you're comfortable with CI running `EXPLAIN` against on every PR.
A nightly-refreshed staging copy is the common choice.

## Setup (about 5 minutes)

1. **Copy the workflow file** into your repo at
   `.github/workflows/postgres-guardrails.yml`, and open it.

2. **Point it at the plugin.** Find this step near the top and change
   `repository:` to wherever you host postgres-guardrails (your own fork
   is fine):
   ```yaml
   - name: Checkout postgres-guardrails plugin
     uses: actions/checkout@v4
     with:
       repository: your-org/postgres-guardrails   # <- change this
       path: .postgres-guardrails
   ```
   This is the one required edit. Everything else in the file works
   as-is.

3. **Add the secret(s).** In your repo: *Settings → Secrets and variables
   → Actions → New repository secret.*
   - `ANTHROPIC_API_KEY` (required)
   - `DATABASE_URL` (optional, see above)

4. **Commit and open a PR that touches a migration file.** The workflow
   triggers on pull requests that change anything under `**/migrations/**`,
   `**/migrate/**`, `db/migrate/**`, or `prisma/migrations/**` — adjust the
   `on.pull_request.paths` list at the top of the file if your migrations
   live somewhere else.

That's it. You should see a `postgres-guardrails` check on the PR, and a
comment summarizing what it found.

## What you'll see

- **Always:** a PR comment listing every finding from the Migration
  Firewall for each changed migration file — rule, severity, line, and the
  exact safe rewrite to use instead.
- **If `DATABASE_URL` is set and the PR also changed a non-migration
  `.sql` file:** a plan-diff section per query, showing base cost, head
  cost, and percent change, flagged if it regressed by more than 20%
  (tune this with `ci/plan_diff.py`'s `--threshold-pct`, edited into the
  prompt in `ci/prompt.txt` if you want a different default).
- **The check fails** only when at least one finding is BLOCK severity.
  Plan regressions are reported but don't fail the check on their own —
  they're for a human to weigh, since "20% more expensive" isn't always
  "bad" (e.g. a query that now correctly joins in data it was silently
  missing before).

## Notes

- The workflow's trigger is scoped to migration paths, matching the
  Migration Firewall's own `MIGRATION_FILE_PATTERNS`. If you want plan
  diffing to run on PRs that change queries but *not* migrations, add
  `"**/*.sql"` (or wherever your query files live) to the `paths` list —
  just be aware that broadens exactly which PRs trigger the whole check.
- Nothing in this workflow ever writes to a database. `ci/plan_diff.py`
  and the Migration Firewall both only ever run read-only `EXPLAIN`
  statements or static analysis — see their own docstrings for the exact
  safety guarantees.
- The job posts a **new** PR comment on every run rather than editing a
  previous one, so a PR pushed to several times will accumulate several
  comments. Swap the `gh pr comment` step for `gh pr comment --edit-last`
  (falling back to a fresh comment on the first run) if you'd rather it
  update in place.
