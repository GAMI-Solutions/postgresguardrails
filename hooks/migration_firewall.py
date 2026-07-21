#!/usr/bin/env python3
"""Migration Firewall — PreToolUse hook for postgres-guardrails.

Fires on Write/Edit tool calls (see hooks/hooks.json). Reads the tool-call
JSON payload from stdin and decides whether to allow, warn, or block.
"""
import json
import sys


def main() -> int:
    # TODO: detect migration files (raw SQL, Prisma, Django, Rails, Alembic),
    # parse DDL with pglast/sqlglot, flag lock-hazardous statements (see
    # DDL hazard list), and block via exit code 2 + reason on stderr when
    # hazardous. Must fail safe: on parse failure, warn only, never block.
    json.load(sys.stdin)
    return 0


if __name__ == "__main__":
    sys.exit(main())
