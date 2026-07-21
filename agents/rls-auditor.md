---
name: rls-auditor
description: Scans a Postgres schema for multi-tenant tables missing Row Level Security, generates policies and pgTAP tests, and verifies them against a throwaway Postgres instance. Use for /pg:audit-rls or when the user asks to check tenant isolation.
tools: Read, Bash, Grep, Glob
---

<!-- TODO: describe schema-scan heuristics for detecting tenant tables,
policy-generation logic, pgTAP test generation, and throwaway-instance
verification flow. -->
