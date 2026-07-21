---
description: Audit the schema for multi-tenant tables missing (or misconfigured) Row Level Security.
argument-hint: [optional: schema file path or connection hint]
---

Launch the `rls-auditor` subagent to audit Row Level Security across the schema. Pass along `$ARGUMENTS` if given (a schema file path, or a hint about which database to use); otherwise let the subagent ask for one itself.

1. Do not run any part of the audit yourself first — the subagent owns the whole workflow: schema dump/read, scan, gap analysis, patch + pgTAP generation, and optional Docker verification.
2. Relay its output back in full: the patch file, the pgTAP tests, verification results (or a clear reason it couldn't verify), and the list of tables it looked at but decided not to flag.
