---
description: Check an existing migration file for lock-hazardous DDL, on demand, using the Migration Firewall's rules engine.
argument-hint: [migration-file]
---

Check `$ARGUMENTS` for lock-hazardous DDL, exactly as the Migration Firewall hook would if this file were being written right now.

1. If `$ARGUMENTS` is empty, ask for a file path. Confirm the file exists.
2. Run it through the firewall engine directly, reusing the live hook so `.sql`, Rails `.rb`, and Django/Alembic `.py` migrations all get the same embedded-SQL extraction and framework-DSL checks the hook applies:
   ```
   python3 -c "import json,sys; print(json.dumps({'tool_name':'Write','tool_input':{'file_path': sys.argv[1], 'content': open(sys.argv[1]).read()}}))" "$ARGUMENTS" | python3 hooks/migration_firewall.py
   ```
3. No stdout output means clean — say so plainly, don't invent findings.
4. Otherwise it printed a `hookSpecificOutput` JSON. Report every finding verbatim from `permissionDecisionReason`: rule id, line, matched snippet, and its exact safe rewrite — don't summarize the rewrite away.
5. Offer to apply a rewrite if asked; don't edit the file unprompted.
