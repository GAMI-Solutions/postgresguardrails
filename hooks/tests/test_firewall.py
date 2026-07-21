"""
Integration tests for the Migration Firewall PreToolUse hook.

These invoke hooks/migration_firewall.py as a real subprocess, piping in
the same JSON payload Claude Code would send on stdin, exactly the way it
runs in production. This exercises the whole path: stdin parsing, pattern
matching, rule checking, and JSON response formatting - not just the
importable functions.

Run with:  pytest hooks/tests/test_firewall.py -v
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
FIREWALL = REPO_ROOT / "hooks" / "migration_firewall.py"


def run_hook(stdin_text: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(FIREWALL)],
        input=stdin_text,
        text=True,
        capture_output=True,
        timeout=15,
    )


def make_payload(tool_name: str, tool_input: dict) -> str:
    return json.dumps(
        {
            "session_id": "test-session",
            "transcript_path": "/tmp/test-transcript.jsonl",
            "cwd": "/tmp",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": tool_input,
        }
    )


def get_hook_output(result: subprocess.CompletedProcess) -> "dict | None":
    """Parse the hookSpecificOutput block if the hook printed one, else
    None (which means the default allow — no opinion)."""
    if not result.stdout.strip():
        return None
    return json.loads(result.stdout)["hookSpecificOutput"]


# --------------------------------------------------------------------------
# 1. Blocked unsafe SQL migration
# --------------------------------------------------------------------------

def test_blocks_unsafe_sql_migration(tmp_path):
    file_path = tmp_path / "db" / "migrations" / "0001_add_index.sql"
    payload = make_payload(
        "Write",
        {
            "file_path": str(file_path),
            "content": "CREATE INDEX idx_orders_customer ON orders (customer_id);",
        },
    )

    result = run_hook(payload)

    assert result.returncode == 0
    out = get_hook_output(result)
    assert out is not None, "expected a deny response, got silent allow"
    assert out["hookEventName"] == "PreToolUse"
    assert out["permissionDecision"] == "deny"
    reason = out["permissionDecisionReason"]
    assert "index_no_concurrently" in reason
    assert "CONCURRENTLY" in reason  # the safe rewrite must be included


# --------------------------------------------------------------------------
# 2. Allowed safe migration
# --------------------------------------------------------------------------

def test_allows_safe_migration(tmp_path):
    file_path = tmp_path / "db" / "migrations" / "0002_safe_index.sql"
    payload = make_payload(
        "Write",
        {
            "file_path": str(file_path),
            "content": (
                "SET lock_timeout = '2s';\n"
                "CREATE INDEX CONCURRENTLY idx_orders_customer ON orders (customer_id);"
            ),
        },
    )

    result = run_hook(payload)

    assert result.returncode == 0
    out = get_hook_output(result)
    # Either silent allow, or an explicit allow (never deny).
    if out is not None:
        assert out["permissionDecision"] != "deny"


# --------------------------------------------------------------------------
# 3. Rails add_index block
# --------------------------------------------------------------------------

def test_blocks_rails_add_index_without_concurrently(tmp_path):
    file_path = tmp_path / "db" / "migrate" / "20240101000000_add_index_to_users.rb"
    rb_source = (
        "class AddIndexToUsers < ActiveRecord::Migration[7.0]\n"
        "  def change\n"
        "    add_index :users, :email\n"
        "  end\n"
        "end\n"
    )
    payload = make_payload("Write", {"file_path": str(file_path), "content": rb_source})

    result = run_hook(payload)

    assert result.returncode == 0
    out = get_hook_output(result)
    assert out is not None, "expected a deny response, got silent allow"
    assert out["permissionDecision"] == "deny"
    assert "index_no_concurrently" in out["permissionDecisionReason"]
    assert "add_index" in out["permissionDecisionReason"]


def test_allows_rails_add_index_with_concurrently(tmp_path):
    file_path = tmp_path / "db" / "migrate" / "20240101000001_add_index_to_users.rb"
    rb_source = (
        "class AddIndexToUsers < ActiveRecord::Migration[7.0]\n"
        "  disable_ddl_transaction!\n"
        "  def change\n"
        "    add_index :users, :email, algorithm: :concurrently\n"
        "  end\n"
        "end\n"
    )
    payload = make_payload("Write", {"file_path": str(file_path), "content": rb_source})

    result = run_hook(payload)

    assert result.returncode == 0
    out = get_hook_output(result)
    if out is not None:
        assert out["permissionDecision"] != "deny"


# --------------------------------------------------------------------------
# 4. Non-migration file ignored
# --------------------------------------------------------------------------

def test_ignores_non_migration_file(tmp_path):
    file_path = tmp_path / "app" / "models" / "user.rb"
    dangerous_but_irrelevant = "add_index :users, :email\nexecute(\"DROP TABLE users;\")\n"
    payload = make_payload("Write", {"file_path": str(file_path), "content": dangerous_but_irrelevant})

    result = run_hook(payload)

    assert result.returncode == 0
    assert result.stdout.strip() == ""


def test_ignores_non_write_edit_tools(tmp_path):
    file_path = tmp_path / "db" / "migrations" / "0001_add_index.sql"
    payload = make_payload("Read", {"file_path": str(file_path)})

    result = run_hook(payload)

    assert result.returncode == 0
    assert result.stdout.strip() == ""


# --------------------------------------------------------------------------
# 5. Fail-safe path
# --------------------------------------------------------------------------

def test_fail_safe_on_malformed_stdin():
    result = run_hook("this is not valid json {{{")

    assert result.returncode == 0, "a bug in the hook must never block the tool call"
    assert result.stdout.strip() == "", "no deny/allow opinion should be emitted on internal error"
    assert result.stderr.strip() != "", "the error must be logged to stderr for debugging"


def test_fail_safe_on_missing_tool_input():
    # tool_name present but tool_input missing entirely - should not crash.
    payload = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Write"})

    result = run_hook(payload)

    assert result.returncode == 0
    assert result.stdout.strip() == ""


# --------------------------------------------------------------------------
# Bonus coverage: Edit tool reconstruction, and embedded/DSL detection for
# the other frameworks, since the hook supports more than just Write+SQL.
# --------------------------------------------------------------------------

def test_edit_tool_is_checked_against_reconstructed_content(tmp_path):
    migrations_dir = tmp_path / "db" / "migrations"
    migrations_dir.mkdir(parents=True)
    file_path = migrations_dir / "0003_add_col.sql"
    file_path.write_text("ALTER TABLE users ADD COLUMN age int;\n")

    payload = make_payload(
        "Edit",
        {
            "file_path": str(file_path),
            "old_string": "ALTER TABLE users ADD COLUMN age int;",
            "new_string": "ALTER TABLE users ADD COLUMN age int DEFAULT random();",
        },
    )

    result = run_hook(payload)

    assert result.returncode == 0
    out = get_hook_output(result)
    assert out is not None
    assert out["permissionDecision"] == "deny"
    assert "add_column_volatile_default" in out["permissionDecisionReason"]


def test_blocks_alembic_op_execute_and_create_index(tmp_path):
    file_path = tmp_path / "migrations" / "0004_x.py"
    py_source = (
        "def upgrade():\n"
        "    op.create_index('ix_x', 'orders', ['customer_id'])\n"
        "    op.execute(\"ALTER TABLE users ALTER COLUMN email SET NOT NULL;\")\n"
    )
    payload = make_payload("Write", {"file_path": str(file_path), "content": py_source})

    result = run_hook(payload)

    assert result.returncode == 0
    out = get_hook_output(result)
    assert out is not None
    assert out["permissionDecision"] == "deny"
    reason = out["permissionDecisionReason"]
    assert "index_no_concurrently" in reason
    assert "unsafe_alter_column" in reason


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
