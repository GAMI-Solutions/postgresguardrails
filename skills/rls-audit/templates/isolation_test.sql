-- ============================================================================
-- isolation_test.sql — pgTAP template proving Row Level Security actually
-- isolates tenant data on {{SCHEMA}}.{{TABLE}}.
--
-- This is a TEMPLATE. Replace every {{PLACEHOLDER}} below with real values
-- before running (the RLS Tenant Auditor agent does this per table):
--
--   {{SCHEMA}}          schema name                          e.g. public
--   {{TABLE}}           table name                           e.g. orders
--   {{PK_COLUMN}}       primary key column                   e.g. id
--   {{TENANT_COLUMN}}   the tenant-scoping column             e.g. tenant_id
--   {{TENANT_A}}        sample tenant A id (literal)          e.g. 11111111-1111-1111-1111-111111111111
--   {{TENANT_B}}        sample tenant B id (literal)          e.g. 22222222-2222-2222-2222-222222222222
--   {{ROW_A_PK}}        PK value for the row seeded for A     e.g. aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
--   {{ROW_B_PK}}        PK value for the row seeded for B     e.g. bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
--   {{EXTRA_COLUMNS}}   any other NOT NULL columns this table needs for a
--                       valid INSERT, WITH a leading comma if non-empty,
--                       else the empty string  e.g. `, status, total`  or  ``
--   {{EXTRA_VALUES_A}}  values for EXTRA_COLUMNS, row A, same comma rule
--                       e.g. `, 'pending', 10.00`  or  ``
--   {{EXTRA_VALUES_B}}  values for EXTRA_COLUMNS, row B, same comma rule
--   {{APP_ROLE}}        the non-superuser, non-table-owner role your
--                       application actually connects as. RLS is NOT
--                       enforced against the table owner or any role with
--                       BYPASSRLS, so running this as anything else will
--                       either give false confidence or fail to prove
--                       anything at all.
--
-- Run with:  pg_prove -d "$TEST_DATABASE_URL" isolation_test.sql
-- or:        psql "$TEST_DATABASE_URL" -f isolation_test.sql
--
-- Safe to run repeatedly against a real database: everything happens
-- inside one transaction that is ALWAYS rolled back at the end, win or
-- lose. Never run this against production — use a disposable database
-- (see the RLS Tenant Auditor agent, which spins one up via Docker).
--
-- Note: the "no tenant context configured" test near the bottom assumes
-- the deployed policy uses current_setting('app.current_tenant')::type
-- WITHOUT the missing_ok argument (so it raises when unset, per the
-- project's standard pattern). If your policy instead uses
-- current_setting('app.current_tenant', true) (missing_ok = true, which
-- returns NULL instead of raising), swap that one throws_ok() call for an
-- is_empty() check instead — see the comment right above it.
-- ============================================================================

BEGIN;

SELECT plan(11);

-- --------------------------------------------------------------------------
-- 0. Sanity checks: RLS must actually be on, or every test below would
--    "pass" for the wrong reason (no isolation being enforced at all).
-- --------------------------------------------------------------------------
SELECT ok(
    (SELECT relrowsecurity FROM pg_class WHERE oid = '{{SCHEMA}}.{{TABLE}}'::regclass),
    'row_security is enabled on {{SCHEMA}}.{{TABLE}}'
);

SELECT ok(
    (SELECT relforcerowsecurity FROM pg_class WHERE oid = '{{SCHEMA}}.{{TABLE}}'::regclass),
    'row_security is FORCEd on {{SCHEMA}}.{{TABLE}} (so it also applies to the table owner)'
);

-- --------------------------------------------------------------------------
-- 1. Seed one row per tenant, each inserted *as that tenant* so every
--    insert satisfies its own WITH CHECK policy (rather than requiring a
--    BYPASSRLS role just to set up the fixtures).
-- --------------------------------------------------------------------------
SET ROLE {{APP_ROLE}};

SELECT set_config('app.current_tenant', '{{TENANT_A}}', true);
INSERT INTO {{SCHEMA}}.{{TABLE}} ({{PK_COLUMN}}, {{TENANT_COLUMN}}{{EXTRA_COLUMNS}})
VALUES ('{{ROW_A_PK}}', '{{TENANT_A}}'{{EXTRA_VALUES_A}});

SELECT set_config('app.current_tenant', '{{TENANT_B}}', true);
INSERT INTO {{SCHEMA}}.{{TABLE}} ({{PK_COLUMN}}, {{TENANT_COLUMN}}{{EXTRA_COLUMNS}})
VALUES ('{{ROW_B_PK}}', '{{TENANT_B}}'{{EXTRA_VALUES_B}});

-- --------------------------------------------------------------------------
-- 2. As tenant A: sees its own row, cannot see, update, or delete
--    tenant B's row — and cannot relabel its own row as tenant B's.
-- --------------------------------------------------------------------------
SELECT set_config('app.current_tenant', '{{TENANT_A}}', true);

SELECT ok(
    EXISTS(SELECT 1 FROM {{SCHEMA}}.{{TABLE}} WHERE {{PK_COLUMN}} = '{{ROW_A_PK}}'),
    'tenant A can see its own row'
);

SELECT is(
    (SELECT count(*)::int FROM {{SCHEMA}}.{{TABLE}} WHERE {{PK_COLUMN}} = '{{ROW_B_PK}}'),
    0,
    'tenant A CANNOT see tenant B''s row  <-- the core isolation guarantee'
);

SELECT is(
    (SELECT count(DISTINCT {{TENANT_COLUMN}})::int FROM {{SCHEMA}}.{{TABLE}}),
    1,
    'every row visible to tenant A belongs to tenant A (no leakage via any other row either)'
);

-- Blind writes matter too: A can't see B's row, but could it still write
-- to it by primary key alone? It shouldn't be able to.
SELECT is(
    (WITH attempt AS (
        UPDATE {{SCHEMA}}.{{TABLE}} SET {{PK_COLUMN}} = {{PK_COLUMN}}
        WHERE {{PK_COLUMN}} = '{{ROW_B_PK}}'
        RETURNING 1
     ) SELECT count(*)::int FROM attempt),
    0,
    'tenant A cannot UPDATE tenant B''s row (blind write by primary key)'
);

SELECT is(
    (WITH attempt AS (
        DELETE FROM {{SCHEMA}}.{{TABLE}} WHERE {{PK_COLUMN}} = '{{ROW_B_PK}}'
        RETURNING 1
     ) SELECT count(*)::int FROM attempt),
    0,
    'tenant A cannot DELETE tenant B''s row (blind delete by primary key)'
);

-- USING alone only protects what's already stored; WITH CHECK is what
-- stops tenant A from relabeling its own row as tenant B's on UPDATE.
SELECT throws_ok(
    format(
        $sql$UPDATE {{SCHEMA}}.{{TABLE}} SET {{TENANT_COLUMN}} = %L WHERE {{PK_COLUMN}} = %L$sql$,
        '{{TENANT_B}}', '{{ROW_A_PK}}'
    ),
    NULL,
    'tenant A cannot relabel its own row as belonging to tenant B (WITH CHECK enforced)'
);

-- --------------------------------------------------------------------------
-- 3. Symmetric check as tenant B — proves this isn't a one-way fluke.
-- --------------------------------------------------------------------------
SELECT set_config('app.current_tenant', '{{TENANT_B}}', true);

SELECT ok(
    EXISTS(SELECT 1 FROM {{SCHEMA}}.{{TABLE}} WHERE {{PK_COLUMN}} = '{{ROW_B_PK}}'),
    'tenant B can see its own row'
);

SELECT is(
    (SELECT count(*)::int FROM {{SCHEMA}}.{{TABLE}} WHERE {{PK_COLUMN}} = '{{ROW_A_PK}}'),
    0,
    'tenant B CANNOT see tenant A''s row'
);

-- --------------------------------------------------------------------------
-- 4. No tenant context configured at all -> must fail closed (raise or
--    return nothing), never silently return every tenant's rows.
--
--    If your policy uses current_setting('app.current_tenant', true)
--    (missing_ok = true) instead of the 1-arg form, replace this
--    throws_ok() with:
--        SELECT is_empty(
--            $sql$SELECT * FROM {{SCHEMA}}.{{TABLE}}$sql$,
--            'with no tenant context configured, zero rows are visible'
--        );
-- --------------------------------------------------------------------------
RESET app.current_tenant;

SELECT throws_ok(
    format($sql$SELECT * FROM {{SCHEMA}}.{{TABLE}}$sql$),
    NULL,
    'with no tenant context configured, querying fails closed (raises) instead of silently returning every tenant''s rows'
);

RESET ROLE;

SELECT * FROM finish();

ROLLBACK;
