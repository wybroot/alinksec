#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${ALINKSEC_MIGRATION_TEST_ALLOW_FIXTURES:-}" != "true" ]]; then
  echo "Set ALINKSEC_MIGRATION_TEST_ALLOW_FIXTURES=true for a disposable PostgreSQL instance." >&2
  exit 1
fi
: "${PGHOST:?PGHOST is required}"
: "${PGDATABASE:?PGDATABASE is required}"
: "${PGUSER:?PGUSER is required}"
: "${PGPASSWORD:?PGPASSWORD is required}"
for command in psql pg_dump pg_restore mktemp; do
  command -v "$command" >/dev/null || { echo "Missing command: $command" >&2; exit 1; }
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/alinksec-pg-migrations.XXXXXX")"
suffix="${BASHPID}_${RANDOM}"
test_database="alinksec_migration_test_${suffix}"
restore_database="alinksec_migration_restore_${suffix}"
app_role="alinksec_migration_app_${suffix}"
app_password="disposable-migration-app-password"
test_database_created=false
restore_database_created=false
cleanup_app_role=false
checks=0

owner_sql() { psql -X -q -v ON_ERROR_STOP=1 "$@"; }
test_sql() { PGDATABASE="$test_database" owner_sql "$@"; }
query() { test_sql -At -c "$1"; }

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  if $restore_database_created; then
    owner_sql --set=test_db="$restore_database" <<'SQL' || status=1
SELECT format('DROP DATABASE %I WITH (FORCE)', :'test_db') \gexec
SQL
  fi
  if $test_database_created; then
    owner_sql --set=test_db="$test_database" <<'SQL' || status=1
SELECT format('DROP DATABASE %I WITH (FORCE)', :'test_db') \gexec
SQL
  fi
  if $cleanup_app_role; then
    owner_sql --set=app_role="$app_role" <<'SQL' || status=1
SELECT format('DROP ROLE IF EXISTS %I', :'app_role') \gexec
SQL
  fi
  if ((status == 0)); then
    rm -rf "$work_dir"
  else
    echo "Migration validation failed; temporary logs and backup: $work_dir" >&2
    if [[ -f "$work_dir/migration.log" ]]; then
      sed -n '1,100p' "$work_dir/migration.log" >&2
    fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { ((checks += 1)); printf 'ok %s - %s\n' "$checks" "$1"; }
assert_query() {
  local actual
  actual="$(query "$1")"
  [[ "$actual" == "$2" ]] || fail "Expected '$2', got '$actual' for: $1"
}
run_migrations() {
  env PGDATABASE="${2:-$test_database}" ALINKSEC_APP_DB_USER="$app_role" \
    ALINKSEC_APP_DB_PASSWORD="$app_password" ALINKSEC_BIND_ADDRESS=127.0.0.1 \
    ALINKSEC_MIGRATIONS_DIR="$1" bash "$repo_root/deploy/migrations/run-migrations.sh" \
    >"$work_dir/migration.log" 2>&1
}
expect_migration_failure() {
  if run_migrations "$1"; then
    fail "Migration unexpectedly succeeded: $2"
  fi
  [[ "$(<"$work_dir/migration.log")" == *"$2"* ]] || fail "Missing expected failure: $2"
}
app_sql() {
  PGDATABASE="$test_database" PGUSER="$app_role" PGPASSWORD="$app_password" \
    owner_sql "$@"
}

existing_role="$(owner_sql -At --set=app_role="$app_role" <<'SQL'
SELECT count(*) FROM pg_roles WHERE rolname = :'app_role';
SQL
)"
[[ "$existing_role" == "0" ]] || fail "Reserved test role already exists: $app_role"
owner_sql --set=test_db="$test_database" <<'SQL'
SELECT format('CREATE DATABASE %I', :'test_db') \gexec
SQL
test_database_created=true
cleanup_app_role=true
mkdir -p "$work_dir"/{empty,base,broken,tampered,renamed,crlf}
cp "$repo_root"/deploy/migrations/V*.sql "$work_dir/base/"

expect_migration_failure "$work_dir/missing" "Migration directory does not exist"
assert_query "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'" "0"
assert_query "SELECT count(*) FROM pg_roles WHERE rolname = '$app_role'" "0"
pass "missing migration directory fails before database or role changes"

expect_migration_failure "$work_dir/empty" "No migration files found"
assert_query "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'" "0"
assert_query "SELECT count(*) FROM pg_roles WHERE rolname = '$app_role'" "0"
pass "empty migration directory fails before database or role changes"

if test_sql --single-transaction -f "$repo_root/deploy/sql/001_init.sql" \
    -f "$repo_root/deploy/tests/fixtures/postgres/V002__broken.sql" >"$work_dir/invalid-schema.log" 2>&1; then
  fail "Schema import accepted invalid SQL"
fi
assert_query "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'" "0"
pass "invalid bootstrap SQL returns failure and rolls back the schema"

test_sql -f "$repo_root/deploy/sql/001_init.sql" >"$work_dir/bootstrap.log" 2>&1
assert_query "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'" "38"
assert_query "SELECT count(*) FROM t_role" "3"
pass "fresh schema imports 38 tables and seeded roles"

# Remove features added before versioned migrations to exercise the upgrade path.
test_sql <<'SQL'
DROP TABLE t_asset_process, t_asset_container, t_alert_notify_delivery;
ALTER TABLE t_agent DROP COLUMN isolation_status;
ALTER TABLE t_agent DROP COLUMN isolation_command_id;
ALTER TABLE t_agent DROP COLUMN isolation_error;
ALTER TABLE t_agent DROP COLUMN isolation_updated_at;
DELETE FROM t_protect_rule WHERE rule_id = 'PR-0001';
UPDATE t_policy_state SET content = '{"legacy":true}'::jsonb WHERE id = 1;
INSERT INTO t_agent (agent_id, hostname, os_type, machine_id)
VALUES ('migration-fixture-agent', 'legacy-host', 1, 'migration-fixture-machine');
INSERT INTO t_asset_software (agent_id, name, version)
VALUES ('migration-fixture-agent', 'legacy-software', '1.0');
INSERT INTO t_audit_log (method, path, body_digest, status, cost_ms)
VALUES ('POST', '/api/notify/channels', 'legacy-webhook-secret', 200, 1);
SQL
PGDATABASE="$test_database" pg_dump --format=custom --file="$work_dir/legacy.dump"
run_migrations "$work_dir/base"
assert_query "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'" "45"
assert_query "SELECT count(*) FROM t_schema_migration" "4"
assert_query "SELECT hostname || '|' || isolation_status FROM t_agent WHERE agent_id = 'migration-fixture-agent'" "legacy-host|0"
assert_query "SELECT name || '|' || version FROM t_asset_software WHERE agent_id = 'migration-fixture-agent'" "legacy-software|1.0"
assert_query "SELECT count(*) FROM t_audit_log WHERE body_digest IS NOT NULL" "0"
assert_query "SELECT count(*) FROM t_protect_rule WHERE rule_id = 'PR-0001'" "1"
assert_query "SELECT content::text FROM t_policy_state WHERE id = 1" "{}"
pass "legacy upgrade restores missing features, preserves assets and scrubs old audit secrets"

test_sql -c "INSERT INTO t_audit_log (method, path, body_digest, status, cost_ms) VALUES ('POST', '/api/hosts/collect', 'new-safe-digest', 200, 1);"
applied_at="$(query "SELECT applied_at FROM t_schema_migration ORDER BY version")"
run_migrations "$work_dir/base"
assert_query "SELECT count(*) FROM t_schema_migration" "4"
assert_query "SELECT applied_at FROM t_schema_migration ORDER BY version" "$applied_at"
assert_query "SELECT count(*) FROM t_audit_log WHERE body_digest = 'new-safe-digest'" "1"
pass "repeat migrations preserve history and new audit records"

assert_query "SELECT NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication OR rolbypassrls) FROM pg_roles WHERE rolname = '$app_role'" "t"
app_sql <<'SQL'
INSERT INTO t_host_group (name) VALUES ('migration-app-group');
INSERT INTO t_agent (agent_id, hostname, os_type, group_id)
SELECT 'migration-app-agent', 'app-host', 1, id FROM t_host_group WHERE name = 'migration-app-group';
UPDATE t_agent SET hostname = 'updated-app-host' WHERE agent_id = 'migration-app-agent';
DELETE FROM t_agent WHERE agent_id = 'migration-app-agent';
DELETE FROM t_host_group WHERE name = 'migration-app-group';
INSERT INTO t_security_feed_schedule(source_id,enabled,interval_ms,updated_at)
VALUES ('migration-feed',1,300000,'2026-10-03T00:00:00Z');
INSERT INTO t_security_feed_state(source_id,kind,status) VALUES ('migration-feed','misp','failed');
UPDATE t_security_feed_state SET failure_count=CASE WHEN failure_count<1000 THEN failure_count+1 ELSE 1000 END
WHERE source_id='migration-feed';
INSERT INTO t_security_feed_run(id,source_id,trigger_type,started_at,status)
VALUES ('migration-run','migration-feed','scheduled','2026-10-03T00:00:00Z','failed');
DELETE FROM t_security_feed_run WHERE source_id='migration-feed' AND id NOT IN
  (SELECT id FROM t_security_feed_run WHERE source_id='migration-feed' ORDER BY started_at DESC,id DESC LIMIT 50);
SQL
assert_query "SELECT enabled || '|' || interval_ms FROM t_security_feed_schedule WHERE source_id='migration-feed'" "1|300000"
assert_query "SELECT failure_count FROM t_security_feed_state WHERE source_id='migration-feed'" "1"
assert_query "SELECT count(*) FROM t_security_feed_run WHERE source_id='migration-feed'" "1"
if app_sql -c 'CREATE TABLE privilege_escape(id INTEGER)' >"$work_dir/denied-ddl.log" 2>&1; then
  fail "Application role can create tables"
fi
if app_sql -c 'SELECT * FROM t_schema_migration' >"$work_dir/denied-history.log" 2>&1; then
  fail "Application role can read migration history"
fi
pass "application role supports DML and sequences but denies DDL and migration history"

cp "$work_dir/base/"*.sql "$work_dir/broken/"
cp "$repo_root/deploy/tests/fixtures/postgres/V002__broken.sql" "$work_dir/broken/V005__broken.sql"
expect_migration_failure "$work_dir/broken" "migration_test_missing_function"
assert_query "SELECT count(*) FROM t_schema_migration" "4"
assert_query "SELECT to_regclass('public.t_migration_rollback_probe') IS NULL" "t"
assert_query "SELECT hostname FROM t_agent WHERE agent_id = 'migration-fixture-agent'" "legacy-host"
pass "failed migration rolls back schema, data and version history together"

cp "$work_dir/base/"*.sql "$work_dir/tampered/"
printf '\n-- changed after release\n' >>"$work_dir/tampered/V001__pre_release_upgrade.sql"
expect_migration_failure "$work_dir/tampered" "Migration checksum mismatch"
assert_query "SELECT count(*) FROM t_schema_migration" "4"
assert_query "SELECT count(*) FROM t_audit_log WHERE body_digest = 'new-safe-digest'" "1"
pass "changed released migration blocks execution"

cp "$work_dir/base/V001__pre_release_upgrade.sql" "$work_dir/renamed/V002__renamed_upgrade.sql"
expect_migration_failure "$work_dir/renamed" "Applied migration file is missing"
assert_query "SELECT count(*) FROM t_schema_migration" "4"
assert_query "SELECT count(*) FROM t_audit_log WHERE body_digest = 'new-safe-digest'" "1"
pass "missing or renamed applied migration blocks execution before pending changes"

for migration in "$work_dir/base/"*.sql; do
  sed 's/$/\r/' "$migration" >"$work_dir/crlf/$(basename "$migration")"
done
run_migrations "$work_dir/crlf"
assert_query "SELECT applied_at FROM t_schema_migration ORDER BY version" "$applied_at"
assert_query "SELECT count(*) FROM t_audit_log WHERE body_digest = 'new-safe-digest'" "1"
pass "CRLF and LF copies share the same migration checksum"

owner_sql --set=test_db="$restore_database" <<'SQL'
SELECT format('CREATE DATABASE %I', :'test_db') \gexec
SQL
restore_database_created=true
PGDATABASE="$restore_database" pg_restore --exit-on-error --no-owner --no-privileges \
  --dbname="$restore_database" "$work_dir/legacy.dump"
restored_state="$(PGDATABASE="$restore_database" owner_sql -At -c "
  SELECT hostname || '|' || (SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public')
  FROM t_agent WHERE agent_id = 'migration-fixture-agent';")"
[[ "$restored_state" == "legacy-host|35" ]] || fail "Unexpected restored legacy state: $restored_state"
pass "legacy backup restores into a fresh database with original schema and host data"

run_migrations "$work_dir/base" "$restore_database"
restored_state="$(PGDATABASE="$restore_database" owner_sql -At -c "
  SELECT isolation_status || '|' || (SELECT count(*) FROM t_schema_migration)
  FROM t_agent WHERE agent_id = 'migration-fixture-agent';")"
[[ "$restored_state" == "0|3" ]] || fail "Unexpected restored upgrade state: $restored_state"
pass "restored backup can upgrade through the production migration runner"
printf 'Passed %s PostgreSQL migration checks.\n' "$checks"
