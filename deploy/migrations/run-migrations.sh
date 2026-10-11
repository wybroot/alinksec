#!/usr/bin/env bash
set -Eeuo pipefail

: "${PGHOST:?PGHOST is required}"
: "${PGDATABASE:?PGDATABASE is required}"
: "${PGUSER:?PGUSER is required}"
: "${PGPASSWORD:?PGPASSWORD is required}"
: "${ALINKSEC_APP_DB_USER:?ALINKSEC_APP_DB_USER is required}"
: "${ALINKSEC_APP_DB_PASSWORD:?ALINKSEC_APP_DB_PASSWORD is required}"
: "${ALINKSEC_BIND_ADDRESS:?ALINKSEC_BIND_ADDRESS is required}"
MIGRATIONS_DIR="${ALINKSEC_MIGRATIONS_DIR:-/migrations}"

if [[ "$ALINKSEC_BIND_ADDRESS" == "0.0.0.0" || "$ALINKSEC_BIND_ADDRESS" == "::" ||
      ! "$ALINKSEC_BIND_ADDRESS" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "ALINKSEC_BIND_ADDRESS must be a specific local IPv4 address, not a wildcard." >&2
  exit 1
fi
IFS=. read -r -a bind_octets <<< "$ALINKSEC_BIND_ADDRESS"
for octet in "${bind_octets[@]}"; do
  if ((10#$octet > 255)); then
    echo "ALINKSEC_BIND_ADDRESS contains an invalid IPv4 octet." >&2
    exit 1
  fi
done
if [[ "$PGUSER" == "$ALINKSEC_APP_DB_USER" || "$PGPASSWORD" == "$ALINKSEC_APP_DB_PASSWORD" ]]; then
  echo "The migration owner and application role must use different names and passwords." >&2
  exit 1
fi

if [[ ! -d "$MIGRATIONS_DIR" ]]; then
  echo "Migration directory does not exist: $MIGRATIONS_DIR" >&2
  exit 1
fi
shopt -s nullglob
migrations=("$MIGRATIONS_DIR"/V*.sql)
if ((${#migrations[@]} == 0)); then
  echo "No migration files found: $MIGRATIONS_DIR" >&2
  exit 1
fi
declare -A migration_checksums
for migration in "${migrations[@]}"; do
  filename="$(basename "$migration")"
  version="${filename%.sql}"
  if [[ ! "$version" =~ ^V[0-9]+__[A-Za-z0-9_]+$ || ! -f "$migration" || ! -r "$migration" || ! -s "$migration" ]]; then
    echo "Invalid, empty or unreadable migration file: $filename" >&2
    exit 1
  fi
  migration_checksums["$version"]="$(sed -e 's/\r$//' "$migration" | sha256sum | awk '{print $1}')"
done

# Check the entire released history before changing roles or applying pending SQL.
history_exists="$(psql -X -v ON_ERROR_STOP=1 -At <<'SQL'
SELECT to_regclass('public.t_schema_migration') IS NOT NULL;
SQL
)"
if [[ "$history_exists" == "t" ]]; then
  applied_migrations="$(psql -X -v ON_ERROR_STOP=1 -At -F $'\t' <<'SQL'
SELECT version, checksum FROM public.t_schema_migration ORDER BY version;
SQL
)"
  while IFS=$'\t' read -r applied_version applied_checksum; do
    [[ -n "$applied_version" ]] || continue
    if [[ -z "${migration_checksums[$applied_version]+present}" ]]; then
      echo "Applied migration file is missing: $applied_version" >&2
      exit 1
    fi
    if [[ "${migration_checksums[$applied_version]}" != "$applied_checksum" ]]; then
      echo "Migration checksum mismatch: $applied_version" >&2
      exit 1
    fi
  done <<< "$applied_migrations"
fi

psql -X -v ON_ERROR_STOP=1 \
  --set=app_user="$ALINKSEC_APP_DB_USER" \
  --set=app_password="$ALINKSEC_APP_DB_PASSWORD" <<'SQL'
SELECT format(
  'CREATE ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS',
  :'app_user', :'app_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'app_user') \gexec

SELECT format(
  'ALTER ROLE %I WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS',
  :'app_user', :'app_password') \gexec

CREATE TABLE IF NOT EXISTS public.t_schema_migration (
  version VARCHAR(128) PRIMARY KEY,
  checksum VARCHAR(64) NOT NULL,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
SQL

for migration in "${migrations[@]}"; do
  filename="$(basename "$migration")"
  version="${filename%.sql}"
  checksum="${migration_checksums[$version]}"
  applied_checksum="$(psql -X -v ON_ERROR_STOP=1 -At \
    --set=migration_version="$version" <<'SQL'
SELECT checksum FROM public.t_schema_migration WHERE version = :'migration_version';
SQL
)"

  if [[ -n "$applied_checksum" ]]; then
    if [[ "$applied_checksum" != "$checksum" ]]; then
      echo "Migration checksum mismatch: $version" >&2
      exit 1
    fi
    echo "Migration already applied: $version"
    continue
  fi

  echo "Applying migration: $version"
  {
    printf '\\set ON_ERROR_STOP on\nBEGIN;\n'
    sed -e 's/\r$//' "$migration"
    printf '\nINSERT INTO public.t_schema_migration (version, checksum) VALUES (:\047migration_version\047, :\047migration_checksum\047);\nCOMMIT;\n'
  } | psql -X \
      --set=migration_version="$version" \
      --set=migration_checksum="$checksum"
done

psql -X -v ON_ERROR_STOP=1 --set=app_user="$ALINKSEC_APP_DB_USER" <<'SQL'
-- The legacy bootstrap inserts template id=1 explicitly. Advance its sequence
-- before new reviewed templates use generated IDs; never reset an advanced one.
-- The table lock serializes ordinary inserts with this startup repair.
BEGIN;
LOCK TABLE public.t_baseline_template IN ACCESS EXCLUSIVE MODE;
SELECT setval(pg_get_serial_sequence('public.t_baseline_template', 'id'),
  GREATEST(COALESCE((SELECT MAX(id) FROM public.t_baseline_template), 1),
           (SELECT last_value FROM public.t_baseline_template_id_seq)), true);
COMMIT;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM :"app_user";
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM :"app_user";
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), :'app_user') \gexec
GRANT USAGE ON SCHEMA public TO :"app_user";
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO :"app_user";
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO :"app_user";
REVOKE ALL PRIVILEGES ON TABLE public.t_schema_migration FROM :"app_user";
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :"app_user";
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO :"app_user";
SQL

echo "Database migrations and application grants are current."
