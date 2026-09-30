#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/.." && pwd)
compose_file="$script_dir/docker/docker-compose.lite.yml"
env_file="${ALINKSEC_LITE_ENV_FILE:-$script_dir/docker/.env.lite}"
backup_dir="${ALINKSEC_BACKUP_DIR:-$repo_root/backups}"

usage() {
  cat <<'EOF'
Usage:
  deploy/sqlite-maintenance.sh backup [backup-name.db]
  deploy/sqlite-maintenance.sh verify <backup-name.db>
  deploy/sqlite-maintenance.sh restore <backup-name.db> --yes

backup uses SQLite VACUUM INTO and is safe while the lightweight server is running.
restore creates a pre-restore snapshot, stops the server, restores the selected file,
checks database integrity, and starts the server again. Failed restores are rolled back.
EOF
}

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

validate_name() {
  [[ "$1" =~ ^[A-Za-z0-9._-]+\.db$ ]] || fail "backup name must contain only letters, numbers, dot, underscore, or dash and end in .db"
}

mkdir -p "$backup_dir"
backup_dir=$(cd "$backup_dir" && pwd)
export ALINKSEC_BACKUP_DIR="$backup_dir"

compose=(docker compose)
if [[ -f "$env_file" ]]; then
  compose+=(--env-file "$env_file")
elif [[ -n "${ALINKSEC_LITE_ENV_FILE:-}" ]]; then
  fail "environment file not found: $env_file"
fi
compose+=(-f "$compose_file" --profile maintenance)

run_sqlite() {
  "${compose[@]}" run --rm -T --no-deps sqlite-maintenance "$@"
}

verify_backup() {
  local name=$1
  validate_name "$name"
  [[ -f "$backup_dir/$name" ]] || fail "backup not found: $backup_dir/$name"
  local result
  result=$(run_sqlite "/backups/$name" "PRAGMA integrity_check;")
  [[ "$result" == *"ok"* ]] || fail "integrity check failed for $name: $result"
  echo "Integrity check passed: $backup_dir/$name"
}

create_backup() {
  local name=$1
  validate_name "$name"
  [[ ! -e "$backup_dir/$name" ]] || fail "backup already exists: $backup_dir/$name"
  run_sqlite /data/alinksec.db "PRAGMA busy_timeout=5000; VACUUM INTO '/backups/$name';"
  verify_backup "$name"
  sha256sum "$backup_dir/$name"
}

rollback_restore() {
  local safety=$1
  local reason=$2
  local result
  if run_sqlite /data/alinksec.db ".restore /backups/$safety" && \
      result=$(run_sqlite /data/alinksec.db "PRAGMA integrity_check;") && \
      [[ "$result" == *"ok"* ]]; then
    "${compose[@]}" up -d server
    fail "$reason; rolled back from $safety"
  fi
  fail "$reason; automatic rollback failed and the server remains stopped; restore $safety manually"
}

command=${1:-}
case "$command" in
  backup)
    name=${2:-"alinksec-$(date -u +%Y%m%dT%H%M%SZ).db"}
    create_backup "$name"
    ;;
  verify)
    [[ $# -eq 2 ]] || { usage; exit 2; }
    verify_backup "$2"
    ;;
  restore)
    [[ $# -eq 3 && "$3" == "--yes" ]] || { usage; exit 2; }
    name=$2
    validate_name "$name"
    verify_backup "$name"
    safety="pre-restore-$(date -u +%Y%m%dT%H%M%SZ).db"
    create_backup "$safety"
    "${compose[@]}" stop server
    if ! run_sqlite /data/alinksec.db ".restore /backups/$name"; then
      rollback_restore "$safety" "restore command failed"
    fi
    result=$(run_sqlite /data/alinksec.db "PRAGMA integrity_check;")
    if [[ "$result" != *"ok"* ]]; then
      rollback_restore "$safety" "restored database failed integrity check"
    fi
    "${compose[@]}" up -d server
    echo "Restore completed from $backup_dir/$name"
    echo "Pre-restore snapshot: $backup_dir/$safety"
    ;;
  *)
    usage
    exit 2
    ;;
esac
