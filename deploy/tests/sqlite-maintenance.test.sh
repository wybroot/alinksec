#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
maintenance_script="$script_dir/../sqlite-maintenance.sh"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/alinksec-maintenance-test.XXXXXX")
trap 'rm -rf -- "$test_root"' EXIT

# Simulate Compose failures at each step without touching a real deployment.
docker() {
  [[ "$1" == compose ]] || return 99
  shift
  while [[ "$1" != run && "$1" != stop && "$1" != up ]]; do
    shift
  done
  local action=$1
  shift
  case "$action" in
    stop)
      [[ "$*" == 'server web' ]] || return 99
      echo stop >> "$TEST_CASE_DIR/events"
      [[ "$TEST_SCENARIO" != stop-error ]] || return 1
      echo stopped > "$TEST_CASE_DIR/server"
      ;;
    up)
      [[ "$*" == '-d --wait --wait-timeout 180 server web' ]] || return 99
      echo up >> "$TEST_CASE_DIR/events"
      echo running > "$TEST_CASE_DIR/server"
      if [[ "$TEST_SCENARIO" == health-error && $(cat "$TEST_CASE_DIR/live") == selected ]] ||
         [[ "$TEST_SCENARIO" == rollback-health-error ]]; then
        return 1
      fi
      ;;
    run)
      [[ "$*" == '--rm -T --no-deps sqlite-maintenance '* ]] || return 99
      shift 4
      local database=$1 sql=$2 name
      printf '%s %s\n' "$database" "$sql" >> "$TEST_CASE_DIR/events"
      case "$sql" in
        *'VACUUM INTO '*)
          [[ "$TEST_SCENARIO" != snapshot-error ]] || return 1
          name=${sql##*"/backups/"}
          name=${name%%"'"*}
          cp "$TEST_CASE_DIR/live" "$ALINKSEC_BACKUP_DIR/$name"
          ;;
        '.restore /backups/'*)
          [[ $(cat "$TEST_CASE_DIR/server") == stopped ]] || return 99
          name=${sql#'.restore /backups/'}
          if [[ "$name" == selected.db ]]; then
            echo selected > "$TEST_CASE_DIR/live"
            case "$TEST_SCENARIO" in
              restore-error|rollback-error|rollback-check-error|rollback-health-error)
                return 1
                ;;
            esac
          else
            [[ "$TEST_SCENARIO" != rollback-error ]] || return 1
            cp "$ALINKSEC_BACKUP_DIR/$name" "$TEST_CASE_DIR/live"
          fi
          ;;
        'PRAGMA integrity_check;')
          if [[ "$database" == /backups/selected.db ]]; then
            case "$TEST_SCENARIO" in
              invalid-backup) echo 'not ok'; return 0 ;;
              backup-check-error) return 1 ;;
            esac
          elif [[ "$database" == /data/alinksec.db && $(cat "$TEST_CASE_DIR/live") == selected ]]; then
            case "$TEST_SCENARIO" in
              integrity-error) return 1 ;;
              invalid-integrity) echo 'not ok'; return 0 ;;
            esac
          elif [[ "$database" == /data/alinksec.db && "$TEST_SCENARIO" == rollback-check-error ]]; then
            return 1
          fi
          printf 'ok\r\n'
          ;;
        *) return 99 ;;
      esac
      ;;
  esac
}
export -f docker

passed=0
run_case() {
  local scenario=$1 command=$2 expected_exit=$3
  export TEST_SCENARIO=$scenario
  export TEST_CASE_DIR="$test_root/$scenario"
  export ALINKSEC_BACKUP_DIR="$TEST_CASE_DIR/backups"
  export ALINKSEC_LITE_ENV_FILE="$TEST_CASE_DIR/env.lite"
  mkdir -p "$ALINKSEC_BACKUP_DIR"
  touch "$ALINKSEC_LITE_ENV_FILE" "$TEST_CASE_DIR/events"
  echo original > "$TEST_CASE_DIR/live"
  echo selected > "$ALINKSEC_BACKUP_DIR/selected.db"
  echo running > "$TEST_CASE_DIR/server"

  local status=0
  if [[ "$command" == backup ]]; then
    bash "$maintenance_script" backup online.db > "$TEST_CASE_DIR/output" 2>&1 || status=$?
  elif [[ "$command" == verify ]]; then
    bash "$maintenance_script" verify selected.db > "$TEST_CASE_DIR/output" 2>&1 || status=$?
  else
    bash "$maintenance_script" restore selected.db --yes > "$TEST_CASE_DIR/output" 2>&1 || status=$?
  fi
  if [[ "$status" != "$expected_exit" ]]; then
    cat "$TEST_CASE_DIR/output" >&2
    echo "FAIL: $scenario exited $status, expected $expected_exit" >&2
    exit 1
  fi
}

assert_state() {
  [[ $(cat "$TEST_CASE_DIR/live") == "$1" ]]
  [[ $(cat "$TEST_CASE_DIR/server") == "$2" ]]
}

assert_untouched() {
  assert_state original running
  ! grep -q '^stop$' "$TEST_CASE_DIR/events"
  ! grep -q '\.restore ' "$TEST_CASE_DIR/events"
}

pass() {
  passed=$((passed + 1))
  echo "PASS: $TEST_SCENARIO"
}

run_case online-backup backup 0
assert_untouched
[[ $(cat "$ALINKSEC_BACKUP_DIR/online.db") == original ]]
pass

for scenario in invalid-backup backup-check-error; do
  run_case "$scenario" restore 1
  assert_untouched
  ! grep -q 'VACUUM INTO' "$TEST_CASE_DIR/events"
  pass
done

run_case snapshot-error restore 1
assert_untouched
pass

run_case stop-error restore 1
assert_state original running
! grep -q '\.restore ' "$TEST_CASE_DIR/events"
pass

run_case restore-success restore 0
assert_state selected running
grep -q 'Restore completed' "$TEST_CASE_DIR/output"
grep -q '^up$' "$TEST_CASE_DIR/events"
[[ $(cat "$ALINKSEC_BACKUP_DIR"/pre-restore-*.db) == original ]]
pass

for scenario in restore-error integrity-error invalid-integrity health-error; do
  run_case "$scenario" restore 1
  assert_state original running
  grep -q 'rolled back from pre-restore-' "$TEST_CASE_DIR/output"
  ! grep -q 'Restore completed' "$TEST_CASE_DIR/output"
  pass
done

run_case rollback-error restore 1
assert_state selected stopped
grep -q 'automatic rollback failed' "$TEST_CASE_DIR/output"
! grep -q '^up$' "$TEST_CASE_DIR/events"
pass

run_case rollback-check-error restore 1
assert_state original stopped
grep -q 'automatic rollback failed' "$TEST_CASE_DIR/output"
! grep -q '^up$' "$TEST_CASE_DIR/events"
pass

run_case rollback-health-error restore 1
assert_state original stopped
grep -q 'database rolled back.*server remains stopped' "$TEST_CASE_DIR/output"
pass

echo "$passed maintenance workflow tests passed."
