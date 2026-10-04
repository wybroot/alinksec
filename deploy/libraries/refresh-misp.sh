#!/usr/bin/env bash
# Complete, curated text export -> atomic signature ZIP; run under one publisher account.
set -euo pipefail
umask 077

if [[ $# != 3 ]]; then
  echo "Usage: bash refresh-misp.sh CURL_CONFIG QUERY_JSON OUTPUT_ZIP" >&2
  exit 2
fi

config=$1
query=$2
output=$3
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
output_dir=$(dirname -- "$output")
for dependency in curl python3 flock; do
  command -v "$dependency" >/dev/null
done
[[ -r "$config" && -r "$query" && -d "$output_dir" ]]

# Shared directory lock avoids concurrent refreshes, including initial publication.
exec 9>"$output_dir/.alinksec-feed.lock"
flock -n 9 || exit 0
export_file=$(mktemp "$output_dir/.misp-export.XXXXXX")
trap 'rm -f -- "$export_file"' EXIT

# No redirects, retry loops or TLS bypass. Re-run the job after a failed request.
curl --config "$config" --fail --silent --show-error \
  --proto '=https' --connect-timeout 10 --max-time 180 \
  --max-filesize 67108864 --data-binary "@$query" --output "$export_file"
python3 "$script_dir/build-signature-package.py" \
  --input "$export_file" --output "$output" --name MISP.KnownHash
