#!/usr/bin/env bash
set -euo pipefail

host="${1:-localhost}"
samples="${2:-100}"
url="${3:-http://127.0.0.1:3000/app1/}"

stable=0
canary=0
unknown=0
failures=0

echo "Sampling ${samples} requests against host '${host}' via ${url}"

for ((i=1; i<=samples; i++)); do
  version=$(curl -sS -D - -o /dev/null -H "Host: ${host}" "${url}" \
    | awk -F': ' 'BEGIN{IGNORECASE=1} /^X-App-Version:/{gsub(/\r/,"",$2); print $2; exit}') || true

  case "${version}" in
    stable)
      stable=$((stable+1))
      ;;
    canary)
      canary=$((canary+1))
      ;;
    "")
      failures=$((failures+1))
      ;;
    *)
      unknown=$((unknown+1))
      ;;
  esac

done

observed=$((stable + canary + unknown))

echo
printf "stable:  %d\n" "$stable"
printf "canary:  %d\n" "$canary"
printf "unknown: %d\n" "$unknown"
printf "failed:  %d\n" "$failures"

if (( observed > 0 )); then
  stable_pct=$(awk -v n="$stable" -v d="$observed" 'BEGIN { printf "%.2f", (n*100)/d }')
  canary_pct=$(awk -v n="$canary" -v d="$observed" 'BEGIN { printf "%.2f", (n*100)/d }')
  echo "observed split (successes only): stable=${stable_pct}% canary=${canary_pct}%"
else
  echo "No successful responses observed."
fi
