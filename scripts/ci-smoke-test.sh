#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://127.0.0.1:3000}"
HOST_HEADER="${2:-localhost}"

retry() {
  local attempts="$1"
  local delay="$2"
  shift 2

  local n=1
  until "$@"; do
    if (( n >= attempts )); then
      echo "Command failed after ${attempts} attempts: $*"
      return 1
    fi
    n=$((n + 1))
    sleep "$delay"
  done
}

check_status_200() {
  local path="$1"
  local code
  code=$(curl -sS -o /dev/null -w "%{http_code}" -H "Host: ${HOST_HEADER}" "${BASE_URL}${path}")
  [[ "$code" == "200" ]]
}

echo "Waiting for services to be reachable through Traefik at ${BASE_URL}"
retry 30 2 check_status_200 "/app1/health"
retry 30 2 check_status_200 "/app2/health"
retry 30 2 check_status_200 "/app3/health"

echo "Checking version header presence on /app1"
version=$(curl -sS -D - -o /dev/null -H "Host: ${HOST_HEADER}" "${BASE_URL}/app1/" \
  | awk -F': ' 'BEGIN{IGNORECASE=1} /^X-App-Version:/{gsub(/\r/,"",$2); print $2; exit}')

if [[ -z "${version}" ]]; then
  echo "Missing X-App-Version header from /app1 response"
  exit 1
fi

if [[ "${version}" != "stable" && "${version}" != "canary" ]]; then
  echo "Unexpected X-App-Version value: ${version}"
  exit 1
fi

echo "Sampling canary/stable distribution"
split_output=$(./check_canary_split.sh "${HOST_HEADER}" 40 "${BASE_URL}/app1/")
echo "${split_output}"

failed=$(echo "${split_output}" | awk '/^failed:/{print $2}')
unknown=$(echo "${split_output}" | awk '/^unknown:/{print $2}')

if [[ -z "${failed}" || -z "${unknown}" ]]; then
  echo "Could not parse check_canary_split.sh output"
  exit 1
fi

if (( failed > 0 )); then
  echo "Canary split check has request failures"
  exit 1
fi

if (( unknown > 0 )); then
  echo "Canary split check returned unknown versions"
  exit 1
fi

echo "Smoke tests passed"
