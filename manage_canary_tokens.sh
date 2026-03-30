#!/usr/bin/env bash
set -euo pipefail

# Canary Token Manager
# Simplifies token-based canary testing and safe scale-down.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DYNAMIC_CONFIG="${SCRIPT_DIR}/traefik/conf/dynamic.yml"

usage() {
  cat <<EOF
Usage: $0 <command> [args]

Commands:
  add-token <TOKEN>           Add a token to the canary allowlist (hot-reload)
  remove-token <TOKEN>        Remove a token from the canary allowlist (hot-reload)
  list-tokens                 Show current allowed tokens
  enable-tokens               Route token-matched requests to canary
  disable-tokens              Drain token-matched traffic back to stable
  status                      Show current canary routing status
  scale-down                  Disable tokens and stop canary container (safe shutdown)
  promote [REPLICAS]          Promote canary to stable and scale down old stable
                              REPLICAS: number of stable replicas to start (default: 1)

Examples:
  $0 add-token qa-user-1
  $0 list-tokens
  $0 enable-tokens
  $0 disable-tokens
  $0 scale-down
  $0 promote 3

EOF
  exit 1
}

# ---------------------------------------------------------------------------
# Helper: update weights for a specific weighted service block in dynamic.yml.
# Args: section_name  app1_weight  canary_weight
# Uses Python3 (pre-installed on macOS) for reliable YAML line editing.
# ---------------------------------------------------------------------------
update_weights() {
  local section="$1"
  local app1_weight="$2"
  local canary_weight="$3"

  python3 - "${DYNAMIC_CONFIG}" "${section}" "${app1_weight}" "${canary_weight}" <<'PYEOF'
import sys, os, tempfile

config_file = sys.argv[1]
section     = sys.argv[2]
app1_w      = sys.argv[3]
canary_w    = sys.argv[4]
section_marker = section + ":"

with open(config_file) as f:
    lines = f.readlines()

in_section         = False
next_app1_weight   = False
next_canary_weight = False
out = []

for line in lines:
    raw     = line.rstrip('\n')
    stripped = raw.strip()

    if not stripped.startswith('#') and section_marker in raw:
        in_section = True

    if in_section and not stripped.startswith('#'):
        if '- name: app1@docker' in stripped:
            next_app1_weight = True
        elif '- name: app1-canary@docker' in stripped:
            next_canary_weight = True
        elif next_app1_weight and stripped.startswith('weight:'):
            leading = len(raw) - len(raw.lstrip())
            line = ' ' * leading + 'weight: ' + app1_w + '\n'
            next_app1_weight = False
        elif next_canary_weight and stripped.startswith('weight:'):
            leading = len(raw) - len(raw.lstrip())
            line = ' ' * leading + 'weight: ' + canary_w + '\n'
            next_canary_weight = False
            in_section = False

    out.append(line)

# Write atomically
tmp_dir = os.path.dirname(os.path.abspath(config_file))
with tempfile.NamedTemporaryFile(mode='w', dir=tmp_dir, delete=False, suffix='.tmp') as tf:
    tf.writelines(out)
    tmp_name = tf.name
os.replace(tmp_name, config_file)
PYEOF
}

cmd_add_token() {
  local token="$1"
  if [[ -z "$token" ]]; then
    echo "Error: token is required"
    exit 1
  fi

  # Read the entire rule line
  local rule_line
  rule_line=$(grep "HeaderRegexp(\`X-Canary-Token\`" "$DYNAMIC_CONFIG" || echo "")

  if [[ -z "$rule_line" ]]; then
    echo "Error: HeaderRegexp not found in config"
    exit 1
  fi

  # Check if token already exists
  if echo "$rule_line" | grep -q "$token"; then
    echo "Token '$token' already in allowlist"
    exit 0
  fi

  # Create new rule by inserting the token before the closing )$
  # Pattern: ^(token1|token2)$  becomes  ^(token1|token2|newtoken)$
  local new_rule
  new_rule=$(echo "$rule_line" | sed "s/)\\$/|${token})\$/")

  # Escape special chars in the rule for use as sed pattern
  local escaped_old
  escaped_old=$(printf '%s\n' "$rule_line" | sed -e 's/[\/&]/\\&/g')
  local escaped_new
  escaped_new=$(printf '%s\n' "$new_rule" | sed -e 's/[\/&]/\\&/g')

  sed -i.bak "s/${escaped_old}/${escaped_new}/" "$DYNAMIC_CONFIG"

  rm -f "${DYNAMIC_CONFIG}.bak"
  echo "✓ Added token '${token}' to canary allowlist"
  echo "  Traefik will hot-reload in ~1 second"
}

cmd_remove_token() {
  local token="$1"
  if [[ -z "$token" ]]; then
    echo "Error: token is required"
    exit 1
  fi

  local rule_line
  rule_line=$(grep "HeaderRegexp(\`X-Canary-Token\`" "$DYNAMIC_CONFIG" || echo "")

  if [[ -z "$rule_line" ]]; then
    echo "Error: HeaderRegexp not found in config"
    exit 1
  fi

  if ! echo "$rule_line" | grep -q "$token"; then
    echo "Token '$token' not found in allowlist"
    exit 1
  fi

  # Remove token from pattern: remove |token or token| if found
  local new_rule
  new_rule=$(echo "$rule_line" | sed "s/|${token}//g" | sed "s/${token}|//g")

  # Check if we would end up with empty token list
  if ! echo "$new_rule" | grep -qE "\^\\([a-zA-Z0-9_-]+\\)\$"; then
    echo "Error: cannot remove last token"
    exit 1
  fi

  local escaped_old
  escaped_old=$(printf '%s\n' "$rule_line" | sed -e 's/[\/&]/\\&/g')
  local escaped_new
  escaped_new=$(printf '%s\n' "$new_rule" | sed -e 's/[\/&]/\\&/g')

  sed -i.bak "s/${escaped_old}/${escaped_new}/" "$DYNAMIC_CONFIG"

  rm -f "${DYNAMIC_CONFIG}.bak"
  echo "✓ Removed token '${token}' from canary allowlist"
  echo "  Traefik will hot-reload in ~1 second"
}

cmd_list_tokens() {
  local current_rule
  current_rule=$(grep "HeaderRegexp(\`X-Canary-Token\`" "$DYNAMIC_CONFIG" || echo "")

  if [[ -z "$current_rule" ]]; then
    echo "No HeaderRegexp found in config"
    exit 1
  fi

  # Extract token list from regex: ^(token1|token2)$
  local token_list
  token_list=$(echo "$current_rule" | sed -n "s/.*\^(\(.*\))\$.*/\1/p")

  if [[ -z "$token_list" ]]; then
    echo "No tokens found"
    exit 1
  fi

  echo "Current allowed tokens:"
  echo "$token_list" | tr '|' '\n' | sed 's/^/  - /'
}

cmd_enable_tokens() {
  echo "Enabling token canary routing..."
  update_weights "app1-token-weighted" 0 10
  echo "✓ Token-matched requests now route to canary"
  echo "  Use 'add-token' to add users to the allowlist"
}

cmd_disable_tokens() {
  echo "Draining token-matched traffic back to stable..."
  update_weights "app1-token-weighted" 10 0
  echo "✓ Token canary routing disabled (all traffic back to stable)"
  echo "  Safe to scale down canary now"
}

cmd_status() {
  echo "=== Canary Status ===="
  echo

  # Check if canary container is running
  if cd "$SCRIPT_DIR" && docker compose ps app1-canary 2>/dev/null | grep -q "Up"; then
    echo "Canary container: running"
  else
    echo "Canary container: stopped"
  fi

  # Show current token allowlist
  echo
  echo "Allowed tokens for canary:"
  cmd_list_tokens 2>/dev/null || echo "  (none or parse error)"

  # Check if token router is enabled
  echo
  if grep -q "^# *app1-canary-token:" "$DYNAMIC_CONFIG"; then
    echo "Token router: disabled (commented out in config)"
  elif grep -q "^[[:space:]]*app1-canary-token:" "$DYNAMIC_CONFIG"; then
    echo "Token router: enabled"
  else
    echo "Token router: not found"
  fi
}

cmd_scale_down() {
  echo "Starting safe canary scale-down..."
  echo

  echo "1. Draining token traffic back to stable..."
  update_weights "app1-token-weighted" 10 0
  sleep 2

  echo
  echo "2. Stopping canary container..."
  cd "$SCRIPT_DIR"
  docker compose stop app1-canary || true

  echo
  echo "✓ Scale-down complete. Canary is stopped and all traffic on stable."
}

cmd_promote() {
  local replicas="${1:-1}"
  cd "$SCRIPT_DIR"

  # Resolve image names from running containers
  local stable_image canary_image
  stable_image=$(docker inspect \
    "$(docker compose ps -q app1 2>/dev/null | head -1)" \
    --format '{{.Config.Image}}' 2>/dev/null || echo "sample-frontend:latest")
  canary_image=$(docker inspect \
    "$(docker compose ps -q app1-canary 2>/dev/null | head -1)" \
    --format '{{.Config.Image}}' 2>/dev/null || echo "sample-frontend-canary:latest")

  echo "=== Canary Promotion ==="
  echo
  echo "  Stable image : ${stable_image}"
  echo "  Canary image : ${canary_image}"
  echo "  Replicas     : ${replicas}"
  echo
  echo "Steps that will run:"
  echo "  1. Shift ALL traffic to canary (Traefik hot-reload)"
  echo "  2. Health-check canary under full load"
  echo "  3. Scale down old stable (app1)"
  echo "  4. Tag canary image as the new stable image"
  echo "  5. Scale up new stable (app1) with promoted image"
  echo "  6. Shift traffic back to new stable (Traefik hot-reload)"
  echo "  7. Drain token router + stop canary"
  echo
  read -r -p "Proceed? [y/N] " confirm
  if [[ "${confirm,,}" != "y" ]]; then
    echo "Promotion cancelled."
    exit 0
  fi
  echo

  # ── Step 1 ──────────────────────────────────────────────────────────────
  echo "Step 1: Shifting all traffic to canary..."
  update_weights "app1-default-weighted" 0 10
  echo "  Waiting for Traefik hot-reload..."
  sleep 3

  # ── Step 2 ──────────────────────────────────────────────────────────────
  echo
  echo "Step 2: Health-checking canary under full traffic..."
  local health
  health=$(curl -sS "http://127.0.0.1:3000/app1/health" \
    | python3 -c \
      "import sys,json; d=json.load(sys.stdin); print(d.get('version','?'))" \
      2>/dev/null || echo "")

  if [[ "$health" == "canary" ]]; then
    echo "  ✓ Canary healthy (version: canary)"
  else
    echo "  WARNING: health check returned '${health:-no response}'"
    read -r -p "  Continue anyway? [y/N] " ok
    if [[ "${ok,,}" != "y" ]]; then
      echo "  Rolling back to stable..."
      update_weights "app1-default-weighted" 10 0
      echo "  Rolled back. Promotion aborted."
      exit 1
    fi
  fi

  # ── Step 3 ──────────────────────────────────────────────────────────────
  echo
  echo "Step 3: Scaling down old stable (app1)..."
  docker compose stop app1
  echo "  ✓ app1 (old stable) stopped"

  # ── Step 4 ──────────────────────────────────────────────────────────────
  echo
  echo "Step 4: Tagging canary image as new stable image..."
  docker tag "${canary_image}" "${stable_image}"
  echo "  ✓ ${canary_image} → ${stable_image}"

  # ── Step 5 ──────────────────────────────────────────────────────────────
  echo
  echo "Step 5: Starting new stable with promoted image (${replicas} replica(s))..."
  docker compose up -d --no-build --scale "app1=${replicas}" app1
  echo "  Waiting for health checks (up to 30s)..."
  local retries=10
  while (( retries > 0 )); do
    if docker compose ps app1 2>/dev/null | grep -q "healthy"; then
      echo "  ✓ New stable is healthy"
      break
    fi
    sleep 3
    retries=$(( retries - 1 ))
  done
  if (( retries == 0 )); then
    echo "  WARNING: health check timed out — verify app1 manually before proceeding"
    read -r -p "  Continue with traffic switch? [y/N] " ok
    if [[ "${ok,,}" != "y" ]]; then
      echo "  Promotion paused. Fix app1, then re-run step 6+ manually."
      exit 1
    fi
  fi

  # ── Step 6 ──────────────────────────────────────────────────────────────
  echo
  echo "Step 6: Routing all traffic back to new stable..."
  update_weights "app1-default-weighted" 10 0
  update_weights "app1-token-weighted"   10 0
  echo "  Waiting for Traefik hot-reload..."
  sleep 3
  echo "  ✓ Traefik updated"

  # ── Step 7 ──────────────────────────────────────────────────────────────
  echo
  echo "Step 7: Stopping canary..."
  docker compose stop app1-canary || true
  echo "  ✓ Canary stopped"

  echo
  echo "✓ Promotion complete!"
  echo "  New stable (app1, ${replicas} replica(s)) is running the promoted image."
  echo "  All traffic routes to new stable via Traefik."
  echo
  echo "Next cycle:"
  echo "  Build new canary : docker compose build app1-canary"
  echo "  Start canary     : docker compose up -d app1-canary"
  echo "  Add test tokens  : $0 add-token <TOKEN>"
}

# Main
if [[ $# -eq 0 ]]; then
  usage
fi

case "$1" in
  add-token)
    shift
    cmd_add_token "$@"
    ;;
  remove-token)
    shift
    cmd_remove_token "$@"
    ;;
  list-tokens)
    cmd_list_tokens
    ;;
  enable-tokens)
    cmd_enable_tokens
    ;;
  disable-tokens)
    cmd_disable_tokens
    ;;
  status)
    cmd_status
    ;;
  scale-down)
    cmd_scale_down
    ;;
  promote)
    shift
    cmd_promote "$@"
    ;;
  *)
    echo "Unknown command: $1"
    usage
    ;;
esac
