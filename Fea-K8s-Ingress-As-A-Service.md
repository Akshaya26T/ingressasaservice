## Add new Traefik as ingress/reverse proxy service and wire the app services behind it.
## Add sample frontend, backend, api app services
## Add Domain variable .env file, to make it flexible
## Configure routing with domain based rules

## test routes are working
```
echo "--- Frontend (app.localhost) ---" && curl -s -o /dev/null -w "HTTP %{http_code}\n" -H "Host: app.localhost" http://127.0.0.1 && echo "--- Frontend (www.app.localhost) ---" && curl -s -o /dev/null -w "HTTP %{http_code}\n" -H "Host: www.app.localhost" http://127.0.0.1 && echo "--- API (api.app.localhost) ---" && curl -s -H "Host: api.app.localhost" http://127.0.0.1
```
## Add node.js webapp in a separate container named "dashboard"
```
docker compose up -d dashboard && sleep 2 && echo "=== Frontend ===" && curl -s -o /dev/null -w "HTTP %{http_code}\n" -H "Host: app.localhost" http://127.0.0.1 && echo "=== API /health ===" && curl -s -w " HTTP %{http_code}\n" -H "Host: api.app.localhost" http://127.0.0.1/health && echo "=== Dashboard ===" && curl -s -o /dev/null -w "HTTP %{http_code}\n" -H "Host: dashboard.app.localhost" http://127.0.0.1
```
## Traefik routing table — all on port 80, domain-based:

| Domain | Service | Port |
|----------|----------|----------|
| app.localhost / www.app.localhost   | frontend | 3000  |
| api.app.localhost | api  | 4000 |
| dashboard.app.localhost | dashboard | 5000|

## Test Direct access to make sure containers are not reachable from host ports without Traefik
```
curl -s -o /dev/null -w 'frontend:%{http_code}\n' http://127.0.0.1:3000 || true; curl -s -o /dev/null -w 'api:%{http_code}\n' http://127.0.0.1:4000 || true; curl -s -o /dev/null -w 'dashboard:%{http_code}\n' http://127.0.0.1:5000 || true
```
## Add Multiple instances and test load balancing
## Add a new frontend-canary service for the new version traffic slice.
## Add health-check labels for stable/canary frontend services

```
# ===========================================================================
# Traefik Dynamic Configuration — Weighted Canary / Load-Balanced Routing
# ===========================================================================
# This file hot-reloads automatically (--providers.file.watch=true).
# Edit weights in-place to shift traffic with zero downtime / no restarts.
#
# Update the Host() rules below if APP_DOMAIN is not "app.localhost".
#
# Traffic weight semantics:
#   weight: 0  — no traffic routed (safe to have backend stopped)
#   weight: 1  — proportional share (1:9 ratio with stable = 10% canary)
#   weight: 10 — full share (use to fully promote canary)
#
# ---------------------------------------------------------------------------
# Canary Deployment Workflow
# ---------------------------------------------------------------------------
# 1. Scale stable instances:
#      docker compose up -d --scale frontend=3
#
# 2. Build & start canary (new image/version):
#      docker compose build frontend-canary
#      docker compose up -d frontend-canary
#
# 3. Route 10% to canary — edit weights below:
#      frontend:        weight: 9
#      frontend-canary: weight: 1
#    (file hot-reloads; no restart needed)
#
# 4. Monitor. Gradually increase canary share (5/5, then 0/10).
#
# 5. Promote canary fully — set:
#      frontend:        weight: 0
#      frontend-canary: weight: 10
#
# 6. After validation, rebuild stable with new image, then scale down canary:
#      docker compose stop frontend-canary
#    Reset weights back to: frontend: 10, frontend-canary: 0
#    Rebuild stable: docker compose build frontend && docker compose up -d --scale frontend=3
# ---------------------------------------------------------------------------

http:
  routers:
    frontend:
      rule: "Host(`app.localhost`) || Host(`www.app.localhost`) || Host(`localhost`) || Host(`127.0.0.1`)"
      entryPoints:
        - web
      service: frontend-weighted

  services:
    # -------------------------------------------------------------------------
    # Weighted entry point — controls traffic split between stable and canary.
    # Traefik auto-round-robins within each service across all running replicas.
    # -------------------------------------------------------------------------
    frontend-weighted:
      weighted:
        services:
          - name: frontend@docker          # stable: all replicas load-balanced equally
            weight: 9                     # 100% initially; reduce when canary is live
          - name: frontend-canary@docker   # canary: receives weight/(stable+canary) % traffic
            weight: 1                      # 0 = disabled; set to 1 for ~10%, 5 for ~50%, etc.
```
## Load test 1
```
bash check_canary_split.sh app.localhost 60
```
## Result
```
Service	Instances	Role
frontend	3 replicas	stable (90%)
frontend-canary	1 replica	canary (10%)
traefik	1	router/LB
api, dashboard, azdevops-agent	1 each	unchanged

Observed traffic split (60 samples):

stable: 54 hits → 90%
canary: 6 hits → 10%
```
## Load test 2 - Test for unhealthy instance and version split
```
cd /Users/karthikpandian/azuredevopsdeployagent && docker pause azuredevopsdeployagent-frontend-2 && sleep 15 && bash -lc '
stable=0; canary=0; other=0; fail=0;
for i in {1..200}; do
  out=$(curl -sS -D - -o /dev/null http://127.0.0.1/ 2>/dev/null || true)
  code=$(printf "%s" "$out" | awk "/^HTTP//{print \$2; exit}")
  ver=$(printf "%s" "$out" | awk -F": " "BEGIN{IGNORECASE=1} /^X-App-Version:/{gsub(/\r/,"",\$2); print \$2; exit}")
  if [[ "$code" != "200" ]]; then
    fail=$((fail+1))
  fi
  case "$ver" in
    stable) stable=$((stable+1));;
    canary) canary=$((canary+1));;
    *) other=$((other+1));;
  esac
  sleep 0.02
done

echo "paused replica: azuredevopsdeployagent-frontend-2"
echo "http_200_stable=$stable"
echo "http_200_canary=$canary"
echo "other_or_missing_version=$other"
echo "non_200_or_errors=$fail"
'
```

## Load test 3 - Test for higher sample size with 5/5 stable/canary 
```
cd /Users/karthikpandian/azuredevopsdeployagent && docker pause azuredevopsdeployagent-frontend-2 && sleep 15 && bash -lc '
stable=0; canary=0; other=0; fail=0;
for i in {1..200}; do
  out=$(curl -sS -D - -o /dev/null http://127.0.0.1/ 2>/dev/null || true)
  code=$(printf "%s" "$out" | awk "/^HTTP//{print \$2; exit}")
  ver=$(printf "%s" "$out" | awk -F": " "BEGIN{IGNORECASE=1} /^X-App-Version:/{gsub(/\r/,"",\$2); print \$2; exit}")
  if [[ "$code" != "200" ]]; then
    fail=$((fail+1))
  fi
  case "$ver" in
    stable) stable=$((stable+1));;
    canary) canary=$((canary+1));;
    *) other=$((other+1));;
  esac
  sleep 0.02
done

echo "paused replica: azuredevopsdeployagent-frontend-2"
echo "http_200_stable=$stable"
echo "http_200_canary=$canary"
echo "other_or_missing_version=$other"
echo "non_200_or_errors=$fail"
'

O/P:
paused replica: azuredevopsdeployagent-frontend-2
http_200_stable=180
http_200_canary=20
other_or_missing_version=0
non_200_or_errors=0
```
```
bash check_canary_split.sh app.localhost 500

O/P:
Sampling 500 requests against host 'app.localhost' via http://127.0.0.1/
stable:  250
canary:  250
unknown: 0
failed:  0
observed split (successes only): sta
```

## Test - Create new version of the app and deploy
1. File changed: server.js
```
app.get('/config.json', (_req, res) => {
  res.json({
    apiUrl: API_URL,
    appVersion: APP_VERSION,
    appRelease: APP_RELEASE,
    featureBanner: FEATURE_BANNER,
  });
});
```
2. File changed : index.html
```
      const meta = document.getElementById('release-meta');
      meta.textContent = `Release: ${cfg.appRelease || 'n/a'} | Version: ${cfg.appVersion || 'n/a'}`;

      const banner = document.getElementById('exp-banner');
      if (cfg.featureBanner) {
        banner.style.display = 'block';
      }
```
3. File changed : docker-compose.yml
```
environment:
      - API_URL=http://api.${APP_DOMAIN:-app.localhost}
      - APP_VERSION=canary
      - APP_RELEASE=v2
      - FEATURE_BANNER=true
```
### Commands ran
```
curl -s http://127.0.0.1/config.json
bash check_canary_split.sh app.localhost 300
```
### Results:
Sampling 300 requests against host 'app.localhost' via http://127.0.0.1/
stable:  150
canary:  150
unknown: 0
failed:  0
observed split (successes only): stable=50.00% canary=50.00%

# Mar 26, 2026
## Route the apps using PATH based routing in Traefik
