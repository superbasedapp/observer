#!/usr/bin/env bash
# redeploy-wsl-unit.sh — safe redeploy of the WSL systemd --user observer.service
# when AI clients route through the proxy (:8820). Replaces the setsid-based
# scripts/restart-daemon.sh for unit-managed daemons (2026-09-03 dev-box model).
#
#   route OFF (drop env.ANTHROPIC_BASE_URL from ~/.claude/settings.json, backup)
#     → mv bin/observer.new over bin/observer (rollback copy kept)
#     → systemctl --user restart observer.service → poll :8820 + :8081
#     → route ON (restore the saved URL)
#
# Build the staged binary first, from the Windows checkout:
#   GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/observer.new ./cmd/observer
# Run from WSL (or from MSYS bash: MSYS_NO_PATHCONV=1 wsl.exe -- bash /mnt/d/.../scripts/redeploy-wsl-unit.sh)
# Bind window on the dev box is ~40–60 s (prewarm / index-on-start) — the route toggle is NOT optional.
set -u
REPO="${REPO:-/mnt/d/programsx/superbased-observer}"
SETTINGS="${SETTINGS:-$HOME/.claude/settings.json}"
STAMP="$(date +%Y%m%d-%H%M%S)"
py() { python3 "$@" 2>/dev/null || python "$@"; }
[ -x "$REPO/bin/observer.new" ] || { echo "no staged binary at $REPO/bin/observer.new" >&2; exit 1; }
SAVED=$(py -c "import json,sys; d=json.load(open(sys.argv[1])); print(d.get('env',{}).get('ANTHROPIC_BASE_URL',''))" "$SETTINGS")
echo "route before: ${SAVED:-<unset>}"
cp "$SETTINGS" "$SETTINGS.bak.redeploy-$STAMP"
if [ -n "$SAVED" ]; then py - "$SETTINGS" <<'PY'
import json,sys; p=sys.argv[1]; d=json.load(open(p)); d.get('env',{}).pop('ANTHROPIC_BASE_URL',None); json.dump(d,open(p,'w'),indent=2)
PY
echo "route OFF"; fi
cd "$REPO" && mv bin/observer "bin/observer.pre-$STAMP" && mv bin/observer.new bin/observer && chmod +x bin/observer && echo "binary swapped (rollback: bin/observer.pre-$STAMP)"
T0=$(date +%s.%N); systemctl --user restart observer.service
for _ in $(seq 1 90); do sleep 1; if curl -s -m 2 -o /dev/null http://127.0.0.1:8820/ && curl -s -m 2 -o /dev/null http://127.0.0.1:8081/api/health; then break; fi; done
T1=$(date +%s.%N); echo "restart window: $(py -c "print(round($T1-$T0,1))")s"
if [ -n "$SAVED" ]; then py - "$SETTINGS" "$SAVED" <<'PY'
import json,sys; p,url=sys.argv[1],sys.argv[2]; d=json.load(open(p)); d.setdefault('env',{})['ANTHROPIC_BASE_URL']=url; json.dump(d,open(p,'w'),indent=2)
PY
echo "route ON"; fi
systemctl --user is-active observer.service; curl -s -m 5 -o /dev/null -w "dashboard %{http_code}\n" http://127.0.0.1:8081/api/health
curl -s -m 5 http://127.0.0.1:8081/api/status | tr ',' '\n' | grep schema_version
journalctl --user -u observer.service -n 40 --no-pager 2>/dev/null | grep -i "level=ERROR" | tail -3 || true
