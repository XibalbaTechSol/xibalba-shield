#!/usr/bin/env bash
# C6 F1 — turn off the development-only responder override on the live sensor, safely.
#
# The override (scripts/enable_dev_unsafe_responders.sh) marks every production readiness
# proof as passed, which unlocks the kill_process, freeze_cgroup and block_flow responders
# without evidence. Removing it restores the evidence-backed gates in
# shield/agent_core/readiness.py. Plain SIGSTOP containment (router -> ActionBroker.contain(pid))
# is not gated, so containment keeps working; this script proves that live.
#
# Steps, each verified before the next; any failure after step 2 restores the backups:
#   1. Back up shield.env and the dev-unsafe-responders drop-in.
#   2. Run scripts/disable_dev_unsafe_responders.sh (strips SHIELD_ENV, SHIELD_DEV_UNSAFE_RESPONDERS,
#      SHIELD_RESPONDER_ARGS; removes the drop-in; restarts the sensor).
#   3. Stability: active, NRestarts unchanged over 20 s, and no override warning since restart.
#   4. Containment canary: run a copy of /bin/sleep from /tmp as the xibalba user; it must be
#      stopped (state T) by Shield within 20 s. The canary is then killed and removed.
set -euo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
REPO=/home/xibalba/Projects/xibalba-shield
ENV_FILE=/etc/xibalba-shield/shield.env
DROPIN=/etc/systemd/system/xibalba-shield.service.d/dev-unsafe-responders.conf
STAMP=$(date +%Y%m%dT%H%M%S)
BACKUP_DIR=/etc/xibalba-shield/backups
LOG=/home/xibalba/Documents/integrity-audit-handoffs/C6-F1-responder-gates-$STAMP.log
exec > >(tee "$LOG") 2>&1

stable() {  # stable <unit> <seconds>: active, and NRestarts unchanged across the window
  local u=$1 s=$2 r0 r1
  r0=$(systemctl show -p NRestarts --value "$u")
  sleep "$s"
  r1=$(systemctl show -p NRestarts --value "$u")
  [[ "$(systemctl is-active "$u")" == active && "$r0" == "$r1" ]]
}

rollback() {
  echo "!! rolling back to the previous responder configuration" >&2
  install -m 0640 -o root -g root "$BACKUP_DIR/shield.env.$STAMP" "$ENV_FILE"
  [[ -f "$BACKUP_DIR/dev-unsafe-responders.conf.$STAMP" ]] && install -m 0644 "$BACKUP_DIR/dev-unsafe-responders.conf.$STAMP" "$DROPIN"
  systemctl daemon-reload
  systemctl restart xibalba-shield.service
  stable xibalba-shield.service 15 && echo "rollback complete; sensor stable" >&2 || echo "ROLLBACK: sensor NOT stable -- check journalctl -u xibalba-shield" >&2
  exit 1
}

canary() {  # canary <label>: echo the canary's final state (T* = contained by Shield)
  local path=/tmp/c6-contain-canary-$1-$STAMP state="" child="" runner
  install -m 0755 -o xibalba -g xibalba /bin/sleep "$path"
  runuser -u xibalba -- "$path" 120 >/dev/null 2>&1 &
  runner=$!
  for _ in $(seq 1 20); do
    sleep 1
    child=$(pgrep -f "^$path 120" | head -1 || true)
    [[ -n "$child" ]] && state=$(ps -o stat= -p "$child" | tr -d ' ')
    [[ "$state" == T* ]] && break
  done
  [[ -n "$child" ]] && kill -KILL "$child" 2>/dev/null || true
  kill -KILL "$runner" 2>/dev/null || true
  wait "$runner" 2>/dev/null || true
  rm -f "$path"
  echo "${state:-gone}"
}

echo "== 0/4 baseline containment canary (before any change)"
BASE=$(canary before)
[[ "$BASE" == T* ]] || { echo "baseline canary not contained (state '$BASE'); the canary cannot validate this change -- stopping, nothing changed" >&2; exit 1; }
echo "baseline contained (state $BASE)"

echo "== 1/4 backups"
if ! grep -q '^SHIELD_DEV_UNSAFE_RESPONDERS=true' "$ENV_FILE"; then
  echo "override is not enabled in $ENV_FILE; nothing to do"; exit 0
fi
install -d -m 0700 "$BACKUP_DIR"
cp -p "$ENV_FILE" "$BACKUP_DIR/shield.env.$STAMP"
[[ -f "$DROPIN" ]] && cp -p "$DROPIN" "$BACKUP_DIR/dev-unsafe-responders.conf.$STAMP"
echo "backed up to $BACKUP_DIR (*.$STAMP)"
# Variable names only -- values are never printed.
echo "responder-related keys before: $(grep -oE '^(SHIELD_ENV|SHIELD_DEV_UNSAFE_RESPONDERS|SHIELD_RESPONDER_ARGS)=' "$ENV_FILE" | tr '\n' ' ')"

echo "== 2/4 disable the override"
SINCE=$(date '+%Y-%m-%d %H:%M:%S')
"$REPO/scripts/disable_dev_unsafe_responders.sh" || rollback
echo "responder-related keys after: $(grep -oE '^(SHIELD_ENV|SHIELD_DEV_UNSAFE_RESPONDERS|SHIELD_RESPONDER_ARGS)=' "$ENV_FILE" | tr '\n' ' ')<none expected>"

echo "== 3/4 stability"
stable xibalba-shield.service 20 || { echo "sensor unstable" >&2; rollback; }
if journalctl -u xibalba-shield.service --since "$SINCE" --no-pager | grep -q "development-only responder override enabled"; then
  echo "override warning still present after restart" >&2; rollback
fi
echo "sensor stable; override warning gone"

echo "== 4/4 containment canary after the change (SIGSTOP of a /tmp executable)"
STATE=$(canary after)
if [[ "$STATE" != T* ]]; then
  echo "canary was NOT contained (state '$STATE') -- containment regressed" >&2; rollback
fi
echo "canary contained (state $STATE); killed and removed"
journalctl -u xibalba-shield.service --since "$SINCE" --no-pager | grep -iE "contain" | tail -2 || true

echo
echo "Done: production responder gates restored (kill_process, freeze_cgroup, block_flow need"
echo "real readiness proofs again); SIGSTOP containment verified live."
echo "Manual rollback: install -m 0640 $BACKUP_DIR/shield.env.$STAMP $ENV_FILE; install -m 0644 $BACKUP_DIR/dev-unsafe-responders.conf.$STAMP $DROPIN; systemctl daemon-reload; systemctl restart xibalba-shield.service"
