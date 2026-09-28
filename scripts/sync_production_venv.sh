#!/usr/bin/env bash
# C6 F2 — make the production venv exactly what CI tests: xibalba-shield's uv.lock.
#
# /opt/xibalba-shield/venv is updated with `--no-deps`, so it drifted from the lock
# (2026-09-27: a web3 8 / eth-abi 6 / hexbytes 2 stack that CI never tested, plus a stale
# integrity-sdk and packages missing entirely). This script:
#   1. Checks the checkout is clean and uv.lock is current.
#   2. Snapshots the whole venv (instant rollback).
#   3. Installs the locked runtime dependencies (pinned; adds/changes, never removes),
#      then integrity-sdk AT THE REF SHIELD'S CI PINS and xibalba-shield from this checkout,
#      both --no-deps (their dependencies are the locked set).
#
# SDK source of truth = the integrity-core `ref:` in .github/workflows/ci.yml, i.e. exactly
# what CI tests. The sibling integrity-core checkout moves independently (its 2026-09-28
# restructure removed integrity_sdk.policy.opa_client, which Shield still imports), so the
# SDK is exported from that ref with `git archive` into a staging dir, and uv.lock is checked
# and exported against the staged SDK. Bumping the CI pin is how production moves forward.
#   4. Requires `uv pip check` to be fully clean, a zero-change dry run against the lock,
#      and an import smoke test.
#   5. Restarts the sensor, the Cortex outbox worker and the Hermes analyst; each must be
#      stable, and a /tmp containment canary must be stopped by Shield.
# Any failure in 3–5 restores the snapshot and restarts the services.
set -euo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
REPO=/home/xibalba/Projects/xibalba-shield
CORE=/home/xibalba/Projects/integrity-core
SDK_REF=$(awk '/repository: XibalbaTechSol\/integrity-core/{f=1} f&&/ref:/{print $2; exit}' "$REPO/.github/workflows/ci.yml")
STAGE=/home/xibalba/.local/state/shield-deploy-stage-$(date +%Y%m%dT%H%M%S)
SDK=$STAGE/integrity-core/integrity-sdk
VENV=/opt/xibalba-shield/venv
PY=$VENV/bin/python
UV=/home/xibalba/.local/bin/uv
STAMP=$(date +%Y%m%dT%H%M%S)
SNAP=$VENV.bak-$STAMP
REQ=$(mktemp /root/shield-lock-req.XXXXXX)
SERVICES=(xibalba-shield.service xibalba-shield-cortex-outbox.service shield-hermes-analyst.service)
LOG=/home/xibalba/Documents/integrity-audit-handoffs/C6-F2-venv-sync-$STAMP.log
exec > >(tee "$LOG") 2>&1
trap 'rm -f "$REQ"; rm -rf "$STAGE"' EXIT

stable() {  # stable <unit> <seconds>
  local u=$1 s=$2 r0 r1
  r0=$(systemctl show -p NRestarts --value "$u")
  sleep "$s"
  r1=$(systemctl show -p NRestarts --value "$u")
  [[ "$(systemctl is-active "$u")" == active && "$r0" == "$r1" ]]
}

rollback() {
  echo "!! restoring the venv snapshot $SNAP" >&2
  rm -rf "$VENV"
  mv "$SNAP" "$VENV"
  systemctl restart "${SERVICES[@]}"
  for u in "${SERVICES[@]}"; do stable "$u" 10 && echo "$u stable" >&2 || echo "ROLLBACK: $u NOT stable" >&2; done
  exit 1
}

canary() {  # echo the final state of a /tmp sleep copy run as xibalba (T* = contained)
  local path=/tmp/c6-venv-canary-$STAMP state="" child="" runner
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

echo "== 1/5 preconditions"
[[ -z "$(git -C "$REPO" status --porcelain)" ]] || { echo "shield checkout dirty; stop" >&2; exit 1; }
[[ "$SDK_REF" =~ ^[0-9a-f]{40}$ ]] || { echo "could not read the integrity-core ref pinned in ci.yml; stop" >&2; exit 1; }
runuser -u xibalba -- git -C "$CORE" cat-file -e "$SDK_REF^{commit}" 2>/dev/null \
  || runuser -u xibalba -- git -C "$CORE" fetch -q origin "$SDK_REF" \
  || { echo "integrity-core does not have the pinned ref $SDK_REF; stop" >&2; exit 1; }
# Stage the pinned SDK next to a copy of this project's metadata, so the relative
# tool.uv.sources path (../integrity-core/integrity-sdk) resolves to the pinned SDK.
runuser -u xibalba -- mkdir -p "$STAGE/integrity-core" "$STAGE/xibalba-shield"
runuser -u xibalba -- bash -c "git -C '$CORE' archive '$SDK_REF' integrity-sdk | tar -x -C '$STAGE/integrity-core'"
runuser -u xibalba -- cp "$REPO/pyproject.toml" "$REPO/uv.lock" "$REPO/README.md" "$STAGE/xibalba-shield/"
echo "integrity-sdk pinned by CI: $SDK_REF (staged)"
(cd "$STAGE/xibalba-shield" && runuser -u xibalba -- "$UV" lock --check) || { echo "uv.lock is not current for the pinned SDK; stop" >&2; exit 1; }
(cd "$STAGE/xibalba-shield" && runuser -u xibalba -- "$UV" export --frozen --no-dev --no-hashes --no-emit-project --no-emit-package integrity-sdk) \
  | grep -vE '^#|^ ' > "$REQ"
echo "locked runtime requirements: $(wc -l < "$REQ") packages"
echo "planned changes:"
"$UV" pip install --dry-run --python "$PY" -r "$REQ" 2>&1 | grep -E '^ [+-]' || echo "  (none)"

echo "== 2/5 snapshot"
cp -a "$VENV" "$SNAP"
echo "snapshot: $SNAP ($(du -sh "$SNAP" | cut -f1))"

echo "== 3/5 install locked set"
"$UV" pip install --python "$PY" --link-mode=copy -r "$REQ" || rollback
"$UV" pip install --python "$PY" --no-deps --reinstall --link-mode=copy "$SDK" || rollback
"$UV" pip install --python "$PY" --no-deps --reinstall --link-mode=copy "$REPO" || rollback

echo "== 4/5 verify"
"$UV" pip check --python "$PY" || { echo "pip check not clean" >&2; rollback; }
if "$UV" pip install --dry-run --python "$PY" -r "$REQ" 2>&1 | grep -qE '^ [+-]'; then
  echo "venv still differs from the lock after sync" >&2; rollback
fi
"$PY" -c "import integrity_sdk, web3, shield.cli, shield.policy_engine.engine, shield.integrity_exporter, shield.hermes_contract, shield.hermes_transport, shield.hermes_analyst, shield.agent_core.cortex_memory; print('imports ok; web3', web3.__version__)" || rollback

echo "== 5/5 restart and prove"
systemctl restart "${SERVICES[@]}"
for u in "${SERVICES[@]}"; do stable "$u" 20 || { echo "$u unstable" >&2; rollback; }; echo "$u stable"; done
STATE=$(canary)
[[ "$STATE" == T* ]] || { echo "containment canary not contained (state '$STATE')" >&2; rollback; }
echo "containment canary contained (state $STATE)"

echo
echo "Done: production venv matches uv.lock (pip check clean, zero drift)."
echo "Snapshot kept for manual rollback: $SNAP"
echo "  rollback: rm -rf $VENV && mv $SNAP $VENV && systemctl restart ${SERVICES[*]}"
echo "  cleanup after a day of stable running: rm -rf $SNAP"
