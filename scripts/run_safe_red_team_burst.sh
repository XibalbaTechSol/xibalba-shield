#!/usr/bin/env bash
set -u

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo." >&2
  exit 1
fi
if [[ "${SHIELD_ENV:-}" != "development" ]]; then
  echo "Refusing to run outside SHIELD_ENV=development" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
iterations="${SHIELD_RED_TEAM_ITERATIONS:-50}"
status=0

for profile in smb professional-services regulated; do
  echo "Starting bounded aggressive red-team batch: profile=$profile iterations=$iterations"
  if ! python3 "$repo_root/scripts/run_safe_red_team_loop.py" "$profile" \
      --iterations "$iterations" \
      --output "$repo_root/artifacts/safe-red-team-report-$profile.json"; then
    status=1
    echo "ATTENTION profile=$profile batch reported failures" >&2
  fi
done

echo "Completed bounded red-team burst; automatic timer shutdown follows."
exit "$status"
