#!/bin/sh
# Daily CVE refresh loop for the cve-sync container (POSIX sh / dash).
#
# - First run after deploy: full sync (~13 min). Later container restarts / VPS
#   reboots SKIP if the mirror is still fresh (sync_cve_pg.py checks
#   CVE_MIN_SYNC_AGE_HOURS) — so a reboot doesn't cause a needless rebuild.
# - On success: sleep ~24h, then re-sync (now stale -> rebuilds).
# - On failure (network blip / OSV hiccup): retry in 1h, not a full day.
#
# Self-contained alternative to host cron / systemd timer. To use those instead,
# disable this service and schedule:
#   docker compose run --rm cve-sync python scripts/sync_cve_pg.py
set -u

while true; do
  if python scripts/sync_cve_pg.py; then
    echo "[sync_loop] ok; next run in 24h"
    sleep 86400
  else
    echo "[sync_loop] sync failed; retrying in 1h"
    sleep 3600
  fi
done
