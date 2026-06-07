#!/usr/bin/env python3
"""Refresh the IaC catalog from the published artifact, then load it into Postgres.

The catalog (4 federated upstreams + bumper's enforced rules) is BUILT in the Go repo
CI (tools/build_catalog.py clones Trivy/Checkov/KICS/Prowler) and published as a rolling
release asset. This script just downloads that artifact and loads it — the heavy 4-repo
clone never runs on the advisor box. Idempotent; safe to run daily. load_iac.py does its
DELETE+INSERT in one transaction, so readers never see an empty catalog mid-refresh.

  CATALOG_URL=... DATABASE_URL=... python scripts/sync_iac.py

The artifact (catalog.tar.gz) is expected to contain, at its root:
  trivy/  checkov/  kics/  prowler/   (per-provider *.json from build_catalog.py)
  enforced.raw.json                   (`bumper list --format json` dump)
"""
import os
import sys
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(BASE, "scripts")
DEFAULT_URL = "https://github.com/gnana997/bumper/releases/download/catalog-latest/catalog.tar.gz"
CATALOG_URL = os.environ.get("CATALOG_URL", DEFAULT_URL)
UA = {"User-Agent": "bumper-advisor-iac-sync/1.0 (+https://bumper.sh)"}


def main():
    work = tempfile.mkdtemp(prefix="iac-catalog-")
    try:
        tgz = os.path.join(work, "catalog.tar.gz")
        print(f"[sync_iac] downloading {CATALOG_URL}", flush=True)
        req = urllib.request.Request(CATALOG_URL, headers=UA)
        with urllib.request.urlopen(req, timeout=120) as r, open(tgz, "wb") as f:
            shutil.copyfileobj(r, f)

        data = os.path.join(work, "data")
        os.makedirs(data, exist_ok=True)
        print(f"[sync_iac] extracting → {data}", flush=True)
        with tarfile.open(tgz) as t:
            t.extractall(data, filter="data")  # 'data' filter blocks path traversal

        raw = os.path.join(data, "enforced.raw.json")
        if not os.path.exists(raw):
            sys.exit("[sync_iac] artifact missing enforced.raw.json")
        # Normalize the enforced-rules dump into the shape load_iac.py expects.
        print("[sync_iac] normalizing enforced rules", flush=True)
        with open(raw) as fin, open(os.path.join(data, "enforced.json"), "w") as fout:
            subprocess.run([sys.executable, os.path.join(SCRIPTS, "normalize_enforced.py")],
                           stdin=fin, stdout=fout, check=True)

        # Load into Postgres (atomic per-corpus swap inside load_iac.py).
        print("[sync_iac] loading into Postgres", flush=True)
        env = {**os.environ, "IAC_DATA_DIR": data}
        subprocess.run([sys.executable, os.path.join(SCRIPTS, "load_iac.py")], env=env, check=True)
        print("[sync_iac] done", flush=True)
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
