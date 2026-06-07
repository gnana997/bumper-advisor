#!/usr/bin/env python3
"""Sync OSV -> Postgres.

Two outputs from one parse:
  * cve_vulns / cve_affected  — structured, for exact version lookup (no vectors)
  * search_docs[corpus='cve'] — one CANONICAL doc per vuln (alias-deduped), embedded
    over the basic OSV metadata (summary + details). No enrichment.

  DATABASE_URL=... [CVE_ECOSYSTEMS=PyPI,npm] python scripts/sync_cve_pg.py
"""
import os
import sys
import json
import time
import zipfile
import urllib.request
import urllib.error
from urllib.parse import quote

import numpy as np
import psycopg
from psycopg.types.json import Json
from pgvector.psycopg import register_vector

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
from app.cve import (  # noqa: E402
    select_ecosystems, normalize_package, canonical_id, severity_from_osv,
)
from app.db import get_model  # noqa: E402
from app.pg import DATABASE_URL  # noqa: E402

OSV_BASE = "https://storage.googleapis.com/osv-vulnerabilities"
UA = {"User-Agent": "bumper-advisor-sync/0.1 (+https://bumper.sh)"}
WORKDIR = os.environ.get("CVE_WORKDIR", "/tmp")
BODY_CAP = 1500           # cap details length fed to the embedder (basic metadata)
PKG_CAP = 50              # cap denormalized package/ecosystem arrays per doc
EMBED_CHUNK = 20000
SCHEMA = os.path.join(BASE, "app", "schema_pg.sql")

# The SEARCH corpus excludes advisory BUNDLES (one advisory -> many CVEs, thin
# templated text) and malware blocklist entries — noise for semantic search. They
# stay in cve_affected/cve_vulns for exact lookup. Per-CVE records (CVE-/GHSA-/
# DEBIAN-CVE-/PYSEC-/GO-/RUSTSEC- ...) are kept.
SEARCH_EXCLUDE_PREFIXES = ("MAL-", "DSA-", "DLA-", "DTSA-", "USN-", "RHSA-", "RHBA-",
                           "RHEA-", "RLSA-", "RXSA-", "ALSA-", "ALBA-", "ALEA-", "ALAS-")


def log(m):
    print(f"[sync_cve_pg] {m}", flush=True)


def fetch_text(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60) as r:
        return r.read().decode("utf-8")


def download(url, dest):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=600) as r, \
            open(dest, "wb") as f:
        while chunk := r.read(1 << 20):
            f.write(chunk)


def run_schema(conn):
    raw = open(SCHEMA).read()
    sql = "\n".join(line.split("--", 1)[0] for line in raw.splitlines())
    for stmt in (s.strip() for s in sql.split(";")):
        if stmt:
            conn.execute(stmt)


def main():
    t0 = time.time()

    # Skip if the mirror is already fresh — so container restarts / VPS reboots don't
    # trigger a needless 13-min rebuild (and unavailable window). FORCE_SYNC=1 or
    # CVE_MIN_SYNC_AGE_HOURS=0 bypasses.
    min_age = float(os.environ.get("CVE_MIN_SYNC_AGE_HOURS", "20"))
    if min_age > 0 and not os.environ.get("FORCE_SYNC"):
        try:
            chk = psycopg.connect(DATABASE_URL, autocommit=True)
            row = chk.execute(
                "SELECT EXTRACT(EPOCH FROM (now() - v::timestamptz))/3600 "
                "FROM meta WHERE k='cve_synced_at'").fetchone()
            chk.close()
            if row and row[0] is not None and float(row[0]) < min_age:
                log(f"mirror is fresh ({float(row[0]):.1f}h < {min_age}h) — skipping sync")
                return
        except Exception:
            pass  # meta/table absent (first run) -> proceed

    ecosystems = select_ecosystems(
        [e for e in fetch_text(f"{OSV_BASE}/ecosystems.txt").splitlines() if e.strip()])
    log(f"mirroring {len(ecosystems)} ecosystem(s)")

    # Zero-downtime (POSTGRES_PLAN §7): build into STAGING tables, then atomic
    # rename-swap. The live cve_vulns/cve_affected keep serving the OLD mirror the whole
    # time — so lookup_cve / scan / check_malware never see an empty table mid-sync
    # (an empty cve_affected would make the deps malware-gate fail open). search_docs is
    # refreshed in one transaction further down (it's shared with IaC + HNSW-indexed,
    # so it can't be rename-swapped). _stg are dropped first so a crashed run is resumable.
    admin = psycopg.connect(DATABASE_URL, autocommit=True)
    run_schema(admin)
    admin.execute("DROP TABLE IF EXISTS cve_vulns_stg")
    admin.execute("DROP TABLE IF EXISTS cve_affected_stg")
    admin.execute("CREATE TABLE cve_vulns_stg (LIKE cve_vulns INCLUDING DEFAULTS INCLUDING CONSTRAINTS)")
    admin.execute("CREATE TABLE cve_affected_stg (LIKE cve_affected INCLUDING DEFAULTS)")
    admin.close()

    conn_aff = psycopg.connect(DATABASE_URL)
    conn_aff.execute("SET synchronous_commit=off")
    conn_vuln = psycopg.connect(DATABASE_URL)
    conn_vuln.execute("SET synchronous_commit=off")

    rec_cache: dict = {}    # rec_id -> (title, body, score, tier, aliases)
    canon: dict = {}        # cid -> {title, body, score, tier, ecos:set, pkgs:set}
    totals = {"vulns": 0, "affected": 0}

    def merge_canon(cid, title, body, score, tier, ecos, pkgs, cwe):
        c = canon.get(cid)
        if c is None:
            canon[cid] = {"title": title, "body": body, "score": score, "tier": tier,
                          "ecos": set(ecos), "pkgs": set(pkgs), "cwe": set(cwe)}
        else:
            if len(body) > len(c["body"]):
                c["title"], c["body"] = title, body
            if (score or 0) > (c["score"] or 0) or (not c["tier"] and tier):
                c["score"], c["tier"] = score, tier
            c["ecos"].update(ecos); c["pkgs"].update(pkgs); c["cwe"].update(cwe)

    with conn_aff.cursor() as ca, \
            ca.copy("COPY cve_affected_stg (vuln_id,ecosystem,package,range_type,ranges,versions) "
                    "FROM STDIN") as cp_aff, \
            conn_vuln.cursor() as cv, \
            cv.copy("COPY cve_vulns_stg (id,summary,details,aliases,severity,severity_score,"
                    "severity_tier,cwe,published,modified,refs) FROM STDIN") as cp_vuln:
        for eco in ecosystems:
            url = f"{OSV_BASE}/{quote(eco, safe=':')}/all.zip"
            zpath = os.path.join(WORKDIR, f"osv_{eco.replace(':', '_').replace('/', '_')}.zip")
            download(url, zpath)
            n = 0
            with zipfile.ZipFile(zpath) as z:
                for name in z.namelist():
                    if not name.endswith(".json"):
                        continue
                    rec = json.loads(z.read(name))
                    if rec.get("withdrawn"):
                        continue
                    rid = rec["id"]
                    matched = []
                    for aff in rec.get("affected", []):
                        aeco = aff.get("package", {}).get("ecosystem")
                        if not aeco or not (aeco == eco or aeco.startswith(eco + ":")):
                            continue
                        pkg = normalize_package(aeco, aff.get("package", {}).get("name", ""))
                        ranges = aff.get("ranges", []) or []
                        versions = aff.get("versions", []) or []
                        types = ",".join(sorted({r.get("type", "") for r in ranges}))
                        cp_aff.write_row((rid, aeco, pkg, types,
                                          json.dumps(ranges), json.dumps(versions)))
                        matched.append((aeco, pkg))
                    if not matched:
                        continue
                    totals["affected"] += len(matched)
                    if rid not in rec_cache:
                        aliases = rec.get("aliases", []) or []
                        cwe = (rec.get("database_specific") or {}).get("cwe_ids", []) or []
                        score, tier = severity_from_osv(rec)
                        summary = rec.get("summary") or ""
                        body = (summary + " " + (rec.get("details") or "")[:BODY_CAP]).strip()
                        rec_cache[rid] = (summary or rid, body, score, tier, aliases, cwe)
                        cp_vuln.write_row((
                            rid, summary, rec.get("details"), json.dumps(aliases),
                            json.dumps(rec.get("severity", [])), score, tier,
                            json.dumps(cwe), rec.get("published"), rec.get("modified"),
                            json.dumps(rec.get("references", []))))
                        totals["vulns"] += 1
                    title, body, score, tier, aliases, cwe = rec_cache[rid]
                    cid = canonical_id(rid, aliases)
                    merge_canon(cid, title, body, score, tier,
                                {m[0] for m in matched}, {m[1] for m in matched}, cwe)
                    n += 1
            os.remove(zpath)
            log(f"  {eco}: {n} records")
    conn_aff.commit(); conn_aff.close()
    conn_vuln.commit(); conn_vuln.close()
    log(f"structured: {totals['vulns']} vulns, {totals['affected']} affected; "
        f"canonical docs: {len(canon)}")

    # Build the lookup index on staging (off the live path), then atomically swap.
    admin = psycopg.connect(DATABASE_URL, autocommit=True)
    admin.execute("CREATE INDEX idx_cve_affected_stg_lookup ON cve_affected_stg (ecosystem, package)")
    admin.close()

    # Atomic rename-swap: ACCESS EXCLUSIVE is held only for this tiny metadata tx (~ms),
    # so concurrent readers see fully-old or fully-new — never empty/blocked for minutes.
    # The new tables have identical columns, so prepared statements in the read pool
    # replan transparently (no "cached plan must not change result type").
    swap = psycopg.connect(DATABASE_URL)
    with swap.cursor() as cur:
        cur.execute("DROP TABLE cve_vulns")
        cur.execute("ALTER TABLE cve_vulns_stg RENAME TO cve_vulns")
        cur.execute("DROP TABLE cve_affected")
        cur.execute("ALTER TABLE cve_affected_stg RENAME TO cve_affected")
        cur.execute("ALTER INDEX idx_cve_affected_stg_lookup RENAME TO idx_cve_affected_lookup")
    swap.commit(); swap.close()
    log("structured tables swapped in (zero-downtime)")

    # --- embed canonical docs over basic metadata + insert search_docs[cve] ----
    model = get_model()
    # Search needs real prose to embed. Distro-only CVEs ship affected-versions but
    # no description (their "body" is ~just the id) -> drop from search (still in
    # cve_affected for exact lookup). >=40 chars keeps real summaries, drops the empties.
    items = [(cid, c) for cid, c in canon.items()
             if len(c["body"].strip()) >= 40 and not cid.startswith(SEARCH_EXCLUDE_PREFIXES)]
    log(f"search corpus after curation: {len(items)} (from {len(canon)} canonical)")
    # Embed everything FIRST (no DB transaction held during model inference), then
    # refresh the cve corpus in ONE short transaction. Until that commits, readers keep
    # seeing the OLD cve docs (MVCC) — no empty window for search_cve.
    all_params = []
    for i in range(0, len(items), EMBED_CHUNK):
        chunk = items[i:i + EMBED_CHUNK]
        vecs = model([c["body"] for _, c in chunk]).astype(np.float32)
        vecs /= np.linalg.norm(vecs, axis=1, keepdims=True)
        for (cid, c), v in zip(chunk, vecs):
            ecos = sorted(c["ecos"])[:PKG_CAP]
            pkgs = sorted(c["pkgs"])[:PKG_CAP]
            cwe = sorted(c["cwe"])
            meta = {"id": cid, "severity": c["tier"], "score": c["score"],
                    "ecosystems": ecos, "packages": pkgs, "cwe": cwe}
            all_params.append(("cve", cid, c["title"][:300], c["body"], c["tier"], None,
                               ecos, pkgs, Json(meta), v))
        log(f"  embedded {len(all_params)}/{len(items)}")

    inserted = len(all_params)
    conn = psycopg.connect(DATABASE_URL)
    register_vector(conn)
    with conn.cursor() as cur:
        cur.execute("DELETE FROM search_docs WHERE corpus='cve'")
        for j in range(0, len(all_params), EMBED_CHUNK):
            cur.executemany(
                "INSERT INTO search_docs "
                "(corpus,doc_id,title,body,severity,provider,ecosystems,packages,meta,embedding) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (corpus,doc_id) DO NOTHING",
                all_params[j:j + EMBED_CHUNK])
        cur.execute("INSERT INTO meta(k,v) VALUES ('cve_synced_at', now()::text) "
                    "ON CONFLICT (k) DO UPDATE SET v=EXCLUDED.v")
        cur.execute("INSERT INTO meta(k,v) VALUES ('cve_docs', %s) "
                    "ON CONFLICT (k) DO UPDATE SET v=EXCLUDED.v", (str(inserted),))
    conn.commit(); conn.close()

    # Post-swap maintenance — BEST-EFFORT: the data swap already committed above, so a
    # maintenance hiccup must NEVER fail the sync (the mirror is live + correct without it).
    # Order matters: ANALYZE first (cheap; fixes planner stats on the fresh rename-swapped
    # tables) so even if the reindex dies, stats are good. Then reclaim the search_docs
    # HNSW delete-tombstones from the in-place DELETE+INSERT (else the vector index bloats
    # and queries slow ~165ms vs ~10ms). The reindex runs SINGLE-THREADED
    # (max_parallel_maintenance_workers=0): pgvector's parallel HNSW build otherwise
    # allocates a multi-GB parallel-build DSM segment that overflows the container's
    # /dev/shm (shm_size) and fails with DiskFull.
    admin2 = psycopg.connect(DATABASE_URL, autocommit=True)
    try:
        admin2.execute("ANALYZE cve_vulns")
        admin2.execute("ANALYZE cve_affected")
        admin2.execute("VACUUM ANALYZE search_docs")
        admin2.execute("SET max_parallel_maintenance_workers = 0")
        admin2.execute("REINDEX INDEX idx_docs_hnsw")
    except Exception as e:
        log(f"WARNING: post-swap maintenance failed (mirror data is committed + serving): {e}")
    finally:
        admin2.close()
    log(f"DONE in {time.time()-t0:.0f}s: {totals['vulns']} vulns, "
        f"{totals['affected']} affected rows, {inserted} search docs")


if __name__ == "__main__":
    main()
