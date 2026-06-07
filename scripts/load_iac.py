#!/usr/bin/env python3
"""Load the IaC catalog (enforced rules + federated advisory) into Postgres
search_docs[corpus='iac']. Same data + same embedding (potion-retrieval-32M) as the
SQLite build_index.py — only the store changes.

  DATABASE_URL=... python scripts/load_iac.py
"""
import os
import sys
import glob
import json
import time

import numpy as np
import psycopg
from psycopg.types.json import Json
from pgvector.psycopg import register_vector

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
from app.db import get_model  # noqa: E402
from app.pg import DATABASE_URL  # noqa: E402

# Default to the baked ./data (boot/init load). The daily sync_iac.py refresh sets
# IAC_DATA_DIR to a writable temp dir holding the freshly-downloaded catalog, since
# /app/data is root-owned and the container runs as an unprivileged user.
DATA = os.environ.get("IAC_DATA_DIR") or os.path.join(BASE, "data")
SCHEMA = os.path.join(BASE, "app", "schema_pg.sql")


def embed_text(e):
    """Rich text for semantic recall — parity with build_index.py."""
    return " ".join(filter(None, [
        e.get("title", ""), e.get("remediation", ""),
        " ".join(e.get("resources", []) or []),
        e.get("provider", ""), e.get("source", ""), e.get("category", "")]))


def lexical_text(e):
    """What we lexically index (tsv) — title + remediation + resources."""
    return " ".join(filter(None, [
        e.get("title", ""), e.get("remediation", ""),
        " ".join(e.get("resources", []) or [])]))


def to_doc(e):
    """Full result-shape record stored in meta (matches the SQLite _row_to_dict)."""
    return {
        "uid": e["_uid"], "enforced": bool(e.get("enforced", 0)),
        "source": e.get("source", ""), "source_id": e.get("source_id", ""),
        "provider": e.get("provider", ""), "severity": e.get("severity", ""),
        "resources": e.get("resources", []) or [], "title": e.get("title", ""),
        "remediation": e.get("remediation", ""), "refs": e.get("refs", []) or [],
        "category": e.get("category", ""), "cwe": e.get("cwe", ""),
    }


def load_rows():
    rows, seen = [], set()
    for f in sorted(glob.glob(os.path.join(DATA, "**", "*.json"), recursive=True)):
        with open(f) as fh:
            for e in json.load(fh):
                uid = f'{e.get("source", "")}:{e.get("source_id", "")}'
                if uid in seen:
                    continue
                seen.add(uid)
                e["_uid"] = uid
                rows.append(e)
    return rows


def run_schema(conn):
    raw = open(SCHEMA).read()
    # strip `--` line comments (some contain ';') before splitting on statement ';'
    sql = "\n".join(line.split("--", 1)[0] for line in raw.splitlines())
    for stmt in (s.strip() for s in sql.split(";")):
        if stmt:
            conn.execute(stmt)


def main():
    t0 = time.time()
    rows = load_rows()
    if not rows:
        sys.exit(f"no IaC catalog under {DATA} — run scripts/sync_catalog.sh first")
    print(f"[load_iac] {len(rows)} rules; embedding…", flush=True)

    vecs = get_model()([embed_text(e) for e in rows]).astype(np.float32)
    vecs /= np.linalg.norm(vecs, axis=1, keepdims=True)

    params = [
        ("iac", e["_uid"], e.get("title", ""), lexical_text(e),
         e.get("severity", ""), e.get("provider", ""), None, None,
         Json(to_doc(e)), v)
        for e, v in zip(rows, vecs)
    ]

    with psycopg.connect(DATABASE_URL, autocommit=False) as conn:
        run_schema(conn)
        conn.commit()
        register_vector(conn)
        with conn.cursor() as cur:
            cur.execute("DELETE FROM search_docs WHERE corpus='iac'")
            cur.executemany(
                "INSERT INTO search_docs "
                "(corpus,doc_id,title,body,severity,provider,ecosystems,packages,meta,embedding) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", params)
            cur.execute(
                "INSERT INTO meta(k,v) VALUES ('iac_synced_at', now()::text), ('iac_count', %s) "
                "ON CONFLICT (k) DO UPDATE SET v=EXCLUDED.v", (str(len(rows)),))
        conn.commit()

    print(f"[load_iac] loaded {len(rows)} iac docs in {time.time()-t0:.1f}s", flush=True)


if __name__ == "__main__":
    main()
