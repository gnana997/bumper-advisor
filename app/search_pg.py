"""Hybrid search over Postgres: lexical (tsvector/ts_rank) + semantic (pgvector
HNSW), fused with RRF in-app. Same contract + RRF as the SQLite search — returns
enforced `results` + round-robined `advisory`.

Async: queries run on the async pool with `await`, so a DB round-trip yields the
event loop instead of blocking it — one worker serves many requests concurrently.
The CPU-bound embed step is pushed to a thread (asyncio.to_thread) for the same reason.
"""
import re
import asyncio
from collections import OrderedDict, deque

from .pg import get_async_pool, embed_vec

# --- AI Insights join (precomputed enrichment, attached at read time) -------------
# Additive + fault-tolerant: any error (e.g. ai_insights not created yet) yields no
# insight rather than breaking the read path — search must never 500 over this.
_AI_DISCLAIMER = "AI-generated from the advisory — illustrative; verify before applying."


def _wrap_insight(insight, model, generated_at):
    return {**insight, "provenance": {
        "model": model,
        "generated_at": generated_at.isoformat() if generated_at else None,
        "disclaimer": _AI_DISCLAIMER}}


async def _insights_for(conn, item_ids):
    """{item_id: wrapped_insight} for the ok-status insights among item_ids."""
    ids = [i for i in set(item_ids) if i]
    if not ids:
        return {}
    try:
        cur = await conn.execute(
            "SELECT item_id, insight, model, generated_at FROM ai_insights "
            "WHERE item_id = ANY(%s) AND status='ok'", [ids])
        return {iid: _wrap_insight(ins, model, ts)
                for iid, ins, model, ts in await cur.fetchall()}
    except Exception:
        return {}


async def _have_insights(conn, item_ids):
    """Subset of item_ids that have an ok insight — for list/search badges."""
    ids = [i for i in set(item_ids) if i]
    if not ids:
        return set()
    try:
        cur = await conn.execute(
            "SELECT item_id FROM ai_insights WHERE item_id = ANY(%s) AND status='ok'", [ids])
        return {r[0] for r in await cur.fetchall()}
    except Exception:
        return set()


RRF_K = 60
CAND = 50
_WORD = re.compile(r"[A-Za-z0-9]+")


def _tsquery(q: str) -> str:
    """OR of word tokens (recall-oriented; vector side adds precision via RRF)."""
    return " | ".join(_WORD.findall(q or ""))


def _facet_sql(corpus, provider, severity):
    clauses, params = ["corpus = %s"], [corpus]
    if provider:
        clauses.append("provider = %s")
        params.append(provider)
    if severity:
        clauses.append("severity = %s")
        params.append(severity)
    return " AND ".join(clauses), params


def _round_robin_by_source(items):
    buckets: "OrderedDict[str, deque]" = OrderedDict()
    for it in items:
        buckets.setdefault(it.get("source", ""), deque()).append(it)
    out = []
    while buckets:
        for src in list(buckets.keys()):
            out.append(buckets[src].popleft())
            if not buckets[src]:
                del buckets[src]
    return out


async def hybrid_search(corpus, query, provider="", severity="", limit=30):
    facet, fparams = _facet_sql(corpus, provider, severity)
    tsq = _tsquery(query)
    qvec = await asyncio.to_thread(embed_vec, query)

    async with get_async_pool().connection() as conn:
        lex = {}
        if tsq:
            # AND semantics (plainto_tsquery): docs must contain ALL query terms, so
            # without IDF the common term ("public") can't drag off-topic docs in.
            # The vector side supplies recall; RRF fuses. Fall back to OR (to_tsquery)
            # only if AND returns nothing.
            cur = await conn.execute(
                f"SELECT doc_id FROM search_docs "
                f"WHERE {facet} AND tsv @@ plainto_tsquery('english', %s) "
                f"ORDER BY ts_rank_cd(tsv, plainto_tsquery('english', %s)) DESC LIMIT {CAND}",
                fparams + [query, query],
            )
            rows = await cur.fetchall()
            if not rows:
                cur = await conn.execute(
                    f"SELECT doc_id FROM search_docs "
                    f"WHERE {facet} AND tsv @@ to_tsquery('english', %s) "
                    f"ORDER BY ts_rank_cd(tsv, to_tsquery('english', %s)) DESC LIMIT {CAND}",
                    fparams + [tsq, tsq],
                )
                rows = await cur.fetchall()
            lex = {r[0]: i for i, r in enumerate(rows)}

        cur = await conn.execute(
            f"SELECT doc_id FROM search_docs WHERE {facet} "
            f"ORDER BY embedding <=> %s LIMIT {CAND}",
            fparams + [qvec],
        )
        rows = await cur.fetchall()
        vec = {r[0]: i for i, r in enumerate(rows)}

        scores: dict[str, float] = {}
        for ranks in (vec, lex):
            for doc_id, rank in ranks.items():
                scores[doc_id] = scores.get(doc_id, 0.0) + 1.0 / (RRF_K + rank)
        if not scores:
            return {"query": query, "results": [], "advisory": [],
                    "count": {"results": 0, "advisory": 0}}

        ordered = sorted(scores, key=lambda d: scores[d], reverse=True)
        cur = await conn.execute(
            "SELECT doc_id, meta FROM search_docs WHERE corpus=%s AND doc_id = ANY(%s)",
            [corpus, ordered],
        )
        recs = await cur.fetchall()
        meta_by = {doc_id: meta for doc_id, meta in recs}
        # IaC item_id == the rule uid; badge the hits that have a precomputed insight.
        have = await _have_insights(conn, [m.get("uid") for m in meta_by.values()])

    enforced, advisory = [], []
    for doc_id in ordered:
        m = meta_by.get(doc_id)
        if m is None:
            continue
        m["has_ai_insight"] = m.get("uid") in have
        (enforced if m.get("enforced") else advisory).append(m)
    advisory = _round_robin_by_source(advisory)
    results, advisory = enforced[:limit], advisory[:limit]
    return {
        "query": query, "results": results, "advisory": advisory,
        "count": {"results": len(results), "advisory": len(advisory)},
    }


async def get_one(corpus, doc_id, enriched=True):
    """One IaC rule. `enriched=True` attaches the full ai_insight; either way a cheap
    `has_ai_insight` flag is set so callers know enrichment is available."""
    async with get_async_pool().connection() as conn:
        cur = await conn.execute(
            "SELECT meta FROM search_docs WHERE corpus=%s AND doc_id=%s",
            [corpus, doc_id],
        )
        row = await cur.fetchone()
        if not row:
            return None
        meta = dict(row[0])
        if enriched:
            ins = await _insights_for(conn, [doc_id])   # IaC item_id == doc_id
            if doc_id in ins:
                meta["ai_insight"] = ins[doc_id]
            meta["has_ai_insight"] = doc_id in ins
        else:
            meta["has_ai_insight"] = bool(await _have_insights(conn, [doc_id]))
        return meta


# --- CVE: semantic search + exact lookup + by-id ---------------------------------
from . import cve as cvelib  # noqa: E402


async def search_cve(query, ecosystem="", severity="", limit=20):
    """Hybrid search over the curated CVE corpus. Flat results (no enforced split)."""
    clauses, params = ["corpus = 'cve'"], []
    if severity:
        clauses.append("severity = %s"); params.append(severity)
    eco = cvelib.canonical_ecosystem(ecosystem) if ecosystem else ""
    if eco:
        clauses.append("ecosystems @> ARRAY[%s]"); params.append(eco)
    where = " AND ".join(clauses)
    tsq = _tsquery(query)
    qvec = await asyncio.to_thread(embed_vec, query)

    async with get_async_pool().connection() as conn:
        lex = {}
        if tsq:
            cur = await conn.execute(
                f"SELECT doc_id FROM search_docs WHERE {where} "
                f"AND tsv @@ plainto_tsquery('english', %s) "
                f"ORDER BY ts_rank_cd(tsv, plainto_tsquery('english', %s)) DESC LIMIT {CAND}",
                params + [query, query],
            )
            rows = await cur.fetchall()
            lex = {r[0]: i for i, r in enumerate(rows)}
        cur = await conn.execute(
            f"SELECT doc_id FROM search_docs WHERE {where} ORDER BY embedding <=> %s LIMIT {CAND}",
            params + [qvec],
        )
        rows = await cur.fetchall()
        vec = {r[0]: i for i, r in enumerate(rows)}

        scores = {}
        for ranks in (vec, lex):
            for doc_id, rank in ranks.items():
                scores[doc_id] = scores.get(doc_id, 0.0) + 1.0 / (RRF_K + rank)
        if not scores:
            return {"query": query, "results": [], "count": 0}
        ordered = sorted(scores, key=lambda d: scores[d], reverse=True)[:limit]
        cur = await conn.execute(
            "SELECT doc_id, title, meta FROM search_docs WHERE corpus='cve' AND doc_id = ANY(%s)",
            [ordered],
        )
        recs = await cur.fetchall()
        have = await _have_insights(conn, ordered)   # CVE corpus doc_id == canonical item_id

    by = {d: (t, m) for d, t, m in recs}
    results = []
    for d in ordered:
        if d not in by:
            continue
        title, m = by[d]
        results.append({"id": m.get("id", d), "title": title, "severity": m.get("severity") or None,
                        "cvss": m.get("score"), "ecosystems": m.get("ecosystems", []),
                        "packages": m.get("packages", []), "cwe": m.get("cwe", []),
                        "has_ai_insight": d in have})
    return {"query": query, "results": results, "count": len(results)}


async def lookup_cve(ecosystem, package, version, limit=100):
    """Exact: which CVEs affect this package@version. Status distinguishes
    ok / unavailable / ecosystem_unsupported so we never imply 'safe' blindly."""
    eco = cvelib.canonical_ecosystem(ecosystem)
    base = {"ecosystem": ecosystem, "package": package, "version": version,
            "vulns": [], "count": 0}
    if not eco:
        return {**base, "status": "ecosystem_unsupported"}
    pkg = cvelib.normalize_package(eco, package)
    async with get_async_pool().connection() as conn:
        cur = await conn.execute(
            "SELECT vuln_id, ranges, versions FROM cve_affected WHERE ecosystem=%s AND package=%s",
            [eco, pkg])
        rows = await cur.fetchall()
        if not rows and ":" not in eco:   # family input (e.g. 'Debian') -> any sub-version
            cur = await conn.execute(
                "SELECT vuln_id, ranges, versions FROM cve_affected WHERE ecosystem LIKE %s AND package=%s",
                [eco + ":%", pkg])
            rows = await cur.fetchall()
        fixes = {}
        for vuln_id, ranges, versions in rows:
            if vuln_id.startswith("MAL-"):
                continue  # malware is owned by check_malware/scan, not the vuln path
            hit, fixed = cvelib.match(version, versions or [], ranges or [], eco)
            if hit:
                fixes[vuln_id] = fixed or fixes.get(vuln_id)
        if not fixes:
            # Distinguish "genuinely clean" from "data not loaded yet" — a security
            # tool must never imply safe before the mirror exists (initial sync /
            # daily rebuild empties the table until commit).
            cur = await conn.execute("SELECT EXISTS(SELECT 1 FROM cve_affected)")
            ready = (await cur.fetchone())[0]
            return {**base, "ecosystem": eco, "status": "ok" if ready else "unavailable"}
        cur = await conn.execute(
            "SELECT id, summary, aliases, severity_tier, cwe, refs FROM cve_vulns WHERE id = ANY(%s)",
            [list(fixes)])
        recs = await cur.fetchall()

    seen, vulns = set(), []
    for vid, summary, aliases, tier, cwe, refs in recs:
        cid = cvelib.canonical_id(vid, aliases or [])
        if cid in seen:
            continue
        seen.add(cid)
        vulns.append({"id": cid, "aliases": aliases or [], "severity": tier or None,
                      "summary": summary, "fixed_version": fixes.get(vid),
                      "cwe": cwe or [], "refs": (refs or [])[:5]})
    vulns.sort(key=lambda x: ({"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["severity"], 4)))
    # Lean by default: a list can be long, and full insights per vuln would flood an
    # agent's context. Flag only — fetch the full insight on demand via get_vuln.
    if vulns:
        async with get_async_pool().connection() as conn:
            have = await _have_insights(conn, [v["id"] for v in vulns])
        for v in vulns:
            v["has_ai_insight"] = v["id"] in have
    return {**base, "ecosystem": eco, "status": "ok", "vulns": vulns, "count": len(vulns)}


# --- batch gates: malware (pre-install) + vuln scan (post-install) ----------------
# Both are EXACT lookups (no embedding) batched into a fixed number of queries
# regardless of list size — a lockfile/SBOM must never become N queries (cf. the prior
# N+1 incident). Name-level MAL- match owns "malicious"; lookup_cve/scan vulns own
# "vulnerable" — the two never overlap (lookup_cve excludes MAL-).
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _norm_deps(deps, need_version, max_deps):
    """Canonicalize + dedupe a dep list. Returns (norm, pairs, skipped, truncated).
    norm: [(orig_dep, eco, pkg, version)] (version '' when not needed);
    pairs: unique {(eco, pkg)} for the affected-rows query. Malformed entries and
    unmirrored ecosystems are skipped (counted) — one bad line never fails the batch."""
    truncated = len(deps) > max_deps
    norm, pairs, seen, skipped = [], set(), set(), 0
    for d in deps[:max_deps]:
        eco_in = (d.get("ecosystem") or "").strip()
        pkg_in = (d.get("package") or "").strip()
        ver = (d.get("version") or "").strip()
        if not eco_in or not pkg_in or (need_version and not ver):
            skipped += 1
            continue
        eco = cvelib.canonical_ecosystem(eco_in)
        if not eco:
            skipped += 1            # ecosystem we don't mirror -> can't speak to it
            continue
        pkg = cvelib.normalize_package(eco, pkg_in)
        key = (eco, pkg, ver)
        if key in seen:
            continue
        seen.add(key)
        norm.append((d, eco, pkg, ver))
        pairs.add((eco, pkg))
    return norm, pairs, skipped, truncated


async def _mirror_ready(conn):
    """A security tool must never imply 'clean' before the mirror exists."""
    cur = await conn.execute("SELECT EXISTS(SELECT 1 FROM cve_affected)")
    return (await cur.fetchone())[0]


async def _affected_rows(conn, pairs):
    """All cve_affected rows for a set of (eco, pkg) pairs in ONE index-driven query
    (unnest-join on idx_cve_affected_lookup). -> {(eco, pkg): [(vuln_id, ranges, versions)]}."""
    pair_list = list(pairs)
    ecos = [e for e, _ in pair_list]
    pkgs = [p for _, p in pair_list]
    cur = await conn.execute(
        "SELECT a.ecosystem, a.package, a.vuln_id, a.ranges, a.versions "
        "FROM cve_affected a "
        "JOIN unnest(%s::text[], %s::text[]) AS q(ecosystem, package) "
        "  ON a.ecosystem = q.ecosystem AND a.package = q.package",
        [ecos, pkgs])
    by = {}
    for eco, pkg, vid, ranges, versions in await cur.fetchall():
        by.setdefault((eco, pkg), []).append((vid, ranges, versions))
    return by


async def malware_check(deps, include_details=True, max_deps=5000):
    """Name-level malware gate for EXPLICITLY named packages (the pre-install block).
    Version is ignored — a malicious package is bad at every version. Returns only the
    malicious subset, each with its MAL- advisories (source `details` verbatim = the
    block reason; dropped when include_details=False for a lean agent response)."""
    norm, pairs, skipped, truncated = _norm_deps(deps, need_version=False, max_deps=max_deps)
    base = {"checked": len(norm), "malicious_count": 0, "skipped": skipped,
            "truncated": truncated, "results": []}
    if not pairs:
        return {"status": "ok", **base}
    async with get_async_pool().connection() as conn:
        if not await _mirror_ready(conn):
            return {"status": "unavailable", **base}
        aff = await _affected_rows(conn, pairs)
        mal_ids = {vid for rows in aff.values() for vid, _, _ in rows
                   if vid.startswith("MAL-")}
        adv = {}
        if mal_ids:
            cur = await conn.execute(
                "SELECT id, summary, details, refs FROM cve_vulns WHERE id = ANY(%s)",
                [list(mal_ids)])
            adv = {vid: (summary, details, refs)
                   for vid, summary, details, refs in await cur.fetchall()}

    results, seen = [], set()
    for d, eco, pkg, _ in norm:
        if (eco, pkg) in seen:
            continue
        advisories = []
        for vid, _, _ in aff.get((eco, pkg), []):
            if not vid.startswith("MAL-") or vid not in adv:
                continue
            summary, details, refs = adv[vid]
            a = {"id": vid, "summary": summary, "refs": (refs or [])[:5]}
            if include_details:
                a["details"] = details
            advisories.append(a)
        if advisories:
            seen.add((eco, pkg))
            results.append({"ecosystem": d.get("ecosystem"), "package": d.get("package"),
                            "malicious": True, "advisories": advisories})
    return {"status": "ok", "checked": len(norm), "malicious_count": len(results),
            "skipped": skipped, "truncated": truncated, "results": results}


async def scan_deps(deps, include_malware=True, max_deps=5000):
    """Version-aware vuln scan over a full lockfile/SBOM (the post-install gate).
    Returns the vulnerable subset only, lean + severity-sorted; folds in transitive
    malware when include_malware (defense in depth — the pre-install gate only saw the
    named packages). Agent pulls full insight via get_vuln for what it fixes."""
    norm, pairs, skipped, truncated = _norm_deps(deps, need_version=True, max_deps=max_deps)
    base = {"scanned": len(norm), "vulnerable_count": 0, "malware_count": 0,
            "skipped": skipped, "truncated": truncated, "findings": []}
    if not pairs:
        return {"status": "ok", **base}
    async with get_async_pool().connection() as conn:
        if not await _mirror_ready(conn):
            return {"status": "unavailable", **base}
        aff = await _affected_rows(conn, pairs)

        per_dep, all_vids = [], set()
        for d, eco, pkg, ver in norm:
            fixes = {}
            for vid, ranges, versions in aff.get((eco, pkg), []):
                if vid.startswith("MAL-") and not include_malware:
                    continue
                hit, fixed = cvelib.match(ver, versions or [], ranges or [], eco)
                if hit:
                    fixes[vid] = fixed or fixes.get(vid)
            if fixes:
                per_dep.append((d, eco, pkg, ver, fixes))
                all_vids.update(fixes)
        if not all_vids:
            return {"status": "ok", **base}

        cur = await conn.execute(
            "SELECT id, summary, aliases, severity_tier FROM cve_vulns WHERE id = ANY(%s)",
            [list(all_vids)])
        meta = {vid: (summary, aliases, tier)
                for vid, summary, aliases, tier in await cur.fetchall()}
        cid_of = {vid: cvelib.canonical_id(vid, aliases or [])
                  for vid, (summary, aliases, tier) in meta.items()
                  if not vid.startswith("MAL-")}
        have = await _have_insights(conn, list(set(cid_of.values())))

    findings = []
    for d, eco, pkg, ver, fixes in per_dep:
        vulns, malware, seen_cid = [], [], set()
        for vid, fixed in fixes.items():
            m = meta.get(vid)
            if not m:
                continue
            summary, aliases, tier = m
            if vid.startswith("MAL-"):
                malware.append({"id": vid, "summary": summary})
            else:
                cid = cid_of.get(vid, vid)
                if cid in seen_cid:
                    continue
                seen_cid.add(cid)
                vulns.append({"id": cid, "severity": tier or None,
                              "fixed_version": fixed, "has_ai_insight": cid in have})
        if not vulns and not malware:
            continue
        vulns.sort(key=lambda x: _SEV_ORDER.get(x["severity"], 4))
        findings.append({"ecosystem": d.get("ecosystem"), "package": d.get("package"),
                         "version": ver, "vulns": vulns, "malware": malware})
    return {"status": "ok", "scanned": len(norm),
            "vulnerable_count": sum(1 for f in findings if f["vulns"]),
            "malware_count": sum(1 for f in findings if f["malware"]),
            "skipped": skipped, "truncated": truncated, "findings": findings}


async def get_vuln(vuln_id, enriched=True):
    """Full record by OSV/CVE id (matches the id directly or via aliases). `enriched=True`
    attaches the full ai_insight; either way a cheap `has_ai_insight` flag is set."""
    cols = "id, summary, details, aliases, severity_tier, cwe, refs, published, modified"
    async with get_async_pool().connection() as conn:
        cur = await conn.execute(f"SELECT {cols} FROM cve_vulns WHERE id=%s", [vuln_id])
        row = await cur.fetchone()
        if not row:
            import json
            cur = await conn.execute(
                f"SELECT {cols} FROM cve_vulns WHERE aliases @> %s::jsonb LIMIT 1",
                [json.dumps([vuln_id])])
            row = await cur.fetchone()
    if not row:
        return None
    keys = ["id", "summary", "details", "aliases", "severity", "cwe", "refs", "published", "modified"]
    result = dict(zip(keys, row))
    cid = cvelib.canonical_id(result.get("id") or "", result.get("aliases") or [])
    async with get_async_pool().connection() as conn:
        if enriched:
            ins = await _insights_for(conn, [cid])
            if cid in ins:
                result["ai_insight"] = ins[cid]
            result["has_ai_insight"] = cid in ins
        else:
            result["has_ai_insight"] = bool(await _have_insights(conn, [cid]))
    return result
