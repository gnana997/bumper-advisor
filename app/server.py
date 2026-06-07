"""bumper Advisor — dual transport over one search core.

  /mcp            MCP streamable-http (stateless, JSON)  -> for agents/editors
  /search         plain REST (GET/POST, JSON)            -> for the web app / anything
  /rule           full record for one rule
  /malware-check  POST batch name-level malware gate     -> for the pre-install hook
  /scan           POST batch version-aware vuln+malware  -> for `bumper scan` (lockfile/SBOM)
  /healthz        liveness + cache stats

Both transports call the same `hybrid_search()` through the same per-worker LRU,
so a query run from the website warms the cache for agents and vice versa.
"""
import os
import re
import asyncio
import contextlib
from collections import OrderedDict

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.routing import Mount, Route
from starlette.responses import JSONResponse
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

from .search_pg import (hybrid_search, get_one,
                        search_cve as _search_cve, lookup_cve as _lookup_cve,
                        get_vuln as _get_vuln, malware_check as _malware_check,
                        scan_deps as _scan_deps)
from .pg import warmup_async, close_async_pool, get_async_pool

# The MCP streamable-http transport validates the Host header (DNS-rebinding
# protection) and returns 421 for any host not in its allow-list (defaults to
# localhost) — so it rejects requests arriving at a public hostname through a
# reverse proxy / tunnel. That protection guards LOCAL (localhost) MCP servers
# against malicious browser pages; it is not meaningful for a public, read-only,
# proxy-fronted server (REST routes have no such check). Disable it so /mcp works
# publicly.
# Hosts the MCP transport accepts (DNS-rebinding guard). Every MCP client
# (Claude Code / Codex / Cline / curl) sends a `Host:` header; the transport 421s
# anything not listed. Self-host: set ADVISOR_ALLOWED_HOSTS to your public
# hostname(s), comma-separated (e.g. "advisor.example.com"). localhost is always
# allowed for on-box testing, and each host also matches its ":port" form.
def _csv_env(name: str, default: str) -> list[str]:
    return [v.strip() for v in os.environ.get(name, default).split(",") if v.strip()]

_allowed_hosts: list[str] = []
for _h in _csv_env("ADVISOR_ALLOWED_HOSTS", "localhost,127.0.0.1"):
    _allowed_hosts += [_h, f"{_h}:*"]
# Origin is browser-only (native/CLI MCP clients send none, and the SDK allows a
# missing Origin) — it only gates BROWSER apps calling /mcp. Set
# ADVISOR_ALLOWED_ORIGINS (comma-separated, exact-match) if a web front-end does.
_allowed_origins = _csv_env("ADVISOR_ALLOWED_ORIGINS", "")

mcp = FastMCP(
    "bumper-advisor", stateless_http=True, json_response=True,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=_allowed_hosts,
        allowed_origins=_allowed_origins,
    ),
)

_WS = re.compile(r"\s+")
MAX_LIMIT = 100
# Cap every string arg before it reaches the embedder / Postgres. A cache MISS embeds
# whatever you send (potion-32M, CPU) and runs HNSW — so an unbounded `q` is the main
# DoS-amplification vector (an attacker randomizes it to defeat the LRU). No legitimate
# query, package, version, or id is anywhere near 512 chars.
MAX_STR = 512
# Batch cap for /scan + /malware-check. Covers virtually every lockfile/SBOM; over-cap
# is processed (first N) with a `truncated` flag rather than silently dropped — silent
# truncation reads as "you're clean" in a security tool. Huge monorepos chunk client-side.
MAX_DEPS = 5000


def _norm(s) -> str:
    return _WS.sub(" ", (s or "").strip().lower())[:MAX_STR]


def _cap(s) -> str:
    """Trim + length-cap a raw (case-preserving) string arg — ids/packages/versions."""
    return (s or "").strip()[:MAX_STR]


def _cap_deps(deps) -> list:
    """Trim + cap each dep's string fields; drop non-dict entries. Shared by the batch
    endpoints so untrusted bodies hit the same per-string ceiling as every other arg."""
    out = []
    for d in deps if isinstance(deps, list) else []:
        if isinstance(d, dict):
            out.append({"ecosystem": _cap(d.get("ecosystem")),
                        "package": _cap(d.get("package")),
                        "version": _cap(d.get("version"))})
    return out


async def _json_body(request) -> dict:
    """Parse a POST JSON body, always returning a dict (never raises)."""
    with contextlib.suppress(Exception):
        data = await request.json()
        if isinstance(data, dict):
            return data
    return {}


def _clamp_limit(v) -> int:
    try:
        return max(1, min(int(v), MAX_LIMIT))
    except (TypeError, ValueError):
        return 30


# --- async cache layer (per worker, results-only; key carries corpus) -------------
# functools.lru_cache can't wrap a coroutine (it would cache the un-re-awaitable
# coroutine object, exploding on the second hit). This caches the awaited RESULT,
# keyed exactly as before, with a per-key lock so a burst of identical misses computes
# once — the production pattern, where everyone asks about the same popular package.
class _AsyncLRU:
    def __init__(self, maxsize, fn):
        self.maxsize = maxsize
        self.fn = fn
        self.cache: "OrderedDict[tuple, object]" = OrderedDict()
        self.locks: "dict[tuple, asyncio.Lock]" = {}
        self.hits = 0
        self.misses = 0

    async def __call__(self, *key):
        if key in self.cache:
            self.hits += 1
            self.cache.move_to_end(key)
            return self.cache[key]
        lock = self.locks.get(key)
        if lock is None:
            lock = self.locks[key] = asyncio.Lock()
        async with lock:
            if key in self.cache:           # filled while we waited on the lock
                self.hits += 1
                self.cache.move_to_end(key)
                return self.cache[key]
            self.misses += 1
            result = await self.fn(*key)
            self.cache[key] = result
            self.cache.move_to_end(key)
            if len(self.cache) > self.maxsize:
                self.cache.popitem(last=False)
            self.locks.pop(key, None)
            return result

    def cache_info(self):
        return type("CacheInfo", (), {
            "hits": self.hits, "misses": self.misses, "currsize": len(self.cache)})()


_search_cached = _AsyncLRU(4096, hybrid_search)
# `enriched` is part of the cache key (lean vs full are distinct cached results).
_rule_cached = _AsyncLRU(2048, lambda doc_id, enriched: get_one("iac", doc_id, enriched))
_cve_search_cached = _AsyncLRU(4096, _search_cve)
_cve_lookup_cached = _AsyncLRU(8192, _lookup_cve)
_vuln_cached = _AsyncLRU(2048, lambda vid, enriched: _get_vuln(vid, enriched))


async def _do_search(query, provider="", severity="", limit=30):
    if not query or not query.strip():
        return {"query": query or "", "results": [], "advisory": [],
                "count": {"results": 0, "advisory": 0}}
    return await _search_cached(
        "iac", _norm(query), _norm(provider), _norm(severity), _clamp_limit(limit),
    )


# --- MCP tools (the agent contract) ----------------------------------------------
@mcp.tool()
async def search_rules(query: str, provider: str = "", severity: str = "",
                       limit: int = 30) -> dict:
    """Semantic + lexical search across bumper's enforced rules and the federated
    advisory catalog (Trivy/Checkov/KICS/Prowler). Returns {results, advisory}; each
    hit carries `has_ai_insight` (fetch the full AI insight via get_rule).
    It answers questions about best practice; it never sees your infrastructure."""
    return await _do_search(query, provider, severity, limit)


@mcp.tool()
async def get_rule(source: str, source_id: str, include_insight: bool = True) -> dict:
    """Full record for one rule: severity, resources, remediation, refs, cwe, etc.
    `source` is one of bumper|trivy|checkov|kics|prowler. When enriched, includes
    `ai_insight` {explanation, vulnerable_example, fixed_example, key_takeaway,
    provenance} — AI-generated from the rule, illustrative; verify before applying.
    Pass include_insight=false for a smaller response without the AI insight;
    `has_ai_insight` is always returned so you know it's available."""
    return await _rule_cached(f"{_norm(source)}:{_cap(source_id)}", bool(include_insight)) \
        or {"error": "not found"}


@mcp.tool()
async def search_cve(query: str, ecosystem: str = "", severity: str = "",
                     limit: int = 20) -> dict:
    """Semantic + lexical search over known CVEs (OSV mirror: language ecosystems +
    OS distros). Returns matching vulns with severity, affected ecosystems/packages,
    and CWE; each hit carries `has_ai_insight` (fetch the full AI insight via get_vuln).
    Lookup only — it never sees your code or dependencies."""
    if not query or not query.strip():
        return {"query": query or "", "results": [], "count": 0}
    return await _cve_search_cached(_norm(query), _norm(ecosystem), _norm(severity),
                                    _clamp_limit(limit))


@mcp.tool()
async def lookup_cve(ecosystem: str, package: str, version: str) -> dict:
    """Which known CVEs affect an EXACT package version — the secure-coding check
    before you pin a dependency. `ecosystem`: npm|PyPI|Maven|Go|crates.io|NuGet|
    RubyGems|Debian:12|Alpine:v3.19|... Returns {status, vulns:[{id, severity,
    fixed_version, summary, cwe, has_ai_insight}], count}. status='ok' even when count=0
    (clean); 'ecosystem_unsupported' when the ecosystem isn't mirrored (never implies safe).
    Vulns carry a `has_ai_insight` flag (lean by design — a list won't flood your context);
    call get_vuln(id) to pull the full AI insight for a specific one."""
    return await _cve_lookup_cached(_cap(ecosystem), _cap(package), _cap(version))


@mcp.tool()
async def get_vuln(id: str, include_insight: bool = True) -> dict:
    """Full record for one CVE/GHSA id: summary, details, severity, CWE, references.
    When enriched, includes `ai_insight` {explanation, vulnerable_example,
    fixed_example, key_takeaway, provenance} — AI-generated, illustrative; verify
    before applying. Pass include_insight=false for a smaller response without the AI
    insight; `has_ai_insight` is always returned so you know it's available."""
    return await _vuln_cached(_cap(id), bool(include_insight)) or {"error": "not found"}


@mcp.tool()
async def check_malware(ecosystem: str = "", package: str = "",
                        packages: list[dict] | None = None) -> dict:
    """Is a dependency KNOWN-MALICIOUS (typosquat / backdoor / install-time payload;
    OSV `MAL-`)? The safety check to run BEFORE adding a package. Pass one
    {ecosystem, package} or a batch via packages=[{ecosystem, package}, ...]. Name-level
    (no version needed — a malicious package is bad at every version). Returns
    {status, checked, malicious_count, results:[{ecosystem, package,
    advisories:[{id, summary, refs}]}]}; empty results = nothing flagged (NOT proof of
    safety — status='unavailable' means the mirror isn't ready, and an unmirrored
    ecosystem is simply skipped). Lean by design: call get_vuln(id) for an advisory's
    full write-up. For known VULNERABILITIES in a legitimate package use lookup_cve —
    malware and vulns are distinct paths."""
    deps = packages if packages else ([{"ecosystem": ecosystem, "package": package}]
                                      if package else [])
    if not deps:
        return {"status": "ok", "checked": 0, "malicious_count": 0, "results": []}
    return await _malware_check(_cap_deps(deps), include_details=False, max_deps=MAX_DEPS)


# --- rate limiting (ONLY /scan) --------------------------------------------------
# /scan is the one endpoint behind the anonymous web upload tool AND the heaviest
# batch call, so it's the lone abuse surface worth gating. A moving-window limiter
# (burst N, refilling over the window — token-bucket-like) keyed on the REAL client
# IP, backed by Redis so the limit is shared across uvicorn workers. It FAILS OPEN on
# any limiter/Redis error: rate limiting must never take /scan down. Every other
# endpoint stays unthrottled (the hook's /malware-check must stay fast; the single
# lookups are already cheap + capped).
_RL_URI = os.environ.get("RATELIMIT_REDIS", "")
_SCAN_RATE = os.environ.get("SCAN_RATE_LIMIT", "40/minute")
try:
    from limits import parse as _rl_parse
    from limits.storage import storage_from_string as _rl_storage_from
    from limits.strategies import MovingWindowRateLimiter
    _rl_limiter = MovingWindowRateLimiter(_rl_storage_from(_RL_URI)) if _RL_URI else None
    _rl_item = _rl_parse(_SCAN_RATE) if _RL_URI else None
except Exception:
    _rl_limiter, _rl_item = None, None  # dep/Redis missing -> /scan simply unthrottled


def _client_ip(request) -> str:
    # Behind a reverse proxy / CDN the socket peer is the proxy — the real client IP
    # is in a forwarded header (CF-Connecting-IP if present, else X-Forwarded-For,
    # then the peer).
    return (request.headers.get("cf-connecting-ip")
            or (request.headers.get("x-forwarded-for", "").split(",")[0].strip())
            or (request.client.host if request.client else "anon"))


async def _scan_rate_ok(request) -> bool:
    """True if the request is within the /scan limit. Fails OPEN on any error."""
    if _rl_limiter is None or _rl_item is None:
        return True
    try:
        return await asyncio.to_thread(_rl_limiter.hit, _rl_item, "scan", _client_ip(request))
    except Exception:
        return True  # Redis down / limiter error -> never block the scan


# --- REST handlers (the web-app door) --------------------------------------------
async def rest_search(request):
    p = request.query_params
    body = {}
    if request.method == "POST":
        with contextlib.suppress(Exception):
            body = await request.json()

    def g(*keys, default=""):
        for k in keys:
            if body.get(k) is not None:
                return body[k]
            if p.get(k) is not None:
                return p[k]
        return default

    query = g("q", "query")
    if not query:
        return JSONResponse({"error": "missing 'q' (or 'query')"}, status_code=400)
    data = await _do_search(query, g("provider"), g("severity"), g("limit", default=30))
    return JSONResponse(data)


async def rest_rule(request):
    p = request.query_params
    source = p.get("source", "")
    source_id = p.get("source_id") or p.get("id") or ""
    if not source or not source_id:
        return JSONResponse({"error": "missing 'source' and 'source_id'"}, status_code=400)
    inc = p.get("include_insight", "true").lower() != "false"
    rec = await _rule_cached(f"{_norm(source)}:{_cap(source_id)}", inc)
    if rec is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(rec)


async def rest_cve_search(request):
    p = request.query_params
    q = p.get("q") or p.get("query")
    if not q:
        return JSONResponse({"error": "missing 'q' (or 'query')"}, status_code=400)
    return JSONResponse(await _cve_search_cached(
        _norm(q), _norm(p.get("ecosystem", "")), _norm(p.get("severity", "")),
        _clamp_limit(p.get("limit", 20))))


async def rest_cve_lookup(request):
    p = request.query_params
    eco, pkg, ver = p.get("ecosystem", ""), p.get("package", ""), p.get("version", "")
    if not (eco and pkg and ver):
        return JSONResponse({"error": "need ecosystem, package, version"}, status_code=400)
    return JSONResponse(await _cve_lookup_cached(_cap(eco), _cap(pkg), _cap(ver)))


async def rest_vuln(request):
    p = request.query_params
    vid = p.get("id", "")
    if not vid:
        return JSONResponse({"error": "missing 'id'"}, status_code=400)
    inc = p.get("include_insight", "true").lower() != "false"
    rec = await _vuln_cached(_cap(vid), inc)
    return JSONResponse(rec) if rec else JSONResponse({"error": "not found"}, status_code=404)


# Batch gates — POST only (the dep list is large and structured). NOTE: bodies carry
# the caller's dependency coordinates; do NOT log them (privacy — opt-in covers them
# leaving the box, server-side logging would undo that).
async def rest_malware_check(request):
    deps = _cap_deps((await _json_body(request)).get("deps"))
    if not deps:
        return JSONResponse({"error": "missing 'deps' (non-empty list)"}, status_code=400)
    return JSONResponse(await _malware_check(deps, include_details=True, max_deps=MAX_DEPS))


async def rest_scan(request):
    if not await _scan_rate_ok(request):
        return JSONResponse(
            {"error": "rate limited — too many scans from your network; try again shortly, "
                      "or run the bumper CLI locally for unlimited full-tree scans"},
            status_code=429, headers={"Retry-After": "60"})
    body = await _json_body(request)
    deps = _cap_deps(body.get("deps"))
    if not deps:
        return JSONResponse({"error": "missing 'deps' (non-empty list)"}, status_code=400)
    include_malware = bool(body.get("include_malware", True))
    return JSONResponse(await _scan_deps(deps, include_malware=include_malware,
                                         max_deps=MAX_DEPS))


async def healthz(request):
    info = _search_cached.cache_info()
    corpora = {}
    synced = {}  # last-sync timestamps (written by the daily sync jobs) — freshness at a glance
    try:
        async with get_async_pool().connection() as conn:
            for key, sql in (
                ("iac", "SELECT count(*) FROM search_docs WHERE corpus='iac'"),
                ("cve_search", "SELECT count(*) FROM search_docs WHERE corpus='cve'"),
                ("cve_affected", "SELECT count(*) FROM cve_affected"),
            ):
                corpora[key] = (await (await conn.execute(sql)).fetchone())[0]
            rows = await (await conn.execute(
                "SELECT k, v FROM meta WHERE k IN ('cve_synced_at', 'iac_synced_at')"
            )).fetchall()
            synced = {k: v for k, v in rows}
    except Exception:
        pass
    return JSONResponse({
        "status": "ok",
        "model": os.environ.get("MODEL_NAME", "minishlab/potion-retrieval-32M"),
        "corpora": corpora,
        "synced": synced,
        "cache": {"hits": info.hits, "misses": info.misses, "size": info.currsize},
    })


# --- compose MCP + REST into one ASGI app ----------------------------------------
mcp_app = mcp.streamable_http_app()


@contextlib.asynccontextmanager
async def lifespan(app):
    # The streamable-http session manager must be started via the MCP app's lifespan.
    # Mounted sub-app lifespans aren't run by the parent, so we run it here.
    async with mcp_app.router.lifespan_context(app):
        await warmup_async()   # load model + open the async pool
        try:
            yield
        finally:
            await close_async_pool()


app = Starlette(
    routes=[
        Route("/search", rest_search, methods=["GET", "POST"]),
        Route("/rule", rest_rule, methods=["GET"]),
        Route("/cve/search", rest_cve_search, methods=["GET"]),
        Route("/cve/lookup", rest_cve_lookup, methods=["GET"]),
        Route("/vuln", rest_vuln, methods=["GET"]),
        Route("/malware-check", rest_malware_check, methods=["POST"]),
        Route("/scan", rest_scan, methods=["POST"]),
        Route("/healthz", healthz, methods=["GET"]),
        Mount("/", app=mcp_app),  # keeps /mcp working
    ],
    middleware=[
        # Public read-only knowledge API — permissive CORS lets the browser call
        # /search directly too (the Next backend proxy needs none of this).
        Middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["GET", "POST", "OPTIONS"], allow_headers=["*"]),
    ],
    lifespan=lifespan,
)
