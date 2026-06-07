# bumper Advisor

The hosted knowledge service behind [**bumper**](https://github.com/gnana997/bumper) — a
read-only, **lookup-not-upload** API over public security data:

- the **federated IaC catalog** — bumper's enforced rules + Trivy / Checkov / KICS / Prowler;
- a **CVE / malware mirror** built from [OSV](https://osv.dev) (language ecosystems **and**
  Linux distros, including `MAL-` known-malicious advisories).

It answers *"what's the best practice?"* and *"is this dependency known-bad?"* over two doors,
one search core:

| Door | Path | For |
|------|------|-----|
| **MCP** (streamable-http, stateless) | `/mcp` | Claude Code / Codex / editors |
| **REST** (GET/POST, JSON) | `/search`, `/cve/lookup`, `/malware-check`, `/scan`, … | the CLI / web / anything |
| health + corpus counts | `/healthz` | monitoring |

> **Lookup, not upload.** It only ever receives a query string or package coordinates
> (`ecosystem` / `name` / `version`) — **never your code, plan, or state** — and request
> bodies aren't logged.

## Why Python (when the CLI is Go)?

Right tool per layer. The **bumper CLI** that ships to users is **Go** — a single static,
offline, dependency-free binary you drop into CI and coding agents. The **Advisor** is a
semantic-search / embedding service (vector model inference + pgvector similarity + OSV
ingestion) — that's Python's ecosystem. Two different jobs, two appropriate stacks.

Retrieval is hybrid: **vector** (`potion-retrieval-32M`, a numpy-only static embedding model —
no PyTorch) + **lexical** (BM25), fused with RRF, over **Postgres + pgvector**.

## Quick start

```sh
cp .env.example .env          # set a real POSTGRES_PASSWORD
docker compose up -d --build
```

On first boot: Postgres comes up, the IaC catalog loads, the API starts on
**`127.0.0.1:8000`**, and the initial OSV mirror syncs in the background (~13 min for the full
set; until it commits, lookups return `status: unavailable` — never a false "clean"). A daily
`scheduler` (supercronic, **no Docker socket**) keeps both corpora fresh.

```sh
curl -s http://localhost:8000/healthz | jq           # corpus counts + last-sync times
curl "http://localhost:8000/cve/lookup?ecosystem=npm&package=lodash&version=4.17.4"
```

Point bumper at it with `bumper deps --advisor-url http://localhost:8000` /
`$BUMPER_ADVISOR_URL` / `bumper init --advisor-url …`. **Full self-hosting guide** (exposing
it, sizing, tuning, troubleshooting) lives in the main repo:
**[docs/self-hosting.md](https://github.com/gnana997/bumper/blob/main/docs/self-hosting.md)**.

## Layout

```
app/        server.py (MCP + REST) · search_pg.py (hybrid + RRF) · pg.py · db.py · cve.py · schema_pg.sql
scripts/    sync_cve_pg.py (OSV mirror, zero-downtime) · sync_iac.py · load_iac.py · crontab
Dockerfile  docker-compose.yml  .env.example
```

## A note on AI insights

The public `advisor.bumper.sh` enriches detail records with AI-generated `ai_insight`
explanations. That enrichment pipeline is **not** part of this open-source distribution — a
self-hosted instance serves the **complete deterministic data** (rules, CVEs, malware — what a
scan actually decides on) with `has_ai_insight: false`. The insights are an explanation layer,
never part of any pass/fail verdict.

## Docs & API

- [Advisor API reference](https://github.com/gnana997/bumper/blob/main/docs/api.md) — every endpoint.
- [Advisor MCP](https://github.com/gnana997/bumper/blob/main/docs/mcp.md) — the agent tools.
- [Self-hosting](https://github.com/gnana997/bumper/blob/main/docs/self-hosting.md) — run it yourself.

## License

[Apache-2.0](LICENSE). Data is built from public [OSV](https://osv.dev) + the Apache-2.0
federated rule catalog (Trivy / Checkov / KICS / Prowler), attributed in the
[main repo's NOTICE](https://github.com/gnana997/bumper/blob/main/NOTICE).
