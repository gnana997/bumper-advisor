-- bumper Advisor — Postgres + pgvector schema (hybrid search plane).
-- One unified corpus table; CVE structured-lookup tables are added in the CVE step.

CREATE EXTENSION IF NOT EXISTS vector;

-- Unified search corpus: IaC rules + (later) canonical CVE docs.
CREATE TABLE IF NOT EXISTS search_docs (
  corpus     text NOT NULL,            -- 'iac' | 'cve'
  doc_id     text NOT NULL,            -- rule uid / canonical vuln id
  title      text,
  body       text,                     -- lexical text (title+remediation+resources)
  severity   text,                     -- normalized tier ('' if none)
  provider   text,                     -- iac: aws|gcp|azure   (null for cve)
  ecosystems text[],                   -- cve only
  packages   text[],                   -- cve only
  meta       jsonb,                    -- full record for result reconstruction
  embedding  vector(512),              -- potion-retrieval-32M
  tsv        tsvector GENERATED ALWAYS AS
               (to_tsvector('english', coalesce(title,'') || ' ' || coalesce(body,''))) STORED,
  PRIMARY KEY (corpus, doc_id)
);

CREATE INDEX IF NOT EXISTS idx_docs_hnsw ON search_docs USING hnsw (embedding vector_cosine_ops);
CREATE INDEX IF NOT EXISTS idx_docs_tsv  ON search_docs USING gin  (tsv);
CREATE INDEX IF NOT EXISTS idx_docs_facet ON search_docs (corpus, severity);
CREATE INDEX IF NOT EXISTS idx_docs_provider ON search_docs (corpus, provider);
CREATE INDEX IF NOT EXISTS idx_docs_eco ON search_docs USING gin (ecosystems);

-- Structured CVE (exact version lookup) — no vectors, just indexed.
CREATE TABLE IF NOT EXISTS cve_vulns (
  id             text PRIMARY KEY,
  summary        text,
  details        text,
  aliases        jsonb,
  severity       jsonb,
  severity_score real,
  severity_tier  text,
  cwe            jsonb,
  published      text,
  modified       text,
  refs           jsonb
);
ALTER TABLE cve_vulns ADD COLUMN IF NOT EXISTS cwe jsonb;
CREATE TABLE IF NOT EXISTS cve_affected (
  vuln_id    text NOT NULL,
  ecosystem  text NOT NULL,
  package    text NOT NULL,
  range_type text,
  ranges     jsonb,
  versions   jsonb
);
CREATE INDEX IF NOT EXISTS idx_cve_affected_lookup ON cve_affected (ecosystem, package);

CREATE TABLE IF NOT EXISTS meta (k text PRIMARY KEY, v text);

-- AI Insights (precomputed LLM enrichment) — DURABLE. Keyed by the STABLE item_id
-- ("source:rule_id" for IaC, canonical CVE id for CVEs), so the destroy-and-rebuild
-- ingest (load_iac.py / sync_cve_pg.py) leaves it intact. NEVER TRUNCATE THIS TABLE.
-- Populated by scripts/enrich_iac.py; joined at read time on item_id.
CREATE TABLE IF NOT EXISTS ai_insights (
  item_id      text PRIMARY KEY,            -- canonical CVE id OR "source:rule_id" (STABLE)
  kind         text NOT NULL,               -- 'cve' | 'iac'
  insight      jsonb NOT NULL,              -- {explanation, vulnerable_example, fixed_example, key_takeaway}
  source_hash  text NOT NULL,               -- sha256(prompt_version + model + exact model inputs)
  model        text NOT NULL,               -- 'claude-haiku-4-5' | 'claude-sonnet-4-6'
  tokens_in    int,
  tokens_out   int,
  status       text NOT NULL DEFAULT 'ok',  -- 'ok' | 'rejected' (validation failed)
  generated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ai_insights_kind ON ai_insights(kind);
