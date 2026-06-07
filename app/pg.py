"""Postgres + pgvector access for the hosted Advisor.

Connection pools + the query-embedding helper. The embedding *model* is unchanged
(potion-retrieval-32M, from db.py) — pgvector only stores/indexes the vectors.

Two pools:
  * sync  ConnectionPool       — legacy / any blocking caller (scripts use direct
    psycopg.connect, not this; kept for compatibility).
  * async AsyncConnectionPool  — what the server uses. With async queries the event
    loop no longer blocks on a DB round-trip, so ONE worker interleaves many requests
    and the pool's connections are actually used concurrently (the whole point).
"""
import os

import numpy as np
from psycopg_pool import ConnectionPool, AsyncConnectionPool
from pgvector.psycopg import register_vector, register_vector_async

from .db import get_model

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://postgres:advisor@127.0.0.1:5433/advisor"
)

_pool: ConnectionPool | None = None
_apool: AsyncConnectionPool | None = None


# --- sync pool (legacy / blocking callers) -----------------------------------
def _configure(conn):
    register_vector(conn)  # adapt python <-> pgvector `vector` type
    # near-exact HNSW recall at this corpus size (default ef_search=40)
    conn.execute("SET hnsw.ef_search = 200")
    # cap any single query so a pathological request can't pin a backend (DoS guard).
    # Only the server's query pool gets this — ingest uses its own psycopg.connect.
    conn.execute("SET statement_timeout = '5s'")


def get_pool() -> ConnectionPool:
    """Lazily-opened pooled connection (the `vector` extension must already exist)."""
    global _pool
    if _pool is None:
        _pool = ConnectionPool(
            DATABASE_URL, min_size=1, max_size=8, configure=_configure, open=True,
            kwargs={"autocommit": True},
        )
    return _pool


# --- async pool (the server's hot path) --------------------------------------
async def _aconfigure(conn):
    await register_vector_async(conn)
    await conn.execute("SET hnsw.ef_search = 200")
    # cap any single query so a pathological request can't pin a backend (DoS guard).
    await conn.execute("SET statement_timeout = '5s'")


def get_async_pool() -> AsyncConnectionPool:
    """The async pool. Created closed; `warmup_async()` opens it inside the running
    loop (psycopg 3.2 deprecates opening in the constructor)."""
    global _apool
    if _apool is None:
        _apool = AsyncConnectionPool(
            DATABASE_URL, min_size=1, max_size=8, configure=_aconfigure, open=False,
            # prepare_threshold=None disables server-side prepared statements. The daily
            # CVE sync atomically RENAME-swaps cve_vulns/cve_affected; a cached plan bound
            # to the old table OID could otherwise error on the first post-swap query. Our
            # reads are simple indexed lookups (+ an app-level LRU cache fronts the heavy
            # semantic path), so the re-parse cost is negligible — worth it for a swap that
            # can never disrupt the malware gate.
            kwargs={"autocommit": True, "prepare_threshold": None},
        )
    return _apool


def embed_vec(text: str) -> np.ndarray:
    """Embed + L2-normalize a single string -> float32 vector for pgvector cosine.
    CPU-bound + synchronous — async callers run it via asyncio.to_thread so it never
    blocks the event loop."""
    v = np.asarray(get_model()([text])[0], dtype=np.float32)
    n = np.linalg.norm(v)
    if n > 0:
        v = v / n
    return v.astype(np.float32)


async def warmup_async() -> None:
    """Load the model, open the async pool, prove a round-trip. Called from lifespan."""
    get_model()  # load weights once (startup blocking is fine)
    pool = get_async_pool()
    await pool.open()
    await pool.wait()  # establish min_size connections before serving
    async with pool.connection() as conn:
        await (await conn.execute("SELECT 1")).fetchone()


async def close_async_pool() -> None:
    global _apool
    if _apool is not None:
        await _apool.close()
        _apool = None


def warmup() -> None:
    """Sync warmup (legacy)."""
    get_model()
    with get_pool().connection() as conn:
        conn.execute("SELECT 1").fetchone()
