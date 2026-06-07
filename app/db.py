"""Embedding model loader (process-wide, lazy). Shared by the query path (app/pg.py)
and the ingest scripts (load_iac.py, sync_cve_pg.py). The data store is Postgres +
pgvector now — the old SQLite/sqlite-vec read path was removed."""
import os
import threading

import numpy as np

MODEL_NAME = os.environ.get("MODEL_NAME", "minishlab/potion-retrieval-32M")

_model = None
_model_lock = threading.Lock()


def get_model():
    """Load the embedding model once (process-wide). Static (numpy) by default."""
    global _model
    if _model is None:
        with _model_lock:
            if _model is None:
                if MODEL_NAME.startswith("sentence-transformers/") or "minilm" in MODEL_NAME.lower():
                    from sentence_transformers import SentenceTransformer
                    st = SentenceTransformer(MODEL_NAME)
                    _model = lambda texts: np.asarray(st.encode(texts))
                else:
                    from model2vec import StaticModel
                    sm = StaticModel.from_pretrained(MODEL_NAME)
                    _model = lambda texts: np.asarray(sm.encode(texts))
    return _model
