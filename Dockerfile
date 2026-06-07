# --- build stage: install deps + bake the embedding model -----------------------
FROM python:3.12-slim AS build
WORKDIR /app

# supercronic: container-native cron for the scheduler service (runs jobs as the
# unprivileged user, passes the container env to them, logs to stdout — and needs
# NO Docker socket, unlike ofelia). Pinned + sha256-verified. Lands in /usr/local/bin,
# which the runtime stage already COPYs over. arch-aware via BuildKit's TARGETARCH.
ARG TARGETARCH
ARG SUPERCRONIC_VERSION=v0.2.46
RUN set -eux; \
    apt-get update && apt-get install -y --no-install-recommends curl ca-certificates; \
    arch="${TARGETARCH:-amd64}"; \
    case "$arch" in \
      amd64) sha=5adff01c5a797663948e656d2b61d10932369ee437eb5cb54fa872b2960f222b ;; \
      arm64) sha=c0576a8eb092e3f79108ed0a2155a25c7766af78456e5a6070e54757ef513bfe ;; \
      *) echo "unsupported TARGETARCH: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /usr/local/bin/supercronic \
      "https://github.com/aptible/supercronic/releases/download/${SUPERCRONIC_VERSION}/supercronic-linux-${arch}"; \
    echo "${sha}  /usr/local/bin/supercronic" | sha256sum -c -; \
    chmod +x /usr/local/bin/supercronic; \
    apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir uv
COPY pyproject.toml uv.lock ./
# Reproducible build: install the EXACT pinned set from uv.lock (not a fresh resolve of
# pyproject's ranges). --frozen fails the build if the lock has drifted from pyproject;
# --no-emit-project keeps it deps-only (the app source is COPYed below). uv verifies the
# per-package hashes carried in the export. Re-lock with `uv lock` when you change deps.
RUN uv export --frozen --no-dev --no-emit-project -o /tmp/requirements.txt \
 && uv pip install --system -r /tmp/requirements.txt

COPY . .
# bake the static model into the HF cache (~30-50 MB) so runtime needs no network.
# Data lives in Postgres now (loaded by the init / cve-sync services), not baked.
RUN python -c "from model2vec import StaticModel; StaticModel.from_pretrained('minishlab/potion-retrieval-32M')"

# --- runtime stage ---------------------------------------------------------------
FROM python:3.12-slim
WORKDIR /app
# HF cache moves into the non-root user's home so the baked model is readable as appuser
ENV PYTHONUNBUFFERED=1 \
    HF_HUB_OFFLINE=1 \
    HF_HOME=/home/appuser/.cache/huggingface \
    WORKERS=2

# run as an unprivileged user — limits blast radius of any dependency RCE
RUN useradd -m -u 10001 appuser

COPY --from=build /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=build /usr/local/bin /usr/local/bin
COPY --from=build --chown=appuser:appuser /root/.cache/huggingface /home/appuser/.cache/huggingface
COPY --from=build /app /app

USER appuser
EXPOSE 8000
# Stays --host 0.0.0.0: inside the container a reverse proxy / tunnel reaches it over
# the Docker network by service name; host-level isolation is the compose
# "127.0.0.1:8000:8000" publish, not the bind. Shell form so $WORKERS expands.
#   --timeout-keep-alive 5  : drop idle/slow-client conns fast (slowloris guard)
#   --limit-concurrency 256 : hard per-worker in-flight ceiling -> fast 503 under flood
#                             (well above the ~125/worker seen at 500 VUs, so it only
#                              trips on genuine abuse, never normal load)
CMD uvicorn app.server:app --host 0.0.0.0 --port 8000 --workers ${WORKERS} \
    --timeout-keep-alive 5 --limit-concurrency 256
