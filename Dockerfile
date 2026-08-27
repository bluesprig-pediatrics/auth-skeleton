# Build stage: resolve dependencies into a virtual environment.
FROM ghcr.io/astral-sh/uv:python3.14-bookworm-slim AS builder

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

# Dependencies before source, so a code change does not invalidate the layer.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-cache --no-dev --no-install-project

# Runtime stage: no uv, no build tooling, no dev dependencies.
FROM python:3.14-slim-bookworm

RUN useradd --create-home --shell /usr/sbin/nologin app

WORKDIR /app

COPY --from=builder /app/.venv /app/.venv
COPY --chown=app:app src/ ./src/
COPY --chown=app:app alembic/ ./alembic/
COPY --chown=app:app alembic.ini ./

# The project is not installed as a package; src/ goes on the path instead.
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1

USER app

EXPOSE 57005

# Uses the venv's python rather than curl, which this image does not carry.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:57005/healthz', timeout=2).status == 200 else 1)"

# Migrations are not run here: a container that migrates on boot races every
# other replica. Run `alembic upgrade head` as a deploy step.
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "57005"]
