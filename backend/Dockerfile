# AEGIS backend image.
# NOTE: written for the 1.0 release but NOT built or run on the development
# machine (Docker was unavailable there). See README "Docker".

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    AEGIS_DATABASE_URL=sqlite:////data/aegis.db

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY alembic.ini .
COPY alembic ./alembic
COPY app ./app

# Run as an unprivileged user; the SQLite database lives on a volume.
RUN useradd --create-home --uid 10001 aegis \
    && mkdir -p /data \
    && chown aegis:aegis /data
USER aegis
VOLUME ["/data"]

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health/live', timeout=2)"

# Apply migrations, then serve. 0.0.0.0 is the container's own interface;
# docker-compose.yml publishes the port on the host's loopback only.
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000"]
