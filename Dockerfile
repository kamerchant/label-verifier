FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# psycopg2-binary bundles libpq, so no compiler or system packages are needed.
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app
COPY seed_admin.py .

# Run as an unprivileged user; /tmp stays writable for CSV upload staging.
RUN useradd --system --no-create-home --uid 10001 appuser
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT', '8000'), timeout=4)"]

# Shell form is needed so a platform-provided $PORT is expanded; exec keeps uvicorn as PID 1 for clean shutdown.
CMD exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
