FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir \
    --index-url https://pypi.org/simple \
    --extra-index-url https://download.pytorch.org/whl/cpu \
    torch==2.5.1+cpu torchvision==0.20.1+cpu
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Uses shell form so Render's dynamic $PORT variable evaluates correctly
CMD uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
