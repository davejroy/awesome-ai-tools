FROM python:3.12-slim

WORKDIR /app

# System deps for psycopg2 (Cloud SQL Postgres driver)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# Cloud Run injects PORT; default to 8080
ENV PORT=8080
EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
