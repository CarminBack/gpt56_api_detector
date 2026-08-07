FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    REPORT_DIR=/data/reports

WORKDIR /app

COPY requirements-web.txt ./
RUN pip install --no-cache-dir -r requirements-web.txt

COPY . .
RUN mkdir -p /data/reports && chown -R nobody:nogroup /data

USER nobody
EXPOSE 8000

CMD ["uvicorn", "webapp.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
