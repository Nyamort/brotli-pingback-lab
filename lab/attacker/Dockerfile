FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PORT=8080 CHUNK_DELAY=1.0

WORKDIR /app
COPY payload.py server.py ./

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)"

CMD ["python3", "server.py"]
