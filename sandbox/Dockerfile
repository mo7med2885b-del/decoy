# Decoy sandbox image: one headless Chromium driven by runner.py. No secrets are ever baked in or passed in.
FROM python:3.12-slim

ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp

RUN pip install --no-cache-dir playwright==1.62.0 \
 && playwright install --with-deps chromium \
 && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin sandbox \
 && rm -rf /var/lib/apt/lists/*

COPY runner.py /runner.py

USER 10001
ENTRYPOINT ["python", "/runner.py"]
