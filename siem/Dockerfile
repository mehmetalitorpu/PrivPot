FROM python:3.12-slim

# Create non-root user
RUN useradd -m -u 10002 siem

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt ./
RUN python -m venv /venv && /venv/bin/pip install --upgrade pip && \
    /venv/bin/pip install -r requirements.txt

COPY . .

# Create necessary directories and set permissions
RUN mkdir -p /var/log/ssh-honeypot /app/instance /app/data && \
    chown -R siem:siem /var/log/ssh-honeypot /app/instance /app/data

USER siem

EXPOSE 5000/tcp

ENTRYPOINT ["/venv/bin/python", "app.py"]
