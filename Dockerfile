FROM python:3.12-slim

# Create non-root user
RUN useradd -m -u 10001 honeypot

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HP_LOG_DIR=/var/log/ssh-honeypot

WORKDIR /app

COPY pyproject.toml ./
RUN python -m venv /venv && /venv/bin/pip install --upgrade pip && \
    /venv/bin/pip install .[dev]

COPY src ./src

RUN mkdir -p ${HP_LOG_DIR} && chown -R honeypot:honeypot ${HP_LOG_DIR}

USER honeypot

EXPOSE 2222/tcp

ENTRYPOINT ["/venv/bin/python", "-m", "src.app"]


