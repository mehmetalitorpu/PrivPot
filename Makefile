PY?=python
PIP?=pip

.PHONY: run test lint build fmt analyze

run:
	$(PY) -m src.app

self-check:
	$(PY) -m src.app self-check

analyze:
	$(PY) -m src.app analyze

analyze-1h:
	$(PY) -m src.app analyze 1

analyze-24h:
	$(PY) -m src.app analyze 24

analyze-7d:
	$(PY) -m src.app analyze 168

test:
	pytest -q --maxfail=1 --disable-warnings --cov=src --cov-report=term-missing

lint:
	ruff check . && black --check .

fmt:
	black . && ruff check --fix .

build:
	docker build -t ssh-honeypot:latest .


