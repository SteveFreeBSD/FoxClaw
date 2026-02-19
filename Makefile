VENV ?= .venv
PYTHON_BIN := $(VENV)/bin/python
PIP_BIN := $(VENV)/bin/pip
PYTEST_BIN := $(VENV)/bin/pytest
RUFF_BIN := $(VENV)/bin/ruff
MYPY_BIN := $(VENV)/bin/mypy

.PHONY: venv install test lint typecheck fixture-scan verify clean clean-venv

venv:
	python3 -m venv $(VENV)

install: venv
	$(PIP_BIN) install --upgrade pip
	$(PIP_BIN) install -e '.[dev]'

test:
	$(PYTEST_BIN) -q

lint:
	$(RUFF_BIN) check .

typecheck:
	$(MYPY_BIN) foxclaw

fixture-scan:
	@./scripts/fixture_scan.sh "$(PYTHON_BIN)"

verify: lint typecheck test fixture-scan

clean:
	rm -f foxclaw.json foxclaw.sarif
	rm -rf .pytest_cache .mypy_cache .ruff_cache foxclaw.egg-info build dist
	find foxclaw tests -type d -name "__pycache__" -prune -exec rm -rf {} +

clean-venv: clean
	rm -rf .venv
