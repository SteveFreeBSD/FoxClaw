VENV ?= .venv
PYTHON_BIN := $(VENV)/bin/python
PIP_BIN := $(VENV)/bin/pip
PYTEST_BIN := $(VENV)/bin/pytest
RUFF_BIN := $(VENV)/bin/ruff
MYPY_BIN := $(VENV)/bin/mypy
BANDIT_BIN := $(VENV)/bin/bandit
VULTURE_BIN := $(VENV)/bin/vulture
DETECT_SECRETS_BIN := $(VENV)/bin/detect-secrets

.PHONY: venv install test lint typecheck fixture-scan verify verify-full bandit vulture secrets certify certify-live hooks-install clean clean-venv

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

bandit:
	$(BANDIT_BIN) -q -r foxclaw -x tests

vulture:
	$(VULTURE_BIN) foxclaw tests --min-confidence 80

secrets:
	@./scripts/check_secrets.sh

verify-full: verify bandit vulture secrets

certify:
	@./scripts/certify.sh

certify-live:
	@./scripts/certify.sh --with-live-profile

hooks-install:
	@./scripts/install_hooks.sh

clean:
	rm -f foxclaw.json foxclaw.sarif
	rm -rf .pytest_cache .mypy_cache .ruff_cache foxclaw.egg-info build dist
	find foxclaw tests -type d -name "__pycache__" -prune -exec rm -rf {} +

clean-venv: clean
	rm -rf .venv
