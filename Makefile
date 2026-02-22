VENV ?= .venv
PYTHON_BIN := $(VENV)/bin/python
PIP_BIN := $(VENV)/bin/pip
PYTEST_BIN := $(VENV)/bin/pytest
RUFF_BIN := $(VENV)/bin/ruff
MYPY_BIN := $(VENV)/bin/mypy
BANDIT_BIN := $(VENV)/bin/bandit
VULTURE_BIN := $(VENV)/bin/vulture
DETECT_SECRETS_BIN := $(VENV)/bin/detect-secrets
DOCKER ?= docker
CARGO_BIN ?= $(shell if command -v cargo >/dev/null 2>&1; then command -v cargo; elif [ -x "$$HOME/.cargo/bin/cargo" ]; then echo "$$HOME/.cargo/bin/cargo"; else echo cargo; fi)

.PHONY: venv install test test-integration testbed-fixtures testbed-fixtures-write migration-contract-fixtures migration-contract-fixtures-write migration-contract-verify-python migration-contract-verify-rust synth-profiles synth-profiles-bootstrap synth-profiles-100 fuzz-profiles profile-fidelity profile-launch-gate extension-catalog rust-workspace-check rust-parity-testbed rust-parity-smoke test-firefox-container demo-insecure-container soak-smoke soak-smoke-fuzz1000 soak-daytime soak-daytime-fuzz1000 soak-daytime-detached soak-stop soak-status lint typecheck fixture-scan trust-smoke sbom sbom-verify verify verify-full bandit vulture secrets dep-audit certify certify-live hooks-install clean clean-venv

venv:
	python3 -m venv $(VENV)

install: venv
	$(PIP_BIN) install --upgrade pip
	$(PIP_BIN) install -e '.[dev]'

test:
	$(PYTEST_BIN) -q -m "not integration"

test-integration: testbed-fixtures
	$(PYTEST_BIN) -q -m integration

testbed-fixtures:
	$(PYTHON_BIN) ./scripts/generate_testbed_fixtures.py --write
	$(PYTHON_BIN) ./scripts/generate_testbed_fixtures.py --check
	@git diff --quiet -- tests/fixtures/testbed || (echo "error: testbed fixtures are out of date; run 'make testbed-fixtures-write' and commit updates." >&2 && git --no-pager diff -- tests/fixtures/testbed && exit 1)

testbed-fixtures-write:
	$(PYTHON_BIN) ./scripts/generate_testbed_fixtures.py --write

migration-contract-fixtures:
	$(PYTHON_BIN) ./scripts/generate_migration_contract_fixtures.py --write --python-cmd "$(PYTHON_BIN) -m foxclaw"
	$(PYTHON_BIN) ./scripts/generate_migration_contract_fixtures.py --check --python-cmd "$(PYTHON_BIN) -m foxclaw"
	@git diff --quiet -- tests/fixtures/migration_contracts || (echo "error: migration contract fixtures are out of date; run 'make migration-contract-fixtures-write' and commit updates." >&2 && git --no-pager diff -- tests/fixtures/migration_contracts && exit 1)

migration-contract-fixtures-write:
	$(PYTHON_BIN) ./scripts/generate_migration_contract_fixtures.py --write --python-cmd "$(PYTHON_BIN) -m foxclaw"

migration-contract-verify-python:
	$(PYTHON_BIN) ./scripts/verify_migration_contract_engine.py \
		--engine-cmd "$(PYTHON_BIN) -m foxclaw" \
		--engine-label python \
		--output-dir /tmp/foxclaw-contract-verify-python

migration-contract-verify-rust: rust-workspace-check
	FOXCLAW_PYTHON_BIN="$(PYTHON_BIN)" "$(CARGO_BIN)" build --manifest-path foxclaw-rs/Cargo.toml -p foxclaw-rs-cli
	FOXCLAW_PYTHON_BIN="$(PYTHON_BIN)" $(PYTHON_BIN) ./scripts/verify_migration_contract_engine.py \
		--engine-cmd "./foxclaw-rs/target/debug/foxclaw-rs-cli" \
		--engine-label rust \
		--output-dir /tmp/foxclaw-contract-verify-rust

synth-profiles:
	$(PYTHON_BIN) ./scripts/synth_profiles.py --count 4 --output-dir /tmp/foxclaw-synth-profiles

synth-profiles-bootstrap:
	$(PYTHON_BIN) ./scripts/synth_profiles.py --mode bootstrap --count 4 --output-dir /tmp/foxclaw-synth-profiles

synth-profiles-100:
	$(PYTHON_BIN) ./scripts/synth_profiles.py --count 100 --output-dir /tmp/foxclaw-synth-profiles

fuzz-profiles:
	$(PYTHON_BIN) ./scripts/fuzz_profiles.py --count 20 --output-dir /tmp/foxclaw-fuzzer-profiles

profile-fidelity:
	$(PYTHON_BIN) ./scripts/profile_fidelity_check.py /tmp/foxclaw-synth-profiles --pattern "*.synth-*" --min-score 70 --enforce-min-score

profile-launch-gate:
	$(PYTHON_BIN) ./scripts/profile_launch_gate.py /tmp/foxclaw-synth-profiles --pattern "*.synth-*" --firefox-bin firefox --min-post-score 50 --enforce

extension-catalog:
	$(PYTHON_BIN) ./scripts/build_extension_catalog.py --output tests/fixtures/intel/amo_extension_catalog.v1.json

rust-workspace-check:
	@test -x "$(CARGO_BIN)" || command -v "$(CARGO_BIN)" >/dev/null 2>&1 || (echo "error: cargo is required for Rust workspace checks." >&2 && exit 1)
	"$(CARGO_BIN)" check --manifest-path foxclaw-rs/Cargo.toml

rust-parity-testbed: testbed-fixtures migration-contract-fixtures rust-workspace-check
	FOXCLAW_PYTHON_BIN="$(PYTHON_BIN)" "$(CARGO_BIN)" build --manifest-path foxclaw-rs/Cargo.toml -p foxclaw-rs-cli
	FOXCLAW_PYTHON_BIN="$(PYTHON_BIN)" $(PYTHON_BIN) ./scripts/rust_parity_runner.py \
		--python-cmd "$(PYTHON_BIN) -m foxclaw" \
		--rust-cmd "./foxclaw-rs/target/debug/foxclaw-rs-cli" \
		--output-dir /tmp/foxclaw-rs-parity
	$(PYTHON_BIN) ./scripts/verify_migration_contract_engine.py \
		--engine-cmd "$(PYTHON_BIN) -m foxclaw" \
		--engine-label python \
		--output-dir /tmp/foxclaw-contract-verify-python
	FOXCLAW_PYTHON_BIN="$(PYTHON_BIN)" $(PYTHON_BIN) ./scripts/verify_migration_contract_engine.py \
		--engine-cmd "./foxclaw-rs/target/debug/foxclaw-rs-cli" \
		--engine-label rust \
		--output-dir /tmp/foxclaw-contract-verify-rust

rust-parity-smoke: testbed-fixtures
	$(PYTHON_BIN) ./scripts/rust_parity_runner.py \
		--scenario profile_baseline \
		--python-cmd "$(PYTHON_BIN) -m foxclaw" \
		--rust-cmd "$(PYTHON_BIN) -m foxclaw" \
		--output-dir /tmp/foxclaw-rs-parity-smoke

test-firefox-container:
	$(DOCKER) build -f docker/testbed/Dockerfile -t foxclaw-firefox-testbed .
	$(DOCKER) run --rm \
		--user "$$(id -u):$$(id -g)" \
		-e HOME=/tmp \
		-v "$$(pwd):/workspace" \
		-w /workspace \
		foxclaw-firefox-testbed \
		bash -lc 'scripts/container_workspace_exec.sh scripts/firefox_container_scan.sh --output-dir /workspace/firefox-container-artifacts'

demo-insecure-container:
	$(DOCKER) build -f docker/testbed/Dockerfile -t foxclaw-firefox-testbed .
	$(DOCKER) run --rm \
		--user "$$(id -u):$$(id -g)" \
		-e HOME=/tmp \
		-v "$$(pwd):/workspace" \
		-w /workspace \
		foxclaw-firefox-testbed \
		bash -lc 'scripts/container_workspace_exec.sh scripts/firefox_container_demo.sh --output-dir /workspace/demo-insecure-artifacts'

soak-smoke:
	@SOAK_SUDO_PASSWORD="$(SOAK_SUDO_PASSWORD)" scripts/soak_runner.sh \
		--duration-hours 1 \
		--max-cycles 1 \
		--integration-runs 1 \
		--snapshot-runs 1 \
		--synth-count 10 \
		--synth-mode bootstrap \
		--synth-seed 424242 \
		--synth-fidelity-min-score 70 \
		--require-launch-gate \
		--launch-gate-min-score 50 \
		--fuzz-count 10 \
		--fuzz-mode chaos \
		--fuzz-seed 525252 \
		--fuzz-fidelity-min-score 50 \
		--matrix-runs 1 \
		--label smoke

soak-smoke-fuzz1000:
	@SOAK_SUDO_PASSWORD="$(SOAK_SUDO_PASSWORD)" scripts/soak_runner.sh \
		--duration-hours 1 \
		--max-cycles 1 \
		--integration-runs 1 \
		--snapshot-runs 1 \
		--synth-count 20 \
		--synth-mode bootstrap \
		--synth-seed 424242 \
		--synth-fidelity-min-score 70 \
		--require-launch-gate \
		--launch-gate-min-score 50 \
		--fuzz-count 1000 \
		--fuzz-mode chaos \
		--fuzz-seed 525252 \
		--fuzz-fidelity-min-score 50 \
		--matrix-runs 1 \
		--label smoke-fuzz1000

soak-daytime:
	@SOAK_SUDO_PASSWORD="$(SOAK_SUDO_PASSWORD)" scripts/soak_runner.sh \
		--duration-hours 3 \
		--max-cycles 6 \
		--integration-runs 2 \
		--snapshot-runs 3 \
		--synth-count 50 \
		--synth-mode bootstrap \
		--synth-seed 424242 \
		--synth-fidelity-min-score 70 \
		--fuzz-count 150 \
		--fuzz-mode chaos \
		--fuzz-seed 525252 \
		--fuzz-fidelity-min-score 50 \
		--matrix-runs 1 \
		--label daytime-burnin

soak-daytime-fuzz1000:
	@SOAK_SUDO_PASSWORD="$(SOAK_SUDO_PASSWORD)" scripts/soak_runner.sh \
		--duration-hours 3 \
		--max-cycles 6 \
		--integration-runs 2 \
		--snapshot-runs 3 \
		--synth-count 50 \
		--synth-mode bootstrap \
		--synth-seed 424242 \
		--synth-fidelity-min-score 70 \
		--fuzz-count 1000 \
		--fuzz-mode chaos \
		--fuzz-seed 525252 \
		--fuzz-fidelity-min-score 50 \
		--matrix-runs 1 \
		--label daytime-burnin-fuzz1000

soak-daytime-detached:
	systemd-run --user \
		--unit foxclaw-soak-daytime \
		--same-dir \
		--collect \
		--setenv=SOAK_SUDO_PASSWORD="$(SOAK_SUDO_PASSWORD)" \
		scripts/soak_runner.sh \
		--duration-hours 3 \
		--max-cycles 6 \
		--integration-runs 2 \
		--snapshot-runs 3 \
		--synth-count 50 \
		--synth-mode bootstrap \
		--synth-seed 424242 \
		--synth-fidelity-min-score 70 \
		--fuzz-count 150 \
		--fuzz-mode chaos \
		--fuzz-seed 525252 \
		--fuzz-fidelity-min-score 50 \
		--matrix-runs 1 \
		--label daytime-burnin

soak-stop:
	systemctl --user stop foxclaw-soak-daytime.service

soak-status:
	@systemctl --user is-active foxclaw-soak-daytime.service || true
	@run=$$(ls -1dt /var/tmp/foxclaw-soak/*daytime-burnin* 2>/dev/null | head -n1); \
		if [ -n "$$run" ]; then \
			echo "latest_run=$$run"; \
			if [ -f "$$run/summary.txt" ]; then \
				cat "$$run/summary.txt"; \
			else \
				tail -n 30 "$$run/run.log"; \
			fi; \
		else \
			echo "no daytime soak runs found"; \
		fi

lint:
	$(RUFF_BIN) check .

typecheck:
	$(MYPY_BIN) foxclaw

fixture-scan:
	@./scripts/fixture_scan.sh "$(PYTHON_BIN)"

trust-smoke:
	@./scripts/trust_scan_smoke.sh "$(PYTHON_BIN)"

sbom:
	@./scripts/generate_sbom.sh --python "$(PYTHON_BIN)" --dist-dir dist --output sbom.cyclonedx.json
	@"$(PYTHON_BIN)" ./scripts/verify_sbom.py sbom.cyclonedx.json

sbom-verify:
	@"$(PYTHON_BIN)" ./scripts/verify_sbom.py sbom.cyclonedx.json

verify: lint typecheck test test-integration migration-contract-fixtures migration-contract-verify-python fixture-scan trust-smoke

bandit:
	$(BANDIT_BIN) -q -r foxclaw -x tests

vulture:
	$(VULTURE_BIN) foxclaw tests --min-confidence 80

secrets:
	@./scripts/check_secrets.sh

dep-audit:
	$(PIP_BIN) install --upgrade "pip-audit==2.7.3"
	@./scripts/dependency_audit.sh --pip-audit-bin "$(VENV)/bin/pip-audit" --output dependency-audit.json

verify-full: verify bandit vulture secrets

certify:
	@./scripts/certify.sh

certify-live:
	@./scripts/certify.sh --with-live-profile

hooks-install:
	@./scripts/install_hooks.sh

clean:
	rm -f foxclaw.json foxclaw.sarif dependency-audit.json sbom.cyclonedx.json
	rm -rf .pytest_cache .mypy_cache .ruff_cache foxclaw.egg-info build dist
	find foxclaw tests -type d -name "__pycache__" -prune -exec rm -rf {} +

clean-venv: clean
	rm -rf .venv
