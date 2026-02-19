# foxclaw

Minimal scaffold for a Firefox security posture agent.

## Badges

[![FoxClaw Security](https://github.com/OWNER/REPO/actions/workflows/foxclaw-security.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/foxclaw-security.yml)
[![Latest Release](https://img.shields.io/github/v/release/OWNER/REPO?label=latest%20release)](https://github.com/OWNER/REPO/releases/latest)

License badge is intentionally omitted until a repository license file is added.

## GitHub Security Integration

- CI runs `pytest -q` on Python 3.12, 3.13, and 3.14.
- A balanced FoxClaw scan runs on a synthetic Firefox profile fixture and emits `foxclaw.json` plus `foxclaw.sarif`.
- SARIF is uploaded with `github/codeql-action/upload-sarif` for GitHub Code Scanning visibility.

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
foxclaw --help
```
