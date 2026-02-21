# Ruleset Trust Manifest

This document defines how FoxClaw verifies a ruleset before evaluation.

## Purpose

Ruleset trust verification prevents silent ruleset swaps or tampering by enforcing:

- a pinned SHA256 digest for the selected ruleset file.
- optional Ed25519 detached signature validation.

Verification is fail-closed. Any trust mismatch returns an operational error (CLI exit code `1`).

## CLI Controls

Available on both `scan` and `fleet aggregate`:

- `--ruleset-trust-manifest <path>`: enable trust verification against a local manifest file.
- `--require-ruleset-signatures`: require at least one valid signature in the matching manifest entry.

Example:

```bash
foxclaw scan \
  --profile tests/fixtures/firefox_profile \
  --ruleset foxclaw/rulesets/balanced.yml \
  --ruleset-trust-manifest policies/ruleset-trust.yml \
  --require-ruleset-signatures \
  --json
```

## Manifest Contract (`schema_version: 1.0.0`)

```yaml
schema_version: "1.0.0"
keys:
  - key_id: release-key-1
    algorithm: ed25519
    public_key: "<base64-encoded-32-byte-ed25519-public-key>"
rulesets:
  - path: foxclaw/rulesets/balanced.yml
    sha256: "<64-char-lowercase-hex-digest>"
    signatures:
      - key_id: release-key-1
        algorithm: ed25519
        signature: "<base64-encoded-ed25519-signature>"
```

## Verification Rules

- `schema_version` must be `1.0.0`.
- A ruleset entry must match exactly one path after path resolution:
  - absolute paths are used directly.
  - relative paths are resolved relative to the manifest file directory.
- `sha256` must match the ruleset file bytes exactly.
- If signatures are present, at least one valid signature must verify.
- If `--require-ruleset-signatures` is set and the matching entry has no signatures, verification fails.
- Duplicate `key_id` values in `keys` are rejected.

## Operational Guidance

- Keep trust manifests in source control and review them like code.
- Update manifest digest/signatures atomically with intended ruleset changes.
- Prefer `--require-ruleset-signatures` in release or CI enforcement paths.
