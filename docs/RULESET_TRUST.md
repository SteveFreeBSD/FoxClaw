# Ruleset Trust Manifest

This document defines how FoxClaw verifies a ruleset before evaluation.

## Purpose

Ruleset trust verification prevents silent ruleset swaps or tampering by enforcing:

- pinned SHA256 digest validation for the selected ruleset file.
- optional Ed25519 detached signature validation.
- optional multi-signature threshold policy and key lifecycle windows.

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

## Manifest Contract (`schema_version: 1.1.0`)

FoxClaw supports `schema_version` `1.0.0` and `1.1.0`.  
`1.1.0` adds key lifecycle and signature-threshold controls:

```yaml
schema_version: "1.1.0"
keys:
  - key_id: release-key-2026-a
    algorithm: ed25519
    public_key: "<base64-encoded-32-byte-ed25519-public-key>"
    status: active
    valid_from: "2026-01-01T00:00:00Z"
    valid_to: "2027-01-01T00:00:00Z"
  - key_id: release-key-2025-b
    algorithm: ed25519
    public_key: "<base64-encoded-32-byte-ed25519-public-key>"
    status: deprecated
rulesets:
  - path: foxclaw/rulesets/balanced.yml
    sha256: "<64-char-lowercase-hex-digest>"
    min_valid_signatures: 2
    signatures:
      - key_id: release-key-2026-a
        algorithm: ed25519
        signature: "<base64-encoded-ed25519-signature>"
      - key_id: release-key-2025-b
        algorithm: ed25519
        signature: "<base64-encoded-ed25519-signature>"
```

## Verification Rules

- `schema_version` must be one of `1.0.0` or `1.1.0`.
- A ruleset entry must match exactly one path after resolution:
  - absolute paths are used directly.
  - relative paths are resolved relative to the manifest file directory.
- `sha256` must match the ruleset file bytes exactly.
- Duplicate `key_id` values in `keys` are rejected.
- If signatures are present:
  - required valid signatures are `max(1, min_valid_signatures)`.
  - only unique verified `key_id` values count toward the threshold.
  - keys with `status: revoked` are rejected.
  - keys outside `valid_from`/`valid_to` windows are rejected.
- If `--require-ruleset-signatures` is set and the matching entry has no signatures, verification fails.
- If `min_valid_signatures > 0` and the entry has no signatures, verification fails.

## Key Rotation Guidance

- Rotate by overlap:
  - publish new key as `active`,
  - keep previous key `deprecated` during rollout,
  - set `min_valid_signatures: 2` while both keys are expected.
- After rollout:
  - reduce threshold if desired,
  - mark old key `revoked` once no longer valid.

## Operational Guidance

- Keep trust manifests in source control and review them like code.
- Update manifest digest/signatures atomically with intended ruleset changes.
- Prefer `--require-ruleset-signatures` in release or CI enforcement paths.

## External Bundle Distribution

FoxClaw supports distributing signed ruleset bundles (TAR archives) for fleet usage. A bundle contains ruleset YAMLs and a `__manifest__.json` defining a `RulesetBundleManifest`. The bundle manifest signs the embedded `RulesetTrustManifest`, allowing you to fetch rulesets from the internet and verify them completely offline before execution.

Bundle commands allow fetching, verifying, and installing bundles independent of the `scan` engine:
```bash
# Safely fetch an untrusted ruleset bundle
foxclaw bundle fetch https://example.com/foxclaw-bundle.tar.gz --output bundle.tar.gz

# Verify the root signature and unpack into your local fleet
foxclaw bundle install bundle.tar.gz \
  --keyring policies/ruleset-keyring.yml \
  --key-id release-key-2026-a \
  --dest ~/.local/share/foxclaw/rulesets/premium-pack
```

The runtime `foxclaw scan` engine automatically reads the unpacked `__manifest__.json` bounding the installed bundle and outputs `BundleProvenance` telemetry on all generated JSON/SARIF reports.
