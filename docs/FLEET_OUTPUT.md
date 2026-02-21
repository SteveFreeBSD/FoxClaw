# Fleet Output Contract

This document defines the machine-consumable multi-profile aggregation contract emitted by:

```bash
foxclaw fleet aggregate ...
```

## Goal

- Provide deterministic, normalized output for SIEM and fleet ingestion pipelines.
- Preserve per-profile scan context while exposing flattened finding records.

## Top-Level Schema

`fleet aggregate --json` emits:

- `fleet_schema_version`
  - contract version for the fleet aggregation payload.
- `host`
  - deterministic host metadata and host identity hash (`host_id`).
- `aggregate`
  - fleet-level totals and severity counters.
- `profiles`
  - normalized per-profile identities and summaries.
- `finding_records`
  - flattened records that include host/profile identity fields and finding metadata.

## Deterministic Identity Model

- `host.host_id`
  - SHA-256 of local machine-id when available (`/etc/machine-id` or dbus fallback).
  - falls back to SHA-256 of stable host metadata fields when machine-id is unavailable.
- `profiles[].identity.profile_uid`
  - SHA-256 of `<profile_id>\n<normalized_profile_path>`.
  - normalized profile paths use `expanduser().resolve(strict=False).as_posix()`.

These identities are deterministic for a stable host/profile layout and suitable as join keys for downstream aggregation.

## Aggregation Semantics

- Profile ordering is deterministic by profile identity.
- Finding record ordering is deterministic by:
  - severity (`HIGH`, `MEDIUM`, `INFO`),
  - rule id,
  - profile uid,
  - evidence tuple.
- `aggregate` counters are computed from merged per-profile summaries.
- `aggregate.unique_rule_ids` is a sorted set across merged finding records.

## Schema Versioning Policy

- Fleet payloads use `fleet_schema_version` with semantic versioning intent:
  - `MAJOR`: breaking field or semantic changes.
  - `MINOR`: additive backward-compatible fields.
  - `PATCH`: non-structural clarifications/fixes with unchanged field contract.
- Consumers should:
  - reject unknown major versions by default,
  - tolerate additive fields for known major versions.
- Current fleet schema version: `1.0.0`.
