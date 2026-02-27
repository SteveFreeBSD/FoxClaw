# WS-76 SIEM Readiness

WS-76 defines a vendor-neutral SIEM interface for FoxClaw and selects one open source SIEM proof target.

## Scope

- research-focused only
- no FoxClaw exporter implementation in this slice
- objective: define the transport, event contract, and simplest proof path

## Decisions

### 1. Portable transport: NDJSON

FoxClaw SIEM output should use newline-delimited JSON (`.ndjson`, `application/x-ndjson`) with one event per line.

Why:

- The NDJSON spec requires each JSON text to be newline-delimited and UTF-8 encoded.
- Wazuh log ingestion expects single-line JSON events.
- Standard tailing shippers already support NDJSON directly.

Official references:

- [NDJSON spec](https://github.com/ndjson/ndjson-spec)
  - Quote: "followed by the newline character `\\n`."
- [Elastic Filebeat `filestream` input](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-filestream)
  - Quote: "processes the logs line by line"
- [Wazuh `localfile` configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html)
  - Quote: "single-line JSON files"
- [Wazuh JSON decoder](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html)
  - Quote: "Type one log per line"

Operational interpretation:

- emit one FoxClaw event object per line
- UTF-8 only
- no pretty-printing
- no multiline JSON arrays

### 2. Open source SIEM test target: Wazuh

Chosen test target: Wazuh.

Why Wazuh:

- It is explicitly "free and open source" and provides "unified XDR and SIEM protection".
- It already has:
  - file-based log collection via `localfile`
  - built-in JSON decoding
  - `wazuh-logtest` for decoder/rule validation
  - `alerts.json` for machine-readable alert verification

Official references:

- [Wazuh quickstart](https://documentation.wazuh.com/current/quickstart.html)
  - Quote: "free and open source"
  - Quote: "unified XDR and SIEM protection"
- [Wazuh log collection](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/how-it-works.html)
  - Quote: "records all alerts in"
- [Wazuh testing decoders and rules](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html)
  - Quote: "verify which decoders match"

Decision:

- Use Wazuh as the first open source ingest proof target.
- Keep the FoxClaw event contract vendor-neutral so the same NDJSON stream can later be tailed by Filebeat or other shippers.

### 3. Portability constraints for the FoxClaw contract

Wazuh's JSON decoder supports objects, but "An array of objects is not supported." That means FoxClaw should prefer:

- scalars
- nested objects
- scalar arrays only when necessary

Avoid in the portable contract:

- arrays of objects
- multiline payload fields
- vendor-specific wrapper envelopes

Reference:

- [Wazuh JSON decoder](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html)

## FoxClaw NDJSON Event Contract

### Format

- one JSON object per line
- UTF-8
- media type: `application/x-ndjson`
- file extension: `.ndjson`

### Event types

- `foxclaw.finding`
- `foxclaw.scan.summary`

### Required top-level fields

Required on every event:

- `schema_version`
- `timestamp`
- `event_type`
- `event_id`
- `host`
- `profile`
- `severity`
- `title`
- `message`

Recommended field semantics:

- `schema_version`: semantic version of the FoxClaw SIEM contract
- `timestamp`: RFC 3339 / ISO 8601 UTC timestamp
- `event_type`: one of the two values above
- `host.id`: stable host identity
- `host.name`: display hostname
- `profile.profile_id`: stable profile identity
- `profile.profile_uid`: optional secondary stable identity when a deterministic path-derived UID is available
- `profile.name`: display profile name or basename
- `event_id`: stable event identifier for deduplication and replay safety
- `severity`: normalized FoxClaw severity string (`HIGH`, `MEDIUM`, `INFO`)
- `title`: short operator-facing title
- `message`: longer human-readable explanation

Recommended optional fields:

- `scan_id`
- `ruleset`
- `finding_count`
- `source`
- `intel`
- `suppressed`
- `tags`

### Compatibility policy

- `schema_version` uses semantic versioning.
- Major version:
  - breaking field rename/removal/type change
- Minor version:
  - additive optional fields only
- Patch version:
  - documentation or clarification only, no contract break

Per-event rules:

- `foxclaw.finding` must include `rule_id`.
- `foxclaw.scan.summary` must omit `rule_id` entirely.

Consumer rules:

- producers must not change meaning of existing fields inside the same major version
- consumers should ignore unknown fields
- required field keys stay present across all minor versions
- `event_id` is computed from a canonical string that includes:
  - `event_type`
  - `host.id`
  - `profile.profile_id`
  - `timestamp`
  - `schema_version`
  - `rule_id` for finding events only

## Contract Shape

### `foxclaw.finding`

```json
{
  "schema_version": "1.0.0",
  "timestamp": "2026-02-27T15:00:00Z",
  "event_id": "<sha256>",
  "event_type": "foxclaw.finding",
  "host": {
    "id": "host-01",
    "name": "workstation-01"
  },
  "profile": {
    "profile_id": "profile-abc123",
    "name": "default-release"
  },
  "rule_id": "FC-HSTS-001",
  "severity": "HIGH",
  "title": "HSTS downgrade state detected",
  "message": "Profile contains HSTS state inconsistent with expected downgrade-safe posture.",
  "scan_id": "scan-20260227-150000Z",
  "ruleset": "strict"
}
```

### `foxclaw.scan.summary`

```json
{
  "schema_version": "1.0.0",
  "timestamp": "2026-02-27T15:00:01Z",
  "event_id": "<sha256>",
  "event_type": "foxclaw.scan.summary",
  "host": {
    "id": "host-01",
    "name": "workstation-01"
  },
  "profile": {
    "profile_id": "profile-abc123",
    "name": "default-release"
  },
  "severity": "INFO",
  "title": "FoxClaw scan summary",
  "message": "Scan completed with 2 findings, 0 suppressed, and 0 operational errors.",
  "scan_id": "scan-20260227-150000Z",
  "finding_count": 2,
  "ruleset": "strict"
}
```

## SIEM Design Notes

### Why not raw JSON arrays?

They are worse for tailing collectors because shippers and decoders generally operate per message or per line, not per file-sized JSON document.

### Why not force OCSF now?

Not yet. The immediate target is a stable vendor-neutral FoxClaw envelope that can be shipped everywhere. OCSF mapping should be a follow-on compatibility layer once Python production behavior and downstream SIEM needs are better proven.

### Why keep host/profile nested?

- nested objects remain readable
- Wazuh JSON decoding supports objects
- the shape remains portable to later field-flattening transforms if a downstream SIEM prefers flat keys

## Recommended Proof Target

First proof target: Wazuh local file ingestion.

Recommended path:

1. Write FoxClaw NDJSON to a file.
2. Configure Wazuh `localfile` with `log_format` `json`.
3. Add a minimal local rule matching `event_type` with anchored regex. If the Wazuh rule chain requires it in your environment, chain the rule from the parent JSON/SIEM rule with `if_sid`.
4. Validate the sample with `wazuh-logtest`.
5. Confirm resulting events in `alerts.json` or the dashboard.

Detailed commands are in [WS76_EVIDENCE_2026-02-27.md](/home/steve/apps/FoxClaw/docs/WS76_EVIDENCE_2026-02-27.md).

## Source Links

- [NDJSON spec](https://github.com/ndjson/ndjson-spec)
- [Elastic Filebeat `filestream` input](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-filestream)
- [Wazuh quickstart](https://documentation.wazuh.com/current/quickstart.html)
- [Wazuh `localfile` reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html)
- [Wazuh JSON decoder](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html)
- [Wazuh testing decoders and rules](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html)
- [Wazuh log collection flow](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/how-it-works.html)
