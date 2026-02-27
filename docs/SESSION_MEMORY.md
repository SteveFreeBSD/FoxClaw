# Session Memory

Persistent handoff context between sessions.

## Usage

```bash
python scripts/session_memory.py show
python scripts/session_memory.py checkpoint \
  --focus "<what changed>" \
  --next "<next action>"
```

## Current Snapshot

- Updated: 2026-02-27T01:16:45.592292+00:00
- Branch: docs/windows-profile-gen
- Commit: `70b7e01fecb045a273eb7e99a456472937d27f67`
- Focus: WS-49: PKCS#11 module injection detection with path validation
- Next: Execute WS-50 session restore data exposure slice when requested
- Risks: PKCS#11 validation currently uses deterministic path heuristics; deeper module signature/vendor validation may be needed for broader environment coverage
- Decisions: Parse pkcs11.txt into deterministic module records, classify non-standard library paths as suspicious, and enforce with pkcs11_module_injection_absent rules in balanced/strict

## Recent Checkpoints

### 2026-02-27T01:16:45.592292+00:00
- Branch: docs/windows-profile-gen
- Commit: `70b7e01fecb045a273eb7e99a456472937d27f67`
- Focus: WS-49: PKCS#11 module injection detection with path validation
- Next: Execute WS-50 session restore data exposure slice when requested
- Risks: PKCS#11 validation currently uses deterministic path heuristics; deeper module signature/vendor validation may be needed for broader environment coverage
- Decisions: Parse pkcs11.txt into deterministic module records, classify non-standard library paths as suspicious, and enforce with pkcs11_module_injection_absent rules in balanced/strict

### 2026-02-27T01:07:05.199002+00:00
- Branch: docs/windows-profile-gen
- Commit: `167e618b940307d29ffb37ba5081089a727c2235`
- Focus: WS-48: cert9.db rogue root CA detection collector and rules
- Next: Execute WS-49 PKCS#11 module injection detection when requested
- Risks: Current cert9 parsing relies on NSS fallback table shape and heuristics; deeper PKCS#11 attribute decoding may be needed for broader real-world trust metadata
- Decisions: Use deterministic read-only cert9 audit with static recent-issuance reference date, encode suspicious roots into artifact metadata, and enforce via rogue_root_ca_absent in balanced/strict rules

### 2026-02-27T00:55:00.854517+00:00
- Branch: docs/windows-profile-gen
- Commit: `895bda51ca8e306b90c7ab1f39a43532bf93a3e9`
- Focus: WS-47: protocol handler hijack detection via handlers.json and rules
- Next: Execute WS-48 NSS certificate store audit when requested
- Risks: Handler rule currently keys off handlers.json artifact metadata; deeper executable provenance/path trust checks may require follow-on refinement
- Decisions: Detect ask=false handlers in schemes map with local executable suffixes, persist deterministic suspicious handler metadata in artifacts, enforce via protocol_handler_hijack_absent rules

### 2026-02-27T00:42:21.046729+00:00
- Branch: docs/windows-profile-gen
- Commit: `696c21f61ed3a061b80f8e956a23fdd4917ab1c7`
- Focus: WS-56: fleet prevalence/correlation enrichment completed
- Next: Execute WS-47 protocol handler hijack detection slice when requested
- Risks: Fleet prevalence fields currently live in learning artifact; broader scan/fleet contract exposure may require a follow-on slice
- Decisions: Use latest snapshot per profile for fleet aggregation, threshold 0.2 for outlier elevation, deterministic sorted pairwise Jaccard correlations

### 2026-02-27T00:27:07.352594+00:00
- Branch: docs/windows-profile-gen
- Commit: `696c21f61ed3a061b80f8e956a23fdd4917ab1c7`
- Focus: WS-56: fleet prevalence/correlation enrichment in learning history artifact
- Next: Update WS-56 status in docs and begin next Current Direction slice only when requested
- Risks: Future integration may need surfacing fleet_prevalence into scan/fleet JSON contracts beyond learning artifact
- Decisions: Use latest-snapshot-per-profile fleet aggregation, prevalence threshold 0.2 for outlier elevation, deterministic pairwise jaccard correlations

### 2026-02-27T00:17:54.275736+00:00
- Branch: docs/windows-profile-gen
- Commit: `e47bbe7be30cf283a0a2fbec82953c834306236e`
- Focus: AGENTS.md hardening for repo flow + cross-session memory
- Next: Execute WS-56 using Current Direction with memory recall loop
- Risks: PREMERGE_READINESS queue text can lag WORKSLICES and cause planning drift
- Decisions: Use docs/INDEX precedence, bootstrap with session_memory show, and reconcile already-implemented slices via status updates

### 2026-02-27T00:04:53.951969+00:00
- Branch: docs/windows-profile-gen
- Commit: `e47bbe7be30cf283a0a2fbec82953c834306236e`
- Focus: WS-55B: reconcile workslice status with implemented trend/novelty logic
- Next: Start WS-56: fleet prevalence/correlation enrichment with deterministic aggregation queries
- Risks: WS-56 may require schema extension and careful ordering guarantees across profiles
- Decisions: Treat WS-55B as complete based on existing implementation/tests; update source-of-truth workslice statuses and focus

### 2026-02-26T23:54:52.648175+00:00
- Branch: docs/windows-profile-gen
- Commit: `09726cde90411e04635561a83d36262a01f6eae3`
- Focus: WS-55B: per-rule trend/novelty analysis from history snapshots
- Next: Implement WS-56: fleet-wide correlation and prevalence enrichment
- Risks: WS-56 may require schema extension for fleet aggregation fields
- Decisions: trend_direction from last two snapshots; novelty_score from prior_hits/prior_scans; stable ordering by rule_id

### 2026-02-26T21:38:29.766395+00:00
- Branch: docs/windows-profile-gen
- Commit: `34f637cbbdacc1b1d6e610f862581266e6f56038`
- Focus: Integrated session-memory and mistakes-hygiene gates into certify/CI/docs
- Next: Run full gate suite and publish workflow tips
- Risks: Strict hygiene checks may need occasional [no-mistake-entry] bypass
- Decisions: Track journal in docs/SESSION_MEMORY.jsonl so context persists across sessions
