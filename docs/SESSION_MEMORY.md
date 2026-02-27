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

- Updated: 2026-02-27T14:30:06.178099+00:00
- Branch: docs/windows-profile-gen
- Commit: `0d92517d8b4f40c5a20ec244ab31e546517d17aa`
- Focus: WS-71: convert validated Python scopes into coherent commit units
- Next: Execute WS-72 mainline merge and Rust branch handoff after rerunning merge-target gates
- Risks: The commit units now exist cleanly on this branch, but Rust work must remain blocked until WS-72 lands the Python baseline on mainline
- Decisions: Created separate Scope A and Scope B commits, closed the docs/evidence queue state in WS-71, and advanced the queue to WS-72 instead of starting Rust work from an unmerged branch

## Recent Checkpoints

### 2026-02-27T14:30:06.178099+00:00
- Branch: docs/windows-profile-gen
- Commit: `0d92517d8b4f40c5a20ec244ab31e546517d17aa`
- Focus: WS-71: convert validated Python scopes into coherent commit units
- Next: Execute WS-72 mainline merge and Rust branch handoff after rerunning merge-target gates
- Risks: The commit units now exist cleanly on this branch, but Rust work must remain blocked until WS-72 lands the Python baseline on mainline
- Decisions: Created separate Scope A and Scope B commits, closed the docs/evidence queue state in WS-71, and advanced the queue to WS-72 instead of starting Rust work from an unmerged branch

### 2026-02-27T14:20:25.021368+00:00
- Branch: docs/windows-profile-gen
- Commit: `8c493de26dc3c0f2cce4c8970b4256d34eff6f4a`
- Focus: WS-70: close Scope C docs/evidence pack and advance queue to merge execution
- Next: Execute WS-71 Python merge execution checkpoint before any Rust branch work
- Risks: Scope sequencing docs are aligned, but the worktree is still mixed until WS-71 converts the validated scope packs into coherent commit/merge units
- Decisions: Resolved WS-70 as docs/evidence reconciliation, marked Scope C complete, added WS-71 as the post-scope merge checkpoint, and kept Rust bootstrap blocked until the Python baseline is merged

### 2026-02-27T14:16:30.083366+00:00
- Branch: docs/windows-profile-gen
- Commit: `8c493de26dc3c0f2cce4c8970b4256d34eff6f4a`
- Focus: WS-69: validate Scope B merge pack and advance queue to Scope C
- Next: Execute WS-70 Scope C merge pack for docs/evidence/queue-control isolation
- Risks: Scope B is validated but the worktree remains mixed until Scope C is isolated; merge remains blocked on finishing the bounded sequencing
- Decisions: Resolved WS-69 as status reconciliation because Scope B behavior was already implemented, recorded gate evidence, marked WS-69 complete, and advanced Current Direction/PREMERGE queue to WS-70

### 2026-02-27T14:13:02.774817+00:00
- Branch: docs/windows-profile-gen
- Commit: `8c493de26dc3c0f2cce4c8970b4256d34eff6f4a`
- Focus: WS-68: validate Scope A merge pack and advance queue to Scope B
- Next: Execute WS-69 Scope B merge pack for matrix/runtime/release hardening isolation
- Risks: Scope A is validated but the worktree is still mixed until Scope B and Scope C are isolated; merge remains blocked on completing that bounded sequencing
- Decisions: Resolved WS-68 as status reconciliation because Scope A behavior was already implemented, recorded focused regression evidence, marked WS-68 complete, and advanced Current Direction/PREMERGE queue to WS-69

### 2026-02-27T14:10:33.689268+00:00
- Branch: docs/windows-profile-gen
- Commit: `8c493de26dc3c0f2cce4c8970b4256d34eff6f4a`
- Focus: WS-67: define bounded merge scopes and advance queue to scope execution slices
- Next: Execute WS-68 Scope A merge pack for threat-surface expansion and generator parity
- Risks: Worktree is still mixed until WS-68/WS-69/WS-70 are executed as bounded scopes; merge remains blocked on that isolation work
- Decisions: Documented three merge scopes in WS67 scope plan, advanced WORKSLICES current direction to WS-68, and updated PREMERGE queue to execute Scope A/B/C before any Rust branch work

### 2026-02-27T14:07:14.311472+00:00
- Branch: docs/windows-profile-gen
- Commit: `8c493de26dc3c0f2cce4c8970b4256d34eff6f4a`
- Focus: WS-66: status reconciliation after Python hardening pass; queue now advances to WS-67
- Next: Execute WS-67 change-set isolation and merge-scope preparation before any merge or Rust branch work
- Risks: Current worktree remains mixed across multiple review scopes; merge sequencing still depends on isolating those changes into bounded commits or PRs
- Decisions: Reconciled WORKSLICES and PREMERGE queue after WS-66 completion, marked WS-66 complete in the queue, and added WS-67 as the next pending Python-first slice

### 2026-02-27T14:04:09.545461+00:00
- Branch: docs/windows-profile-gen
- Commit: `8c493de26dc3c0f2cce4c8970b4256d34eff6f4a`
- Focus: WS-66: Python pre-merge hardening gates and short soak confidence pass
- Next: Isolate mixed in-flight changes into coherent review scopes before any merge; keep Rust deferred until after Python baseline lands
- Risks: Worktree still contains unrelated pending changes across multiple slices; merge should wait for change-set separation even though Python gates are green
- Decisions: Cleared ruff/mypy/detect-secrets blockers, updated SBOM generator pin to cyclonedx-bom 7.2.2 for Python 3.14 compatibility, and confirmed short soak matrix ESR/beta/nightly lanes now pass after bootstrap hardening

### 2026-02-27T13:50:09.777688+00:00
- Branch: docs/windows-profile-gen
- Commit: `8c493de26dc3c0f2cce4c8970b4256d34eff6f4a`
- Focus: WS-65: restore Python as canonical merge target and defer Rust bootstrap to dedicated branch
- Next: Execute WS-66 Python pre-merge hardening gates and short soak confidence pass
- Risks: Current worktree still contains unrelated in-flight changes; WS-66 should separate hardening evidence from unrelated edits before any merge decision
- Decisions: Updated WORKSLICES/PREMERGE_READINESS/ROADMAP so mainline stays Python-first, added WS-65 complete and WS-66 pending, and deferred WS-31/WS-32 to a dedicated Rust branch after Python validation

### 2026-02-27T02:39:48.787983+00:00
- Branch: docs/windows-profile-gen
- Commit: `8c493de26dc3c0f2cce4c8970b4256d34eff6f4a`
- Focus: WS-54: CVE advisory simulation scenarios in Python/Windows generators with round-trip rule verification
- Next: Execute WS-31 Rust workspace bootstrap slice
- Risks: Windows mutator round-trip tests are dependency-gated on Node better-sqlite3 and will skip when unavailable; CVE scenario mappings currently target strict ruleset IDs only
- Decisions: Implemented deterministic per-scenario artifact writers for WS-47..WS-53 triggers, added explicit expected strict rule-ID mappings, and captured finding IDs from scan payload using finding.id with rule_id fallback

### 2026-02-27T01:58:56.246537+00:00
- Branch: docs/windows-profile-gen
- Commit: `8c493de26dc3c0f2cce4c8970b4256d34eff6f4a`
- Focus: WS-53: HSTS integrity collector and downgrade/removal rule coverage
- Next: Execute WS-54 CVE advisory simulation scenarios slice when requested
- Risks: HSTS critical-domain baseline currently derives from HTTPS history hosts in places.sqlite and may under-signal when history is incomplete; registrable-domain heuristics for selective deletion are intentionally conservative and may need future eTLD-aware tuning
- Decisions: Parse SiteSecurityServiceState.txt with deterministic tab-delimited handling, infer critical-domain expectations from local HTTPS history only, and emit downgrade signals via hsts_downgrade_absent using serialized suspicious_hsts_state_entries

### 2026-02-27T01:50:15.685054+00:00
- Branch: docs/windows-profile-gen
- Commit: `8c493de26dc3c0f2cce4c8970b4256d34eff6f4a`
- Focus: WS-52: cookie security posture collector and DSL/rules coverage
- Next: Execute WS-53 HSTS state integrity slice when requested
- Risks: Cookie sensitive-domain/tracker heuristics may need threshold tuning for edge enterprise environments; moz_cookies schema drift without expected columns currently yields zero posture signals
- Decisions: Use deterministic cookie lifetime checks from creationTime-to-expiry deltas, enforce excessive tracker threshold at >10 known third-party cookies, and surface rule evidence from serialized suspicious_cookie_security_signals

### 2026-02-27T01:41:21.973166+00:00
- Branch: docs/windows-profile-gen
- Commit: `b961ca14104a1657c854acd18d370412317d2ebd`
- Focus: WS-51: search engine integrity validation for search.json.mozlz4
- Next: Execute WS-52 cookie security posture slice when requested
- Risks: Compressed mozlz4 payload support remains optional via lz4.block; fully compressed captures may need expanded decoding support in environments without lz4
- Decisions: Audit default search engine via deterministic allowlists for engine names/domains, surface suspicious defaults through artifact metadata, and enforce with search_engine_hijack_absent in balanced/strict rules

### 2026-02-27T01:35:20.884530+00:00
- Branch: docs/windows-profile-gen
- Commit: `89a0a021d2d5e46563f534c35a96984527c026a1`
- Focus: WS-50: sessionstore data exposure detection and rules
- Next: Execute WS-51 search engine integrity slice when requested
- Risks: Compressed Mozilla LZ4 payload parsing uses optional lz4.block; environments without it rely on plain/header JSON handling and may need follow-on support for fully compressed captures
- Decisions: Audit sessionstore.jsonlz4 deterministically, require both restore-enabled and sensitive entries for findings, and expose session-sensitive metadata via artifacts and session_restore_sensitive_data_absent rules

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
