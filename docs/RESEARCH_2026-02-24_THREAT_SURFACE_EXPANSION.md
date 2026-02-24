# Research: Threat Surface Expansion (2026-02-24)

## Objective

Identify Firefox profile artifact attack surfaces that FoxClaw does not yet cover, map them to real-world CVEs and ATT&CK techniques, and design a self-learning feedback loop that makes FoxClaw smarter with every scan — all while preserving offline-by-default, deterministic scan behavior.

## Method

- Gap analysis of FoxClaw's existing 8 collectors against the full Firefox profile artifact inventory.
- Online research of Firefox security advisories (2025–2026) and MITRE ATT&CK browser techniques.
- Cross-reference with existing FoxClaw research docs and workslice history.

## Part 1: Firefox Profile Artifact Gap Analysis

### Currently Covered

| Artifact | Collector | What It Detects |
|---|---|---|
| `prefs.js` / `user.js` | `collect/prefs.py` | Risky preference settings, policy drift |
| `logins.json` | `collect/credentials.py` | Saved credential exposure, master password absence |
| `extensions.json` / `addons/*.xpi` | `collect/extensions.py` | Permission risk, blocklist, AMO reputation, sideload posture |
| `policies.json` | `collect/policies.py` | Enterprise policy surface compliance |
| `places.sqlite` / `favicons.sqlite` | `collect/artifacts.py` | Profile structure validation |
| `compatibility.ini` | `collect/artifacts.py` | Firefox version extraction for CVE correlation |
| Profile lock markers | `collect/filesystem.py` | Active profile detection |
| SQLite integrity | `collect/sqlite.py` | Database corruption detection |

### Not Yet Covered (Gaps)

| Artifact | Attack Surface | Risk Level | ATT&CK Technique |
|---|---|---|---|
| `handlers.json` | Protocol handler hijacking → local code execution | Critical | T1204 (User Execution) |
| `cert9.db` | Rogue root CA injection → MitM on all HTTPS traffic | Critical | T1553.004 (Install Root Certificate) |
| `key4.db` | Master key theft → offline credential decryption | Critical | T1555.003 (Credentials from Web Browsers) |
| `pkcs11.txt` | PKCS#11 DLL injection → arbitrary code execution in Firefox process | Critical | T1129 (Shared Modules) |
| `sessionstore.jsonlz4` | Session replay → form data, auth tokens, active sessions | High | T1005 (Data from Local System) |
| `search.json.mozlz4` | Search engine hijacking → query interception, phishing redirect | Medium | T1583.001 (Acquire Infrastructure) |
| `cookies.sqlite` | Session cookie theft, tracking, SameSite bypass | High | T1539 (Steal Web Session Cookie) |
| `SiteSecurityServiceState.txt` | HSTS downgrade → force HTTP for targeted domains | High | T1557 (Adversary-in-the-Middle) |
| `content-prefs.sqlite` | Overly permissive site permissions (camera, mic, geolocation) | Medium | T1119 (Automated Collection) |
| `addonStartup.json.lz4` | Sideloaded extension persistence metadata | High | T1176 (Browser Extensions) |

## Part 2: Firefox CVE Landscape (2025–2026)

### Actively Exploited in the Wild

| CVE | Date | Type | Notes |
|---|---|---|---|
| CVE-2025-4918 | May 2025 | OOB access (Pwn2Own zero-day) | Read/write on JS objects → arbitrary code execution |
| CVE-2025-4919 | May 2025 | OOB access (Pwn2Own zero-day) | Same class as CVE-2025-4918 |
| CVE-2025-2857 | Mar 2025 | Sandbox escape (Windows IPC) | Similar to Chrome zero-day CVE-2025-2783 |

### Critical but Not Yet Exploited

| CVE | Date | Type | CVSS | Notes |
|---|---|---|---|---|
| CVE-2025-13016 | Nov 2025 | WASM GC pointer corruption | Critical | 180M users affected, unnoticed for 6 months |
| CVE-2025-13027 | Nov 2025 | Memory safety bugs | Critical | Firefox 145 batch fix |
| CVE-2025-13021–13026 | Nov 2025 | WebGPU sandbox escapes | High | Multiple vectors for sandbox escape |
| CVE-2025-14321 | Dec 2025 | Use-after-free | Critical | Firefox 146 |
| CVE-2025-14322 | Dec 2025 | Sandbox escape | Critical | Firefox 146 |
| CVE-2025-14324–14325 | Dec 2025 | JIT miscompilation | Critical | Firefox 146 |
| CVE-2026-0881 | Jan 2026 | Sandbox escape (Messaging System) | **10.0** | Highest severity possible |
| CVE-2026-0879 | Jan 2026 | Sandbox escape (boundary conditions) | Critical | |
| CVE-2026-0884 | Jan 2026 | Use-after-free (JS Engine) | Critical | |
| CVE-2026-2447 | Feb 2026 | Heap buffer overflow (libvpx) | Critical | Malicious video → RCE |

### Implications for FoxClaw

- Version correlation (existing WS-07/WS-08) is the primary defense against these.
- FoxClaw should detect **post-exploitation artifacts**: modified `prefs.js` enabling remote debugging, injected PKCS#11 modules, rogue certificates, and suspicious protocol handlers are the forensic evidence left behind after a sandbox escape or privilege escalation.
- The new collectors (WS-47 through WS-53) are specifically designed to catch these post-exploitation signals.

## Part 3: ATT&CK Technique Coverage Matrix

### Current Coverage (After WS-33 completion)

| ATT&CK ID | Technique Name | FoxClaw Coverage |
|---|---|---|
| T1176 | Browser Extensions | ✅ Extensions collector + blocklist + AMO reputation |
| T1555.003 | Credentials from Web Browsers | ✅ Credentials collector + logins.json |
| T1217 | Browser Information Discovery | Partial (version/profile metadata) |

### Proposed Additions (WS-47 through WS-53)

| ATT&CK ID | Technique Name | New Collector | Workslice |
|---|---|---|---|
| T1204 | User Execution | `handlers.py` | WS-47 |
| T1553.004 | Install Root Certificate | `certificates.py` | WS-48 |
| T1129 | Shared Modules | `pkcs11.txt` parser | WS-49 |
| T1005 | Data from Local System | `session.py` | WS-50 |
| T1583.001 | Acquire Infrastructure | `search.py` | WS-51 |
| T1539 | Steal Web Session Cookie | `cookies.py` | WS-52 |
| T1557 | Adversary-in-the-Middle | HSTS parser | WS-53 |
| T1185 | Browser Session Hijacking | `session.py` + `cookies.py` | WS-50/WS-52 |
| T1119 | Automated Collection | `content-prefs.sqlite` | WS-52 |

## Part 4: Self-Learning Architecture

### Design Principles

1. **Deterministic**: Given identical inputs + identical history state, results are identical.
2. **Offline**: No network calls. History is local SQLite.
3. **Append-only**: Scan history is never modified, only appended.
4. **Optional**: Self-learning enrichment is controlled by explicit CLI flags.
5. **Transparent**: All learning-derived metadata is clearly labeled in outputs.

### Architecture

```
                          ┌─────────────────┐
                          │  foxclaw scan    │
                          │  (deterministic) │
                          └────────┬────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼               ▼
            ┌─────────────┐ ┌───────────┐ ┌──────────────┐
            │  Collectors  │ │   Rules   │ │ Intel Store  │
            │  (read-only) │ │   (DSL)   │ │ (snapshots)  │
            └──────┬──────┘ └─────┬─────┘ └──────┬───────┘
                   │              │               │
                   └──────────────┼───────────────┘
                                  ▼
                          ┌───────────────┐
                          │   Findings     │
                          └───────┬───────┘
                                  │
                    ┌─────────────┼─────────────┐
                    ▼                           ▼
            ┌──────────────┐          ┌──────────────────┐
            │ JSON / SARIF │          │  History DB       │
            │ (output)     │          │  (append-only)    │
            └──────────────┘          └────────┬─────────┘
                                               │
                                    ┌──────────┴──────────┐
                                    ▼                     ▼
                            ┌─────────────┐      ┌──────────────┐
                            │ Trend Engine │      │ Novelty      │
                            │ (optional)   │      │ Detection    │
                            └─────────────┘      └──────────────┘
```

### History Database Schema

```sql
CREATE TABLE scan_history (
    id              INTEGER PRIMARY KEY,
    scan_id         TEXT NOT NULL UNIQUE,
    profile_uid     TEXT NOT NULL,
    scanned_at_utc  TEXT NOT NULL,
    firefox_version TEXT,
    finding_count   INTEGER NOT NULL,
    high_count      INTEGER NOT NULL,
    medium_count    INTEGER NOT NULL,
    low_count       INTEGER NOT NULL,
    rule_ids_json   TEXT NOT NULL,        -- JSON array of triggered rule IDs
    profile_hash    TEXT NOT NULL          -- hash of profile shape for similarity
);

CREATE TABLE finding_history (
    id              INTEGER PRIMARY KEY,
    scan_id         TEXT NOT NULL REFERENCES scan_history(scan_id),
    rule_id         TEXT NOT NULL,
    severity        TEXT NOT NULL,
    evidence_hash   TEXT NOT NULL,
    first_seen_scan TEXT,                  -- earliest scan_id where this exact finding appeared
    UNIQUE(scan_id, rule_id, evidence_hash)
);
```

### Enrichment Fields (added to JSON/SARIF output)

- `trend_direction`: `improving` | `stable` | `degrading` | `new_profile`
- `first_seen_at`: ISO timestamp of earliest scan containing this finding
- `novelty_score`: `0.0` (seen in every scan) to `1.0` (never seen before)
- `fleet_prevalence`: percentage of scanned profiles with this finding (fleet mode only)

## Part 5: CVE Simulation Scenarios for Testbed

### New Scenarios for `mutate_profile.mjs` and `adversary_profiles.py`

| Scenario Name | What It Simulates | Expected FoxClaw Detection |
|---|---|---|
| `cve_sandbox_escape` | Post-exploitation: remote debugging prefs enabled, suspicious PKCS#11 entry | WS-49 PKCS#11 + prefs rules |
| `cve_extension_abuse` | Sideloaded extension with `nativeMessaging` + `<all_urls>` | Extension collector flags |
| `cve_session_hijack` | Active session cookies + session restore with auth tokens | WS-50 + WS-52 |
| `cve_cert_injection` | Rogue root CA in `cert9.db` | WS-48 certificate audit |
| `cve_handler_hijack` | Malicious protocol handler → `cmd.exe` | WS-47 handler check |
| `cve_hsts_downgrade` | Missing HSTS entries for banking/corporate domains | WS-53 HSTS integrity |
| `cve_search_hijack` | Default search engine changed to attacker domain | WS-51 search integrity |

## External References

### Firefox-Specific
- Mozilla Security Advisories: https://www.mozilla.org/en-US/security/advisories/
- Firefox Enterprise Policy Templates: https://mozilla.github.io/policy-templates/
- Firefox Profile Artifact Reference: https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile
- NSS Shared DB: https://nss-crypto.org/reference/security/nss/legacy/reference/nss_tools__colon__certutil/index.html
- Extension Permission Model: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/permissions
- AMO Blocklist: https://mozilla.github.io/addons-server/topics/blocklist.html

### ATT&CK Techniques
- T1176 Browser Extensions: https://attack.mitre.org/techniques/T1176/
- T1555.003 Credentials from Web Browsers: https://attack.mitre.org/techniques/T1555/003/
- T1539 Steal Web Session Cookie: https://attack.mitre.org/techniques/T1539/
- T1553.004 Install Root Certificate: https://attack.mitre.org/techniques/T1553/004/
- T1185 Browser Session Hijacking: https://attack.mitre.org/techniques/T1185/
- T1204 User Execution: https://attack.mitre.org/techniques/T1204/
- T1129 Shared Modules: https://attack.mitre.org/techniques/T1129/
- T1005 Data from Local System: https://attack.mitre.org/techniques/T1005/
- T1557 Adversary-in-the-Middle: https://attack.mitre.org/techniques/T1557/
- T1217 Browser Information Discovery: https://attack.mitre.org/techniques/T1217/

### Vulnerability Intelligence
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- NVD API: https://nvd.nist.gov/developers/vulnerabilities
- EPSS: https://www.first.org/epss
- CVE Program: https://github.com/CVEProject/cvelistV5

### Forensics and Detection
- OpenWPM: https://github.com/openwpm/OpenWPM
- Firefox Password Manager: https://support.mozilla.org/en-US/kb/password-manager-remember-delete-edit-logins
