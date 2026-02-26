# FoxClaw Roadmap Update: The Behavioral Injection Acceleration (2026)

*Draft prepared following the Ultimate 8h Soak (2026-02-24) and the successful integration of the v4.0.0 `better-sqlite3` hybrid profile generator.*

## 1. Executive Summary

The 8-hour deep soak proved the FoxClaw `scan` engine is deterministic, stable, and highly performant (consuming only ~3.8% of pipeline runtime). However, the legacy Python profile generators were bottlenecking the pipeline and over-emphasizing structural parser corruption (e.g., SQLite `quick_check` failures) rather than realistic security posture degradation. 

The successful deployment of the v4.0.0 Node.js direct-injection generator proved that **Direct SQLite Behavioral Injection** is the superior path forward. By writing directly to `places.sqlite`, `permissions.sqlite`, and NSS stores (`cert9.db`), we bypass modern browser App-Bound Encryption and network orchestration flakiness. The result is a 100x speedup in profile generation, producing 100% mathematically valid SQLite databases that trigger rich, behavior-based security findings.

To make FoxClaw a bleeding-edge, appliance-grade security tool in 2026, we are accelerating the immediate roadmap to lean heavily into this behavioral injection architecture, fast-tracking our integration with modern SIEM data lakes via OCSF, and adopting MITRE ATT&CK v18 detection analytics.

## 2. Workslice Revisions & New Guidance

### Rebalance WS-21: Controlled Mutation Engine
**Old Goal:** Corrupt profile artifacts to test parser resilience.
**New Guidance (2026):** Transition all Python fuzzers to App-Bound Encryption-aware direct SQLite injection. Ensure fuzzing creates valid schemas with adversarial data (e.g., malicious URL histories, altered privacy preferences) instead of structural corruption. This aligns with modern 2026 live-forensic techniques where dead-box imaging is obsolete.

### Accelerate WS-35: Cross-OS Profile Corpus Expansion
**Current Status:** Pending.
**New Guidance:** Instantly unblock this by wrapping the cross-platform `mutate_profile.mjs` script for macOS and Linux. Generate a massive, deterministic, highly-diverse corpus of behavioral profiles *now* so they are ready to serve as the undisputed ground-truth fixtures when the Rust `foxclaw-rs` port (WS-38/39) begins. 

### Redefine WS-54: CVE Advisory Simulation Scenarios
**Current Status:** Pending.
**New Guidance:** Ban all UI-level browser orchestration (e.g., Playwright) for generating CVE scenarios. All CVE simulations (like Session Hijacking or Certificate Injection) MUST be implemented using direct SQLite and NSS API manipulation. For example, to simulate T1553.004 (Install Root Certificate), inject the rogue certificate directly into `cert9.db`. This guarantees deterministic, network-free adversary emulation perfectly suited for offline CI pipelines.

### Pull Forward WS-55B & WS-56: Adaptive Scan Intelligence 
**Current Status:** Dependent on previous stages.
**New Guidance:** Because the v4.0.0 generator is successfully producing clean, high-fidelity security signals (triggering exact rule matches without false-positive parser noise), the data is ready *now*. Immediately begin building the append-only SQLite local history store to track fleet prevalence, finding novelty, and trend directions across the enterprise.

## 3. Threat-Context and Integration (2026 Industry Alignment)

### OCSF Alignment (WS-41 Expansion)
The 2026 cybersecurity landscape has standardized on the Open Cybersecurity Schema Framework (OCSF) to normalize data across tools and eliminate custom SPL/integration overhead. FoxClaw must prioritize emitting its JSON outputs natively mapped to the **OCSF v1.3+ Cybersecurity Schema**. This positions FoxClaw as a zero-ETL integration for modern data lakes like SentinelOne, Splunk, and AWS Security Lake.

### MITRE ATT&CK v18+ Alignment (WS-33 Expansion)
Align all ruleset mappings with the MITRE ATT&CK v18 (October 2025) framework and the 2026 Detection Strategies model. Critically, ensure coverage for newly categorized techniques such as **Masquerading: Browser Fingerprint (v1.0)**, and map FoxClaw's behavioral insights to MITRE's latest AI-driven threat and cloud-native detection analytics parameters.

## Conclusion
This evolution abandons flaky, network-dependent browser orchestration in favor of surgical, forensic-grade database injection. It stabilizes the test corpus for the upcoming Rust migration while accelerating FoxClaw's journey into a standalone, OCSF-compliant security analytics appliance.
