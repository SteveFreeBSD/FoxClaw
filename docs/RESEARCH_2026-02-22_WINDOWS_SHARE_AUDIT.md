# Windows Share Firefox Audit Research - 2026-02-22

This research snapshot defines how FoxClaw should handle Firefox profile auditing from Windows shares in enterprise environments, using primary sources current as of **February 22, 2026**.

## Scope

- Problem: enterprise incident-response and posture workflows often stage user profile data on SMB shares before analysis.
- Goal: define a safe, deterministic, and appliance-grade FoxClaw pattern for remote Firefox profile auditing.
- Constraint alignment: maintain read-only scan semantics and no scan-runtime network activity.

## 2026 Findings (Primary Sources)

### 1) SMB hardening expectations are now stricter by default

- Microsoft documents that modern Windows releases increased SMB signing and encryption defaults in 24H2/Server 2025-era builds.
- SMB over QUIC is available for enterprise/professional workstation tiers and Server 2025, enabling encrypted SMB transport without VPN dependence.

FoxClaw implication:
- Enterprise runbooks should assume signed/encrypted transport for profile shares and enforce least-privilege collector access.

### 2) Firefox profile locations vary across packaging modes

- Mozilla documents default Firefox profile roots under `%APPDATA%\Mozilla\Firefox\Profiles`.
- For MSIX deployments, profile paths differ (`%LOCALAPPDATA%\Packages\Mozilla.Firefox\LocalCache\Roaming\Mozilla\Firefox\Profiles`).
FoxClaw implication:
- Acquisition docs must include both standard and MSIX path variants so share exports do not miss data.

### 3) SQLite consistency constraints make in-place share scanning unsafe

- SQLite guidance states filesystems are not all equally reliable under locking and synchronization semantics; network filesystems are especially risky.
- SQLite explicitly documents corruption hazards when copying live database files while transactions are active.
- WAL mode documentation notes shared-memory requirements and non-support over network filesystems.

FoxClaw implication:
- Do **not** scan live Firefox profiles in place on SMB shares.
- First stage profile contents to local storage, then scan local snapshot copy.

## Recommended FoxClaw Pattern (Enterprise)

1. Acquire profile from SMB/UNC path with transport hardening in place.
2. Fail closed if profile lock markers indicate active browser state unless acquisition snapshot consistency is externally guaranteed.
3. Copy to local staging snapshot and remove write bits in staged copy.
4. Run deterministic FoxClaw scan on staged local copy.
5. Persist JSON/SARIF/snapshot artifacts plus a staging manifest for chain-of-custody.

## Roadmap Impact

- Treat Windows-share acquisition as a first-class operational lane feeding WS-35 (cross-OS corpus growth) and WS-38 (high-risk parser migration).
- Keep acquisition outside scan runtime boundaries to preserve offline and read-only guarantees.

## Source Index

- SMB security hardening (Microsoft): https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening
- SMB security enhancements in Windows Server 2025 / Windows 11 (Microsoft): https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening#smb-security-enhancements
- SMB over QUIC (Microsoft): https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-over-quic
- Robocopy reference (Microsoft): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Firefox profile locations (Mozilla): https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data
- SQLite on network filesystems (SQLite): https://sqlite.org/useovernet.html
- SQLite WAL behavior (SQLite): https://sqlite.org/wal.html
- SQLite corruption hazards (SQLite): https://sqlite.org/howtocorrupt.html
- SQLite locking model (SQLite): https://sqlite.org/lockingv3.html
