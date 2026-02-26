# CLI Contract

This document is the canonical command/exit/artifact contract for FoxClaw CLI behavior.

## Global Exit Codes

- `0`: success with no high-severity signal condition.
- `1`: operational/configuration/runtime error.
- `2`: high-signal result (for commands that encode findings/drift/governance violations).

Source anchors:
- exit code constants (`foxclaw/cli.py:38-40`)
- command-specific overrides (`foxclaw/cli.py:438-449`, `foxclaw/cli.py:659-661`, `foxclaw/cli.py:1054-1056`, `foxclaw/cli.py:1104-1105`, `foxclaw/cli.py:1254-1256`, `foxclaw/acquire/windows_share_batch.py:330-334`)

## Command Contracts

| Command | Key Flags | Exit Contract | Artifacts / Outputs | Determinism Contract |
|---|---|---|---|---|
| `foxclaw profiles list` | none | `0` on success | terminal table only | sorted by profile id (`foxclaw/cli.py:78`) |
| `foxclaw scan` | `--profile`, `--ruleset`, `--output`, `--sarif-out`, `--snapshot-out`, `--history-db`, `--learning-artifact-out` | `0` clean, `1` operational, `2` high findings | JSON/SARIF/snapshot files and optional learning artifact | deterministic ordering in renderers; timestamps volatile unless deterministic mode or pinned inputs (`foxclaw/report/jsonout.py:10-13`, `foxclaw/report/sarif.py:25-40`, `foxclaw/report/snapshot.py:49-81`) |
| `foxclaw live` | `--source` (repeatable), scan-like output flags | mirrors scan result (`0/1/2`) | same as scan | sync then pinned scan (`foxclaw/cli.py:544-560`) |
| `foxclaw acquire windows-share-scan` | `--source-profile`, `--staging-root`, `--output-dir`, `--treat-high-findings-as-success` | returns scan code (`0`/`2`) or `1` for operational errors; optional normalization of `2 -> 0` | `foxclaw.json`, `foxclaw.sarif`, `foxclaw.snapshot.json`, `stage-manifest.json` | deterministic staged manifest shape and explicit command capture |
| `foxclaw acquire windows-share-batch` | `--source-root`, `--staging-root`, `--out-root`, `--workers`, `--profile-timeout-seconds` | `1` if any operational failure, else `2` if findings present, else `0` | `windows-share-batch-summary.json` plus per-profile output directories | summary sorted by profile (`foxclaw/acquire/windows_share_batch.py:308-334`) |
| `foxclaw fleet aggregate` | repeatable `--profile`, `--output` or `--json` | `0` clean, `1` operational, `2` if any high finding in aggregate | fleet JSON payload | profiles and finding records sorted (`foxclaw/report/fleet.py:68-81`) |
| `foxclaw snapshot diff` | `--before`, `--after`, `--json`/`--output` | `0` no drift, `1` operational, `2` drift | snapshot diff JSON + optional terminal summary | deterministic added/removed/changed ordering, duplicate finding IDs fail closed |
| `foxclaw intel sync` | repeatable `--source`, `--store-dir`, `--allow-insecure-http`, `--output`/`--json` | `0` success, `1` operational | synced intel manifest and source artifacts under store | source specs sorted by name; normalized JSON optional and deterministic by default |
| `foxclaw suppression audit` | repeatable `--suppression-path`, optional `--json` | `2` when expired entries or duplicate IDs, else `0`; `1` on load/validation errors | governance audit JSON or terminal summary | JSON output uses sorted keys |
| `foxclaw bundle fetch` | bundle URL, `--output` | `0` success, `1` operational | downloaded archive | transport safety and path checks fail closed in helper |
| `foxclaw bundle install` | archive path, `--keyring`, `--key-id`, `--dest` | `0` success, `1` operational | verified unpacked bundle | signature verification is mandatory/fail-closed |
| `foxclaw bundle verify` | archive path, `--keyring`, `--key-id` | `0` success, `1` operational | verification-only terminal output | verification runs strictly without install side-effects |

## Determinism Rules

- Output ordering is deterministic for identical inputs and pinned snapshots.
- `scan` remains offline-by-default; network calls are confined to explicit intel sync paths.
- Timestamp and host metadata fields are environment/time dependent unless deterministic mode/pinned inputs are used.

## Verification Commands

- `python -m foxclaw --help`
- `rg -n "@.*command\(" foxclaw/cli.py`
- `pytest -q tests/test_cli_exit_codes.py tests/test_determinism.py`
