#!/usr/bin/env bash
# --------------------------------------------------------------------------
# firefox_container_demo.sh — "Red Profile" Demo
#
# Generates a deliberately insecure Firefox profile inside a container
# and runs a FoxClaw scan against it with the STRICT ruleset to
# demonstrate all detection capabilities.
#
# Expected result: 9 HIGH findings across 5 categories, exit code 2.
# --------------------------------------------------------------------------
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/firefox_container_demo.sh [--python <python-bin>] [--firefox <firefox-bin>] [--profile-dir <dir>] [--output-dir <dir>]

Generates an intentionally insecure Firefox profile and runs FoxClaw
with the strict ruleset to demonstrate all detection categories.
EOF
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="python"
FIREFOX_BIN="firefox"
PROFILE_DIR="/tmp/foxclaw-demo-profile"
OUTPUT_DIR="/tmp/foxclaw-demo-artifacts"
RULESET_PATH="foxclaw/rulesets/strict.yml"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --python)   PYTHON_BIN="${2:-}"; shift 2 ;;
    --firefox)  FIREFOX_BIN="${2:-}"; shift 2 ;;
    --profile-dir) PROFILE_DIR="${2:-}"; shift 2 ;;
    --output-dir)  OUTPUT_DIR="${2:-}"; shift 2 ;;
    -h|--help)  usage; exit 0 ;;
    *)          echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "${PYTHON_BIN}" || -z "${FIREFOX_BIN}" ]]; then
  echo "error: --python and --firefox require values." >&2
  exit 2
fi
command -v "${PYTHON_BIN}" >/dev/null 2>&1 || { echo "error: python not found: ${PYTHON_BIN}" >&2; exit 2; }
command -v "${FIREFOX_BIN}" >/dev/null 2>&1 || { echo "error: firefox not found: ${FIREFOX_BIN}" >&2; exit 2; }

cd "${ROOT_DIR}"
rm -rf "${PROFILE_DIR}" "${OUTPUT_DIR}"
mkdir -p "${PROFILE_DIR}" "${OUTPUT_DIR}"

# ── Step 1: Launch Firefox headless to create a real profile ──────────
echo "[demo] Launching Firefox headless to generate profile..."
firefox_log="${OUTPUT_DIR}/firefox-headless.log"
firefox_exit=0
if command -v timeout >/dev/null 2>&1; then
  timeout 45s "${FIREFOX_BIN}" --headless --no-remote --profile "${PROFILE_DIR}" about:blank >"${firefox_log}" 2>&1 || firefox_exit=$?
  if [[ "${firefox_exit}" -ne 0 && "${firefox_exit}" -ne 124 ]]; then
    echo "error: firefox headless launch failed (exit=${firefox_exit})." >&2
    cat "${firefox_log}" >&2 || true
    exit "${firefox_exit}"
  fi
else
  "${FIREFOX_BIN}" --headless --no-remote --profile "${PROFILE_DIR}" about:blank >"${firefox_log}" 2>&1 || firefox_exit=$?
  if [[ "${firefox_exit}" -ne 0 ]]; then
    echo "error: firefox headless launch failed (exit=${firefox_exit})." >&2
    cat "${firefox_log}" >&2 || true
    exit "${firefox_exit}"
  fi
fi

if [[ ! -f "${PROFILE_DIR}/prefs.js" ]]; then
  echo "error: firefox did not create prefs.js." >&2
  cat "${firefox_log}" >&2 || true
  exit 1
fi
echo "[demo] Profile created at ${PROFILE_DIR}"

# ── Step 2: Inject weak user.js preferences ───────────────────────────
# Triggers: FC-STRICT-PREF-002 (content blocking = standard)
# FC-STRICT-PREF-001 fires because datareporting.healthreport.uploadEnabled is never set.
cat > "${PROFILE_DIR}/user.js" <<'JS'
// Deliberately weak settings for FoxClaw demo
user_pref("browser.contentblocking.category", "standard");
JS
echo "[demo] Injected weak user.js (content blocking = standard)"

# ── Step 3: Weaken file permissions ───────────────────────────────────
# Triggers: FC-STRICT-FILE-001 (key4.db) and FC-STRICT-FILE-002 (cookies)
# Create key4.db if Firefox didn't
touch "${PROFILE_DIR}/key4.db"
chmod 644 "${PROFILE_DIR}/key4.db"
echo "[demo] key4.db set to 0644 (world-readable)"

# ── Step 4: Corrupt places.sqlite ─────────────────────────────────────
# Triggers: FC-STRICT-SQL-001
echo "THIS IS NOT A VALID SQLITE DATABASE" > "${PROFILE_DIR}/places.sqlite"
echo "[demo] places.sqlite corrupted with junk data"

# ── Step 5: Create + weaken cookies.sqlite ────────────────────────────
# Triggers: FC-STRICT-SQL-002 (corrupt) AND FC-STRICT-FILE-002 (permissions)
echo "THIS IS NOT A VALID SQLITE DATABASE" > "${PROFILE_DIR}/cookies.sqlite"
chmod 644 "${PROFILE_DIR}/cookies.sqlite"
echo "[demo] cookies.sqlite corrupted and set to 0644"

# ── Step 6: Inject a fake unsigned extension with dangerous permissions
# Triggers: FC-STRICT-EXT-001 (unsigned) and FC-STRICT-EXT-002 (high-risk perms)
"${PYTHON_BIN}" - <<'PY' "${PROFILE_DIR}"
import json
import sys
from pathlib import Path

profile = Path(sys.argv[1])

# Create the extension directory structure
ext_id = "totally-not-malware@evil.example"
ext_dir = profile / "extensions" / ext_id
ext_dir.mkdir(parents=True, exist_ok=True)

# Write a manifest with dangerous permissions
manifest = {
    "manifest_version": 2,
    "name": "Totally Not Malware",
    "version": "6.6.6",
    "description": "A suspiciously powerful extension for demo purposes",
    "permissions": [
        "<all_urls>",
        "webRequest",
        "webRequestBlocking",
        "cookies",
        "tabs",
        "history",
        "downloads",
    ],
}
(ext_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

# Inject into extensions.json (create or patch)
extensions_path = profile / "extensions.json"
if extensions_path.exists():
    ext_data = json.loads(extensions_path.read_text(encoding="utf-8"))
else:
    ext_data = {"schemaVersion": 35, "addons": []}

ext_data["addons"].append({
    "id": ext_id,
    "type": "extension",
    "name": "Totally Not Malware",
    "version": "6.6.6",
    "active": True,
    "visible": True,
    "userDisabled": False,
    "signedState": 0,
    "location": "app-profile",
    "path": str(ext_dir),
    "defaultLocale": {"name": "Totally Not Malware"},
})

extensions_path.write_text(json.dumps(ext_data, indent=2), encoding="utf-8")
print("[demo] Injected unsigned extension: 'Totally Not Malware' with 7 dangerous permissions")
PY

# ── Step 7: No policy file — deliberately omitted ────────────────────
# Triggers: FC-STRICT-POLICY-001 (no DisableTelemetry in policies)
echo "[demo] No enterprise policies.json (intentionally omitted)"

echo ""
echo "=============================================="
echo "  RED PROFILE READY — Running FoxClaw scan"
echo "=============================================="
echo ""

# ── Step 8: Run FoxClaw scan with strict ruleset ──────────────────────
scan_exit=0
"${PYTHON_BIN}" -m foxclaw scan \
  --profile "${PROFILE_DIR}" \
  --intel-store-dir "${INTEL_DIR}" \
  --output "${OUTPUT_DIR}/foxclaw.json" \
  --deterministic \
  --sarif-out "${OUTPUT_DIR}/foxclaw.sarif" \
  --snapshot-out "${OUTPUT_DIR}/foxclaw.snapshot.json" || scan_exit=$?

# ── Step 9: Print detailed results ───────────────────────────────────
echo ""
"${PYTHON_BIN}" - <<'PY' "${OUTPUT_DIR}/foxclaw.json" "${scan_exit}"
import json
import sys
from pathlib import Path

json_path = Path(sys.argv[1])
scan_exit = int(sys.argv[2])

data = json.loads(json_path.read_text(encoding="utf-8"))
summary = data["summary"]
findings = data["findings"]

print("=" * 60)
print("  FOXCLAW DEMO RESULTS — INSECURE PROFILE SCAN")
print("=" * 60)
print()
print(f"  Exit code:    {scan_exit}")
print(f"  Total:        {summary['findings_total']} findings")
print(f"  HIGH:         {summary['findings_high_count']}")
print(f"  MEDIUM:       {summary.get('findings_medium_count', 0)}")
print(f"  INFO:         {summary.get('findings_info_count', 0)}")
print(f"  Prefs parsed: {summary['prefs_parsed']}")
print(f"  Extensions:   {summary['extensions_found']}/{summary['extensions_active']}")
print()
print("-" * 60)
print(f"  {'SEVERITY':<10} {'RULE ID':<24} {'CATEGORY':<14}")
print("-" * 60)
for f in sorted(findings, key=lambda x: x["severity"]):
    print(f"  {f['severity']:<10} {f['id']:<24} {f['category']:<14}")
print("-" * 60)
print()

for f in sorted(findings, key=lambda x: x["severity"]):
    print(f"  [{f['severity']}] {f['id']}: {f['title']}")
    for ev in f.get("evidence", []):
        print(f"           ↳ {ev}")
    print()

if summary["findings_high_count"] >= 10:
    print("  ✅ All 10 strict rules fired — demo successful!")
else:
    print(f"  ⚠️  Only {summary['findings_high_count']}/10 HIGH findings — check profile setup.")
print()
PY

echo "[demo] Artifacts written to ${OUTPUT_DIR}/"
echo "[demo] Done."
