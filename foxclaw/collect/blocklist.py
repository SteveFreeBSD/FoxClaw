"""Mock module for resolving Mozilla AMO extension blocklists.

In Phase 2, this will be replaced with a real fetcher that downloads and
caches the AMO blocklist signals to verify extensions against known bad lists.
"""

from __future__ import annotations

# Dummy list of known-bad extension IDs for Phase 1 testing.
MOCK_BLOCKLIST_IDS = {
    "totally-not-malware@evil.example",
    "evil-extension@bad.actor",
}

def is_extension_blocklisted(addon_id: str, version: str | None) -> bool:
    """Return True if the given extension ID and version is blocklisted."""
    # In Phase 2: Query a local sqlite cache of the AMO blocklist.
    return addon_id in MOCK_BLOCKLIST_IDS
