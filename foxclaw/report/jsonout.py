"""JSON rendering helpers."""

from __future__ import annotations

import json

from foxclaw.models import EvidenceBundle


def render_scan_json(bundle: EvidenceBundle) -> str:
    """Render a deterministic JSON scan payload."""
    payload = bundle.model_dump(mode="json")
    return json.dumps(payload, indent=2, sort_keys=True)
