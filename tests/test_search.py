from __future__ import annotations

import json
from pathlib import Path

from foxclaw.collect.search import audit_search_json


def test_audit_search_json_missing_file_returns_empty(tmp_path: Path) -> None:
    result = audit_search_json(tmp_path / "search.json.mozlz4")

    assert result.parse_error is None
    assert result.engines == ()
    assert result.default_engine_name is None
    assert result.default_engine_url is None
    assert result.suspicious_defaults == ()


def test_audit_search_json_benign_default_engine(tmp_path: Path) -> None:
    search_path = tmp_path / "search.json.mozlz4"
    search_path.write_text(
        json.dumps(
            {
                "engines": [
                    {
                        "name": "Google",
                        "searchUrl": "https://www.google.com/search?q={searchTerms}",
                        "isDefault": True,
                    }
                ],
                "metaData": {"currentEngine": "Google"},
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    result = audit_search_json(search_path)

    assert result.parse_error is None
    assert len(result.engines) == 1
    assert result.default_engine_name == "Google"
    assert result.default_engine_url == "https://www.google.com/search?q={searchTerms}"
    assert result.suspicious_defaults == ()


def test_audit_search_json_flags_non_standard_default_and_custom_url(tmp_path: Path) -> None:
    search_path = tmp_path / "search.json.mozlz4"
    search_path.write_text(
        json.dumps(
            {
                "engines": [
                    {
                        "name": "EvilSearch",
                        "searchUrl": "https://search.evil-example.invalid/query?q={searchTerms}",
                        "isDefault": True,
                    }
                ],
                "metaData": {"currentEngine": "EvilSearch"},
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    result = audit_search_json(search_path)

    assert result.parse_error is None
    assert len(result.suspicious_defaults) == 1
    risk = result.suspicious_defaults[0]
    assert risk.name == "EvilSearch"
    assert risk.search_url == "https://search.evil-example.invalid/query?q={searchTerms}"
    assert risk.reasons == ("custom_search_url", "non_standard_default_engine")


def test_audit_search_json_mozlz4_header_payload(tmp_path: Path) -> None:
    search_path = tmp_path / "search.json.mozlz4"
    payload = {
        "engines": [
            {
                "name": "DuckDuckGo",
                "searchUrl": "https://duckduckgo.com/?q={searchTerms}",
                "isDefault": True,
            }
        ],
        "metaData": {"currentEngine": "DuckDuckGo"},
    }
    search_path.write_bytes(b"mozLz40\x00" + json.dumps(payload, sort_keys=True).encode("utf-8"))

    result = audit_search_json(search_path)

    assert result.parse_error is None
    assert result.default_engine_name == "DuckDuckGo"
    assert result.default_engine_url == "https://duckduckgo.com/?q={searchTerms}"
    assert result.suspicious_defaults == ()


def test_audit_search_json_invalid_payload_reports_error(tmp_path: Path) -> None:
    search_path = tmp_path / "search.json.mozlz4"
    search_path.write_bytes(b"not-json")

    result = audit_search_json(search_path)

    assert result.parse_error == "unable to decode search payload as JSON"
    assert result.engines == ()
    assert result.suspicious_defaults == ()

