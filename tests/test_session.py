from __future__ import annotations

import json
from pathlib import Path

from foxclaw.collect.session import audit_sessionstore


def test_audit_sessionstore_missing_file_returns_empty(tmp_path: Path) -> None:
    result = audit_sessionstore(tmp_path / "sessionstore.jsonlz4")

    assert result.parse_error is None
    assert result.session_restore_enabled is False
    assert result.windows_count == 0
    assert result.sensitive_entries == ()


def test_audit_sessionstore_benign_payload(tmp_path: Path) -> None:
    sessionstore_path = tmp_path / "sessionstore.jsonlz4"
    sessionstore_path.write_text(
        json.dumps(
            {
                "selectedWindow": 1,
                "windows": [{"tabs": [{"entries": [{"url": "https://example.com"}]}]}],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    result = audit_sessionstore(sessionstore_path)

    assert result.parse_error is None
    assert result.session_restore_enabled is True
    assert result.windows_count == 1
    assert result.sensitive_entries == ()


def test_audit_sessionstore_mozlz4_header_payload(tmp_path: Path) -> None:
    sessionstore_path = tmp_path / "sessionstore.jsonlz4"
    payload = {
        "selectedWindow": 1,
        "windows": [
            {
                "tabs": [
                    {
                        "entries": [
                            {
                                "formdata": {
                                    "id": {
                                        "authToken": "tok_abc123",
                                        "cardNumber": "4111 1111 1111 1111",
                                        "password": "hunter2",
                                    }
                                },
                                "url": "https://example.com/account",
                            }
                        ]
                    }
                ]
            }
        ],
    }
    sessionstore_path.write_bytes(b"mozLz40\x00" + json.dumps(payload, sort_keys=True).encode("utf-8"))

    result = audit_sessionstore(sessionstore_path)

    assert result.parse_error is None
    assert result.session_restore_enabled is True
    assert result.windows_count == 1
    assert [(item.path, item.kind) for item in result.sensitive_entries] == [
        (
            "$.windows[0].tabs[0].entries[0].formdata.id.authToken",
            "auth_token_field",
        ),
        (
            "$.windows[0].tabs[0].entries[0].formdata.id.cardNumber",
            "credit_card_pattern",
        ),
        (
            "$.windows[0].tabs[0].entries[0].formdata.id.password",
            "password_field",
        ),
    ]


def test_audit_sessionstore_invalid_payload_reports_error(tmp_path: Path) -> None:
    sessionstore_path = tmp_path / "sessionstore.jsonlz4"
    sessionstore_path.write_bytes(b"not-json")

    result = audit_sessionstore(sessionstore_path)

    assert result.parse_error == "unable to decode sessionstore payload as JSON"
    assert result.session_restore_enabled is False
    assert result.windows_count == 0
    assert result.sensitive_entries == ()

