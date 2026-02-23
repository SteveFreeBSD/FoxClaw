#!/usr/bin/env python3
"""Run Windows-share profile staging and scan orchestration."""

from __future__ import annotations

import sys

from foxclaw.acquire.windows_share import run_windows_share_scan_from_argv

if __name__ == "__main__":
    raise SystemExit(run_windows_share_scan_from_argv(sys.argv[1:]))
