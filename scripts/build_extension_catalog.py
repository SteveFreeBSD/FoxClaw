#!/usr/bin/env python3
"""Build a pinned AMO extension catalog snapshot for realistic profile generation."""

from __future__ import annotations

import argparse
import json
import time
import urllib.parse
import urllib.request
from pathlib import Path

AMO_SEARCH_URL = "https://addons.mozilla.org/api/v5/addons/search/"
AMO_DETAIL_URL = "https://addons.mozilla.org/api/v5/addons/addon/{guid}/"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        default="tests/fixtures/intel/amo_extension_catalog.v1.json",
        help="Output JSON path",
    )
    parser.add_argument("--pages", type=int, default=4, help="Number of paginated search pages")
    parser.add_argument("--page-size", type=int, default=50, help="Search page size")
    parser.add_argument(
        "--detail-limit",
        type=int,
        default=60,
        help="How many entries should fetch detail metadata",
    )
    parser.add_argument("--sleep-ms", type=int, default=100, help="Pause between detail requests")
    return parser.parse_args()


def fetch_json(url: str) -> dict[str, object]:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as response:
        payload = json.loads(response.read())
    if not isinstance(payload, dict):
        raise ValueError(f"expected object payload from {url}")
    return payload


def _search_page(page: int, page_size: int) -> dict[str, object]:
    query = urllib.parse.urlencode(
        {
            "app": "firefox",
            "type": "extension",
            "sort": "users",
            "page_size": str(page_size),
            "page": str(page),
        }
    )
    return fetch_json(f"{AMO_SEARCH_URL}?{query}")


def _entry_from_search(item: dict[str, object]) -> dict[str, object] | None:
    guid = item.get("guid")
    slug = item.get("slug")
    if not isinstance(guid, str) or not guid:
        return None
    if not isinstance(slug, str) or not slug:
        return None

    name_obj = item.get("name")
    name = ""
    if isinstance(name_obj, dict):
        en_us = name_obj.get("en-US")
        if isinstance(en_us, str):
            name = en_us

    promoted = item.get("promoted")
    promoted_categories: list[str] = []
    if isinstance(promoted, list):
        for promo in promoted:
            if isinstance(promo, dict):
                category = promo.get("category")
                if isinstance(category, str):
                    promoted_categories.append(category)

    categories = item.get("categories")
    category_values: list[str] = []
    if isinstance(categories, list):
        for category in categories:
            if isinstance(category, str):
                category_values.append(category)

    version = item.get("current_version")
    download_url = None
    if isinstance(version, dict):
        file_obj = version.get("file")
        if isinstance(file_obj, dict):
            url = file_obj.get("url")
            if isinstance(url, str) and url:
                download_url = url

    average_daily_users = item.get("average_daily_users")
    if not isinstance(average_daily_users, int):
        average_daily_users = 0

    return {
        "guid": guid,
        "slug": slug,
        "name": name,
        "average_daily_users": average_daily_users,
        "categories": sorted(set(category_values)),
        "promoted_categories": sorted(set(promoted_categories)),
        "last_updated": item.get("last_updated") if isinstance(item.get("last_updated"), str) else None,
        "created": item.get("created") if isinstance(item.get("created"), str) else None,
        "download_url": download_url,
        "download_size": None,
        "download_hash": None,
        "version": None,
        "source": "search",
    }


def _enrich_from_detail(entry: dict[str, object]) -> None:
    guid = entry["guid"]
    payload = fetch_json(AMO_DETAIL_URL.format(guid=urllib.parse.quote(str(guid), safe="")))

    version = payload.get("current_version")
    if isinstance(version, dict):
        version_number = version.get("version")
        if isinstance(version_number, str):
            entry["version"] = version_number

        file_obj = version.get("file")
        if isinstance(file_obj, dict):
            url = file_obj.get("url")
            if isinstance(url, str) and url:
                entry["download_url"] = url

            size = file_obj.get("size")
            if isinstance(size, int):
                entry["download_size"] = size

            hash_value = file_obj.get("hash")
            if isinstance(hash_value, str):
                entry["download_hash"] = hash_value

    entry["source"] = "detail"


def build_catalog(args: argparse.Namespace) -> dict[str, object]:
    if args.pages <= 0:
        raise ValueError("--pages must be greater than zero")
    if args.page_size <= 0:
        raise ValueError("--page-size must be greater than zero")
    if args.detail_limit < 0:
        raise ValueError("--detail-limit must be non-negative")

    by_guid: dict[str, dict[str, object]] = {}
    for page in range(1, args.pages + 1):
        payload = _search_page(page=page, page_size=args.page_size)
        results = payload.get("results")
        if not isinstance(results, list):
            continue
        for item in results:
            if not isinstance(item, dict):
                continue
            entry = _entry_from_search(item)
            if entry is None:
                continue
            by_guid[str(entry["guid"])] = entry

    ordered = sorted(
        by_guid.values(),
        key=lambda item: (-int(item.get("average_daily_users", 0)), str(item.get("guid", ""))),
    )

    for index, entry in enumerate(ordered[: args.detail_limit]):
        _enrich_from_detail(entry)
        if index + 1 < min(args.detail_limit, len(ordered)) and args.sleep_ms > 0:
            time.sleep(args.sleep_ms / 1000.0)

    catalog = {
        "schema_version": "foxclaw.amo.extension_catalog.v1",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "query": {
            "app": "firefox",
            "type": "extension",
            "sort": "users",
            "pages": args.pages,
            "page_size": args.page_size,
            "detail_limit": args.detail_limit,
        },
        "extensions": ordered,
    }
    return catalog


def main() -> int:
    args = parse_args()
    catalog = build_catalog(args)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(catalog, indent=2, sort_keys=True), encoding="utf-8")
    print(
        f"[catalog] wrote {len(catalog['extensions'])} entries to {output_path} "
        f"schema={catalog['schema_version']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
