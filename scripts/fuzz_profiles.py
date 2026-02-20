#!/usr/bin/env python3
"""FoxClaw Profile Fuzzer

Generates wildly randomized, corrupted, and edge-case Firefox profiles to
stress test the FoxClaw collection and validation engines.
"""

from __future__ import annotations

import argparse
import io
import json
import logging
import os
import random
import sqlite3
import string
import zipfile
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-n",
        "--count",
        type=int,
        default=10,
        help="Number of random profiles to generate (default: 10)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="/tmp/foxclaw-fuzzer-profiles",
        help="Target directory for generated profiles",
    )
    parser.add_argument(
        "--quiet", action="store_true", help="Suppress log output"
    )
    return parser.parse_args()


class ProfileGenerator:
    def __init__(self, output_dir: Path, index: int) -> None:
        self.profile_dir = output_dir / f"profile_{index:04d}"
        self.profile_dir.mkdir(parents=True, exist_ok=True)

    def generate(self) -> None:
        self._generate_prefs()
        self._generate_sqlite_dbs()
        self._generate_extensions()
        self._generate_policies()
        self._generate_locks()

    def _generate_prefs(self) -> None:
        if random.random() < 0.1:
            # 10% chance to not have prefs.js
            pass
        elif random.random() < 0.2:
            # 20% chance for corrupted prefs.js
            junk = "".join(random.choices(string.printable, k=500))
            (self.profile_dir / "prefs.js").write_text(junk, encoding="utf-8")
        else:
            prefs = []
            if random.random() < 0.5:
                prefs.append('user_pref("datareporting.healthreport.uploadEnabled", false);')
            if random.random() < 0.5:
                prefs.append('user_pref("browser.contentblocking.category", "strict");')
            elif random.random() < 0.5:
                prefs.append('user_pref("browser.contentblocking.category", "standard");')

            # Add some random junk prefs
            for _ in range(random.randint(0, 100)):
                key = f"test.random.pref.{random.randint(1, 1000)}"
                val = random.choice(["true", "false", "42", '"broken_string"'])
                prefs.append(f'user_pref("{key}", {val});')

            (self.profile_dir / "prefs.js").write_text("\n".join(prefs) + "\n", encoding="utf-8")

        # user.js
        if random.random() < 0.3:
            if random.random() < 0.2:
                junk = "".join(random.choices(string.printable, k=500))
                (self.profile_dir / "user.js").write_text(junk, encoding="utf-8")
            else:
                (self.profile_dir / "user.js").write_text(
                    'user_pref("browser.contentblocking.category", "strict");\n', encoding="utf-8"
                )

    def _generate_sqlite_dbs(self) -> None:
        for db_name in ("places.sqlite", "cookies.sqlite", "key4.db"):
            db_path = self.profile_dir / db_name
            mode = random.choice([0o600, 0o644, 0o666, 0o777, 0o000])

            if random.random() < 0.1:
                # 10% chance to skip
                continue

            if random.random() < 0.3:
                # 30% chance for corrupted garbage
                db_path.write_bytes(os.urandom(random.randint(0, 4096)))
            elif db_name != "key4.db":
                # Valid SQLite DB
                conn = sqlite3.connect(db_path)
                conn.execute(f"CREATE TABLE {db_name.split('.')[0]} (id INTEGER PRIMARY KEY)")
                conn.commit()
                conn.close()
            else:
                # Dummy key4
                db_path.write_bytes(b"dummy_key4_data")

            try:
                db_path.chmod(mode)
            except OSError:
                pass

    def _generate_extensions(self) -> None:
        if random.random() < 0.1:
            return  # No extensions

        ext_json_path = self.profile_dir / "extensions.json"

        if random.random() < 0.1:
            ext_json_path.write_text("INVALID JSON {" * 50)
            return

        addons = []
        for i in range(random.randint(1, 20)):
            if random.random() < 0.1:
                addons.append("GARBAGE NOT AN OBJECT")
                continue

            # Random permissions mix
            perms = []
            for perm in ("<all_urls>", "webRequest", "cookies", "history", "random_junk"):
                if random.random() < 0.3:
                    perms.append(perm)

            # Generate mocked XPI
            ext_id = f"fuzz{i}@test.com"
            xpi_path = f"extensions/{ext_id}.xpi"

            if random.random() < 0.8:
                # Actually write the XPI
                xpi_abs_path = self.profile_dir / xpi_path
                xpi_abs_path.parent.mkdir(parents=True, exist_ok=True)

                manifest = {
                    "manifest_version": random.choice([2, 3, "foo", None]),
                    "name": f"Fuzz Ext {i}",
                    "permissions": perms,
                }

                buf = io.BytesIO()
                with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as archive:
                    # Randomly inject valid or invalid manifest inside the XPI
                    if random.random() < 0.1:
                        archive.writestr("manifest.json", "INVALID JSON {")
                    elif random.random() < 0.1:
                        # Missing manifest.json path.
                        pass
                    else:
                        archive.writestr("manifest.json", json.dumps(manifest))

                    # Inject a very large file to test extraction limits.
                    if random.random() < 0.1:
                        archive.writestr("large.js", "A" * (1024 * 1024 * 10))

                xpi_abs_path.write_bytes(buf.getvalue())

            addons.append(
                {
                    "id": ext_id,
                    "type": "extension",
                    "active": random.choice([True, False, "broken_type", None]),
                    "location": random.choice(["app-profile", "app-system-defaults", "app-builtin", None]),
                    "path": xpi_path,
                    "signedState": random.choice([2, 0, -1, "broken", None]),
                }
            )

        payload = {"addons": addons}
        ext_json_path.write_text(json.dumps(payload), encoding="utf-8")

    def _generate_policies(self) -> None:
        if random.random() < 0.2:
            policy_path = self.profile_dir / "policies.json"
            if random.random() < 0.5:
                policy_path.write_text("INVALID JSON", encoding="utf-8")
            else:
                payload = {"policies": {}}
                if random.random() < 0.5:
                    payload["policies"]["DisableTelemetry"] = True
                policy_path.write_text(json.dumps(payload), encoding="utf-8")

    def _generate_locks(self) -> None:
        if random.random() < 0.1:
            (self.profile_dir / "parent.lock").write_bytes(b"")


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.ERROR if args.quiet else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    output_dir = Path(args.output_dir)
    logging.info(f"Target directory: {output_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)

    for i in range(args.count):
        gen = ProfileGenerator(output_dir, i)
        gen.generate()

    logging.info(f"Generated {args.count} fuzzed profiles.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
