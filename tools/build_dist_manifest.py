#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "DIST_MANIFEST.json"

# This is the single source of truth for files published through jsDelivr.
# Add a new generated/client output here and both commit staging and CDN cache
# purging will pick it up automatically through DIST_MANIFEST.json.
PUBLISHED_FILES = (
    "proxy_added.list",
    "direct_added.list",
    "reject_added.list",
    "zju.list",
    "proxy.list",
    "direct.list",
    "reject.list",
    "oxidns/proxy_added.txt",
    "oxidns/direct_added.txt",
    "oxidns/reject_added.txt",
    "oxidns/proxy.txt",
    "oxidns/direct.txt",
    "oxidns/reject.txt",
)


def main() -> int:
    missing = [path for path in PUBLISHED_FILES if not (ROOT / path).is_file()]
    if missing:
        formatted = "\n".join(f"- {path}" for path in missing)
        raise SystemExit(f"Cannot build distribution manifest; missing files:\n{formatted}")

    manifest = {
        "schema_version": 1,
        "repository": "ciallothu/proxy_rules",
        "files": list(PUBLISHED_FILES),
    }
    MANIFEST_PATH.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {MANIFEST_PATH.relative_to(ROOT)} with {len(PUBLISHED_FILES)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
