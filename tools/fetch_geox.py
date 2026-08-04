#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GEOX_DIR = ROOT / "geox"

ASSETS = {
    "geoip.dat": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
    "geosite.dat": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
}

CHUNK_SIZE = 1024 * 1024
MIN_ASSET_SIZE = 1024


def download_asset(filename: str, url: str) -> None:
    destination = GEOX_DIR / filename
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    request = urllib.request.Request(url, headers={"User-Agent": "proxy-rules-geox-mirror/1.0"})

    digest = hashlib.sha256()
    size = 0

    try:
        with urllib.request.urlopen(request, timeout=120) as response, temporary.open("wb") as output:
            while chunk := response.read(CHUNK_SIZE):
                output.write(chunk)
                digest.update(chunk)
                size += len(chunk)

        if size < MIN_ASSET_SIZE:
            raise RuntimeError(f"Downloaded {filename} is unexpectedly small: {size} bytes")

        temporary.replace(destination)
    finally:
        if temporary.exists():
            temporary.unlink()

    print(f"Downloaded {filename}: {size} bytes, sha256={digest.hexdigest()}")


def main() -> int:
    GEOX_DIR.mkdir(parents=True, exist_ok=True)
    for filename, url in ASSETS.items():
        download_asset(filename, url)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
