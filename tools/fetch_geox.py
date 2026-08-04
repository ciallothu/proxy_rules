#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import re
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GEOX_DIR = ROOT / "geox"
UPSTREAM_BASE = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release"

ASSETS = {
    "geoip.dat": f"{UPSTREAM_BASE}/geoip.dat",
    "geosite.dat": f"{UPSTREAM_BASE}/geosite.dat",
}

CHUNK_SIZE = 1024 * 1024
MIN_ASSET_SIZE = 1024 * 1024
USER_AGENT = "proxy-rules-geox-mirror/1.1"
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def request_url(url: str) -> urllib.request.Request:
    return urllib.request.Request(url, headers={"User-Agent": USER_AGENT})


def fetch_expected_sha256(filename: str, url: str) -> str:
    checksum_url = f"{url}.sha256sum"
    with urllib.request.urlopen(request_url(checksum_url), timeout=60) as response:
        text = response.read(4096).decode("utf-8", errors="strict").strip()

    expected = text.split()[0].lower() if text else ""
    if not SHA256_RE.fullmatch(expected):
        raise RuntimeError(f"Invalid checksum response for {filename}: {text!r}")
    return expected


def download_asset(filename: str, url: str) -> None:
    destination = GEOX_DIR / filename
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    checksum_path = GEOX_DIR / f"{filename}.sha256sum"
    expected_sha256 = fetch_expected_sha256(filename, url)

    digest = hashlib.sha256()
    size = 0
    prefix = bytearray()

    try:
        with urllib.request.urlopen(request_url(url), timeout=180) as response, temporary.open("wb") as output:
            content_length = response.headers.get("Content-Length")
            expected_size = int(content_length) if content_length and content_length.isdigit() else None

            while chunk := response.read(CHUNK_SIZE):
                if len(prefix) < 256:
                    prefix.extend(chunk[: 256 - len(prefix)])
                output.write(chunk)
                digest.update(chunk)
                size += len(chunk)

        if size < MIN_ASSET_SIZE:
            raise RuntimeError(f"Downloaded {filename} is unexpectedly small: {size} bytes")
        if expected_size is not None and size != expected_size:
            raise RuntimeError(
                f"Downloaded {filename} is incomplete: expected {expected_size} bytes, got {size}"
            )

        lowered_prefix = bytes(prefix).lstrip().lower()
        if lowered_prefix.startswith((b"<!doctype html", b"<html", b"version https://git-lfs")):
            raise RuntimeError(f"Downloaded {filename} is not a GeoX binary file")

        actual_sha256 = digest.hexdigest()
        if actual_sha256 != expected_sha256:
            raise RuntimeError(
                f"SHA-256 mismatch for {filename}: expected {expected_sha256}, got {actual_sha256}"
            )

        temporary.replace(destination)
        checksum_path.write_text(f"{actual_sha256}  {filename}\n", encoding="utf-8")
    finally:
        if temporary.exists():
            temporary.unlink()

    print(f"Downloaded and verified {filename}: {size} bytes, sha256={expected_sha256}")


def main() -> int:
    GEOX_DIR.mkdir(parents=True, exist_ok=True)
    for filename, url in ASSETS.items():
        download_asset(filename, url)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
