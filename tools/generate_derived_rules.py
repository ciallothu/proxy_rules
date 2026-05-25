#!/usr/bin/env python3
from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path
from typing import Iterable

COMMENT_PREFIXES = ("#", ";", "//")
TARGET_SUFFIX = {
    "surge": ".list",
    "loon": ".lsr",
}


def eprint(*args, **kwargs) -> None:
    print(*args, file=sys.stderr, **kwargs)


def strip_inline_comment(line: str) -> str:
    """Remove inline comments outside quotes."""
    out: list[str] = []
    in_single = False
    in_double = False
    i = 0

    while i < len(line):
        ch = line[i]

        if ch == "'" and not in_double:
            in_single = not in_single
            out.append(ch)
            i += 1
            continue

        if ch == '"' and not in_single:
            in_double = not in_double
            out.append(ch)
            i += 1
            continue

        if not in_single and not in_double:
            if line.startswith("//", i):
                break
            if ch in ("#", ";"):
                break

        out.append(ch)
        i += 1

    return "".join(out).strip()


def dedupe_keep_order(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []

    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)

    return out


def parse_mihomo_yaml(path: Path) -> list[str]:
    """
    Parse a simple Mihomo rule-provider YAML file:

        payload:
          - DOMAIN-SUFFIX,example.com
          - IP-CIDR,1.2.3.0/24,no-resolve

    This intentionally avoids a PyYAML dependency because these files are simple
    rule-provider payloads and GitHub Actions runners should stay dependency-free.
    """
    rules: list[str] = []
    in_payload = False

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = strip_inline_comment(raw.rstrip())
        if not line:
            continue

        if re.match(r"^\s*payload\s*:\s*$", line):
            in_payload = True
            continue

        if not in_payload and not re.match(r"^\s*-\s+", line):
            continue

        match = re.match(r"^\s*-\s*(.+?)\s*$", line)
        if not match:
            continue

        rule = match.group(1).strip()
        if (rule.startswith("'") and rule.endswith("'")) or (rule.startswith('"') and rule.endswith('"')):
            rule = rule[1:-1].strip()

        if rule:
            rules.append(rule)

    return dedupe_keep_order(rules)


def split_rule(rule: str) -> tuple[str, str, str]:
    head, sep, tail = rule.partition(",")
    kind = head.strip().upper()

    if not sep:
        return kind, "", ""

    payload, sep2, extra = tail.partition(",")
    return kind, payload.strip(), extra.strip()


def build_rule(kind: str, payload: str = "", extra: str = "") -> str:
    parts = [kind]
    if payload:
        parts.append(payload)
    if extra:
        parts.append(extra)
    return ",".join(parts)


def warn_skip(dst: str, rule: str, reason: str) -> None:
    eprint(f"[skip:{dst}] {rule}  ({reason})")


def convert_rule(rule: str, dst: str) -> str | None:
    """
    Convert one Mihomo rule-provider rule to a target ruleset syntax.

    Targets:
      - surge: Surge RULE-SET file syntax, one rule per line, no policy.
      - loon:  Loon Remote Rule file syntax, one rule per line, no policy.

    Loon and Surge share most domain/IP rule syntax. The generated Loon files
    use the Loon-specific .lsr extension, but the line-level rule syntax remains
    the normal Loon remote-rule syntax.
    """
    kind, payload, extra = split_rule(rule)

    if kind in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6", "IP-ASN", "SRC-IP-CIDR"}:
        if dst == "surge" and kind == "SRC-IP-CIDR":
            return build_rule("SRC-IP", payload, extra)
        return build_rule(kind, payload, extra)

    if kind in {"DST-PORT", "DEST-PORT"}:
        return build_rule("DEST-PORT", payload, extra)

    if kind == "SRC-PORT":
        return build_rule("SRC-PORT", payload, extra)

    if kind == "NETWORK":
        val = payload.upper()
        if val in {"TCP", "UDP"}:
            return build_rule("PROTOCOL", val, extra)
        warn_skip(dst, rule, "NETWORK only maps cleanly to PROTOCOL for TCP/UDP")
        return None

    if kind in {"RULE-SET", "GEOSITE", "GEOIP", "MATCH"}:
        warn_skip(dst, rule, "route-control rule should not be inside a remote ruleset")
        return None

    if kind in {"PROCESS-NAME-WILDCARD", "PROCESS-PATH-WILDCARD"}:
        if dst == "surge":
            return build_rule("PROCESS-NAME", payload, extra)
        warn_skip(dst, rule, "Loon Remote Rule process wildcard support is not portable")
        return None

    if kind in {"PROCESS-NAME", "PROCESS-PATH"}:
        if dst == "surge":
            return build_rule("PROCESS-NAME", payload, extra)
        warn_skip(dst, rule, "Loon process rules are not portable across iOS/tvOS configs")
        return None

    if kind in {"PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX", "UID", "DSCP", "IN-TYPE", "IN-USER", "IN-NAME"}:
        warn_skip(dst, rule, "Mihomo-only or non-portable rule type")
        return None

    # Conservative default: keep unknown rules so new compatible rule types are not lost.
    return rule


def write_rule_file(path: Path, rules: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(rules) + ("\n" if rules else ""), encoding="utf-8")


def clean_generated_dirs(*dirs: Path) -> None:
    for directory in dirs:
        if directory.exists():
            shutil.rmtree(directory)
        directory.mkdir(parents=True, exist_ok=True)


def generate(mihomo_dir: Path, surge_dir: Path, loon_dir: Path) -> int:
    if not mihomo_dir.is_dir():
        raise SystemExit(f"Missing source directory: {mihomo_dir}")

    clean_generated_dirs(surge_dir, loon_dir)

    count = 0
    for src in sorted(mihomo_dir.glob("*.yaml")):
        source_rules = parse_mihomo_yaml(src)
        stem = src.stem

        for dst_name, dst_dir in (("surge", surge_dir), ("loon", loon_dir)):
            converted: list[str] = []
            for rule in source_rules:
                out = convert_rule(rule, dst_name)
                if out:
                    converted.append(out)

            converted = dedupe_keep_order(converted)
            suffix = TARGET_SUFFIX[dst_name]
            dst_file = dst_dir / f"{stem}{suffix}"
            write_rule_file(dst_file, converted)
            eprint(f"[ok] {src} -> {dst_file} ({len(converted)} rules)")
            count += 1

    return count


def main() -> int:
    repo = Path(__file__).resolve().parents[1]
    generated = generate(repo / "mihomo", repo / "surge", repo / "loon")
    eprint(f"[done] generated {generated} derived rule files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
