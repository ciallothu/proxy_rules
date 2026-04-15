#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Iterable

COMMENT_PREFIXES = ("#", ";", "//")


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def strip_inline_comment(line: str) -> str:
    """
    Remove inline comments outside quotes.
    Supports #, ;, // as comment starters.
    """
    out = []
    in_single = False
    in_double = False
    i = 0
    n = len(line)

    while i < n:
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


def detect_engine(path: Path, text: str) -> str:
    ext = path.suffix.lower()
    if ext in {".yaml", ".yml"}:
        return "mihomo"
    if ext in {".list", ".txt", ".rules"}:
        return "surge"

    if re.search(r"(?m)^\s*payload\s*:\s*$", text):
        return "mihomo"

    return "surge"


def parse_mihomo_yaml(text: str) -> list[str]:
    """
    Parse a simple mihomo rules YAML file of the form:

    payload:
      - RULE,...
      - RULE,...
    """
    rules: list[str] = []
    in_payload = False

    for raw in text.splitlines():
        line = strip_inline_comment(raw.rstrip())
        if not line:
            continue

        if re.match(r"^\s*payload\s*:\s*$", line):
            in_payload = True
            continue

        if not in_payload:
            # tolerate bare "- RULE,..." even if payload: line is missing
            if not re.match(r"^\s*-\s+", line):
                continue

        m = re.match(r"^\s*-\s*(.+?)\s*$", line)
        if m:
            rule = m.group(1).strip()
            if rule:
                rules.append(rule)

    return dedupe_keep_order(rules)


def parse_surge_text(text: str) -> list[str]:
    """
    Parse a Surge ruleset text file:
    one rule per line, no policy, comments allowed.
    """
    rules: list[str] = []

    for raw in text.splitlines():
        line = strip_inline_comment(raw.strip())
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            # tolerate accidental section headers like [Rule]
            continue
        rules.append(line)

    return dedupe_keep_order(rules)


def parse_rules(path: Path) -> tuple[str, list[str]]:
    text = path.read_text(encoding="utf-8")
    engine = detect_engine(path, text)

    if engine == "mihomo":
        return engine, parse_mihomo_yaml(text)
    return engine, parse_surge_text(text)


def dedupe_keep_order(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def split_rule(rule: str) -> tuple[str, str, str]:
    """
    Split into:
      kind, payload, extra
    Examples:
      DOMAIN-SUFFIX,google.com
        -> ("DOMAIN-SUFFIX", "google.com", "")
      IP-CIDR,1.2.3.0/24,no-resolve
        -> ("IP-CIDR", "1.2.3.0/24", "no-resolve")
    """
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


def has_wildcards(s: str) -> bool:
    return "*" in s or "?" in s


def ip_default_mask(ip: str) -> str:
    return "/128" if ":" in ip else "/32"


def unsupported(rule: str, reason: str) -> None:
    eprint(f"[skip] {rule}  ({reason})")


def convert_rule(rule: str, src: str, dst: str) -> str | None:
    """
    Best-effort conversion.
    Returns None if the rule cannot be converted safely.
    """
    if src == dst:
        return rule

    kind, payload, extra = split_rule(rule)

    # -------------------------
    # Surge -> Mihomo
    # -------------------------
    if src == "surge" and dst == "mihomo":
        # Surge PROCESS-NAME itself supports * and ?, Mihomo separates exact vs wildcard
        if kind == "PROCESS-NAME":
            new_kind = "PROCESS-NAME-WILDCARD" if has_wildcards(payload) else "PROCESS-NAME"
            return build_rule(new_kind, payload, extra)

        # Surge PROCESS-NAME may also accept full path on Mac.
        # If you explicitly wrote PROCESS-PATH in a Surge-like list, keep the same intent.
        if kind == "PROCESS-PATH":
            new_kind = "PROCESS-PATH-WILDCARD" if has_wildcards(payload) else "PROCESS-PATH"
            return build_rule(new_kind, payload, extra)

        # Port naming difference
        if kind == "DEST-PORT":
            return build_rule("DST-PORT", payload, extra)

        # Surge PROTOCOL is broader; only TCP/UDP map cleanly to mihomo NETWORK
        if kind == "PROTOCOL":
            val = payload.lower()
            if val in {"tcp", "udp"}:
                return build_rule("NETWORK", val, extra)
            unsupported(rule, "Surge PROTOCOL value has no direct mihomo NETWORK equivalent")
            return None

        # Surge SRC-IP supports plain IP and CIDR; mihomo uses SRC-IP-CIDR
        if kind == "SRC-IP":
            new_payload = payload if "/" in payload else payload + ip_default_mask(payload)
            return build_rule("SRC-IP-CIDR", new_payload, extra)

        # Likely Surge-only / no clean mihomo route equivalent
        if kind in {
            "URL-REGEX",
            "USER-AGENT",
            "DOMAIN-SET",
            "FINAL",
            "SCRIPT",
            "CELLULAR-RADIO",
            "DEVICE-NAME",
            "MAC-ADDRESS",
            "HOSTNAME-TYPE",
        }:
            unsupported(rule, "no clean mihomo route-rule equivalent")
            return None

        # Default: keep the same rule string
        return rule

    # -------------------------
    # Mihomo -> Surge
    # -------------------------
    if src == "mihomo" and dst == "surge":
        if kind == "PROCESS-NAME-WILDCARD":
            return build_rule("PROCESS-NAME", payload, extra)

        if kind == "PROCESS-NAME":
            return build_rule("PROCESS-NAME", payload, extra)

        # Surge process rule supports filename/full path + wildcards using PROCESS-NAME
        if kind == "PROCESS-PATH-WILDCARD":
            return build_rule("PROCESS-NAME", payload, extra)

        if kind == "PROCESS-PATH":
            return build_rule("PROCESS-NAME", payload, extra)

        if kind in {"PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX"}:
            unsupported(rule, "Surge process rule has wildcard matching, not regex process matching")
            return None

        if kind == "DST-PORT":
            return build_rule("DEST-PORT", payload, extra)

        if kind == "NETWORK":
            val = payload.upper()
            if val in {"TCP", "UDP"}:
                return build_rule("PROTOCOL", val, extra)
            unsupported(rule, "mihomo NETWORK only maps cleanly to Surge PROTOCOL for TCP/UDP")
            return None

        if kind == "SRC-IP-CIDR":
            return build_rule("SRC-IP", payload, extra)

        # Likely Mihomo-only / no clean Surge equivalent
        if kind in {
            "MATCH",
            "UID",
            "DSCP",
            "IN-TYPE",
            "IN-USER",
            "IN-NAME",
            "PROCESS-NAME-REGEX",
            "PROCESS-PATH-REGEX",
        }:
            unsupported(rule, "no clean Surge rule equivalent")
            return None

        return rule

    raise ValueError(f"Unsupported conversion: {src} -> {dst}")


def format_mihomo_yaml(rules: list[str]) -> str:
    lines = ["payload:"]
    lines.extend(f"  - {r}" for r in rules)
    return "\n".join(lines) + "\n"


def format_surge_text(rules: list[str]) -> str:
    return "\n".join(rules) + ("\n" if rules else "")


def main() -> int:
    if len(sys.argv) != 3:
        eprint("Usage:")
        eprint("  sync_rules.py <src> <dst>")
        eprint("Examples:")
        eprint("  sync_rules.py surge/added.list mihomo/added.yaml")
        eprint("  sync_rules.py mihomo/added.yaml surge/added.list")
        return 2

    src_path = Path(sys.argv[1])
    dst_path = Path(sys.argv[2])

    src_engine, src_rules = parse_rules(src_path)

    # Infer destination engine from path name when possible
    dummy_text = dst_path.read_text(encoding="utf-8") if dst_path.exists() else ""
    dst_engine = detect_engine(dst_path, dummy_text)

    converted: list[str] = []
    for rule in src_rules:
        out = convert_rule(rule, src_engine, dst_engine)
        if out:
            converted.append(out)

    converted = dedupe_keep_order(converted)

    dst_path.parent.mkdir(parents=True, exist_ok=True)
    if dst_engine == "mihomo":
        dst_path.write_text(format_mihomo_yaml(converted), encoding="utf-8")
    else:
        dst_path.write_text(format_surge_text(converted), encoding="utf-8")

    eprint(f"[ok] {src_path} ({src_engine}) -> {dst_path} ({dst_engine}), {len(converted)} rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
