#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
import time
import urllib.request
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
OXIDNS_DIR = ROOT / "oxidns"

COMMENT_PREFIXES = ("#", ";", "//")
PORTABLE_KINDS = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6", "IP-ASN"}

# Generated lists are built only from current external upstream sources declared
# here. Manual overrides live in *_added.list and are referenced separately by
# client configs, so they are not merged into proxy/direct/reject outputs.
SOURCES = {
    "proxy": [
        # AI / proxy / global
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/OpenAI/OpenAI.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Gemini/Gemini.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/OneDrive/OneDrive.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Proxy/Proxy.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Proxy/Proxy_Domain.list",
        "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/gfw.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/proxy.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/proxy-list.txt",
        "https://ruleset.skk.moe/List/non_ip/ai.conf",
        "https://ruleset.skk.moe/List/non_ip/apple_intelligence.conf",
        "https://ruleset.skk.moe/List/non_ip/global.conf",
        "https://ruleset.skk.moe/List/non_ip/global_plus.conf",
        # Stream / media
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/GlobalMedia/GlobalMedia.list",
        "https://ruleset.skk.moe/List/non_ip/stream.conf",
        "https://ruleset.skk.moe/List/ip/stream.conf",
        "https://ruleset.skk.moe/List/non_ip/stream_us.conf",
        "https://ruleset.skk.moe/List/ip/stream_us.conf",
        "https://ruleset.skk.moe/List/non_ip/stream_eu.conf",
        "https://ruleset.skk.moe/List/ip/stream_eu.conf",
        "https://ruleset.skk.moe/List/non_ip/stream_jp.conf",
        "https://ruleset.skk.moe/List/ip/stream_jp.conf",
        "https://ruleset.skk.moe/List/non_ip/stream_kr.conf",
        "https://ruleset.skk.moe/List/ip/stream_kr.conf",
        "https://ruleset.skk.moe/List/non_ip/stream_hk.conf",
        "https://ruleset.skk.moe/List/ip/stream_hk.conf",
        "https://ruleset.skk.moe/List/non_ip/stream_tw.conf",
        "https://ruleset.skk.moe/List/ip/stream_tw.conf",
    ],
    "direct": [
        # Apple / China / direct / LAN
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Apple/Apple.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Apple/Apple_Domain.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/China/China.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/China/China_Domain.list",
        "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/apple.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/direct.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/google.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/apple-cn.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/china-list.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/google-cn.txt",
        "https://ruleset.skk.moe/List/non_ip/apple_cn.conf",
        "https://ruleset.skk.moe/List/non_ip/apple_services.conf",
        "https://ruleset.skk.moe/List/ip/apple_services.conf",
        "https://ruleset.skk.moe/List/non_ip/lan.conf",
        "https://ruleset.skk.moe/List/ip/lan.conf",
        "https://ruleset.skk.moe/List/non_ip/direct.conf",
        "https://ruleset.skk.moe/List/non_ip/domestic.conf",
        "https://ruleset.skk.moe/List/ip/domestic.conf",
        "https://ruleset.skk.moe/List/ip/china_ip.conf",
    ],
    "reject": [
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Advertising/Advertising.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Advertising/Advertising_Domain.list",
        "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblocksurge.list",
        "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockmihomo.yaml",
        "https://raw.githubusercontent.com/afwfv/DD-AD/refs/heads/release/clash.yaml",
        "https://raw.githubusercontent.com/ciallothu/DD-AD/release/surge-domainset.txt",
        "https://anti-ad.net/surge.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/reject.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/reject-list.txt",
        "https://ruleset.skk.moe/List/non_ip/reject-drop.conf",
        "https://ruleset.skk.moe/List/domainset/reject.conf",
        "https://ruleset.skk.moe/List/domainset/reject_extra.conf",
        "https://ruleset.skk.moe/List/non_ip/reject.conf",
        "https://ruleset.skk.moe/List/non_ip/reject-no-drop.conf",
        "https://ruleset.skk.moe/List/ip/reject.conf",
    ],
}

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_-]{1,63}\.)+[a-z0-9_-]{2,63}\.?$", re.I)
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")
IPV6_LIKE_RE = re.compile(r"^[0-9a-f:]+(?:/\d{1,3})?$", re.I)


def eprint(*args, **kwargs) -> None:
    print(*args, file=sys.stderr, **kwargs)


def strip_inline_comment(line: str) -> str:
    line = line.rstrip()
    if not line:
        return ""
    if line.lstrip().upper().startswith(("URL-REGEX", "DOMAIN-REGEX")):
        return line.strip()
    out: list[str] = []
    in_single = False
    in_double = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        if not in_single and not in_double:
            if line.startswith("//", i):
                break
            if ch in ("#", ";"):
                break
        out.append(ch)
        i += 1
    return "".join(out).strip()


def clean_yaml_item(line: str) -> str:
    line = line.strip()
    if line.startswith("- "):
        line = line[2:].strip()
    elif line.startswith("-"):
        line = line[1:].strip()
    if (line.startswith("'") and line.endswith("'")) or (line.startswith('"') and line.endswith('"')):
        line = line[1:-1].strip()
    return line.strip().rstrip(",")


def normalize_domain(value: str) -> str:
    value = value.strip().strip("'\"").strip().split(",", 1)[0].strip().lower().lstrip("+")
    if value.startswith("*."):
        value = value[2:]
    if value.startswith("."):
        value = value[1:]
    return value.rstrip(".")


def looks_like_domain(value: str) -> bool:
    if not value or "/" in value or " " in value or "@" in value or value.startswith(("http://", "https://")):
        return False
    if IPV4_RE.match(value) or IPV6_LIKE_RE.match(value):
        return False
    return bool(DOMAIN_RE.match(value))


def build(kind: str, payload: str, extra: str = "") -> str | None:
    kind = kind.upper().strip()
    payload = payload.strip().strip("'\"")
    extra = extra.strip().strip("'\"")
    if kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
        domain = normalize_domain(payload)
        return f"{kind},{domain}" if looks_like_domain(domain) else None
    if kind == "DOMAIN-KEYWORD":
        return f"DOMAIN-KEYWORD,{payload}" if payload else None
    if kind in {"IP-CIDR", "IP-CIDR6", "IP-ASN"}:
        return f"{kind},{payload}{',' + extra if extra else ''}"
    return None


def convert_line(raw: str) -> str | None:
    line = strip_inline_comment(raw)
    if not line or line.lstrip().startswith(COMMENT_PREFIXES):
        return None
    line = clean_yaml_item(line)
    if not line:
        return None
    lower = line.lower().strip()
    if lower in {"payload:", "payload", "rules:", "rules"}:
        return None
    if re.match(r"^[a-zA-Z0-9_-]+\s*:\s*$", line) or re.match(r"^(type|behavior|format|url|path|interval|proxy|name|description|payload)\s*:", lower):
        return None
    for prefix, kind in (("domain:", "DOMAIN-SUFFIX"), ("full:", "DOMAIN"), ("keyword:", "DOMAIN-KEYWORD")):
        if lower.startswith(prefix):
            return build(kind, line[len(prefix):])
    if lower.startswith(("regexp:", "regex:", "include:")):
        return None
    parts = [p.strip() for p in line.split(",")]
    if len(parts) >= 2:
        kind = {"HOST": "DOMAIN", "HOST-SUFFIX": "DOMAIN-SUFFIX", "HOST-KEYWORD": "DOMAIN-KEYWORD", "DOMAIN-WILDCARD": "DOMAIN-SUFFIX"}.get(parts[0].upper(), parts[0].upper())
        if kind in PORTABLE_KINDS:
            return build(kind, parts[1], ",".join(parts[2:]).strip())
        return None
    domain = normalize_domain(line)
    return build("DOMAIN-SUFFIX", domain) if looks_like_domain(domain) else None


def dedupe_keep_order(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def fetch_remote(url: str) -> list[str]:
    req = urllib.request.Request(url, headers={"User-Agent": "proxy-rules-builder/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            data = resp.read()
        text = data.decode("utf-8", errors="ignore")
        eprint(f"[remote:ok] {url} ({len(text)} bytes)")
        return text.splitlines()
    except Exception as exc:
        eprint(f"[remote:failed] {url}: {exc}")
        return []


def collect_group(name: str) -> list[str]:
    rules: list[str] = []
    for url in SOURCES[name]:
        for line in fetch_remote(url):
            converted = convert_line(line)
            if converted:
                rules.append(converted)
        time.sleep(0.15)
    return dedupe_keep_order(rules)


def read_local_rules(path: Path) -> list[str]:
    if not path.exists():
        return []
    rules: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        converted = convert_line(line)
        if converted:
            rules.append(converted)
    return dedupe_keep_order(rules)


def write_rules(path: Path, title: str, rules: list[str]) -> None:
    body = [
        f"# {title}",
        "# Auto-generated by tools/build_rules.py.",
        "# Do not edit this generated file directly; edit *_added.list or sources in tools/build_rules.py.",
        "",
    ]
    body.extend(rules)
    body.append("")
    path.write_text("\n".join(body), encoding="utf-8")
    eprint(f"[write] {path.relative_to(ROOT)} ({len(rules)} rules)")


def to_oxidns_domain_set(rule: str) -> str | None:
    parts = [p.strip() for p in rule.split(",")]
    if len(parts) < 2:
        return None
    kind = parts[0].upper()
    value = parts[1]
    if kind == "DOMAIN":
        domain = normalize_domain(value)
        return f"full:{domain}" if looks_like_domain(domain) else None
    if kind == "DOMAIN-SUFFIX":
        domain = normalize_domain(value)
        return f"domain:{domain}" if looks_like_domain(domain) else None
    if kind == "DOMAIN-KEYWORD":
        keyword = value.strip().strip("'\"")
        return f"keyword:{keyword}" if keyword else None
    # OxiDNS domain_set cannot use IP-CIDR / IP-CIDR6 / IP-ASN entries.
    return None


def write_oxidns_rules(path: Path, title: str, rules: list[str]) -> None:
    entries = dedupe_keep_order(entry for rule in rules if (entry := to_oxidns_domain_set(rule)))
    body = [
        f"# {title}",
        "# Auto-generated by tools/build_rules.py for OxiDNS domain_set.",
        "# Do not edit this generated file directly.",
        "# DOMAIN -> full:, DOMAIN-SUFFIX -> domain:, DOMAIN-KEYWORD -> keyword:.",
        "# IP rules are intentionally omitted because OxiDNS domain_set matches qname only.",
        "",
    ]
    body.extend(entries)
    body.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(body), encoding="utf-8")
    eprint(f"[write] {path.relative_to(ROOT)} ({len(entries)} OxiDNS domain rules)")


def ensure_added_files() -> None:
    templates = {
        "proxy_added.list": "# Manual proxy rules. One portable classical rule per line.\n",
        "direct_added.list": "# Manual direct rules. One portable classical rule per line.\n",
        "reject_added.list": "# Manual reject rules. One portable classical rule per line.\n",
    }
    for filename, content in templates.items():
        path = ROOT / filename
        if not path.exists():
            path.write_text(content, encoding="utf-8")


def main() -> int:
    ensure_added_files()

    manual_reject = read_local_rules(ROOT / "reject_added.list")
    manual_proxy = read_local_rules(ROOT / "proxy_added.list")
    manual_direct = read_local_rules(ROOT / "direct_added.list")

    reject = collect_group("reject")
    proxy = collect_group("proxy")
    direct = collect_group("direct")

    reject_set = set(reject)
    proxy = [r for r in proxy if r not in reject_set]
    proxy_set = set(proxy)
    direct = [r for r in direct if r not in reject_set and r not in proxy_set]

    write_rules(ROOT / "reject.list", "Consolidated reject rules", reject)
    write_rules(ROOT / "proxy.list", "Consolidated proxy/global rules", proxy)
    write_rules(ROOT / "direct.list", "Consolidated direct/domestic rules", direct)

    write_oxidns_rules(OXIDNS_DIR / "reject_added.txt", "Manual reject rules", manual_reject)
    write_oxidns_rules(OXIDNS_DIR / "reject.txt", "Consolidated reject rules", reject)
    write_oxidns_rules(OXIDNS_DIR / "proxy_added.txt", "Manual proxy/global rules", manual_proxy)
    write_oxidns_rules(OXIDNS_DIR / "proxy.txt", "Consolidated proxy/global rules", proxy)
    write_oxidns_rules(OXIDNS_DIR / "direct_added.txt", "Manual direct/domestic rules", manual_direct)
    write_oxidns_rules(OXIDNS_DIR / "direct.txt", "Consolidated direct/domestic rules", direct)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
