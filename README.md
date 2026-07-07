# proxy_rules

`proxy_rules` is a consolidated proxy-rule repository for Surge, mihomo, Egern, Loon, OxiDNS, and other clients that can consume remote rule lists.

The repository exposes six canonical portable client rule files and six generated OxiDNS domain-set files. Client configurations should reference the canonical files instead of directly referencing many third-party upstream rule sources.

## Canonical client files

| File | Type | Purpose |
| --- | --- | --- |
| `proxy_added.list` | Manual | Temporary or personal proxy/global rules. Edit this file directly when a domain should go through proxy immediately. |
| `direct_added.list` | Manual | Temporary or personal direct/domestic rules. Edit this file directly when a domain should go direct immediately. |
| `reject_added.list` | Manual | Temporary or personal reject/adblock rules. Edit this file directly when a domain should be blocked immediately. |
| `proxy.list` | Generated | Consolidated proxy/global rules from upstream sources. Do not edit manually. |
| `direct.list` | Generated | Consolidated direct/domestic rules from upstream sources. Do not edit manually. |
| `reject.list` | Generated | Consolidated reject/adblock rules from upstream sources. Do not edit manually. |

## Generated OxiDNS files

OxiDNS `domain_set` uses a different domain format, so the workflow also generates OxiDNS-specific files under `oxidns/`:

| File | Source | Purpose |
| --- | --- | --- |
| `oxidns/proxy_added.txt` | `proxy_added.list` | Manual proxy/global domain-set rules for OxiDNS. |
| `oxidns/direct_added.txt` | `direct_added.list` | Manual direct/domestic domain-set rules for OxiDNS. |
| `oxidns/reject_added.txt` | `reject_added.list` | Manual reject/adblock domain-set rules for OxiDNS. |
| `oxidns/proxy.txt` | `proxy.list` | Generated proxy/global domain-set rules for OxiDNS. |
| `oxidns/direct.txt` | `direct.list` | Generated direct/domestic domain-set rules for OxiDNS. |
| `oxidns/reject.txt` | `reject.list` | Generated reject/adblock domain-set rules for OxiDNS. |

The conversion is:

```text
DOMAIN,example.com         -> full:example.com
DOMAIN-SUFFIX,example.com  -> domain:example.com
DOMAIN-KEYWORD,example     -> keyword:example
```

IP-based rules are intentionally omitted from OxiDNS files because OxiDNS `domain_set` matches DNS query names.

## Recommended jsDelivr URLs

Use jsDelivr as the client-side distribution endpoint:

```text
https://cdn.jsdelivr.net/gh/ciallothu/proxy_rules@main/proxy_added.list
https://cdn.jsdelivr.net/gh/ciallothu/proxy_rules@main/direct_added.list
https://cdn.jsdelivr.net/gh/ciallothu/proxy_rules@main/reject_added.list
https://cdn.jsdelivr.net/gh/ciallothu/proxy_rules@main/proxy.list
https://cdn.jsdelivr.net/gh/ciallothu/proxy_rules@main/direct.list
https://cdn.jsdelivr.net/gh/ciallothu/proxy_rules@main/reject.list
```

Use these URLs for OxiDNS:

```text
https://cdn.jsdelivr.net/gh/ciallothu/proxy_rules@main/oxidns/proxy_added.txt
https://cdn.jsdelivr.net/gh/ciallothu/proxy_rules@main/oxidns/direct_added.txt
https://cdn.jsdelivr.net/gh/ciallothu/proxy_rules@main/oxidns/reject_added.txt
https://cdn.jsdelivr.net/gh/ciallothu/proxy_rules@main/oxidns/proxy.txt
https://cdn.jsdelivr.net/gh/ciallothu/proxy_rules@main/oxidns/direct.txt
https://cdn.jsdelivr.net/gh/ciallothu/proxy_rules@main/oxidns/reject.txt
```

Raw GitHub URLs are fallback only:

```text
https://raw.githubusercontent.com/ciallothu/proxy_rules/main/proxy_added.list
https://raw.githubusercontent.com/ciallothu/proxy_rules/main/direct_added.list
https://raw.githubusercontent.com/ciallothu/proxy_rules/main/reject_added.list
https://raw.githubusercontent.com/ciallothu/proxy_rules/main/proxy.list
https://raw.githubusercontent.com/ciallothu/proxy_rules/main/direct.list
https://raw.githubusercontent.com/ciallothu/proxy_rules/main/reject.list
```

## Update model

For daily use, edit only the manual files:

```text
proxy_added.list
direct_added.list
reject_added.list
```

Do not manually edit generated files:

```text
proxy.list
direct.list
reject.list
oxidns/*.txt
```

Generated files are rebuilt by:

```text
tools/build_rules.py
.github/workflows/build-rules.yml
```

The workflow runs every day at 04:17 Asia/Shanghai / Asia/Tokyo and can also be triggered manually from GitHub Actions.

After each build, the workflow purges jsDelivr cache for all six canonical client files and all six OxiDNS files through:

```text
https://purge.jsdelivr.net/gh/ciallothu/proxy_rules@main/<file>
```

This keeps `https://cdn.jsdelivr.net/gh/ciallothu/proxy_rules@main/*.list` and `https://cdn.jsdelivr.net/gh/ciallothu/proxy_rules@main/oxidns/*.txt` reasonably fresh after GitHub Actions updates generated rule files.

## Client rule format

Use portable classical rule syntax, one rule per line:

```text
DOMAIN,example.com
DOMAIN-SUFFIX,example.com
DOMAIN-KEYWORD,example
IP-CIDR,1.2.3.0/24,no-resolve
IP-CIDR6,2001:db8::/32,no-resolve
IP-ASN,15169
```

Avoid client-specific route-control rules inside these remote lists, such as:

```text
RULE-SET
GEOSITE
GEOIP
MATCH
PROCESS-NAME
SCRIPT
policy names
```

Put route-control logic in the client config instead.

## Typical client priority

Client configurations should normally apply rules in this order:

```text
reject_added
reject
proxy_added
proxy
direct_added
direct
final/default
```

This keeps blocking rules first, then proxy/global rules, then direct/domestic rules.
