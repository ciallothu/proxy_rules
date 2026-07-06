# proxy_rules

`proxy_rules` is a consolidated proxy-rule repository for Surge, mihomo, Egern, Loon, and other clients that can consume classical remote rule lists.

The repository exposes six canonical portable rule files. Client configurations should reference only these six files instead of directly referencing many third-party rule sources.

## Canonical files

| File | Type | Purpose |
| --- | --- | --- |
| `proxy_added.list` | Manual | Temporary or personal proxy/global rules. Edit this file directly when a domain should go through proxy immediately. |
| `direct_added.list` | Manual | Temporary or personal direct/domestic rules. Edit this file directly when a domain should go direct immediately. |
| `reject_added.list` | Manual | Temporary or personal reject/adblock rules. Edit this file directly when a domain should be blocked immediately. |
| `proxy.list` | Generated | Consolidated proxy/global rules from upstream sources. Do not edit manually. |
| `direct.list` | Generated | Consolidated direct/domestic rules from upstream sources. Do not edit manually. |
| `reject.list` | Generated | Consolidated reject/adblock rules from upstream sources. Do not edit manually. |

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

Raw GitHub URLs are kept as fallback only:

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
```

Generated files are rebuilt by:

```text
tools/build_rules.py
.github/workflows/build-rules.yml
```

The workflow runs every day at 04:17 Asia/Shanghai / Asia/Tokyo and can also be triggered manually from GitHub Actions.

After each build, the workflow purges jsDelivr cache for all six canonical files through:

```text
https://purge.jsdelivr.net/gh/ciallothu/proxy_rules@main/<file>
```

This keeps `https://cdn.jsdelivr.net/gh/ciallothu/proxy_rules@main/*.list` reasonably fresh after GitHub Actions updates the generated rule files.

## Rule format

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
