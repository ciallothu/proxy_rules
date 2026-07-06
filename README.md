# proxy_rules

This repository now uses six canonical portable rule files:

- `proxy_added.list`: manual proxy/global rules for temporary additions.
- `direct_added.list`: manual direct/domestic rules for temporary additions.
- `reject_added.list`: manual reject/adblock rules for temporary additions.
- `proxy.list`: generated consolidated proxy/global rules.
- `direct.list`: generated consolidated direct/domestic rules.
- `reject.list`: generated consolidated reject/adblock rules.

The generated files are built by `tools/build_rules.py` and the GitHub Actions workflow in `.github/workflows/build-rules.yml`.

## Update model

Edit only the manual files when you need a quick override:

```text
proxy_added.list
direct_added.list
reject_added.list
```

Do not manually edit these generated files:

```text
proxy.list
direct.list
reject.list
```

The workflow runs every day at 04:17 Asia/Shanghai / Asia/Tokyo and can also be triggered manually from GitHub Actions.

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

Avoid client-specific route-control rules inside these remote lists, such as `RULE-SET`, `GEOSITE`, `GEOIP`, `MATCH`, `PROCESS-NAME`, `SCRIPT`, or policy names. Put route-control logic in the client config instead.

## Raw URLs

```text
https://raw.githubusercontent.com/ciallothu/proxy_rules/main/proxy_added.list
https://raw.githubusercontent.com/ciallothu/proxy_rules/main/direct_added.list
https://raw.githubusercontent.com/ciallothu/proxy_rules/main/reject_added.list
https://raw.githubusercontent.com/ciallothu/proxy_rules/main/proxy.list
https://raw.githubusercontent.com/ciallothu/proxy_rules/main/direct.list
https://raw.githubusercontent.com/ciallothu/proxy_rules/main/reject.list
```
