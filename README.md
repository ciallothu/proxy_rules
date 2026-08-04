# proxy_rules

`proxy_rules` is a consolidated proxy-rule repository for Surge, mihomo, Egern, Loon, OxiDNS, and other clients that can consume remote rule lists.

The repository exposes canonical portable client rule files, generated OxiDNS domain-set files, and mirrored GeoX assets. Client configurations should reference this repository instead of directly depending on many third-party upstream sources.

## GeoX assets

The workflow mirrors Loyalsoldier v2ray-rules-dat GeoX databases for machines that cannot directly access external networks:

| File | Source |
| --- | --- |
| `geox/geoip.dat` | `https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat` |
| `geox/geosite.dat` | `https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat` |

Recommended URLs:

```text
https://cdn.jsdelivr.net/gh/ciallothu/proxy_rules@main/geox/geoip.dat
https://cdn.jsdelivr.net/gh/ciallothu/proxy_rules@main/geosite.dat
```

## Update model

Generated assets are updated by:

```text
tools/build_rules.py
tools/fetch_geox.py
.github/workflows/build-rules.yml
```

The workflow runs every day at 04:17 Asia/Shanghai / Asia/Tokyo and can also be triggered manually from GitHub Actions.
