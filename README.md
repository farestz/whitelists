# whitelists

Russian internet whitelisted domains and IPs in v2ray/xray format.

Unique entries merged from multiple upstream sources, rebuilt daily.

## Download

Grab the latest release assets:

- [`whitedomains.dat`](../../releases/latest/download/whitedomains.dat) — domains (v2ray/xray)
- [`whiteips.dat`](../../releases/latest/download/whiteips.dat) — IPs (CIDR, v2ray/xray)
- [`whitedomains.list`](../../releases/latest/download/whitedomains.list) — same curated whitelist as a Shadowrocket/Surge rule-set (the `geosite:direct` twin of `whitedomains.dat`)
- [`category-ru.list`](../../releases/latest/download/category-ru.list) — `geosite:category-ru` as a Shadowrocket/Surge rule-set
- [`youtube.list`](../../releases/latest/download/youtube.list) — `geosite:youtube` as a Shadowrocket/Surge rule-set

## Usage

In v2ray/xray routing rules:

    ext:whitedomains.dat:direct
    ext:whiteips.dat:direct

In Shadowrocket / Surge (`[Rule]`):

    RULE-SET,https://github.com/farestz/whitelists/releases/latest/download/whitedomains.list,DIRECT
    RULE-SET,https://github.com/farestz/whitelists/releases/latest/download/category-ru.list,DIRECT
    RULE-SET,https://github.com/farestz/whitelists/releases/latest/download/youtube.list,PROXY

## Sources

- [hxehex/russia-mobile-internet-whitelist](https://github.com/hxehex/russia-mobile-internet-whitelist) — IP CIDRs (domains list not used)
- [openlibrecommunity/twl](https://github.com/openlibrecommunity/twl) — IP subnets (CIDRs only)
- [kirilllavrov/RU-domain-list-for-whitelist](https://github.com/kirilllavrov/RU-domain-list-for-whitelist) — per-service RU domain lists from `domains/ru/` (fetched as tarball at build time)
- [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat) — compiled `geosite.dat`; the `CATEGORY-RU` and `YOUTUBE` tags are decoded into `category-ru.list` / `youtube.list` (Shadowrocket/Surge). Independent of the `.dat` build above.

Local additions: [`lists/domains-custom.txt`](lists/domains-custom.txt) (domains), [`lists/ips-custom.txt`](lists/ips-custom.txt) — merged on top. Local exclusions subtracted from the merged result: [`lists/domains-exclude.txt`](lists/domains-exclude.txt) (domains), [`lists/ips-exclude.txt`](lists/ips-exclude.txt) (CIDRs).

## Build locally

```bash
docker build --output=. .
```
