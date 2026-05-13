# whitelists

Russian internet whitelisted domains and IPs in v2ray/xray format.

Unique entries merged from multiple upstream sources, rebuilt daily.

## Download

Grab the latest release assets:
- [`whitedomains.dat`](../../releases/latest/download/whitedomains.dat) — domains
- [`whiteips.dat`](../../releases/latest/download/whiteips.dat) — IPs (CIDR)

## Usage

In v2ray/xray routing rules:

    ext:whitedomains.dat:direct
    ext:whiteips.dat:direct

## Sources

- [artembolotov/custom-geosite](https://github.com/artembolotov/custom-geosite) — curated Russian domains
- [hxehex/russia-mobile-internet-whitelist](https://github.com/hxehex/russia-mobile-internet-whitelist) — mobile network whitelisted domains & IPs
- [openlibrecommunity/twl](https://github.com/openlibrecommunity/twl) — IP subnets (CIDRs only)

Custom additions: [`lists/`](lists/)

## Build locally

```bash
docker build --output=. .
```
