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

- [hxehex/russia-mobile-internet-whitelist](https://github.com/hxehex/russia-mobile-internet-whitelist) — IP CIDRs (domains list not used)
- [openlibrecommunity/twl](https://github.com/openlibrecommunity/twl) — IP subnets (CIDRs only)

Domains come only from [`lists/domains-custom.txt`](lists/domains-custom.txt).

Custom additions: [`lists/`](lists/)

## Build locally

```bash
docker build --output=. .
```
