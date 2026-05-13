# Whitelists

Generates v2ray/xray-compatible `whitedomains.dat` and `whiteips.dat` with Russian whitelisted domains and IPs.

## Build

```bash
docker build --output=. .
```

Produces `whitedomains.dat`, `whiteips.dat`, `*.sha256sum` in the current directory.

## Client usage

Tag `DIRECT` — use in routing rules:
- `ext:whitedomains.dat:direct` — domains
- `ext:whiteips.dat:direct` — IP addresses

## Data sources

Upstream (fetched at build time):
- [artembolotov/custom-geosite](https://github.com/artembolotov/custom-geosite) → `lists/direct.txt`
- [hxehex/russia-mobile-internet-whitelist](https://github.com/hxehex/russia-mobile-internet-whitelist) → `whitelist.txt`, `cidrwhitelist.txt`
- [openlibrecommunity/twl](https://github.com/openlibrecommunity/twl) → `code/subnet/out/subnets.c.json` (JSON; only `cidr` field is used)

Custom (committed to repo):
- `lists/domains-custom.txt` — domains, one per line
- `lists/ips-custom.txt` — CIDRs, one per line

### Custom domain format

```
example.ru          # domain: match (host + subdomains), default
full:exact.host.ru  # full: exact match only
domain:example.ru   # domain: explicit
regex:^.*\.ru$      # regex: regular expression
```

## CLI — check entries

```bash
go run . check oneme.ru vk.com           # check domains
go run . check 2.63.1.1                  # check IP
go run . check oneme.ru 2.63.1.1         # mixed — auto-detects domain vs IP
```

- Decodes .dat files (hand-rolled protobuf decoder)
- Matching follows v2ray semantics: domain: (subdomains), full: (exact), regex:, keyword:
- Domains: O(1) map lookup + hierarchy walk for subdomains
- IPs: CIDR containment via net.IPNet.Contains()
- Exit code: 0 if all found, 1 if any miss

## Technical details

- Go 1.23+, zero dependencies
- Hand-rolled protobuf encoding/decoding (v2ray-core GeoSite/GeoIP format)
- Domain and CIDR deduplication when merging sources
