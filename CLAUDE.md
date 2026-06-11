# Whitelists

Generates v2ray/xray-compatible `whitedomains.dat` and `whiteips.dat` with Russian whitelisted domains and IPs, plus Shadowrocket/Surge rule-sets (`category-ru.list`, `youtube.list`) decoded from Loyalsoldier's `geosite:*`.

## Build

```bash
docker build --output=. .
```

Produces `whitedomains.dat`, `whiteips.dat`, `category-ru.list`, `youtube.list`, `*.sha256sum` in the current directory.

## Client usage

v2ray/xray (tag `DIRECT`):

- `ext:whitedomains.dat:direct` — domains
- `ext:whiteips.dat:direct` — IP addresses

Shadowrocket / Surge (`[Rule]`) — note the policy differs per list:

- `RULE-SET,…/releases/latest/download/category-ru.list,DIRECT`
- `RULE-SET,…/releases/latest/download/youtube.list,PROXY`

## Two independent datasets

- `whitedomains.dat` / `whiteips.dat` — **our curated** RU whitelist (custom + kirilllavrov + CIDR upstreams).
- `category-ru.list` / `youtube.list` — **Loyalsoldier's** `geosite:*` tags, decoded to Shadowrocket rule-sets. NOT derived from the curated set; separate upstream so Shadowrocket clients get parity with the xray `geosite:*` rules. Built by `buildGeositeRuleSets()` in `main.go`: downloads `geosite.dat` once, then `writeGeositeList()` extracts each tag in `geositeRuleSets` (domain→DOMAIN-SUFFIX, full→DOMAIN, plain→DOMAIN-KEYWORD; regex skipped). The `.list` carries no policy — the consumer's RULE-SET line picks DIRECT/PROXY. To add another geosite tag: append to `geositeRuleSets` + the Dockerfile/CI artifact lists.

## Data sources

Upstream CIDR sources (fetched at build time):

- [hxehex/russia-mobile-internet-whitelist](https://github.com/hxehex/russia-mobile-internet-whitelist) → `cidrwhitelist.txt`
- [openlibrecommunity/twl](https://github.com/openlibrecommunity/twl) → `code/subnet/out/subnets.c.json` (JSON; only `cidr` field is used)

Upstream domain source (fetched at build time as tarball):

- [kirilllavrov/RU-domain-list-for-whitelist](https://github.com/kirilllavrov/RU-domain-list-for-whitelist) → `domains/ru/*` files flattened into `data/kirilllavrov-ru/` (one file per service, one domain per line)

Custom (committed to repo):

- `lists/domains-custom.txt` — local domain additions, merged on top of the upstream list
- `lists/ips-custom.txt` — extra CIDRs to add, one per line
- `lists/ips-exclude.txt` — CIDRs to subtract from the merged IP whitelist (for RKN-SNI-blocked sites that must go through the VPN)

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
