# Whitelists

Generates v2ray/xray-compatible `whitedomains.dat` and `whiteips.dat` with Russian whitelisted domains and IPs, plus Shadowrocket/Surge rule-sets: `whitedomains.list` (our curated whitelist, the `geosite:direct` twin) and `category-ru.list` / `youtube.list` (decoded from Loyalsoldier's `geosite:*`).

## Build

```bash
docker build --output=. .
```

Produces `whitedomains.dat`, `whiteips.dat`, `whitedomains.list`, `category-ru.list`, `youtube.list`, `*.sha256sum` in the current directory.

## Client usage

v2ray/xray (tag `DIRECT`):

- `ext:whitedomains.dat:direct` — domains
- `ext:whiteips.dat:direct` — IP addresses

Shadowrocket / Surge (`[Rule]`) — note the policy differs per list:

- `RULE-SET,…/releases/latest/download/whitedomains.list,DIRECT`
- `RULE-SET,…/releases/latest/download/category-ru.list,DIRECT`
- `RULE-SET,…/releases/latest/download/youtube.list,PROXY`

## Rule-set artifacts — two origins

All three `.list` files share the same Shadowrocket format (policy-less; consumer's RULE-SET line picks DIRECT/PROXY) and the same domain→rule conversion (`writeDomainRuleSet()`: domain→DOMAIN-SUFFIX, full→DOMAIN, plain→DOMAIN-KEYWORD; regex skipped — no domain-regexp rule type in Shadowrocket). They differ in where their domains come from:

- `whitedomains.list` — **our curated** RU whitelist, the Shadowrocket twin of `whitedomains.dat` (same `domains` slice, i.e. the `geosite:direct` tag). Emitted inline in `main()` right after `whitedomains.dat`. This is what a Shadowrocket _whitelist-mode_ config routes to DIRECT (everything else → PROXY), matching the Happ `whitelists.json` profile (`DirectSites: ["geosite:direct"]`).
- `category-ru.list` / `youtube.list` — **Loyalsoldier's** `geosite:*` tags, decoded from their compiled `geosite.dat`. NOT derived from the curated set; separate upstream so Shadowrocket clients get parity with the xray `geosite:*` rules. Built by `buildGeositeRuleSets()` → `writeGeositeList()` per tag in `geositeRuleSets`. To add another geosite tag: append to `geositeRuleSets` + the Dockerfile/CI artifact lists.

`whitedomains.dat` / `whiteips.dat` are the v2ray/xray form of the curated whitelist (custom + kirilllavrov + CIDR upstreams).

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
