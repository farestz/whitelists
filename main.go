package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	domainDatFile  = "whitedomains.dat"
	ipDatFile      = "whiteips.dat"
	domainListFile = "whitedomains.list" // Shadowrocket twin of whitedomains.dat (geosite:direct)
)

// Loyalsoldier publishes a compiled geosite.dat with all geosite:* tags fully
// resolved. We decode selected tags into Shadowrocket-format rule-sets for
// clients that can't read v2ray .dat (Shadowrocket, Surge, etc.). The .list is
// policy-less (DOMAIN-SUFFIX/DOMAIN/DOMAIN-KEYWORD only); the consumer picks the
// policy in its RULE-SET line (category-ru → DIRECT, youtube → PROXY).
var loyalsoldierGeositeURL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"

// loyalsoldierGeositeDat is where the compiled geosite.dat is downloaded once per
// build. Reused for both the embedded block tags (below) and the Shadowrocket
// rule-sets (geositeRuleSets).
const loyalsoldierGeositeDat = "data/loyalsoldier-geosite.dat"

// geositeBlockTags are decoded from Loyalsoldier's geosite and embedded as extra
// tags inside whitedomains.dat, so Happ can block them on-device via BlockSites
// (geosite:category-ads-all, geosite:category-ip-geo-detect) against the same
// Geositeurl .dat. Mirrors the server-side `block` outbound, moving the drop to
// the client (no proxy round-trip). The file keeps its DIRECT whitelist tag
// untouched — friends consuming only geosite:direct are unaffected.
var geositeBlockTags = []string{"category-ads-all", "category-ip-geo-detect"}

// geositeRuleSets maps a geosite tag to the rule-set file emitted from it.
var geositeRuleSets = []struct {
	tag  string
	file string
}{
	{"category-ru", "category-ru.list"},
	{"youtube", "youtube.list"},
}

// Domain type enum — matches v2ray-core app/router/config.proto
const (
	domainTypePlain  = 0
	domainTypeRegex  = 1
	domainTypeDomain = 2
	domainTypeFull   = 3
)

type upstream struct {
	url  string
	file string
}

var upstreamSources = []upstream{
	{"https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/cidrwhitelist.txt", "data/hxehex-cidrs.txt"},
}

var jsonCIDRSources = []upstream{
	{"https://raw.githubusercontent.com/openlibrecommunity/twl/main/code/subnet/out/subnets.c.json", "data/openlibre-cidrs.txt"},
}

// kirilllavrovDomainsTarball is a per-site list of RU domains (one file per
// service in domains/ru/). Extracted into kirilllavrovDomainsDir on build.
var (
	kirilllavrovDomainsTarball = "https://codeload.github.com/kirilllavrov/RU-domain-list-for-whitelist/tar.gz/refs/heads/main"
	kirilllavrovDomainsSubdir  = "domains/ru/"
	kirilllavrovDomainsDir     = "data/kirilllavrov-ru"
)

// kirilllavrovSkip lists domains/ru/* files NOT merged into the whitelist.
//   - "private": v2fly geosite:private (router admin panels, *.in-addr.arpa,
//     special-use TLDs, Tailscale ts.net) — not RU sites; bloats the DIRECT set
//     and its regexp:-prefixed entry (v2fly syntax) leaked as a malformed rule.
//   - "category-ru"/"whitelist-ru": pure v2fly aggregators — only `include:<svc>`
//     directives, no domains of their own. Every target already has its own
//     domains/ru/<svc> file that we flatten directly, so skipping these loses
//     nothing; keeping them only leaked junk `include:<svc>` entries.
var kirilllavrovSkip = map[string]bool{
	"private":      true,
	"category-ru":  true,
	"whitelist-ru": true,
}

var domainFiles = []string{
	"lists/domains-custom.txt",
}

var cidrFiles = []string{
	"data/hxehex-cidrs.txt",
	"data/openlibre-cidrs.txt",
	"lists/ips-custom.txt",
}

var cidrExcludeFile = "lists/ips-exclude.txt"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "check" {
		runCheck(os.Args[2:])
		return
	}
	runBuild()
}

// =============================================================================
// BUILD
// =============================================================================

func runBuild() {
	os.MkdirAll("data", 0755)

	for _, src := range upstreamSources {
		if err := download(src.url, src.file); err != nil {
			fmt.Fprintf(os.Stderr, "download %s: %v\n", src.url, err)
			os.Exit(1)
		}
	}

	for _, src := range jsonCIDRSources {
		if err := downloadJSONCIDRs(src.url, src.file); err != nil {
			fmt.Fprintf(os.Stderr, "download %s: %v\n", src.url, err)
			os.Exit(1)
		}
	}

	kirilllavrovFiles, err := extractTarballSubdir(kirilllavrovDomainsTarball, kirilllavrovDomainsSubdir, kirilllavrovDomainsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "download %s: %v\n", kirilllavrovDomainsTarball, err)
		os.Exit(1)
	}
	kirilllavrovFiles = filterOutBasenames(kirilllavrovFiles, kirilllavrovSkip)

	// Loyalsoldier's compiled geosite.dat — downloaded once, reused for the
	// embedded block tags below and the Shadowrocket rule-sets at the end.
	if err := download(loyalsoldierGeositeURL, loyalsoldierGeositeDat); err != nil {
		fmt.Fprintf(os.Stderr, "download geosite.dat: %v\n", err)
		os.Exit(1)
	}

	// Build whitedomains.dat
	allDomainFiles := append([]string{}, domainFiles...)
	allDomainFiles = append(allDomainFiles, kirilllavrovFiles...)
	domains, err := mergeDomains(allDomainFiles)
	if err != nil {
		fmt.Fprintf(os.Stderr, "domains: %v\n", err)
		os.Exit(1)
	}
	var encodedDomains [][]byte
	for _, e := range domains {
		encodedDomains = append(encodedDomains, encodeDomain(e.typ, e.value))
	}

	// DIRECT tag = our curated whitelist; plus block-category tags (ads, ip-geo-
	// detect) copied verbatim from Loyalsoldier so Happ can block them on-device.
	geositeItems := [][]byte{encodeTagged("DIRECT", encodedDomains)}
	for _, tag := range geositeBlockTags {
		entries, err := decodeTaggedDomains(loyalsoldierGeositeDat, tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "block tag %s: %v\n", tag, err)
			os.Exit(1)
		}
		if len(entries) == 0 {
			fmt.Fprintf(os.Stderr, "block tag %s: not found or empty in %s\n", tag, loyalsoldierGeositeDat)
			os.Exit(1)
		}
		var enc [][]byte
		for _, e := range entries {
			enc = append(enc, encodeDomain(e.typ, e.value))
		}
		geositeItems = append(geositeItems, encodeTagged(strings.ToUpper(tag), enc))
		fmt.Printf("whitedomains.dat += geosite:%s: %d domains (block)\n", tag, len(entries))
	}
	geositeDat := encodeRepeated(geositeItems)

	if err := os.WriteFile(domainDatFile, geositeDat, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write whitedomains.dat: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("whitedomains.dat: %d domains, %d bytes\n", len(domains), len(geositeDat))

	// Shadowrocket twin of whitedomains.dat: same curated RU whitelist as a
	// policy-less rule-set (the geosite:direct equivalent) for clients that can't
	// read .dat. Consumed as RULE-SET,…/whitedomains.list,DIRECT in whitelist mode.
	if err := writeDomainRuleSet(domainListFile, domains); err != nil {
		fmt.Fprintf(os.Stderr, "write whitedomains.list: %v\n", err)
		os.Exit(1)
	}

	// Build whiteips.dat
	cidrs, err := mergeCIDRs(cidrFiles)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cidrs: %v\n", err)
		os.Exit(1)
	}

	excludes, err := mergeCIDRs([]string{cidrExcludeFile})
	if err != nil {
		fmt.Fprintf(os.Stderr, "exclude cidrs: %v\n", err)
		os.Exit(1)
	}
	before := len(cidrs)
	cidrs = subtractCIDRs(cidrs, excludes)

	var encodedCIDRs [][]byte
	for _, c := range cidrs {
		encodedCIDRs = append(encodedCIDRs, encodeCIDR(c.ip, c.prefix))
	}
	geoipDat := encodeRepeated([][]byte{encodeTagged("DIRECT", encodedCIDRs)})

	if err := os.WriteFile(ipDatFile, geoipDat, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write whiteips.dat: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("whiteips.dat: %d CIDRs (%d before exclude of %d), %d bytes\n", len(cidrs), before, len(excludes), len(geoipDat))

	writeChecksum(domainDatFile, geositeDat)
	writeChecksum(ipDatFile, geoipDat)

	// Build Shadowrocket rule-sets (category-ru.list, youtube.list, …) from
	// Loyalsoldier geosite. Downloaded once, decoded per tag.
	if err := buildGeositeRuleSets(); err != nil {
		fmt.Fprintf(os.Stderr, "geosite rule-sets: %v\n", err)
		os.Exit(1)
	}
}

// buildGeositeRuleSets writes one Shadowrocket-format rule-set per entry in
// geositeRuleSets from the geosite.dat already downloaded in runBuild.
func buildGeositeRuleSets() error {
	for _, rs := range geositeRuleSets {
		if err := writeGeositeList(loyalsoldierGeositeDat, rs.tag, rs.file); err != nil {
			return fmt.Errorf("%s: %w", rs.file, err)
		}
	}
	return nil
}

// writeGeositeList extracts the given tag from a geosite .dat and writes a
// Shadowrocket rule-set. Domain types map to: domain → DOMAIN-SUFFIX, full →
// DOMAIN, plain → DOMAIN-KEYWORD. Regex entries are skipped — Shadowrocket
// rule-sets have no domain-regexp rule type. The list carries no policy; the
// consumer's RULE-SET line picks DIRECT/PROXY/REJECT.
func writeGeositeList(dat, tag, outFile string) error {
	entries, err := decodeTaggedDomains(dat, tag)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return fmt.Errorf("tag %q not found or empty in %s", tag, dat)
	}
	return writeDomainRuleSet(outFile, entries)
}

// writeDomainRuleSet converts domain entries to a Shadowrocket rule-set (domain →
// DOMAIN-SUFFIX, full → DOMAIN, plain → DOMAIN-KEYWORD; regex skipped — no
// domain-regexp rule type in Shadowrocket) and writes it with a checksum. The
// list is policy-less; the consumer's RULE-SET line picks DIRECT/PROXY/REJECT.
//
// No header/comment lines: Shadowrocket's remote rule-set parser is finicky
// (proven-working sets like surge.bojin.co's are pure TYPE,VALUE lines), and a
// non-ASCII or malformed leading line can make it drop the whole set. Provenance
// lives in the repo/release notes instead.
func writeDomainRuleSet(outFile string, entries []domainEntry) error {
	var b strings.Builder
	var rules, skipped int
	for _, e := range entries {
		var rt string
		switch e.typ {
		case domainTypeFull:
			rt = "DOMAIN"
		case domainTypeDomain:
			rt = "DOMAIN-SUFFIX"
		case domainTypePlain:
			rt = "DOMAIN-KEYWORD"
		default: // domainTypeRegex — unsupported in Shadowrocket rule-sets
			skipped++
			continue
		}
		b.WriteString(rt + "," + e.value + "\n")
		rules++
	}

	data := []byte(b.String())
	if err := os.WriteFile(outFile, data, 0644); err != nil {
		return err
	}
	fmt.Printf("%s: %d rules (%d regex skipped), %d bytes\n", outFile, rules, skipped, len(data))
	writeChecksum(outFile, data)
	return nil
}

// =============================================================================
// CHECK — decode .dat files and match queries using v2ray semantics
// =============================================================================

func runCheck(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: whitelists check <domain|ip> [...]")
		os.Exit(1)
	}

	var domainQueries, ipQueries []string
	for _, a := range args {
		if net.ParseIP(a) != nil {
			ipQueries = append(ipQueries, a)
		} else {
			domainQueries = append(domainQueries, a)
		}
	}

	allFound := true

	if len(domainQueries) > 0 {
		// DIRECT only — whitedomains.dat also carries block tags (category-ads-all,
		// category-ip-geo-detect); "is this whitelisted?" must ignore those.
		entries, err := decodeTaggedDomains(domainDatFile, "direct")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		m := buildDomainMatcher(entries)
		for _, q := range domainQueries {
			if !m.match(q) {
				allFound = false
			}
		}
	}

	if len(ipQueries) > 0 {
		ipNets, err := decodeCIDRNets(ipDatFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		for _, q := range ipQueries {
			if !matchIP(q, ipNets) {
				allFound = false
			}
		}
	}

	if !allFound {
		os.Exit(1)
	}
}

// --- domain matcher: O(1) map lookups + hierarchy walk ---

type regexRule struct {
	re  *regexp.Regexp
	src string
}

type domainMatcher struct {
	full    map[string]string // lowercase → original value
	domain  map[string]string
	regex   []regexRule
	keyword []string // pre-lowercased
}

func buildDomainMatcher(entries []domainEntry) *domainMatcher {
	m := &domainMatcher{
		full:   make(map[string]string),
		domain: make(map[string]string),
	}
	for _, e := range entries {
		low := strings.ToLower(e.value)
		switch e.typ {
		case domainTypeFull:
			m.full[low] = e.value
		case domainTypeDomain:
			m.domain[low] = e.value
		case domainTypeRegex:
			if re, err := regexp.Compile(e.value); err == nil {
				m.regex = append(m.regex, regexRule{re, e.value})
			}
		case domainTypePlain:
			m.keyword = append(m.keyword, low)
		}
	}
	return m
}

func (m *domainMatcher) match(query string) bool {
	q := strings.ToLower(query)

	if v, ok := m.full[q]; ok {
		fmt.Printf("FOUND  %s  (full:%s)\n", query, v)
		return true
	}

	// Domain hierarchy walk: sub.example.ru → example.ru → ru
	for candidate := q; candidate != ""; {
		if v, ok := m.domain[candidate]; ok {
			if candidate == q {
				fmt.Printf("FOUND  %s  (domain:%s)\n", query, v)
			} else {
				fmt.Printf("FOUND  %s  (domain:%s, subdomain)\n", query, v)
			}
			return true
		}
		dot := strings.IndexByte(candidate, '.')
		if dot == -1 {
			break
		}
		candidate = candidate[dot+1:]
	}

	for _, r := range m.regex {
		if r.re.MatchString(q) {
			fmt.Printf("FOUND  %s  (regex:%s)\n", query, r.src)
			return true
		}
	}

	for _, kw := range m.keyword {
		if strings.Contains(q, kw) {
			fmt.Printf("FOUND  %s  (keyword:%s)\n", query, kw)
			return true
		}
	}

	fmt.Printf("MISS   %s\n", query)
	return false
}

// --- IP matcher ---

func matchIP(query string, nets []*net.IPNet) bool {
	ip := net.ParseIP(query)
	if ip == nil {
		fmt.Fprintf(os.Stderr, "invalid IP: %s\n", query)
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			fmt.Printf("FOUND  %s  (%s)\n", query, n)
			return true
		}
	}
	fmt.Printf("MISS   %s\n", query)
	return false
}

// =============================================================================
// PROTOBUF DECODER — hand-rolled, mirrors the encoder
// =============================================================================

func pbReadVarint(buf []byte, pos int) (uint64, int) {
	var v uint64
	var shift uint
	for pos < len(buf) {
		b := buf[pos]
		pos++
		v |= uint64(b&0x7f) << shift
		if b < 0x80 {
			return v, pos
		}
		shift += 7
	}
	return v, pos
}

func pbReadBytes(buf []byte, pos int) ([]byte, int) {
	length, pos := pbReadVarint(buf, pos)
	end := pos + int(length)
	return buf[pos:end], end
}

func pbSkip(buf []byte, pos int, wireType int) int {
	switch wireType {
	case 0: // varint
		_, pos = pbReadVarint(buf, pos)
	case 2: // length-delimited
		_, pos = pbReadBytes(buf, pos)
	case 1: // 64-bit fixed
		pos += 8
	case 5: // 32-bit fixed
		pos += 4
	}
	return pos
}

// pbIterBytes iterates over length-delimited fields matching targetField.
func pbIterBytes(buf []byte, targetField int, fn func([]byte)) {
	pos := 0
	for pos < len(buf) {
		tag, newPos := pbReadVarint(buf, pos)
		pos = newPos
		fieldNum := int(tag >> 3)
		wireType := int(tag & 7)
		if fieldNum == targetField && wireType == 2 {
			data, newPos := pbReadBytes(buf, pos)
			pos = newPos
			fn(data)
		} else {
			pos = pbSkip(buf, pos, wireType)
		}
	}
}

// decodeTaggedDomains decodes a multi-tag geosite .dat (e.g. Loyalsoldier's, or
// our own whitedomains.dat) and returns the domain entries under the given tag,
// matched case-insensitively (v2ray stores tags uppercased: "category-ru" →
// "CATEGORY-RU").
func decodeTaggedDomains(path, tag string) ([]domainEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	want := strings.ToUpper(tag)
	var entries []domainEntry
	// GeoSiteList → field 1 repeated GeoSite
	pbIterBytes(data, 1, func(geosite []byte) {
		if strings.ToUpper(decodeGeoSiteTag(geosite)) != want {
			return
		}
		// GeoSite → field 2 repeated Domain
		pbIterBytes(geosite, 2, func(domain []byte) {
			typ, value := decodeDomainMsg(domain)
			if value != "" {
				entries = append(entries, domainEntry{typ: typ, value: value})
			}
		})
	})
	return entries, nil
}

// decodeGeoSiteTag reads field 1 (CountryCode/tag string) of a GeoSite message.
func decodeGeoSiteTag(buf []byte) string {
	pos := 0
	for pos < len(buf) {
		tag, np := pbReadVarint(buf, pos)
		pos = np
		fieldNum := int(tag >> 3)
		wireType := int(tag & 7)
		if fieldNum == 1 && wireType == 2 {
			vb, _ := pbReadBytes(buf, pos)
			return string(vb)
		}
		pos = pbSkip(buf, pos, wireType)
	}
	return ""
}

func decodeDomainMsg(buf []byte) (typ int, value string) {
	pos := 0
	for pos < len(buf) {
		tag, newPos := pbReadVarint(buf, pos)
		pos = newPos
		fieldNum := int(tag >> 3)
		wireType := int(tag & 7)
		switch {
		case fieldNum == 1 && wireType == 0: // type enum
			v, np := pbReadVarint(buf, pos)
			typ = int(v)
			pos = np
		case fieldNum == 2 && wireType == 2: // value string
			vb, np := pbReadBytes(buf, pos)
			value = string(vb)
			pos = np
		default:
			pos = pbSkip(buf, pos, wireType)
		}
	}
	return
}

func decodeCIDRNets(path string) ([]*net.IPNet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var nets []*net.IPNet
	pbIterBytes(data, 1, func(geoip []byte) {
		pbIterBytes(geoip, 2, func(cidr []byte) {
			ip, prefix := decodeCIDRMsg(cidr)
			if ip != nil {
				nets = append(nets, &net.IPNet{
					IP:   ip,
					Mask: net.CIDRMask(int(prefix), len(ip)*8),
				})
			}
		})
	})
	return nets, nil
}

func decodeCIDRMsg(buf []byte) (ip []byte, prefix uint32) {
	pos := 0
	for pos < len(buf) {
		tag, newPos := pbReadVarint(buf, pos)
		pos = newPos
		fieldNum := int(tag >> 3)
		wireType := int(tag & 7)
		switch {
		case fieldNum == 1 && wireType == 2: // ip bytes
			vb, np := pbReadBytes(buf, pos)
			ip = vb
			pos = np
		case fieldNum == 2 && wireType == 0: // prefix varint
			v, np := pbReadVarint(buf, pos)
			prefix = uint32(v)
			pos = np
		default:
			pos = pbSkip(buf, pos, wireType)
		}
	}
	return
}

// =============================================================================
// BUILD HELPERS — download, parse, merge
// =============================================================================

var httpClient = &http.Client{Timeout: 30 * time.Second}

func download(url, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	resp, err := httpClient.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	tmp := dest + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest)
}

// downloadJSONCIDRs fetches a JSON array of {"cidr": "..."} objects and
// writes one CIDR per line to dest, so it plugs into the standard CIDR
// merge/dedup pipeline.
func downloadJSONCIDRs(url, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	resp, err := httpClient.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var entries []struct {
		CIDR string `json:"cidr"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return fmt.Errorf("parse JSON: %w", err)
	}

	tmp := dest + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, e := range entries {
		if e.CIDR == "" {
			continue
		}
		if _, err := w.WriteString(e.CIDR + "\n"); err != nil {
			f.Close()
			os.Remove(tmp)
			return err
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest)
}

// extractTarballSubdir downloads a .tar.gz from url and writes every regular
// file whose path (after the leading top-level directory GitHub injects) starts
// with subdir into destDir, flattened. Returns the destination paths sorted by
// name. destDir is wiped before extraction so stale files don't linger.
func extractTarballSubdir(url, subdir, destDir string) ([]string, error) {
	if err := os.RemoveAll(destDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return nil, err
	}

	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var written []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		// GitHub tarballs prefix everything with "<repo>-<ref>/". Strip it.
		parts := strings.SplitN(hdr.Name, "/", 2)
		if len(parts) != 2 {
			continue
		}
		rel := parts[1]
		if !strings.HasPrefix(rel, subdir) {
			continue
		}
		name := strings.TrimPrefix(rel, subdir)
		if name == "" || strings.Contains(name, "/") {
			continue // skip nested dirs — flat layout only
		}
		dest := filepath.Join(destDir, name)
		f, err := os.Create(dest)
		if err != nil {
			return nil, err
		}
		if _, err := io.Copy(f, tr); err != nil {
			f.Close()
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
		written = append(written, dest)
	}
	sort.Strings(written)
	return written, nil
}

// filterOutBasenames drops paths whose base name is in skip.
func filterOutBasenames(paths []string, skip map[string]bool) []string {
	kept := paths[:0:0]
	for _, p := range paths {
		if skip[filepath.Base(p)] {
			continue
		}
		kept = append(kept, p)
	}
	return kept
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, scanner.Err()
}

type domainEntry struct {
	typ   int
	value string
}

func mergeDomains(files []string) ([]domainEntry, error) {
	seen := make(map[string]bool)
	var result []domainEntry

	for _, path := range files {
		lines, err := readLines(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		for _, line := range lines {
			if strings.HasPrefix(line, "include:") {
				continue // v2fly aggregator directive — the referenced file is flattened directly
			}
			e, err := parseDomainLine(line)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: %s: skipping %q: %v\n", path, line, err)
				continue
			}
			key := fmt.Sprintf("%d:%s", e.typ, strings.ToLower(e.value))
			if !seen[key] {
				seen[key] = true
				result = append(result, e)
			}
		}
	}
	return result, nil
}

func parseDomainLine(line string) (domainEntry, error) {
	prefixes := []struct {
		p string
		t int
	}{
		{"full:", domainTypeFull},
		{"domain:", domainTypeDomain},
		{"regex:", domainTypeRegex},
		{"regexp:", domainTypeRegex}, // v2fly spelling — else it leaks as a bare domain
	}
	for _, pf := range prefixes {
		if strings.HasPrefix(line, pf.p) {
			val := strings.TrimPrefix(line, pf.p)
			if val == "" {
				return domainEntry{}, fmt.Errorf("empty value")
			}
			if pf.t != domainTypeRegex {
				val = domainToASCII(val)
			}
			return domainEntry{typ: pf.t, value: val}, nil
		}
	}
	return domainEntry{typ: domainTypeDomain, value: domainToASCII(line)}, nil
}

// domainToASCII converts any non-ASCII (IDN U-label) parts of a domain to their
// punycode A-label form (xn--…). Real traffic arrives as A-labels (SNI/Host), and
// both Shadowrocket rule-sets and the v2ray .dat want ASCII — a U-label rule like
// "яндекс.рф" matches nothing and is non-ASCII junk. ASCII labels pass through.
// Hand-rolled RFC 3492 to keep the build zero-dependency (no x/net/idna).
func domainToASCII(domain string) string {
	if isASCII(domain) {
		return domain
	}
	labels := strings.Split(domain, ".")
	for i, lab := range labels {
		if !isASCII(lab) {
			labels[i] = "xn--" + punycodeEncode(lab)
		}
	}
	return strings.Join(labels, ".")
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// punycodeEncode encodes a single non-ASCII label per RFC 3492 (Punycode).
func punycodeEncode(label string) string {
	const (
		base        = 36
		tmin        = 1
		tmax        = 26
		initialBias = 72
		initialN    = 128
	)
	input := []rune(label)
	var out strings.Builder
	basic := 0
	for _, r := range input {
		if r < initialN {
			out.WriteByte(byte(r))
			basic++
		}
	}
	h := basic
	if basic > 0 {
		out.WriteByte('-')
	}
	n, delta, bias := initialN, 0, initialBias
	for h < len(input) {
		m := 0x7fffffff
		for _, r := range input {
			if int(r) >= n && int(r) < m {
				m = int(r)
			}
		}
		delta += (m - n) * (h + 1)
		n = m
		for _, r := range input {
			c := int(r)
			if c < n {
				delta++
			}
			if c == n {
				q := delta
				for k := base; ; k += base {
					t := k - bias
					if t < tmin {
						t = tmin
					} else if t > tmax {
						t = tmax
					}
					if q < t {
						break
					}
					out.WriteByte(punyDigit(t + (q-t)%(base-t)))
					q = (q - t) / (base - t)
				}
				out.WriteByte(punyDigit(q))
				bias = punyAdapt(delta, h+1, h == basic)
				delta = 0
				h++
			}
		}
		delta++
		n++
	}
	return out.String()
}

func punyAdapt(delta, numPoints int, firstTime bool) int {
	const (
		base = 36
		tmin = 1
		tmax = 26
		skew = 38
		damp = 700
	)
	if firstTime {
		delta /= damp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := 0
	for delta > ((base-tmin)*tmax)/2 {
		delta /= base - tmin
		k += base
	}
	return k + (base-tmin+1)*delta/(delta+skew)
}

func punyDigit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}

type cidrEntry struct {
	ip     []byte
	prefix uint32
}

func mergeCIDRs(files []string) ([]cidrEntry, error) {
	seen := make(map[string]bool)
	var result []cidrEntry

	for _, path := range files {
		lines, err := readLines(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		for _, line := range lines {
			_, ipNet, err := net.ParseCIDR(line)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: %s: skipping %q: %v\n", path, line, err)
				continue
			}
			ip := ipNet.IP.To4()
			if ip == nil {
				ip = ipNet.IP.To16()
			}
			ones, _ := ipNet.Mask.Size()
			e := cidrEntry{ip: ip, prefix: uint32(ones)}
			key := string(e.ip) + "/" + line[strings.IndexByte(line, '/')+1:]
			if !seen[key] {
				seen[key] = true
				result = append(result, e)
			}
		}
	}
	return result, nil
}

// subtractCIDRs removes every prefix in excludes from includes, splitting
// covering prefixes into smaller ones where needed so no excluded address
// remains in the result.
func subtractCIDRs(includes, excludes []cidrEntry) []cidrEntry {
	result := includes
	for _, e := range excludes {
		var next []cidrEntry
		for _, i := range result {
			next = append(next, subtractOne(i, e)...)
		}
		result = next
	}
	return result
}

func subtractOne(inc, exc cidrEntry) []cidrEntry {
	if len(inc.ip) != len(exc.ip) {
		return []cidrEntry{inc} // different address families
	}
	if cidrContains(exc, inc) {
		return nil // include fully covered → drop
	}
	if !cidrContains(inc, exc) {
		return []cidrEntry{inc} // no overlap
	}
	lo, hi := splitPrefix(inc)
	return append(subtractOne(lo, exc), subtractOne(hi, exc)...)
}

// cidrContains reports whether parent contains child (parent ⊇ child).
func cidrContains(parent, child cidrEntry) bool {
	if parent.prefix > child.prefix {
		return false
	}
	full := int(parent.prefix) / 8
	rem := int(parent.prefix) % 8
	for i := 0; i < full; i++ {
		if parent.ip[i] != child.ip[i] {
			return false
		}
	}
	if rem > 0 {
		mask := byte(0xff << (8 - rem))
		if parent.ip[full]&mask != child.ip[full]&mask {
			return false
		}
	}
	return true
}

// splitPrefix splits p into two prefixes of length p.prefix+1, differing
// in the next bit. Caller must ensure p.prefix < len(p.ip)*8.
func splitPrefix(p cidrEntry) (cidrEntry, cidrEntry) {
	lo := cidrEntry{ip: append([]byte(nil), p.ip...), prefix: p.prefix + 1}
	hi := cidrEntry{ip: append([]byte(nil), p.ip...), prefix: p.prefix + 1}
	byteIdx := int(p.prefix) / 8
	bitIdx := int(p.prefix) % 8
	hi.ip[byteIdx] |= 1 << (7 - bitIdx)
	return lo, hi
}

func writeChecksum(path string, data []byte) {
	hash := sha256.Sum256(data)
	line := fmt.Sprintf("%x  %s\n", hash, path)
	if err := os.WriteFile(path+".sha256sum", []byte(line), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "checksum %s: %v\n", path, err)
	}
}

// =============================================================================
// PROTOBUF ENCODER
// =============================================================================

func encodeDomain(typ int, value string) []byte {
	var b []byte
	if typ != 0 {
		b = appendVarintField(b, 1, uint64(typ))
	}
	b = appendStringField(b, 2, value)
	return b
}

func encodeCIDR(ip []byte, prefix uint32) []byte {
	var b []byte
	b = appendBytesField(b, 1, ip)
	if prefix != 0 {
		b = appendVarintField(b, 2, uint64(prefix))
	}
	return b
}

func encodeTagged(tag string, entries [][]byte) []byte {
	var b []byte
	b = appendStringField(b, 1, tag)
	for _, e := range entries {
		b = appendBytesField(b, 2, e)
	}
	return b
}

func encodeRepeated(items [][]byte) []byte {
	var b []byte
	for _, item := range items {
		b = appendBytesField(b, 1, item)
	}
	return b
}

func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func appendVarintField(b []byte, fieldNum int, v uint64) []byte {
	b = appendVarint(b, uint64(fieldNum<<3|0))
	b = appendVarint(b, v)
	return b
}

func appendBytesField(b []byte, fieldNum int, data []byte) []byte {
	b = appendVarint(b, uint64(fieldNum<<3|2))
	b = appendVarint(b, uint64(len(data)))
	b = append(b, data...)
	return b
}

func appendStringField(b []byte, fieldNum int, s string) []byte {
	return appendBytesField(b, fieldNum, []byte(s))
}
