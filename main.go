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
	domainDatFile = "whitedomains.dat"
	ipDatFile     = "whiteips.dat"
)

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
	geositeDat := encodeRepeated([][]byte{encodeTagged("DIRECT", encodedDomains)})

	if err := os.WriteFile(domainDatFile, geositeDat, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write whitedomains.dat: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("whitedomains.dat: %d domains, %d bytes\n", len(domains), len(geositeDat))

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
		entries, err := decodeDomains(domainDatFile)
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

func decodeDomains(path string) ([]domainEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var entries []domainEntry
	// GeoSiteList → field 1 repeated GeoSite
	pbIterBytes(data, 1, func(geosite []byte) {
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
	}
	for _, pf := range prefixes {
		if strings.HasPrefix(line, pf.p) {
			val := strings.TrimPrefix(line, pf.p)
			if val == "" {
				return domainEntry{}, fmt.Errorf("empty value")
			}
			return domainEntry{typ: pf.t, value: val}, nil
		}
	}
	return domainEntry{typ: domainTypeDomain, value: line}, nil
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
