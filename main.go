package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Domain type enum — matches v2ray-core app/router/config.proto
const (
	domainTypePlain  = 0
	domainTypeRegex  = 1
	domainTypeDomain = 2
	domainTypeFull   = 3
)

// Upstream source URLs
var upstreamDomains = []struct {
	url  string
	file string
}{
	{"https://raw.githubusercontent.com/artembolotov/custom-geosite/main/lists/direct.txt", "data/artembolotov-domains.txt"},
	{"https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/whitelist.txt", "data/hxehex-domains.txt"},
}

var upstreamCIDRs = []struct {
	url  string
	file string
}{
	{"https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/cidrwhitelist.txt", "data/hxehex-cidrs.txt"},
}

func main() {
	os.MkdirAll("data", 0755)

	// Download upstream sources
	for _, src := range upstreamDomains {
		if err := download(src.url, src.file); err != nil {
			fmt.Fprintf(os.Stderr, "download %s: %v\n", src.url, err)
			os.Exit(1)
		}
	}
	for _, src := range upstreamCIDRs {
		if err := download(src.url, src.file); err != nil {
			fmt.Fprintf(os.Stderr, "download %s: %v\n", src.url, err)
			os.Exit(1)
		}
	}

	// Build whitedomains.dat
	domainFiles := []string{
		"data/artembolotov-domains.txt",
		"data/hxehex-domains.txt",
		"lists/domains-custom.txt",
	}
	domains, err := mergeDomains(domainFiles)
	if err != nil {
		fmt.Fprintf(os.Stderr, "domains: %v\n", err)
		os.Exit(1)
	}

	var encodedDomains [][]byte
	for _, e := range domains {
		encodedDomains = append(encodedDomains, encodeDomain(e.typ, e.value))
	}
	geoSite := encodeGeoSite("DIRECT", encodedDomains)
	geositeDat := encodeGeoSiteList([][]byte{geoSite})

	if err := os.WriteFile("whitedomains.dat", geositeDat, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write whitedomains.dat: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("whitedomains.dat: %d domains, %d bytes\n", len(domains), len(geositeDat))

	// Build whiteips.dat
	cidrFiles := []string{
		"data/hxehex-cidrs.txt",
		"lists/ips-custom.txt",
	}
	cidrs, err := mergeCIDRs(cidrFiles)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cidrs: %v\n", err)
		os.Exit(1)
	}

	var encodedCIDRs [][]byte
	for _, c := range cidrs {
		encodedCIDRs = append(encodedCIDRs, encodeCIDR(c.ip, c.prefix))
	}
	geoIP := encodeGeoIP("DIRECT", encodedCIDRs)
	geoipDat := encodeGeoIPList([][]byte{geoIP})

	if err := os.WriteFile("whiteips.dat", geoipDat, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write whiteips.dat: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("whiteips.dat: %d CIDRs, %d bytes\n", len(cidrs), len(geoipDat))

	// SHA256 checksums
	writeChecksum("whitedomains.dat")
	writeChecksum("whiteips.dat")
}

// --- download ---

func download(url, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

// --- domain parsing ---

type domainEntry struct {
	typ   int
	value string
}

func mergeDomains(files []string) ([]domainEntry, error) {
	seen := make(map[string]bool)
	var result []domainEntry

	for _, path := range files {
		entries, err := readDomains(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		for _, e := range entries {
			key := fmt.Sprintf("%d:%s", e.typ, strings.ToLower(e.value))
			if !seen[key] {
				seen[key] = true
				result = append(result, e)
			}
		}
	}
	return result, nil
}

func readDomains(path string) ([]domainEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []domainEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		e, err := parseDomainLine(line)
		if err != nil {
			continue // skip malformed lines
		}
		entries = append(entries, e)
	}
	return entries, scanner.Err()
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

// --- CIDR parsing ---

type cidrEntry struct {
	ip     []byte // 4 bytes IPv4, 16 bytes IPv6
	prefix uint32
}

func mergeCIDRs(files []string) ([]cidrEntry, error) {
	seen := make(map[string]bool)
	var result []cidrEntry

	for _, path := range files {
		entries, err := readCIDRs(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		for _, e := range entries {
			key := fmt.Sprintf("%v/%d", e.ip, e.prefix)
			if !seen[key] {
				seen[key] = true
				result = append(result, e)
			}
		}
	}
	return result, nil
}

func readCIDRs(path string) ([]cidrEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []cidrEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, ipNet, err := net.ParseCIDR(line)
		if err != nil {
			continue // skip malformed lines
		}
		ip := ipNet.IP.To4()
		if ip == nil {
			ip = ipNet.IP.To16()
		}
		ones, _ := ipNet.Mask.Size()
		entries = append(entries, cidrEntry{ip: ip, prefix: uint32(ones)})
	}
	return entries, scanner.Err()
}

// --- SHA256 checksum ---

func writeChecksum(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "checksum %s: %v\n", path, err)
		return
	}
	hash := sha256.Sum256(data)
	line := fmt.Sprintf("%x  %s\n", hash, path)
	os.WriteFile(path+".sha256sum", []byte(line), 0644)
}

// --- protobuf encoding (GeoSite) ---

func encodeDomain(typ int, value string) []byte {
	var b []byte
	if typ != 0 {
		b = appendVarintField(b, 1, uint64(typ))
	}
	b = appendStringField(b, 2, value)
	return b
}

func encodeGeoSite(tag string, domains [][]byte) []byte {
	var b []byte
	b = appendStringField(b, 1, tag)
	for _, d := range domains {
		b = appendBytesField(b, 2, d)
	}
	return b
}

func encodeGeoSiteList(geoSites [][]byte) []byte {
	var b []byte
	for _, gs := range geoSites {
		b = appendBytesField(b, 1, gs)
	}
	return b
}

// --- protobuf encoding (GeoIP) ---
// Schema: v2ray-core app/router/routercommon/common.proto

func encodeCIDR(ip []byte, prefix uint32) []byte {
	var b []byte
	b = appendBytesField(b, 1, ip)
	if prefix != 0 {
		b = appendVarintField(b, 2, uint64(prefix))
	}
	return b
}

func encodeGeoIP(tag string, cidrs [][]byte) []byte {
	var b []byte
	b = appendStringField(b, 1, tag)
	for _, c := range cidrs {
		b = appendBytesField(b, 2, c)
	}
	return b
}

func encodeGeoIPList(geoIPs [][]byte) []byte {
	var b []byte
	for _, g := range geoIPs {
		b = appendBytesField(b, 1, g)
	}
	return b
}

// --- low-level protobuf wire helpers ---

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
