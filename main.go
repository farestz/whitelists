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
	"time"
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
	{"https://raw.githubusercontent.com/artembolotov/custom-geosite/main/lists/direct.txt", "data/artembolotov-domains.txt"},
	{"https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/whitelist.txt", "data/hxehex-domains.txt"},
	{"https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/cidrwhitelist.txt", "data/hxehex-cidrs.txt"},
}

var domainFiles = []string{
	"data/artembolotov-domains.txt",
	"data/hxehex-domains.txt",
	"lists/domains-custom.txt",
}

var cidrFiles = []string{
	"data/hxehex-cidrs.txt",
	"lists/ips-custom.txt",
}

func main() {
	os.MkdirAll("data", 0755)

	for _, src := range upstreamSources {
		if err := download(src.url, src.file); err != nil {
			fmt.Fprintf(os.Stderr, "download %s: %v\n", src.url, err)
			os.Exit(1)
		}
	}

	// Build whitedomains.dat
	domains, err := mergeDomains(domainFiles)
	if err != nil {
		fmt.Fprintf(os.Stderr, "domains: %v\n", err)
		os.Exit(1)
	}

	var encodedDomains [][]byte
	for _, e := range domains {
		encodedDomains = append(encodedDomains, encodeDomain(e.typ, e.value))
	}
	geositeDat := encodeRepeated([][]byte{encodeTagged("DIRECT", encodedDomains)})

	if err := os.WriteFile("whitedomains.dat", geositeDat, 0644); err != nil {
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

	var encodedCIDRs [][]byte
	for _, c := range cidrs {
		encodedCIDRs = append(encodedCIDRs, encodeCIDR(c.ip, c.prefix))
	}
	geoipDat := encodeRepeated([][]byte{encodeTagged("DIRECT", encodedCIDRs)})

	if err := os.WriteFile("whiteips.dat", geoipDat, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write whiteips.dat: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("whiteips.dat: %d CIDRs, %d bytes\n", len(cidrs), len(geoipDat))

	// SHA256 checksums
	writeChecksum("whitedomains.dat", geositeDat)
	writeChecksum("whiteips.dat", geoipDat)
}

// --- download ---

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

// --- line reading ---

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

// --- domain parsing ---

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

// --- CIDR parsing ---

type cidrEntry struct {
	ip     []byte // 4 bytes IPv4, 16 bytes IPv6
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

// --- SHA256 checksum ---

func writeChecksum(path string, data []byte) {
	hash := sha256.Sum256(data)
	line := fmt.Sprintf("%x  %s\n", hash, path)
	if err := os.WriteFile(path+".sha256sum", []byte(line), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "checksum %s: %v\n", path, err)
	}
}

// --- protobuf encoding ---
// Schema: v2ray-core app/router/routercommon/common.proto

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

// encodeTagged encodes a GeoSite or GeoIP message: tag (field 1) + repeated entries (field 2).
func encodeTagged(tag string, entries [][]byte) []byte {
	var b []byte
	b = appendStringField(b, 1, tag)
	for _, e := range entries {
		b = appendBytesField(b, 2, e)
	}
	return b
}

// encodeRepeated encodes a GeoSiteList or GeoIPList: repeated messages (field 1).
func encodeRepeated(items [][]byte) []byte {
	var b []byte
	for _, item := range items {
		b = appendBytesField(b, 1, item)
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
