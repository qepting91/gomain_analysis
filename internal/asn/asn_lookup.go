package asn

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// ASNInfo represents information about an Autonomous System
type ASNInfo struct {
	ASN         string   `json:"asn"`
	Name        string   `json:"name"`
	Country     string   `json:"country"`
	IPRanges    []string `json:"ip_ranges"`
	Description string   `json:"description"`
}

// HackerTargetResponse represents the response from HackerTarget API
type HackerTargetResponse struct {
	ASN         string
	Description string
	IPRanges    []string
}

// LookupASN discovers the Autonomous System Number for an IP or domain
// Uses multiple free sources: HackerTarget, RIPE, ARIN
func LookupASN(target string) (*ASNInfo, error) {
	// If target is a domain, resolve to IP first
	var ip string
	if net.ParseIP(target) != nil {
		ip = target
	} else {
		ips, err := net.LookupHost(target)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("failed to resolve domain: %v", err)
		}
		ip = ips[0]
	}

	// Try HackerTarget first (no API key required, rate limited)
	info, err := lookupASNHackerTarget(ip)
	if err == nil && info != nil {
		return info, nil
	}

	log.Printf("HackerTarget failed: %v, trying WHOIS fallback", err)

	// Fallback to WHOIS-based lookup
	return lookupASNWhois(ip)
}

// lookupASNHackerTarget queries HackerTarget's free ASN lookup
func lookupASNHackerTarget(ip string) (*ASNInfo, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/aslookup/?q=%s", ip)
	client := &http.Client{Timeout: 15 * time.Second}

	req, err := http.NewRequest("GET", url, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "gomain_analysis/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse response format: "AS15169","GOOGLE","US"
	// or "error no results"
	result := string(body)
	if strings.Contains(result, "error") {
		return nil, fmt.Errorf("no results found")
	}

	parts := strings.Split(strings.ReplaceAll(result, "\"", ""), ",")
	if len(parts) < 2 {
		return nil, fmt.Errorf("unexpected response format")
	}

	info := &ASNInfo{
		ASN:     strings.TrimSpace(parts[0]),
		Name:    strings.TrimSpace(parts[1]),
		Country: "",
	}
	if len(parts) >= 3 {
		info.Country = strings.TrimSpace(parts[2])
	}

	// Now get IP ranges for this ASN
	ranges, err := getASNIPRanges(info.ASN)
	if err != nil {
		log.Printf("Warning: failed to get IP ranges for %s: %v", info.ASN, err)
	}
	info.IPRanges = ranges

	log.Printf("[+] ASN discovered: %s (%s) - %d IP ranges", info.ASN, info.Name, len(info.IPRanges))
	return info, nil
}

// getASNIPRanges retrieves all IP ranges announced by an ASN
func getASNIPRanges(asn string) ([]string, error) {
	// Remove "AS" prefix if present
	asn = strings.TrimPrefix(asn, "AS")

	url := fmt.Sprintf("https://api.hackertarget.com/aslookup/?q=AS%s", asn)
	client := &http.Client{Timeout: 15 * time.Second}

	req, err := http.NewRequest("GET", url, http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse IP ranges from response
	var ranges []string
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Look for CIDR notation
		if strings.Contains(line, "/") && (strings.Contains(line, ".") || strings.Contains(line, ":")) {
			ranges = append(ranges, line)
		}
	}

	return ranges, nil
}

// lookupASNWhois performs WHOIS-based ASN lookup (fallback method)
func lookupASNWhois(ip string) (*ASNInfo, error) {
	// Use Team Cymru's WHOIS service (no API key, highly reliable)
	url := fmt.Sprintf("https://whois.cymru.com/cgi-bin/whois.cgi?action=do_whois&bulk_paste=%s", ip)
	client := &http.Client{Timeout: 15 * time.Second}

	req, err := http.NewRequest("GET", url, http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse Cymru response
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		if strings.Contains(line, "|") && !strings.HasPrefix(line, "AS") {
			parts := strings.Split(line, "|")
			if len(parts) >= 3 {
				return &ASNInfo{
					ASN:         strings.TrimSpace(parts[0]),
					Name:        strings.TrimSpace(parts[2]),
					Country:     strings.TrimSpace(parts[1]),
					Description: strings.TrimSpace(parts[2]),
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("failed to parse WHOIS response")
}

// EnumerateRelatedDomains finds other domains hosted in the same ASN
// This reveals the target's infrastructure neighbors and potential related assets
func EnumerateRelatedDomains(asn string) ([]string, error) {
	// This would typically require:
	// 1. Get all IP ranges for ASN
	// 2. Perform reverse DNS on sample IPs
	// 3. Query certificate transparency for those IPs

	// For now, return a placeholder
	log.Println("[*] Related domain enumeration requires extended implementation")
	return []string{}, nil
}

// RIPEStatResponse represents response from RIPE Stat API
type RIPEStatResponse struct {
	Data struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"prefixes"`
	} `json:"data"`
}

// GetASNPrefixesRIPE queries RIPE NCC's free API for ASN prefixes
func GetASNPrefixesRIPE(asn string) ([]string, error) {
	asn = strings.TrimPrefix(asn, "AS")
	url := fmt.Sprintf("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%s", asn)

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", url, http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RIPE API returned status %d", resp.StatusCode)
	}

	var ripeResp RIPEStatResponse
	if err := json.NewDecoder(resp.Body).Decode(&ripeResp); err != nil {
		return nil, err
	}

	var prefixes []string
	for _, prefix := range ripeResp.Data.Prefixes {
		prefixes = append(prefixes, prefix.Prefix)
	}

	log.Printf("[+] RIPE Stat: Found %d prefixes for %s", len(prefixes), asn)
	return prefixes, nil
}
