package threatfeed

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// ThreatIntelligence aggregates threat data from multiple sources
type ThreatIntelligence struct {
	Domain          string
	IPs             []string
	URLhausMatches  []URLhausEntry
	ThreatFoxIOCs   []ThreatFoxIOC
	SSLBlacklist    []string
	FeodoTrackerIPs []string
	IsCompromised   bool
	ThreatScore     int // 0-100, higher = more dangerous
	ThreatTags      []string
}

// URLhausEntry represents a malicious URL from URLhaus
type URLhausEntry struct {
	URL           string
	Status        string
	Threat        string
	Tags          []string
	FirstSeen     string
	Takedown      string
	MalwareFamily string
	ReporterName  string
}

// ThreatFoxIOC represents an Indicator of Compromise from ThreatFox
type ThreatFoxIOC struct {
	IOCType       string
	IOCValue      string
	MalwareFamily string
	Confidence    int
	FirstSeen     string
	Tags          []string
	Reporter      string
}

// CheckAbuseCH queries multiple abuse.ch services for threat intelligence
// All services are FREE and require NO API keys
func CheckAbuseCH(domain string, ips []string) (*ThreatIntelligence, error) {
	result := &ThreatIntelligence{
		Domain:      domain,
		IPs:         ips,
		ThreatScore: 0,
	}

	log.Printf("[*] Checking abuse.ch threat feeds for %s", domain)

	// 1. URLhaus - Malicious URL database
	urlhausResults := checkURLhaus(domain)
	result.URLhausMatches = urlhausResults
	if len(urlhausResults) > 0 {
		result.IsCompromised = true
		result.ThreatScore += 30
		result.ThreatTags = append(result.ThreatTags, "urlhaus")
	}

	// 2. ThreatFox - IOC database
	threatFoxResults := checkThreatFox(domain, ips)
	result.ThreatFoxIOCs = threatFoxResults
	if len(threatFoxResults) > 0 {
		result.IsCompromised = true
		result.ThreatScore += 40
		result.ThreatTags = append(result.ThreatTags, "threatfox")
	}

	// 3. SSL Blacklist - Bad SSL certificates
	sslResults := checkSSLBlacklist(ips)
	result.SSLBlacklist = sslResults
	if len(sslResults) > 0 {
		result.ThreatScore += 15
		result.ThreatTags = append(result.ThreatTags, "ssl_blacklist")
	}

	// 4. Feodo Tracker - Botnet C2 IPs
	feodoResults := checkFeodoTracker(ips)
	result.FeodoTrackerIPs = feodoResults
	if len(feodoResults) > 0 {
		result.IsCompromised = true
		result.ThreatScore += 50
		result.ThreatTags = append(result.ThreatTags, "botnet_c2")
	}

	if result.ThreatScore > 100 {
		result.ThreatScore = 100
	}

	log.Printf("[+] Abuse.ch check complete: ThreatScore=%d/100, Compromised=%v",
		result.ThreatScore, result.IsCompromised)

	return result, nil
}

// checkURLhaus queries URLhaus for malicious URLs associated with the domain
func checkURLhaus(domain string) []URLhausEntry {
	// URLhaus API endpoint (free, no key required)
	url := "https://urlhaus-api.abuse.ch/v1/host/"

	payload := fmt.Sprintf("host=%s", domain)
	req, err := http.NewRequest("POST", url, strings.NewReader(payload))
	if err != nil {
		log.Printf("[-] Failed to create URLhaus request: %v", err)
		return nil
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "gomain_analysis/1.0 (Threat Intelligence Tool)")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[-] URLhaus query failed: %v", err)
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	// Parse JSON response
	var apiResp struct {
		QueryStatus string `json:"query_status"`
		URLs        []struct {
			URL         string   `json:"url"`
			URLStatus   string   `json:"url_status"`
			DateAdded   string   `json:"date_added"`
			Threat      string   `json:"threat"`
			Tags        []string `json:"tags"`
			URLhausLink string   `json:"urlhaus_link"`
			Reporter    string   `json:"reporter"`
		} `json:"urls"`
	}

	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil
	}

	if apiResp.QueryStatus != "ok" {
		return nil
	}

	var results []URLhausEntry
	for _, u := range apiResp.URLs {
		results = append(results, URLhausEntry{
			URL:          u.URL,
			Status:       u.URLStatus,
			Threat:       u.Threat,
			Tags:         u.Tags,
			FirstSeen:    u.DateAdded,
			ReporterName: u.Reporter,
		})
	}

	if len(results) > 0 {
		log.Printf("[!] URLhaus: Found %d malicious URLs for %s", len(results), domain)
	}

	return results
}

// checkThreatFox queries ThreatFox IOC database
func checkThreatFox(domain string, ips []string) []ThreatFoxIOC {
	// ThreatFox API (free, no key required)
	url := "https://threatfox-api.abuse.ch/api/v1/"

	// Check domain first
	iocs := queryThreatFoxIOC(url, "domain", domain)

	// Check each IP
	for _, ip := range ips {
		ipIOCs := queryThreatFoxIOC(url, "ip:port", ip)
		iocs = append(iocs, ipIOCs...)
	}

	if len(iocs) > 0 {
		log.Printf("[!] ThreatFox: Found %d IOCs", len(iocs))
	}

	return iocs
}

// queryThreatFoxIOC performs the actual ThreatFox API query
func queryThreatFoxIOC(apiURL, iocType, value string) []ThreatFoxIOC {
	payload := fmt.Sprintf(`{"query":"search_ioc","search_term":%q}`, value)

	req, err := http.NewRequest("POST", apiURL, strings.NewReader(payload))
	if err != nil {
		return nil
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "gomain_analysis/1.0")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var apiResp struct {
		QueryStatus string `json:"query_status"`
		Data        []struct {
			IOCType      string   `json:"ioc_type"`
			IOCValue     string   `json:"ioc_value"`
			MalwareAlias string   `json:"malware_alias"`
			Confidence   int      `json:"confidence_level"`
			FirstSeen    string   `json:"first_seen"`
			Tags         []string `json:"tags"`
			Reporter     string   `json:"reporter"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil
	}

	if apiResp.QueryStatus != "ok" {
		return nil
	}

	var results []ThreatFoxIOC
	for _, d := range apiResp.Data {
		results = append(results, ThreatFoxIOC{
			IOCType:       d.IOCType,
			IOCValue:      d.IOCValue,
			MalwareFamily: d.MalwareAlias,
			Confidence:    d.Confidence,
			FirstSeen:     d.FirstSeen,
			Tags:          d.Tags,
			Reporter:      d.Reporter,
		})
	}

	return results
}

// checkSSLBlacklist checks if any IPs are in SSL Blacklist
func checkSSLBlacklist(ips []string) []string {
	// Download the SSL Blacklist CSV (updated daily, free)
	url := "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"

	req, err := http.NewRequest("GET", url, http.NoBody)
	if err != nil {
		return nil
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	// Parse CSV
	reader := csv.NewReader(resp.Body)
	reader.Comment = '#'

	blacklistedIPs := make(map[string]bool)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if len(record) > 0 {
			blacklistedIPs[record[0]] = true
		}
	}

	// Check our IPs against blacklist
	var matches []string
	for _, ip := range ips {
		if blacklistedIPs[ip] {
			matches = append(matches, ip)
			log.Printf("[!] SSL Blacklist: IP %s is blacklisted", ip)
		}
	}

	return matches
}

// checkFeodoTracker checks if IPs are Feodo Tracker botnet C2s
func checkFeodoTracker(ips []string) []string {
	// Feodo Tracker IP blocklist (updated frequently, free)
	url := "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"

	req, err := http.NewRequest("GET", url, http.NoBody)
	if err != nil {
		return nil
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	// Parse line-by-line
	scanner := bufio.NewScanner(resp.Body)
	botnetIPs := make(map[string]bool)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Validate it's an IP
		if net.ParseIP(line) != nil {
			botnetIPs[line] = true
		}
	}

	// Check our IPs
	var matches []string
	for _, ip := range ips {
		if botnetIPs[ip] {
			matches = append(matches, ip)
			log.Printf("[!!!] CRITICAL: IP %s is a known botnet C2 server (Feodo Tracker)", ip)
		}
	}

	return matches
}

// GetThreatSeverity returns a human-readable threat level
func (t *ThreatIntelligence) GetThreatSeverity() string {
	switch {
	case t.ThreatScore >= 80:
		return "CRITICAL"
	case t.ThreatScore >= 60:
		return "HIGH"
	case t.ThreatScore >= 40:
		return "MEDIUM"
	case t.ThreatScore >= 20:
		return "LOW"
	default:
		return "CLEAN"
	}
}
