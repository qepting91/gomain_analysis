package subfinder

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// CTEntry represents a Certificate Transparency log entry from crt.sh
type CTEntry struct {
	NameValue string `json:"name_value"`
}

// VTSubdomainResponse represents VirusTotal's subdomain API response
type VTSubdomainResponse struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
}

// EnumerateWithFallback attempts multiple passive subdomain enumeration methods
// in order of preference: Subfinder -> crt.sh -> VirusTotal -> Amass
func EnumerateWithFallback(domain string) []string {
	// Try 1: Subfinder (primary method)
	log.Println("[*] Attempting subdomain enumeration with Subfinder...")
	results := Enumerate(domain)
	if len(results) > 0 {
		log.Printf("[+] Subfinder successful: %d subdomains found", len(results))
		return results
	}

	// Try 2: Certificate Transparency logs via crt.sh (100% passive, no dependencies)
	log.Println("[*] Subfinder unavailable. Falling back to Certificate Transparency logs (crt.sh)...")
	results = enumerateViaCrtSh(domain)
	if len(results) > 0 {
		log.Printf("[+] crt.sh successful: %d subdomains found", len(results))
		return results
	}

	// Try 3: VirusTotal API (if API key available)
	if vtAPIKey := os.Getenv("VT_API_KEY"); vtAPIKey != "" {
		log.Println("[*] Attempting VirusTotal subdomain API...")
		results = enumerateViaVirusTotal(domain, vtAPIKey)
		if len(results) > 0 {
			log.Printf("[+] VirusTotal successful: %d subdomains found", len(results))
			return results
		}
	}

	// Try 4: Amass (if installed)
	log.Println("[*] Checking for Amass installation...")
	results = enumerateViaAmass(domain)
	if len(results) > 0 {
		log.Printf("[+] Amass successful: %d subdomains found", len(results))
		return results
	}

	log.Println("[!] All subdomain enumeration methods exhausted. Returning empty results.")
	return []string{}
}

// enumerateViaCrtSh queries Certificate Transparency logs via crt.sh API
// This is 100% passive and requires no authentication
func enumerateViaCrtSh(domain string) []string {
	// Use the JSON endpoint format that crt.sh prefers: /json?q=%.domain
	url := fmt.Sprintf("https://crt.sh/json?q=%%.%s", domain)

	// crt.sh can be VERY slow (30-90 seconds) for popular domains with many certs
	client := &http.Client{Timeout: 90 * time.Second}

	log.Println("[*] Querying crt.sh Certificate Transparency logs (this may take 30-60 seconds)...")

	req, err := http.NewRequest("GET", url, http.NoBody)
	if err != nil {
		log.Printf("[-] Failed to create crt.sh request: %v", err)
		return []string{}
	}

	req.Header.Set("User-Agent", "gomain_analysis/1.0 (CTI Research Tool)")
	req.Header.Set("Accept", "application/json")

	// Retry logic: crt.sh can return 503/429 when overloaded
	maxRetries := 2
	var resp *http.Response
	var respErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			waitTime := time.Duration(attempt*5) * time.Second
			log.Printf("[*] crt.sh query failed, retrying in %v (attempt %d/%d)...", waitTime, attempt+1, maxRetries+1)
			time.Sleep(waitTime)
		}

		resp, respErr = client.Do(req)
		if respErr != nil {
			if attempt == maxRetries {
				log.Printf("[-] Failed to query crt.sh after %d attempts: %v", maxRetries+1, respErr)
				return []string{}
			}
			continue
		}

		// Check status code
		if resp.StatusCode == http.StatusOK {
			break // Success!
		}

		// Handle rate limiting / service unavailable
		if resp.StatusCode == 503 || resp.StatusCode == 429 {
			resp.Body.Close()
			if attempt == maxRetries {
				log.Printf("[-] crt.sh overloaded (status %d) after %d attempts", resp.StatusCode, maxRetries+1)
				return []string{}
			}
			continue
		}

		// Other non-200 status
		resp.Body.Close()
		log.Printf("[-] crt.sh returned status %d", resp.StatusCode)
		return []string{}
	}
	defer resp.Body.Close()

	log.Println("[*] crt.sh responded, processing certificate data...")

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[-] Failed to read crt.sh response: %v", err)
		return []string{}
	}

	// Log response size for debugging slow queries
	if len(body) > 1024*1024 {
		log.Printf("[*] Large response received: %.2f MB", float64(len(body))/1024/1024)
	}

	var entries []CTEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		log.Printf("[-] Failed to parse crt.sh JSON: %v", err)
		return []string{}
	}

	log.Printf("[*] Processing %d certificate entries...", len(entries))

	// Deduplicate and clean subdomains
	subdomainMap := make(map[string]bool)
	for _, entry := range entries {
		// CT logs can contain multiple subdomains per entry (separated by newlines)
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(name)
			name = strings.ToLower(name)
			// Remove wildcard indicators
			name = strings.TrimPrefix(name, "*.")
			if name != "" && strings.HasSuffix(name, domain) {
				subdomainMap[name] = true
			}
		}
	}

	results := make([]string, 0, len(subdomainMap))
	for subdomain := range subdomainMap {
		results = append(results, subdomain)
	}

	return results
}

// enumerateViaVirusTotal uses VirusTotal's subdomain API
func enumerateViaVirusTotal(domain, apiKey string) []string {
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=100", domain)
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequest("GET", url, http.NoBody)
	if err != nil {
		log.Printf("[-] Failed to create VirusTotal request: %v", err)
		return []string{}
	}

	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[-] Failed to query VirusTotal: %v", err)
		return []string{}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[-] VirusTotal returned non-200 status: %d", resp.StatusCode)
		return []string{}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[-] Failed to read VirusTotal response: %v", err)
		return []string{}
	}

	var vtResp VTSubdomainResponse
	if err := json.Unmarshal(body, &vtResp); err != nil {
		log.Printf("[-] Failed to parse VirusTotal JSON: %v", err)
		return []string{}
	}

	results := make([]string, 0, len(vtResp.Data))
	for _, item := range vtResp.Data {
		if item.ID != "" {
			results = append(results, item.ID)
		}
	}

	return results
}

// enumerateViaAmass attempts to use Amass if it's installed on the system
func enumerateViaAmass(domain string) []string {
	// Check if Amass is installed
	_, err := exec.LookPath("amass")
	if err != nil {
		log.Println("[-] Amass not found in PATH. Skipping.")
		return []string{}
	}

	// #nosec G204 -- domain is validated by caller, used for legitimate CTI purposes
	cmd := exec.Command("amass", "enum", "-passive", "-d", domain, "-silent")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("[-] Amass execution failed: %v", err)
		return []string{}
	}

	results := []string{}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		subdomain := strings.TrimSpace(line)
		if subdomain != "" {
			results = append(results, subdomain)
		}
	}

	return results
}
