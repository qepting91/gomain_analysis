package crt

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// CRTSHURL is the base URL for crt.sh
const CRTSHURL = "https://crt.sh"

// CTLog represents a single record from crt.sh
type CTLog struct {
	IssuerCaID        int    `json:"issuer_ca_id"`
	IssuerName        string `json:"issuer_name"`
	NameValue         string `json:"name_value"`
	MinCertID         int    `json:"min_cert_id"`
	MinEntryTimestamp string `json:"min_entry_timestamp"`
	NotBefore         string `json:"not_before"`
	NotAfter          string `json:"not_after"`
}

// QueryCrtsh sends an HTTP GET request to crt.sh and returns the response body, with retries.
func QueryCrtsh(url string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	var lastErr error
	for attempts := 1; attempts <= 3; attempts++ {
		req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %v", err)
		}

		// Spoof a normal browser to avoid basic WAF blocking
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			log.Printf("crt.sh query attempt %d failed: %v", attempts, err)
			time.Sleep(time.Duration(attempts) * 2 * time.Second) // backoff
			continue
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("unexpected status code from crt.sh: %d", resp.StatusCode)
			log.Printf("crt.sh query attempt %d failed: %v", attempts, lastErr)
			time.Sleep(time.Duration(attempts) * 2 * time.Second)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read crt.sh response body: %v", err)
		}

		return body, nil
	}

	return nil, fmt.Errorf("all crt.sh query attempts failed. Last error: %v", lastErr)
}

// QueryByDomain queries crt.sh for certificates by domain, extracts all subdomains,
// handles newlines in SANs, strips wildcards, and deduplicates the final list.
func QueryByDomain(domain string) ([]string, error) {
	// FIXED: Added %%25. to act as the URL-encoded wildcard query (%.domain)
	url := fmt.Sprintf("%s/?output=json&q=%%25.%s", CRTSHURL, domain)

	body, err := QueryCrtsh(url)
	if err != nil {
		return nil, err
	}

	var logs []CTLog
	if err := json.Unmarshal(body, &logs); err != nil {
		return nil, fmt.Errorf("failed to parse crt.sh response (likely returned HTML 502 error): %v", err)
	}

	// FIXED: Deduplicate by domain string, not by Certificate ID
	seen := make(map[string]struct{})
	var uniqueSubdomains []string

	for _, l := range logs {
		// FIXED: Split multiple SANs hidden inside the single name_value string
		names := strings.Split(l.NameValue, "\n")

		for _, name := range names {
			// Clean up the string by removing wildcard prefixes
			cleanName := strings.TrimPrefix(name, "*.")
			cleanName = strings.TrimSpace(cleanName)

			// Deduplicate using an empty struct map (memory efficient)
			if cleanName != "" {
				if _, exists := seen[cleanName]; !exists {
					seen[cleanName] = struct{}{}
					uniqueSubdomains = append(uniqueSubdomains, cleanName)
				}
			}
		}
	}

	log.Printf("Successfully retrieved %d unique subdomains for %s", len(uniqueSubdomains), domain)
	return uniqueSubdomains, nil
}

// GetHistoricalCerts queries crt.sh for a domain and returns the raw JSON history.
// This is used for CTI enrichment (tracking infrastructure migrations and timelines).
func GetHistoricalCerts(domain string) ([]CTLog, error) {
	url := fmt.Sprintf("%s/?output=json&q=%%25.%s", CRTSHURL, domain)

	body, err := QueryCrtsh(url)
	if err != nil {
		return nil, err
	}

	var logs []CTLog
	if err := json.Unmarshal(body, &logs); err != nil {
		return nil, fmt.Errorf("failed to parse crt.sh response: %v", err)
	}

	return logs, nil
}

// DownloadPemFile downloads a PEM file for the given certificate ID.
func DownloadPemFile(certID int) ([]byte, error) {
	url := fmt.Sprintf("%s/?d=%d", CRTSHURL, certID)
	return QueryCrtsh(url)
}

// ParseCertificate parses a PEM-encoded certificate and returns an x509.Certificate.
func ParseCertificate(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}
	return cert, nil
}

// PrintCertDetails prints details from an x509.Certificate.
func PrintCertDetails(cert *x509.Certificate) {
	log.Println("Certificate Details:")
	log.Printf("  Subject: %s", cert.Subject)
	log.Printf("  Issuer: %s", cert.Issuer)
	log.Printf("  Valid From: %s", cert.NotBefore)
	log.Printf("  Valid To: %s", cert.NotAfter)
	log.Println("  DNS Names:")
	for _, dnsName := range cert.DNSNames {
		log.Printf("    - %s", dnsName)
	}
}
