package whois

import (
	"fmt"
	"log"
	"strings"

	"github.com/domainr/whois"
)

// LookupWHOIS retrieves WHOIS information for the given domain
func LookupWHOIS(domain string) (string, error) {
	// Perform WHOIS lookup
	req, err := whois.NewRequest(domain)
	if err != nil {
		return "", fmt.Errorf("failed to create WHOIS request for domain %s: %v", domain, err)
	}

	res, err := whois.DefaultClient.Fetch(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch WHOIS information for domain %s: %v", domain, err)
	}

	log.Printf("Successfully retrieved WHOIS information for domain: %s", domain)

	// Process response and return it as a string
	whoisInfo := strings.TrimSpace(res.String())
	return whoisInfo, nil
}
