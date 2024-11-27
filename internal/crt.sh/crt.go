package crtsh

import (
	"fmt"
	"log"
	"net/http"
	"encoding/json"
	"github.com/e-zk/go-crtsh"
)

// Certificate represents the structure of a certificate retrieved from crt.sh
type Certificate struct {
	IssuerName  string `json:"issuer_name"`
	NotBefore   string `json:"not_before"`
	NotAfter    string `json:"not_after"`
	CommonName  string `json:"common_name"`
	SANs        []string `json:"sans"`
}

// FetchCertificates retrieves a list of SSL/TLS certificates for a given domain using crt.sh
func FetchCertificates(domain string) {
	certificates, err := crtsh.GetCertificates(domain)
	if err != nil {
		log.Printf("Error fetching certificates for domain %s: %v", domain, err)
		return
	}

	for _, cert := range certificates {
		certJSON, err := json.MarshalIndent(cert, "", "  ")
		if err != nil {
			log.Printf("Error marshalling certificate data: %v", err)
			continue
		}
		fmt.Printf("Certificate Data: %s\n", certJSON)
	}
}
