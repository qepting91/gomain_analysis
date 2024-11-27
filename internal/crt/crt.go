package crt

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
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

// queryCrtsh sends an HTTP GET request to crt.sh and returns the response body.
func QueryCrtsh(url string) ([]byte, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to query crt.sh: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}
	return body, nil
}

// queryByDomain queries crt.sh for certificates by domain.
func QueryByDomain(domain string) ([]CTLog, error) {
	url := fmt.Sprintf("%s/?output=json&q=%s", CRTSHURL, domain)
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

// downloadPemFile downloads a PEM file for the given certificate ID.
func DownloadPemFile(certID int) ([]byte, error) {
	url := fmt.Sprintf("%s/?d=%d", CRTSHURL, certID)
	return QueryCrtsh(url)
}

// parseCertificate parses a PEM-encoded certificate and returns an x509.Certificate.
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

// printCertDetails prints details from an x509.Certificate.
func PrintCertDetails(cert *x509.Certificate) {
	fmt.Println("Certificate Details:")
	fmt.Printf("  Subject: %s\n", cert.Subject)
	fmt.Printf("  Issuer: %s\n", cert.Issuer)
	fmt.Printf("  Valid From: %s\n", cert.NotBefore)
	fmt.Printf("  Valid To: %s\n", cert.NotAfter)
	fmt.Println("  DNS Names:")
	for _, dnsName := range cert.DNSNames {
		fmt.Printf("    - %s\n", dnsName)
	}
}

// main function parses flags and runs the program.
func main() {
	var domain string
	var certID int
	var showOnlyDomains bool

	flag.StringVar(&domain, "domain", "", "Domain to search for (e.g., example.com)")
	flag.IntVar(&certID, "cert", 0, "Certificate ID to download and parse")
	flag.BoolVar(&showOnlyDomains, "only-domains", false, "Show only domains in the results")
	flag.Parse()

	if domain == "" && certID == 0 {
		fmt.Println("Usage:")
		fmt.Println("  -domain <domain>       Query crt.sh for certificates matching the domain")
		fmt.Println("  -cert <certID>         Download and parse a specific certificate by ID")
		fmt.Println("  -only-domains          Show only domains in the results (when using -domain)")
		os.Exit(1)
	}

	if domain != "" {
		logs, err := QueryByDomain(domain)
		if err != nil {
			log.Fatalf("Error querying domain: %v", err)
		}

		if showOnlyDomains {
			fmt.Println("Domains:")
			for _, log := range logs {
				fmt.Println(log.NameValue)
			}
		} else {
			fmt.Println("Certificates:")
			for _, log := range logs {
				fmt.Printf("Cert ID: %d, Domain: %s, Issuer: %s, Valid From: %s, Valid To: %s\n",
					log.MinCertID, log.NameValue, log.IssuerName, log.NotBefore, log.NotAfter)
			}
		}
	}

	if certID != 0 {
		pemData, err := DownloadPemFile(certID)
		if err != nil {
			log.Fatalf("Error downloading PEM file: %v", err)
		}

		cert, err := ParseCertificate(pemData)
		if err != nil {
			log.Fatalf("Error parsing certificate: %v", err)
		}

		PrintCertDetails(cert)
	}
}
