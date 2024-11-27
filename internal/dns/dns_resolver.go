package dns_resolver

import (
	"fmt"
	"log"
	"net"
)

// ResolveARecords takes a domain name and returns its A records (IPv4 addresses)
func ResolveARecords(domain string) ([]string, error) {
	ips, err := net.LookupHost(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve A records for domain %s: %v", domain, err)
	}

	log.Printf("A records for domain %s: %v", domain, ips)
	return ips, nil
}

// ResolveMXRecords takes a domain name and returns its MX records (mail exchange servers)
func ResolveMXRecords(domain string) ([]*net.MX, error) {
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve MX records for domain %s: %v", domain, err)
	}

	for _, mx := range mxRecords {
		log.Printf("MX record for domain %s: %s, Priority: %d", domain, mx.Host, mx.Pref)
	}

	return mxRecords, nil
}

// ResolveNSRecords takes a domain name and returns its NS records (name servers)
func ResolveNSRecords(domain string) ([]*net.NS, error) {
	nsRecords, err := net.LookupNS(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve NS records for domain %s: %v", domain, err)
	}

	for _, ns := range nsRecords {
		log.Printf("NS record for domain %s: %s", domain, ns.Host)
	}

	return nsRecords, nil
}

// ResolveTXTRecords takes a domain name and returns its TXT records
func ResolveTXTRecords(domain string) ([]string, error) {
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve TXT records for domain %s: %v", domain, err)
	}

	log.Printf("TXT records for domain %s: %v", domain, txtRecords)
	return txtRecords, nil
}
