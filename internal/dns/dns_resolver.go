package dns

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
)

type DNSResolver struct {
	Threads     int
	Resolver    string
	UseDefaults bool
}

func NewDNSResolver() *DNSResolver {
	return &DNSResolver{
		Threads:     8,
		UseDefaults: true,
	}
}

// RunAmassPassive performs passive subdomain enumeration using Amass
func (d *DNSResolver) RunAmassPassive(domain string) ([]string, error) {
	cmd := exec.Command("amass", "enum", "-passive", "-d", domain)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to run Amass: %v, %s", err, stderr.String())
	}

	var results []string
	scanner := bufio.NewScanner(strings.NewReader(out.String()))
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			results = append(results, line)
			log.Printf("Discovered subdomain: %s", line)
		}
	}

	return results, nil
}

// ResolveARecords returns IPv4 addresses for a domain
func (d *DNSResolver) ResolveARecords(domain string) ([]string, error) {
	ips, err := net.LookupHost(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve A records for domain %s: %v", domain, err)
	}
	log.Printf("A records for domain %s: %v", domain, ips)
	return ips, nil
}

// ResolveMXRecords returns mail servers for a domain
func (d *DNSResolver) ResolveMXRecords(domain string) ([]*net.MX, error) {
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve MX records for domain %s: %v", domain, err)
	}
	return mxRecords, nil
}

// ReverseLookup performs reverse DNS lookups using hakrevdns
func (d *DNSResolver) ReverseLookup(ips []string) (map[string][]string, error) {
	results := make(map[string][]string)

	args := []string{"-d"}
	if d.Resolver != "" {
		args = append(args, "-r", d.Resolver)
	}
	if !d.UseDefaults {
		args = append(args, "-U")
	}

	for _, ip := range ips {
		cmd := exec.Command("hakrevdns", args...)
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return nil, err
		}

		go func() {
			defer stdin.Close()
			fmt.Fprintln(stdin, ip)
		}()

		output, err := cmd.Output()
		if err != nil {
			log.Printf("Error looking up IP %s: %v", ip, err)
			continue
		}

		domains := parseHakrevdnsOutput(string(output))
		results[ip] = domains
	}

	return results, nil
}

func parseHakrevdnsOutput(output string) []string {
	var domains []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		if domain := strings.TrimSpace(scanner.Text()); domain != "" {
			domains = append(domains, domain)
		}
	}
	return domains
}
