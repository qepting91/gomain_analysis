package main

import (
	"fmt"
	"log"
	"os"

	"gomain_analysis/internal/crtsh"
	"gomain_analysis/internal/dns/dns_resolver"
	"gomain_analysis/internal/dns/reverse_dns"
	"gomain_analysis/internal/geolocation/geo_lookup"
	"gomain_analysis/internal/report/pdf_generator"
	"gomain_analysis/internal/wayback"
	"gomain_analysis/internal/whois/whois_lookup"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "gomain_analysis",
		Usage: "Perform OSINT on domains",
		Commands: []*cli.Command{
			{
				Name:  "domain",
				Usage: "Perform OSINT on a domain",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "domain",
						Usage:    "Domain to perform OSINT on (e.g., example.com)",
						Required: true,
					},
				},
				Action: func(c *cli.Context) error {
					domain := c.String("domain")

					fmt.Printf("Fetching SSL/TLS certificates for domain: %s\n", domain)
					crtsh.FetchCertificates(domain)

					fmt.Printf("\nFetching Wayback Machine snapshots for domain: %s\n", domain)
					wayback.FetchSnapshots(domain)

					fmt.Printf("\nFetching WHOIS information for domain: %s\n", domain)
					whoisInfo, err := whois_lookup.LookupWHOIS(domain)
					if err != nil {
						log.Printf("Error fetching WHOIS information: %v", err)
					} else {
						fmt.Println(whoisInfo)
					}

					fmt.Printf("\nResolving DNS records for domain: %s\n", domain)
					dnsRecords, err := dns_resolver.ResolveARecords(domain)
					if err != nil {
						log.Printf("Error resolving DNS records: %v", err)
					}

					fmt.Printf("\nResolving MX records for domain: %s\n", domain)
					mxRecords, err := dns_resolver.ResolveMXRecords(domain)
					if err != nil {
						log.Printf("Error resolving MX records: %v", err)
					}

					fmt.Printf("\nPerforming reverse DNS lookup for domain: %s\n", domain)
					reverseDNS, err := reverse_dns.ReverseLookup(dnsRecords[0])
					if err != nil {
						log.Printf("Error performing reverse DNS lookup: %v", err)
					}

					fmt.Printf("\nFetching geolocation information for domain: %s\n", domain)
					geoInfo, err := geo_lookup.LookupGeolocation(dnsRecords[0])
					if err != nil {
						log.Printf("Error fetching geolocation information: %v", err)
					}

					fmt.Printf("\nGenerating PDF report for domain: %s\n", domain)
					err = pdf_generator.GeneratePDFReport(domain, []string{}, "", fmt.Sprintf("Country: %s, City: %s", geoInfo.Country.Names["en"], geoInfo.City.Names["en"]), dnsRecords, mxRecords, reverseDNS, []string{}, whoisInfo)
					if err != nil {
						log.Printf("Error generating PDF report: %v", err)
					}

					return nil
				},
			},
			{
				Name:  "archive",
				Usage: "Archive a URL using Wayback Machine",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "url",
						Usage:    "URL to archive using Wayback Machine",
						Required: true,
					},
				},
				Action: func(c *cli.Context) error {
					url := c.String("url")
					fmt.Printf("\nArchiving URL using Wayback Machine: %s\n", url)
					wayback.ArchiveURL(url)
					return nil
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
