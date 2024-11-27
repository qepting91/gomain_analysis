package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/qepting91/gomain_analysis/internal/config"
	"github.com/qepting91/gomain_analysis/internal/crt"
	"github.com/qepting91/gomain_analysis/internal/dns"
	"github.com/qepting91/gomain_analysis/internal/dork"
	"github.com/qepting91/gomain_analysis/internal/fetcher"
	"github.com/qepting91/gomain_analysis/internal/geolocation"
	"github.com/qepting91/gomain_analysis/internal/parser"
	"github.com/qepting91/gomain_analysis/internal/report"
	"github.com/qepting91/gomain_analysis/internal/wayback"
	"github.com/qepting91/gomain_analysis/internal/whois"

	"github.com/urfave/cli/v2"
)

// Helper function to format social media links
func formatSocialMedia(socialMedia map[string][]string) string {
	var result strings.Builder
	for platform, links := range socialMedia {
		fmt.Fprintf(&result, "• %s: %s\n", platform, strings.Join(links, ", "))
	}
	return result.String()
}

func main() {
	if err := geolite.Initialize(); err != nil {
		log.Fatal(err)
	}
	defer geolite.Close()

	app := &cli.App{
		Name:  "gomain_analysis",
		Usage: "Perform OSINT on domains",
		Commands: []*cli.Command{
			{
				Name:  "analyze",
				Usage: "Perform comprehensive domain analysis",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "domain",
						Usage:    "Domain to analyze (e.g., example.com)",
						Required: true,
					},
				},
				Action: func(c *cli.Context) error {
					domain := c.String("domain")

					dnsResolver := dns.NewDNSResolver()
					webFetcher := fetcher.NewWebFetcher()

					// Certificate Analysis
					fmt.Printf("\nFetching SSL/TLS certificates for %s\n", domain)
					logs, err := crt.QueryByDomain(domain)
					if err != nil {
						log.Printf("Error fetching certificates: %v", err)
					}
					var certDetails []string
					for _, log := range logs {
						pemData, err := crt.DownloadPemFile(log.MinCertID)
						if err != nil {
							continue
						}
						cert, err := crt.ParseCertificate(pemData)
						if err != nil {
							continue
						}
						certInfo := fmt.Sprintf(`
Certificate Details:
ID: %d
Subject: %s
Issuer: %s
Valid From: %s
Valid To: %s
DNS Names: %v
`,
							log.MinCertID, cert.Subject, cert.Issuer, cert.NotBefore, cert.NotAfter, cert.DNSNames)
						certDetails = append(certDetails, certInfo)
						crt.PrintCertDetails(cert)
					}

					// DNS Analysis
					fmt.Printf("\nResolving DNS records for %s\n", domain)
					dnsRecords, err := dnsResolver.ResolveARecords(domain)
					if err != nil {
						log.Printf("Error resolving DNS records: %v", err)
					}
					var dnsInfo []string
					for _, record := range dnsRecords {
						dnsInfo = append(dnsInfo, fmt.Sprintf("DNS Record: %s", record))
					}

					// Reverse DNS
					fmt.Printf("\nPerforming reverse DNS lookup\n")
					reverseDNS, err := dnsResolver.ReverseLookup(dnsRecords)
					if err != nil {
						log.Printf("Error performing reverse DNS: %v", err)
					}
					var reverseDNSInfo []string
					for ip, domains := range reverseDNS {
						info := fmt.Sprintf("IP: %s\nAssociated Domains: %v", ip, domains)
						reverseDNSInfo = append(reverseDNSInfo, info)
					}

					// WHOIS Information
					fmt.Printf("\nFetching WHOIS information\n")
					whoisInfo, err := whois.LookupWHOIS(domain)
					if err != nil {
						log.Printf("Error fetching WHOIS: %v", err)
					}

					// Website Content
					fmt.Printf("\nFetching website content\n")
					content, err := webFetcher.FetchWebContent("https://" + domain)
					if err != nil {
						log.Printf("Error fetching website content: %v", err)
					}

					// HTML Parsing
					fmt.Printf("\nParsing HTML content\n")
					parsedContent, err := parser.ParseHTMLContent(content)
					if err != nil {
						log.Printf("Error parsing HTML content: %v", err)
					}
					htmlInfo := fmt.Sprintf(`
Website Analysis
---------------
Title: %s

Contact Information:
• Emails: %v
• Phone Numbers: %v

Links Analysis:
• Internal Links Count: %d
• External Links Count: %d

Social Media Presence:
%s

Technical Details:
• Technologies: %v
• Forms: %v
• Scripts: %v
• Stylesheets: %v

Additional Information:
• Comments: %v
`,
						parsedContent.Title,
						strings.Join(parsedContent.Emails, ", "),
						strings.Join(parsedContent.PhoneNumbers, ", "),
						len(parsedContent.InternalLinks),
						len(parsedContent.ExternalLinks),
						formatSocialMedia(parsedContent.SocialMedia),
						strings.Join(parsedContent.Technologies, ", "),
						strings.Join(parsedContent.Forms, ", "),
						strings.Join(parsedContent.Scripts, "\n  "),
						strings.Join(parsedContent.StyleSheets, "\n  "),
						strings.Join(parsedContent.Comments, "\n  "),
					)

					// Wayback Machine
					fmt.Printf("\nFetching Wayback Machine snapshots\n")
					waybackSnapshots := wayback.FetchSnapshots(domain)

					// Google Dorking
					fmt.Printf("\nPerforming Google dorking\n")
					queries, err := dork.LoadDorkQueries()
					var dorkResults []string
					if err != nil {
						log.Printf("Error loading dork queries: %v", err)
					} else {
						dorkResults = dork.PerformDorkSearch(domain, queries)
					}

					// Geolocation
					var geoLocationInfo string
					fmt.Printf("\nFetching geolocation information\n")
					for _, ip := range dnsRecords {
						geoInfo, err := geolocation.LookupGeolocation(ip)
						if err != nil {
							log.Printf("Error getting geolocation for IP %s: %v", ip, err)
							continue
						}
						geoLocationInfo += fmt.Sprintf(`
IP: %s
Location Information:
%s
`, ip, geolocation.FormatGeoLocation(geoInfo))
					}

					// Generate PDF Report
					fmt.Printf("\nGenerating PDF report\n")
					err = report.GeneratePDFReport(
						domain,
						parsedContent.Links,
						htmlInfo,
						geoLocationInfo,
						dnsInfo,
						certDetails,
						reverseDNSInfo,
						waybackSnapshots,
						whoisInfo,
						dorkResults,
					)
					if err != nil {
						log.Printf("Error generating PDF report: %v", err)
					}

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
