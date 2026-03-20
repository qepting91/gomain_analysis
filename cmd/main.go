package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/qepting91/gomain_analysis/internal/breach"
	"github.com/qepting91/gomain_analysis/internal/config"
	"github.com/qepting91/gomain_analysis/internal/crt"
	"github.com/qepting91/gomain_analysis/internal/dns"
	"github.com/qepting91/gomain_analysis/internal/dork"
	"github.com/qepting91/gomain_analysis/internal/fetcher"
	"github.com/qepting91/gomain_analysis/internal/geolocation"
	"github.com/qepting91/gomain_analysis/internal/parser"
	"github.com/qepting91/gomain_analysis/internal/report"
	"github.com/qepting91/gomain_analysis/internal/reputation"
	"github.com/qepting91/gomain_analysis/internal/subfinder"
	"github.com/qepting91/gomain_analysis/internal/wayback"
	"github.com/qepting91/gomain_analysis/internal/whois"

	"github.com/urfave/cli/v2"
)


func main() {
	if err := geolite.Initialize(); err != nil {
		log.Printf("WARNING: GeoLite2 initialization failed (geolocation will be skipped): %v", err)
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

					reportData := &report.ReportData{
						Domain:        domain,
						ScanTimestamp: time.Now(),
						ReverseDNS:    make(map[string][]string),
					}

					// Live Certificate Analysis
					fmt.Printf("\nInspecting Live SSL/TLS certificates for %s\n", domain)
					liveCerts, err := crt.InspectTLS(domain, "443")
					if err != nil {
						log.Printf("Error inspecting live TLS: %v", err)
					} else {
						for _, cert := range liveCerts {
							reportData.Certificates = append(reportData.Certificates, report.CertData{
								Source:    "LIVE",
								Subject:   cert.Subject.String(),
								Issuer:    cert.Issuer.String(),
								ValidFrom: cert.NotBefore,
								ValidTo:   cert.NotAfter,
								DNSNames:  cert.DNSNames,
							})
							crt.PrintCertDetails(cert)
						}
					}

					// Historical Certificate Analysis (CT Logs)
					fmt.Printf("\nFetching Historical CT logs for %s from crt.sh\n", domain)
					logsArray, err := crt.QueryByDomain(domain)
					if err != nil {
						log.Printf("Error fetching historical certificates: %v", err)
					} else {
						for _, logEntry := range logsArray {
							pemData, err := crt.DownloadPemFile(logEntry.MinCertID)
							if err != nil {
								continue
							}
							cert, err := crt.ParseCertificate(pemData)
							if err != nil {
								continue
							}
							reportData.Certificates = append(reportData.Certificates, report.CertData{
								Source:    "CT LOG",
								ID:        logEntry.MinCertID,
								Subject:   cert.Subject.String(),
								Issuer:    cert.Issuer.String(),
								ValidFrom: cert.NotBefore,
								ValidTo:   cert.NotAfter,
								DNSNames:  cert.DNSNames,
							})
						}
					}

					// DNS Analysis
					fmt.Printf("\nResolving DNS records for %s\n", domain)
					dnsRecords, err := dnsResolver.ResolveARecords(domain)
					if err != nil {
						log.Printf("Error resolving DNS records: %v", err)
					}
					reportData.DNSRecords = dnsRecords

					// Reverse DNS
					fmt.Printf("\nPerforming reverse DNS lookup\n")
					reverseDNS, err := dnsResolver.ReverseLookup(dnsRecords)
					if err != nil {
						log.Printf("Error performing reverse DNS: %v", err)
					}
					reportData.ReverseDNS = reverseDNS

					// WHOIS Information
					fmt.Printf("\nFetching WHOIS information\n")
					whoisInfo, err := whois.LookupWHOIS(domain)
					if err != nil {
						log.Printf("Error fetching WHOIS: %v", err)
					}
					reportData.WHOIS = whoisInfo

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
					} else {
						reportData.WebAnalysis = &report.WebData{
							Title:         parsedContent.Title,
							MetaTags:      parsedContent.MetaTags,
							Links:         parsedContent.Links,
							ExternalLinks: parsedContent.ExternalLinks,
							InternalLinks: parsedContent.InternalLinks,
							Emails:        parsedContent.Emails,
							PhoneNumbers:  parsedContent.PhoneNumbers,
							SocialMedia:   parsedContent.SocialMedia,
							Technologies:  parsedContent.Technologies,
							Scripts:       parsedContent.Scripts,
							StyleSheets:   parsedContent.StyleSheets,
							Forms:         parsedContent.Forms,
							Comments:      parsedContent.Comments,
						}
					}

					// Wayback Machine
					fmt.Printf("\nFetching Wayback Machine snapshots\n")
					waybackSnaps := wayback.FetchSnapshots(domain)
					for _, snapStr := range waybackSnaps {
						parts := strings.Split(snapStr, "\nURL: ")
						if len(parts) == 2 {
							// Ex: "[20260320] Status 200"
							statusPart := parts[0]
							reportData.WaybackSnapshots = append(reportData.WaybackSnapshots, report.WaybackSnapshot{
								Timestamp: statusPart,
								URL:       parts[1],
								Status:    "Archived",
							})
						}
					}

					// Google Dorking
					fmt.Printf("\nPerforming Google dorking\n")
					queries, err := dork.LoadDorkQueries()
					if err != nil {
						log.Printf("Error loading dork queries: %v", err)
					} else {
						dorkRes := dork.PerformDorkSearch(domain, queries)
						for _, resStr := range dorkRes {
							parts := strings.Split(resStr, "\nURL: ")
							if len(parts) == 2 {
								reportData.Dorks = append(reportData.Dorks, report.DorkResult{
									Query: parts[0],
									URL:   parts[1],
								})
							}
						}
					}

					// Geolocation
					fmt.Printf("\nFetching geolocation information\n")
					for _, ip := range dnsRecords {
						geoInfo, err := geolocation.LookupGeolocation(ip)
						if err != nil {
							log.Printf("Error getting geolocation for IP %s: %v", ip, err)
							continue
						}
						
						geo := report.GeoData{
							IP:          ip,
							City:        geoInfo.City.Names["en"],
							Country:     geoInfo.Country.Names["en"],
							CountryCode: geoInfo.Country.IsoCode,
							Continent:   geoInfo.Continent.Names["en"],
							Latitude:    geoInfo.Location.Latitude,
							Longitude:   geoInfo.Location.Longitude,
							Timezone:    geoInfo.Location.TimeZone,
						}
						if len(geoInfo.Subdivisions) > 0 {
							geo.Region = geoInfo.Subdivisions[0].Names["en"]
						}
						reportData.Geolocation = append(reportData.Geolocation, geo)
					}

					// Passive OSINT Enhancements (Subfinder, VirusTotal, HIBP)
					fmt.Printf("\nExecuting passive subdomain enumeration (Subfinder)\n")
					reportData.Subdomains = subfinder.Enumerate(domain)

					fmt.Printf("\nQuerying VirusTotal community reputation database\n")
					vtResult := reputation.CheckDomain(domain)
					if vtResult != nil {
						reportData.MaliciousScore = vtResult.Malicious
						reportData.VT_Tags = vtResult.Tags
					}

					if reportData.WebAnalysis != nil && len(reportData.WebAnalysis.Emails) > 0 {
						fmt.Printf("\nChecking %d extracted emails against HaveIBeenPwned database\n", len(reportData.WebAnalysis.Emails))
						reportData.BreachedEmails = breach.CheckEmails(reportData.WebAnalysis.Emails)
					}

					// Generate PDF Report
					fmt.Printf("\nGenerating PDF report\n")
					err = report.GeneratePDFReport(reportData)
					if err != nil {
						log.Printf("Error generating PDF report: %v", err)
					}

					// Generate JSON Report
					fmt.Printf("\nGenerating raw JSON report\n")
					err = report.GenerateJSONReport(reportData)
					if err != nil {
						log.Printf("Error generating JSON report: %v", err)
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
