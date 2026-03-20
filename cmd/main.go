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

					// Historical Certificate Analysis (CT Logs) - Rich JSON History
					fmt.Printf("\nFetching rich historical certificates from CT logs via crt.sh\n")
					historicalCerts, err := crt.GetHistoricalCerts(domain)
					if err != nil {
						log.Printf("Error fetching historical CT logs: %v", err)
					} else {
						log.Printf("Found %d historical certificates", len(historicalCerts))
						for _, ct := range historicalCerts {
							// Example format: 2026-01-26T11:25:44
							notBefore, _ := time.Parse("2006-01-02T15:04:05", ct.NotBefore)
							notAfter, _ := time.Parse("2006-01-02T15:04:05", ct.NotAfter)

							dnsNames := strings.Split(ct.NameValue, "\n")
							for i, n := range dnsNames {
								dnsNames[i] = strings.TrimSpace(n)
							}

							reportData.Certificates = append(reportData.Certificates, report.CertData{
								Source:    "CT LOG (HISTORY)",
								ID:        ct.IssuerCaID,
								Issuer:    ct.IssuerName,
								ValidFrom: notBefore,
								ValidTo:   notAfter,
								DNSNames:  dnsNames,
							})
						}
					}

					// Historical Certificate Analysis (CT Logs) - Now returns unique subdomains
					fmt.Printf("\nFetching subdomains from CT logs via crt.sh (wildcard query)\n")
					ctSubdomains, err := crt.QueryByDomain(domain)
					if err != nil {
						log.Printf("Error fetching CT log subdomains: %v", err)
					} else {
						log.Printf("Found %d unique subdomains from CT logs", len(ctSubdomains))

						// Probe a sample of discovered subdomains to check which are alive
						// (Limit to first 20 to avoid excessive probing)
						maxProbe := 20
						if len(ctSubdomains) < maxProbe {
							maxProbe = len(ctSubdomains)
						}

						for i := 0; i < maxProbe; i++ {
							subdomain := ctSubdomains[i]
							log.Printf("Probing subdomain %d/%d: %s", i+1, maxProbe, subdomain)

							certs, probeErr := crt.InspectTLS(subdomain, "443")
							if probeErr != nil {
								// Subdomain not reachable or no TLS
								continue
							}

							// Successfully connected - add the live certificate
							for _, cert := range certs {
								reportData.Certificates = append(reportData.Certificates, report.CertData{
									Source:    "CT LOG (LIVE)",
									Subject:   cert.Subject.String(),
									Issuer:    cert.Issuer.String(),
									ValidFrom: cert.NotBefore,
									ValidTo:   cert.NotAfter,
									DNSNames:  cert.DNSNames,
								})
							}
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

					// Wayback Machine (100% Passive - CDX API)
					fmt.Printf("\nFetching Wayback Machine snapshots (passive CDX query)\n")
					waybackSnaps := wayback.FetchSnapshots(domain)
					for _, snap := range waybackSnaps {
						reportData.WaybackSnapshots = append(reportData.WaybackSnapshots, report.WaybackSnapshot{
							Timestamp: wayback.FormatTimestamp(snap.Timestamp),
							URL:       wayback.GetSnapshotURL(snap.Timestamp, snap.URL),
							Status:    snap.StatusCode,
						})
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
						geoInfo, geoErr := geolocation.LookupGeolocation(ip)
						if geoErr != nil {
							log.Printf("Error getting geolocation for IP %s: %v", ip, geoErr)
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
					fmt.Printf("\nExecuting passive subdomain enumeration (Subfinder with fallback methods)\n")
					reportData.Subdomains = subfinder.EnumerateWithFallback(domain)

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

	if err := app.Run(os.Args); err != nil {
		log.Printf("Application error: %v", err)
		os.Exit(1)
	}
}
