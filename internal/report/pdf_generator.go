package report

import (
	"fmt"
	"log"
	"strings"

	"github.com/go-pdf/fpdf"
)

func GeneratePDFReport(
	domain string,
	links []string,
	htmlInfo string,
	geolocationInfo string,
	dnsRecords []string,
	certDetails []string,
	reverseDNSInfo []string,
	waybackSnapshots []string,
	whoisInfo string,
	dorkResults []string,
) error {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetTitle(fmt.Sprintf("OSINT Report for %s", domain), false)
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 16)

	// Add title
	title := fmt.Sprintf("OSINT Report for %s", domain)
	pdf.Cell(40, 10, title)
	pdf.Ln(12)

	// WHOIS Information
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 10, "WHOIS Information")
	pdf.Ln(10)
	pdf.SetFont("Arial", "", 10)
	pdf.MultiCell(0, 10, whoisInfo, "", "", false)
	pdf.Ln(10)

	// Geolocation Information
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 10, "Geolocation Information")
	pdf.Ln(10)
	pdf.SetFont("Arial", "", 10)
	pdf.MultiCell(0, 10, geolocationInfo, "", "", false)
	pdf.Ln(10)

	// Certificate Details
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 10, "SSL/TLS Certificates")
	pdf.Ln(10)
	pdf.SetFont("Arial", "", 10)
	if len(certDetails) > 0 {
		for _, cert := range certDetails {
			pdf.MultiCell(0, 10, cert, "", "", false)
		}
	} else {
		pdf.Cell(0, 10, "No certificate information available.")
	}
	pdf.Ln(10)

	// DNS Records
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 10, "DNS Records")
	pdf.Ln(10)
	pdf.SetFont("Arial", "", 10)
	if len(dnsRecords) > 0 {
		for _, record := range dnsRecords {
			pdf.CellFormat(0, 10, record, "", 1, "", false, 0, "")
		}
	} else {
		pdf.Cell(0, 10, "No DNS records found.")
	}
	pdf.Ln(10)

	// Reverse DNS Information
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 10, "Reverse DNS Information")
	pdf.Ln(10)
	pdf.SetFont("Arial", "", 10)
	if len(reverseDNSInfo) > 0 {
		for _, info := range reverseDNSInfo {
			pdf.MultiCell(0, 10, info, "", "", false)
		}
	} else {
		pdf.Cell(0, 10, "No reverse DNS information found.")
	}
	pdf.Ln(10)

	// Website Analysis
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 10, "Website Analysis")
	pdf.Ln(10)
	pdf.SetFont("Arial", "", 10)
	pdf.MultiCell(0, 10, htmlInfo, "", "", false)
	pdf.Ln(10)

	// Links Section
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 10, "Extracted Links")
	pdf.Ln(10)
	pdf.SetFont("Arial", "", 10)
	if len(links) > 0 {
		for _, link := range links {
			pdf.CellFormat(0, 10, link, "", 1, "", false, 0, "")
		}
	} else {
		pdf.Cell(0, 10, "No links found.")
	}
	pdf.Ln(10)

	// Wayback Machine Snapshots
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 10, "Wayback Machine Snapshots")
	pdf.Ln(10)
	pdf.SetFont("Arial", "", 10)
	if len(waybackSnapshots) > 0 {
		for _, snapshot := range waybackSnapshots {
			// Split the snapshot info to separate URL from other details
			parts := strings.Split(snapshot, "\nURL: ")
			pdf.MultiCell(0, 10, parts[0], "", "", false)
			if len(parts) > 1 {
				pdf.SetTextColor(0, 0, 255)   // Blue color for links
				pdf.SetFont("Arial", "U", 10) // Underlined
				pdf.AddLink()
				pdf.WriteLinkString(10, parts[1], parts[1])
				pdf.SetTextColor(0, 0, 0)    // Reset to black
				pdf.SetFont("Arial", "", 10) // Reset font
			}
			pdf.Ln(5)
		}
	} else {
		pdf.Cell(0, 10, "No Wayback Machine snapshots found.")
	}
	pdf.Ln(10)

	// Google Dork Results
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 10, "Google Dork Results")
	pdf.Ln(10)
	pdf.SetFont("Arial", "", 10)
	if len(dorkResults) > 0 {
		for _, result := range dorkResults {
			// Split the result into query and URL
			parts := strings.Split(result, "\nURL: ")
			pdf.MultiCell(0, 10, parts[0], "", "", false)
			if len(parts) > 1 {
				pdf.SetTextColor(0, 0, 255)   // Blue color for links
				pdf.SetFont("Arial", "U", 10) // Underlined
				pdf.AddLink()
				pdf.WriteLinkString(10, parts[1], parts[1])
				pdf.SetTextColor(0, 0, 0)    // Reset to black
				pdf.SetFont("Arial", "", 10) // Reset font
			}
			pdf.Ln(5)
		}
	} else {
		pdf.Cell(0, 10, "No Google dork results found.")
	}
	pdf.Ln(10)

	// Save PDF to file
	outputFile := fmt.Sprintf("%s_report.pdf", domain)
	err := pdf.OutputFileAndClose(outputFile)
	if err != nil {
		return fmt.Errorf("failed to generate PDF report: %v", err)
	}

	log.Printf("PDF report generated successfully: %s", outputFile)
	return nil
}
