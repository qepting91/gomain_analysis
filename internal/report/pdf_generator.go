package report

import (
	"fmt"
	"log"

	"github.com/jung-kurt/gofpdf"
)

// GeneratePDFReport generates a PDF report with the given information
func GeneratePDFReport(domain string, links []string, textContent string, geolocationInfo string, dnsRecords []string, mxRecords []string, reverseDNS []string, waybackSnapshots []string, whoisInfo string) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetTitle(fmt.Sprintf("OSINT Report for %s", domain), false)
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 16)

	// Add title
	title := fmt.Sprintf("OSINT Report for %s", domain)
	pdf.Cell(40, 10, title)
	pdf.Ln(12)

	// Add WHOIS Information
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 10, "WHOIS Information")
	pdf.Ln(10)
	pdf.SetFont("Arial", "", 10)
	pdf.MultiCell(0, 10, whoisInfo, "", "", false)
	pdf.Ln(10)

	// Add Geolocation Information
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 10, "Geolocation Information")
	pdf.Ln(10)
	pdf.SetFont("Arial", "", 10)
	pdf.MultiCell(0, 10, geolocationInfo, "", "", false)
	pdf.Ln(10)

	// Add Links Section
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

	// Add DNS Records Section
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

	// Add MX Records Section
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 10, "MX Records")
	pdf.Ln(10)
	pdf.SetFont("Arial", "", 10)
	if len(mxRecords) > 0 {
		for _, record := range mxRecords {
			pdf.CellFormat(0, 10, record, "", 1, "", false, 0, "")
		}
	} else {
		pdf.Cell(0, 10, "No MX records found.")
	}
	pdf.Ln(10)

	// Add Reverse DNS Section
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 10, "Reverse DNS Information")
	pdf.Ln(10)
	pdf.SetFont("Arial", "", 10)
	if len(reverseDNS) > 0 {
		for _, record := range reverseDNS {
			pdf.CellFormat(0, 10, record, "", 1, "", false, 0, "")
		}
	} else {
		pdf.Cell(0, 10, "No reverse DNS information found.")
	}
	pdf.Ln(10)

	// Add Wayback Machine Snapshots Section
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 10, "Wayback Machine Snapshots")
	pdf.Ln(10)
	pdf.SetFont("Arial", "", 10)
	if len(waybackSnapshots) > 0 {
		for _, snapshot := range waybackSnapshots {
			pdf.CellFormat(0, 10, snapshot, "", 1, "", false, 0, "")
		}
	} else {
		pdf.Cell(0, 10, "No Wayback Machine snapshots found.")
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
