package report

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

// GenerateJSONReport serializes the ReportData struct to a JSON file
// for ingestion into SIEMs, graphing tools, or databases.
func GenerateJSONReport(data *ReportData) error {
	outputFile := fmt.Sprintf("%s_raw.json", data.Domain)

	// Marshal with indentation for human readability if needed,
	// though standard SIEM ingestion usually doesn't care.
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report data to JSON: %v", err)
	}

	err = os.WriteFile(outputFile, jsonData, 0o600)
	if err != nil {
		return fmt.Errorf("failed to write JSON report file: %v", err)
	}

	log.Printf("JSON raw report generated successfully: %s", outputFile)
	return nil
}
