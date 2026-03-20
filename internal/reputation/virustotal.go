package reputation

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

type VTResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
			} `json:"last_analysis_stats"`
			Tags []string `json:"tags"`
		} `json:"attributes"`
	} `json:"data"`
}

type VTResult struct {
	Malicious  int
	Suspicious int
	Tags       []string
}

// CheckDomain passively queries the VirusTotal community database to score a domain.
// It requires the VT_API_KEY environment variable.
func CheckDomain(domain string) *VTResult {
	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		log.Println("VT_API_KEY not found in environment. Skipping passive VirusTotal check.")
		return nil
	}

	url := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s", domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Failed to create VirusTotal request: %v", err)
		return nil
	}

	req.Header.Add("x-apikey", apiKey)
	req.Header.Add("accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to query VirusTotal: %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("VirusTotal API returned non-200 status: %d", resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var vtResp VTResponse
	if err := json.Unmarshal(body, &vtResp); err != nil {
		log.Printf("Failed to decode VirusTotal response: %v", err)
		return nil
	}

	stats := vtResp.Data.Attributes.LastAnalysisStats
	return &VTResult{
		Malicious:  stats.Malicious,
		Suspicious: stats.Suspicious,
		Tags:       vtResp.Data.Attributes.Tags,
	}
}
