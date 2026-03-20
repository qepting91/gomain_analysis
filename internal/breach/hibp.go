package breach

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

// HIBPBreach represents a single breach event returned by the API
type HIBPBreach struct {
	Name       string `json:"Name"`
	Domain     string `json:"Domain"`
	BreachDate string `json:"BreachDate"`
}

// CheckEmails passively takes a list of discovered emails and queries the 
// HaveIBeenPwned API to see if they were exposed in known data dumps.
// It requires the HIBP_API_KEY environment variable.
func CheckEmails(emails []string) map[string][]string {
	breachesFound := make(map[string][]string)
	
	apiKey := os.Getenv("HIBP_API_KEY")
	if apiKey == "" {
		log.Println("HIBP_API_KEY not found in environment. Skipping passive Identity Breach checks.")
		return breachesFound
	}

	client := &http.Client{Timeout: 10 * time.Second}

	for i, email := range emails {
		// HIBP strictly enforces a rate limit (1 request per 1.5 seconds)
		if i > 0 {
			time.Sleep(1600 * time.Millisecond)
		}

		url := fmt.Sprintf("https://haveibeenpwned.com/api/v3/breachedaccount/%s?truncateResponse=false", email)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			log.Printf("Failed to create HIBP request for %s: %v", email, err)
			continue
		}

		req.Header.Add("hibp-api-key", apiKey)
		req.Header.Add("user-agent", "gomain_analysis-CTI-Tool")

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("HIBP query failed for %s: %v", email, err)
			continue
		}
		
		// 404 means no breaches found for this email, which is good!
		if resp.StatusCode == http.StatusNotFound {
			resp.Body.Close()
			continue
		}

		if resp.StatusCode != http.StatusOK {
			log.Printf("HIBP API returned non-200 status for %s: %d", email, resp.StatusCode)
			resp.Body.Close()
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		var breaches []HIBPBreach
		if err := json.Unmarshal(body, &breaches); err != nil {
			continue
		}

		var breachNames []string
		for _, b := range breaches {
			breachNames = append(breachNames, fmt.Sprintf("%s (%s)", b.Name, b.BreachDate))
		}
		
		if len(breachNames) > 0 {
			breachesFound[email] = breachNames
		}
	}

	return breachesFound
}
