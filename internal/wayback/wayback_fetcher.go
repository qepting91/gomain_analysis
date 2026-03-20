package wayback

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
)

// Snapshot represents a single Wayback Machine capture
type Snapshot struct {
	Timestamp  string // YYYYMMDDHHMMSS format
	URL        string
	StatusCode string
	MIMEType   string
	Digest     string
	Length     string
}

// CDXResponse represents the raw CDX API response
type CDXResponse [][]string

// FetchSnapshots retrieves historical snapshots using the PASSIVE CDX API
// This is 100% read-only and does NOT trigger any active crawling of the target
func FetchSnapshots(domain string) []Snapshot {
	var snapshots []Snapshot

	// Query for domain and common subdomains
	urls := []string{
		"https://" + domain,
		"http://" + domain,
		"https://www." + domain,
	}

	for _, targetURL := range urls {
		results := queryCDXAPI(targetURL)
		snapshots = append(snapshots, results...)
	}

	// Deduplicate by timestamp
	seen := make(map[string]bool)
	var uniqueSnapshots []Snapshot
	for _, snap := range snapshots {
		key := snap.Timestamp + snap.URL
		if !seen[key] {
			seen[key] = true
			uniqueSnapshots = append(uniqueSnapshots, snap)
		}
	}

	log.Printf("[+] Wayback Machine: Found %d historical snapshots (100%% passive query)", len(uniqueSnapshots))
	return uniqueSnapshots
}

// queryCDXAPI queries the Wayback Machine CDX (Capture Index) API
// CDX API is 100% passive - only reads existing archive data, never triggers crawls
func queryCDXAPI(targetURL string) []Snapshot {
	// Build CDX API request
	// Documentation: https://archive.org/help/wayback_api.php
	cdxURL := "https://web.archive.org/cdx/search/cdx"

	params := url.Values{}
	params.Add("url", targetURL)
	params.Add("output", "json")
	params.Add("limit", "100")             // Get up to 100 most recent snapshots
	params.Add("filter", "statuscode:200") // Only successful captures
	params.Add("collapse", "timestamp:8")  // One per day (YYYYMMDD)

	fullURL := cdxURL + "?" + params.Encode()

	log.Printf("[*] Querying Wayback CDX API for %s (passive, read-only)", targetURL)

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", fullURL, http.NoBody)
	if err != nil {
		log.Printf("[-] Failed to create CDX request: %v", err)
		return nil
	}

	req.Header.Set("User-Agent", "gomain_analysis/1.0 (Passive OSINT Tool)")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[-] Failed to query CDX API: %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[-] CDX API returned status %d", resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[-] Failed to read CDX response: %v", err)
		return nil
	}

	// Parse CDX JSON response
	// Format: [["urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"], ...]
	var cdxData CDXResponse
	if err := json.Unmarshal(body, &cdxData); err != nil {
		log.Printf("[-] Failed to parse CDX JSON: %v", err)
		return nil
	}

	var snapshots []Snapshot
	for i, row := range cdxData {
		// First row is headers, skip it
		if i == 0 {
			continue
		}

		// CDX format: [urlkey, timestamp, original, mimetype, statuscode, digest, length]
		if len(row) < 7 {
			continue
		}

		snapshot := Snapshot{
			Timestamp:  row[1], // YYYYMMDDHHMMSS
			URL:        row[2], // Original URL
			MIMEType:   row[3],
			StatusCode: row[4],
			Digest:     row[5],
			Length:     row[6],
		}

		snapshots = append(snapshots, snapshot)
	}

	return snapshots
}

// GetAvailability checks if a URL has ever been archived (passive check)
// Uses the Availability API which is read-only
func GetAvailability(targetURL string) (*Snapshot, error) {
	// Availability API endpoint
	availURL := "https://archive.org/wayback/available"

	params := url.Values{}
	params.Add("url", targetURL)

	fullURL := availURL + "?" + params.Encode()

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", fullURL, http.NoBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "gomain_analysis/1.0 (Passive OSINT Tool)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("availability API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse availability response
	var result struct {
		ArchivedSnapshots struct {
			Closest struct {
				Available bool   `json:"available"`
				URL       string `json:"url"`
				Timestamp string `json:"timestamp"`
				Status    string `json:"status"`
			} `json:"closest"`
		} `json:"archived_snapshots"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	if !result.ArchivedSnapshots.Closest.Available {
		return nil, fmt.Errorf("no archived snapshots available")
	}

	snapshot := &Snapshot{
		Timestamp:  result.ArchivedSnapshots.Closest.Timestamp,
		URL:        result.ArchivedSnapshots.Closest.URL,
		StatusCode: result.ArchivedSnapshots.Closest.Status,
	}

	return snapshot, nil
}

// FormatTimestamp converts YYYYMMDDHHMMSS to human-readable format
func FormatTimestamp(timestamp string) string {
	if len(timestamp) < 14 {
		return timestamp
	}

	// Parse: YYYYMMDDHHMMSS
	year := timestamp[0:4]
	month := timestamp[4:6]
	day := timestamp[6:8]
	hour := timestamp[8:10]
	minute := timestamp[10:12]
	second := timestamp[12:14]

	return fmt.Sprintf("%s-%s-%s %s:%s:%s", year, month, day, hour, minute, second)
}

// GetSnapshotURL constructs the Wayback Machine URL for a snapshot
func GetSnapshotURL(timestamp, originalURL string) string {
	return fmt.Sprintf("https://web.archive.org/web/%s/%s", timestamp, originalURL)
}

// GetOldestSnapshot returns the oldest archived snapshot for a URL
func GetOldestSnapshot(targetURL string) *Snapshot {
	cdxURL := "https://web.archive.org/cdx/search/cdx"

	params := url.Values{}
	params.Add("url", targetURL)
	params.Add("output", "json")
	params.Add("limit", "1")
	params.Add("filter", "statuscode:200")

	fullURL := cdxURL + "?" + params.Encode()

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequest("GET", fullURL, http.NoBody)
	req.Header.Set("User-Agent", "gomain_analysis/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var cdxData CDXResponse
	if err := json.Unmarshal(body, &cdxData); err != nil {
		return nil
	}

	if len(cdxData) < 2 {
		return nil
	}

	row := cdxData[1]
	if len(row) < 7 {
		return nil
	}

	return &Snapshot{
		Timestamp:  row[1],
		URL:        row[2],
		StatusCode: row[4],
	}
}

// GetNewestSnapshot returns the most recent archived snapshot
func GetNewestSnapshot(targetURL string) *Snapshot {
	cdxURL := "https://web.archive.org/cdx/search/cdx"

	params := url.Values{}
	params.Add("url", targetURL)
	params.Add("output", "json")
	params.Add("limit", "-1") // Negative limit gets most recent
	params.Add("filter", "statuscode:200")

	fullURL := cdxURL + "?" + params.Encode()

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequest("GET", fullURL, http.NoBody)
	req.Header.Set("User-Agent", "gomain_analysis/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var cdxData CDXResponse
	if err := json.Unmarshal(body, &cdxData); err != nil {
		return nil
	}

	if len(cdxData) < 2 {
		return nil
	}

	row := cdxData[1]
	if len(row) < 7 {
		return nil
	}

	return &Snapshot{
		Timestamp:  row[1],
		URL:        row[2],
		StatusCode: row[4],
	}
}
