package wayback

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/seekr-osint/wayback-machine-golang/wayback"
)

// FetchSnapshots retrieves historical snapshots and proactively triggers
// a live capture of the current domain infrastructure.
func FetchSnapshots(domain string) []string {
	var results []string
	targetURL := "https://" + domain
	
	// Create a client with a reasonable timeout for both requests
	client := &http.Client{Timeout: 30 * time.Second}

	// 1. Proactively grab a live snapshot (Archive)
	log.Printf("Triggering live Wayback Machine archive capture for %s...", targetURL)
	archiveURL, err := wayback.Archive(targetURL, client)
	
	if err != nil {
		log.Printf("Warning: Failed to capture live archive for %s: %v", domain, err)
		results = append(results, fmt.Sprintf("URL: %s\nTimestamp: %s\nStatus: Error Archive Failed", targetURL, time.Now().Format("20060102150405")))
	} else {
		// Example return is typically something like "https://web.archive.org/web/2026.../https://domain.com"
		results = append(results, fmt.Sprintf("URL: %s\nTimestamp: %s\nStatus: Proactive Live Capture", archiveURL, time.Now().Format("20060102150405")))
	}

	// 2. Query historical data (GetSnapshotData)
	snapshots, err := wayback.GetSnapshotData(targetURL, client)
	if err != nil {
		log.Printf("Error fetching historical snapshots for domain %s: %v", domain, err)
		return results
	}

	if snapshots != nil && snapshots.ArchivedSnapshots.Closest.Available {
		snapshotInfo := fmt.Sprintf("URL: %s\nTimestamp: %s\nStatus: Historical (%s)",
			snapshots.ArchivedSnapshots.Closest.URL,
			snapshots.ArchivedSnapshots.Closest.Timestamp,
			snapshots.ArchivedSnapshots.Closest.Status)
		results = append(results, snapshotInfo)
	}

	return results
}

