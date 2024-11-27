package wayback

import (
	"fmt"
	"log"
	"net/http"

	"github.com/seekr-osint/wayback-machine-golang/wayback"
)

// FetchSnapshots retrieves available snapshots and returns them as formatted strings
func FetchSnapshots(domain string) []string {
	client := &http.Client{}
	snapshots, err := wayback.GetSnapshotData("https://"+domain, client)
	if err != nil {
		log.Printf("Error fetching snapshots for domain %s: %v", domain, err)
		return nil
	}

	var results []string
	if snapshots.ArchivedSnapshots.Closest.Available {
		snapshotInfo := fmt.Sprintf("URL: %s\nTimestamp: %s\nStatus: %s",
			snapshots.ArchivedSnapshots.Closest.URL,
			snapshots.ArchivedSnapshots.Closest.Timestamp,
			snapshots.ArchivedSnapshots.Closest.Status)
		results = append(results, snapshotInfo)
	}

	return results
}
