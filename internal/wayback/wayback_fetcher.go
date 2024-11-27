package wayback

import (
	"fmt"
	"log"
	"net/http"

	"github.com/seekr-osint/wayback-machine-golang/wayback"
)

// FetchSnapshots retrieves a list of available snapshots for a given domain using the Wayback Machine API
func FetchSnapshots(domain string) {
	client := &http.Client{}
	snapshots, err := wayback.GetSnapshotData("https://"+domain, client)
	if err != nil {
		log.Printf("Error fetching snapshots for domain %s: %v", domain, err)
		return
	}

	for _, snapshot := range snapshots {
		fmt.Printf("Snapshot URL: %s, Timestamp: %s\n", snapshot.URL, snapshot.Timestamp)
	}
}

// ArchiveURL archives the given URL using the Wayback Machine
func ArchiveURL(url string) {
	client := &http.Client{}
	archivedURL, err := wayback.Archive(url, client)
	if err != nil {
		log.Printf("Error archiving URL %s: %v", url, err)
		return
	}

	fmt.Printf("Archived URL: %s\n", archivedURL)
}
