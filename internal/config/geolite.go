package geolite

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/oschwald/geoip2-golang"
)

// GeoLiteDB represents the GeoLite2 database file
var GeoLiteDB *geoip2.Reader

// Initialize loads the GeoLite2 database from the provided file path
func Initialize() error {
	dbPath := filepath.Join("assets", "GeoLite2-City.mmdb")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return fmt.Errorf("GeoLite2 database file not found at %s", dbPath)
	}

	db, err := geoip2.Open(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open GeoLite2 database: %v", err)
	}

	GeoLiteDB = db
	log.Println("GeoLite2 database initialized successfully")
	return nil
}

// Close closes the GeoLite2 database
func Close() {
	if GeoLiteDB != nil {
		GeoLiteDB.Close()
		log.Println("GeoLite2 database closed successfully")
	}
}
