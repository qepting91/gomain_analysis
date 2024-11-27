package geolite

import (
	"fmt"
	"log"
	"os"

	"github.com/oschwald/geoip2-golang"
)

// GeoLiteDB represents the GeoLite2 database file
var GeoLiteDB *geoip2.Reader

// Initialize loads the GeoLite2 database from the provided file path
func Initialize(dbPath string) error {
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

// LookupIP takes an IP address and returns geolocation information
func LookupIP(ip string) (*geoip2.City, error) {
	if GeoLiteDB == nil {
		return nil, fmt.Errorf("GeoLite2 database is not initialized")
	}

	record, err := GeoLiteDB.City([]byte(ip))
	if err != nil {
		return nil, fmt.Errorf("failed to lookup IP: %v", err)
	}

	return record, nil
}
