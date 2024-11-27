package geolocation

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/qepting91/gomain_analysis/internal/config"

	"github.com/oschwald/geoip2-golang"
)

// LookupGeolocation takes an IP address and returns geolocation information
func LookupGeolocation(ip string) (*geoip2.City, error) {
	if geolite.GeoLiteDB == nil {
		return nil, fmt.Errorf("GeoLite2 database is not initialized")
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	record, err := geolite.GeoLiteDB.City(parsedIP)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup IP: %v", err)
	}

	log.Printf("Successfully retrieved geolocation for IP: %s", ip)
	return record, nil
}

// FormatGeoLocation formats the City record into a readable string
func FormatGeoLocation(record *geoip2.City) string {
	var info strings.Builder

	// Location Information
	fmt.Fprintf(&info, "City: %s\n", record.City.Names["en"])
	if len(record.Subdivisions) > 0 {
		fmt.Fprintf(&info, "Region: %s\n", record.Subdivisions[0].Names["en"])
	}
	fmt.Fprintf(&info, "Country: %s (%s)\n", record.Country.Names["en"], record.Country.IsoCode)
	fmt.Fprintf(&info, "Continent: %s (%s)\n", record.Continent.Names["en"], record.Continent.Code)

	// Geographical Coordinates
	fmt.Fprintf(&info, "Coordinates: %.4f, %.4f\n", record.Location.Latitude, record.Location.Longitude)
	fmt.Fprintf(&info, "Timezone: %s\n", record.Location.TimeZone)

	// Additional Details
	fmt.Fprintf(&info, "Accuracy Radius: %d km\n", record.Location.AccuracyRadius)
	if record.Postal.Code != "" {
		fmt.Fprintf(&info, "Postal Code: %s\n", record.Postal.Code)
	}

	// Network Traits
	fmt.Fprintf(&info, "Network Traits:\n")
	fmt.Fprintf(&info, "- Anonymous Proxy: %t\n", record.Traits.IsAnonymousProxy)
	fmt.Fprintf(&info, "- Satellite Provider: %t\n", record.Traits.IsSatelliteProvider)
	fmt.Fprintf(&info, "- Anycast: %t\n", record.Traits.IsAnycast)

	return info.String()
}
