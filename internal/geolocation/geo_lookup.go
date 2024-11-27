package geolocation

import (
	"fmt"
	"log"
	"net"

	"gomain_analysis/internal/config/geolite"

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
