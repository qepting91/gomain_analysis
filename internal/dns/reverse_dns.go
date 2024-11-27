package reverse_dns

import (
	"fmt"
	"log"
	"net"
)

// ReverseLookup takes an IP address and returns the associated domain names
func ReverseLookup(ip string) ([]string, error) {
	hosts, err := net.LookupAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("failed to perform reverse DNS lookup for IP %s: %v", ip, err)
	}

	log.Printf("Reverse DNS lookup for IP %s: %v", ip, hosts)
	return hosts, nil
}
