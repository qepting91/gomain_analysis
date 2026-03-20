package crt

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"time"
)

// InspectTLS performs a direct TLS handshake with the given domain
// and returns the live certificate chain provided by the server.
func InspectTLS(domain, port string) ([]*x509.Certificate, error) {
	if port == "" {
		port = "443"
	}
	address := net.JoinHostPort(domain, port)

	// Configure the TLS connection
	config := &tls.Config{
		ServerName: domain,
		// We want to fetch the cert even if it's expired or untrusted
		/* #nosec G402 */ // Intentional for OSINT tool
		InsecureSkipVerify: true, 
	}

	// Dial with a 10-second timeout
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, config)
	if err != nil {
		return nil, fmt.Errorf("failed to perform TLS handshake with %s: %v", address, err)
	}
	defer conn.Close()

	// Retrieve the certificate chain from the connection state
	state := conn.ConnectionState()
	certs := state.PeerCertificates

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates returned by %s", address)
	}

	log.Printf("Successfully retrieved live certificate chain for %s (%d certs)", domain, len(certs))
	return certs, nil
}
