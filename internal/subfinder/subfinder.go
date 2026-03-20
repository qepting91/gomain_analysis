package subfinder

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// Enumerate passively queries multiple external APIs and databases to find subdomains
// without directly interacting with the target domain infrastructure.
func Enumerate(domain string) []string {
	var results []string

	opts := &runner.Options{
		Threads:            10,
		Timeout:            30,
		MaxEnumerationTime: 5, // Maximum time to run in minutes
		Silent:             true, // Prevents banner printing and verbose logs
	}

	subfinderRunner, err := runner.NewRunner(opts)
	if err != nil {
		log.Printf("Warning: Failed to initialize Subfinder: %v", err)
		return results
	}

	buf := bytes.NewBuffer(nil)

	_, err = subfinderRunner.EnumerateSingleDomainWithCtx(context.Background(), domain, []io.Writer{buf})
	if err != nil {
		log.Printf("Warning: Failed to execute Subfinder enumeration: %v", err)
		return results
	}

	// Subfinder outputs one subdomain per line directly to the io.Writer
	scanner := bufio.NewScanner(buf)
	for scanner.Scan() {
		subdomain := scanner.Text()
		if subdomain != "" {
			results = append(results, subdomain)
		}
	}

	log.Printf("Subfinder enumeration complete: Discovered %d passive subdomains", len(results))
	return results
}
