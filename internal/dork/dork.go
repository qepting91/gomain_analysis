package dork

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// LoadDorkQueries loads Google dork queries from queries.txt
func LoadDorkQueries() ([]string, error) {
	file, err := os.Open("queries/queries.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to open dork queries file: %v", err)
	}
	defer file.Close()

	var queries []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		queries = append(queries, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read dork queries file: %v", err)
	}

	log.Printf("Loaded %d dork queries from queries/queries.txt", len(queries))
	return queries, nil
}

// PerformDorkSearch performs a Google dork search for each query
func PerformDorkSearch(domain string, queries []string) []string {
	client := &http.Client{}
	var results []string

	for _, query := range queries {
		// Replace the domain placeholder with actual domain
		processedQuery := strings.Replace(query, "{domain}", domain, -1)
		// URL encode the processed query
		encodedQuery := url.QueryEscape(processedQuery)
		searchURL := fmt.Sprintf("https://www.google.com/search?q=%s", encodedQuery)

		req, err := http.NewRequest("GET", searchURL, nil)
		if err != nil {
			results = append(results, fmt.Sprintf("Query: %s - Error: %v", query, err))
			continue
		}

		// Add User-Agent header to mimic browser behavior
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

		resp, err := client.Do(req)
		if err != nil {
			results = append(results, fmt.Sprintf("Query: %s - Error: %v", query, err))
			continue
		}
		defer resp.Body.Close()

		results = append(results, fmt.Sprintf("Query: %s\nURL: %s", processedQuery, searchURL))

	}

	return results
}
