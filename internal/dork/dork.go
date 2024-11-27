package dork

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

// LoadDorkQueries loads Google dork queries from a given file
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

// PerformDorkSearch performs a Google dork search for each query and prints the results
func PerformDorkSearch(domain string, queries []string) {
	client := &http.Client{}

	for _, query := range queries {
		searchURL := fmt.Sprintf("https://www.google.com/search?q=%s", strings.Replace(query, "{domain}", domain, -1))
		req, err := http.NewRequest("GET", searchURL, nil)
		if err != nil {
			log.Printf("Error creating request for query %s: %v", query, err)
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Error performing dork search for query %s: %v", query, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			log.Printf("Successfully performed dork search for query: %s", query)
		} else {
			log.Printf("Failed to perform dork search for query: %s, Status code: %d", query, resp.StatusCode)
		}
	}
}
