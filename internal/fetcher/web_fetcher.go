package fetcher

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

// FetchWebContent retrieves the HTML content of the given URL
func FetchWebContent(url string) (string, error) {
	client := &http.Client{}
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to fetch content from %s: %v", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch content from %s, status code: %d", url, resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body from %s: %v", url, err)
	}

	log.Printf("Successfully fetched content from %s", url)
	return string(body), nil
}
