package fetcher

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

type WebFetcher struct {
	client *http.Client
}

func NewWebFetcher() *WebFetcher {
	return &WebFetcher{
		client: &http.Client{},
	}
}

// FetchRobotsTxt retrieves robots.txt content
func (w *WebFetcher) FetchRobotsTxt(domain string) (string, error) {
	url := fmt.Sprintf("https://%s/robots.txt", domain)
	return w.FetchWebContent(url)
}

// FetchSitemap retrieves sitemap content
func (w *WebFetcher) FetchSitemap(domain string) (string, error) {
	url := fmt.Sprintf("https://%s/sitemap.xml", domain)
	return w.FetchWebContent(url)
}

// FetchWebContent retrieves content from any URL
func (w *WebFetcher) FetchWebContent(url string) (string, error) {
	resp, err := w.client.Get(url)
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

// FetchCommonFiles attempts to fetch common files that might contain domain info
func (w *WebFetcher) FetchCommonFiles(domain string) map[string]string {
	commonPaths := []string{
		"/.well-known/security.txt",
		"/crossdomain.xml",
		"/humans.txt",
		"/.git/config",
		"/package.json",
		"/composer.json",
	}

	results := make(map[string]string)
	for _, path := range commonPaths {
		url := fmt.Sprintf("https://%s%s", domain, path)
		content, err := w.FetchWebContent(url)
		if err == nil {
			results[path] = content
		}
	}

	return results
}
