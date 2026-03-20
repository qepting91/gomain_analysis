package discovery

import (
	"bufio"
	"encoding/xml"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// DiscoveryResult contains discovered endpoints from passive analysis
type DiscoveryResult struct {
	RobotsTxt        RobotsTxtResult
	Sitemaps         []SitemapResult
	SecurityTxt      string
	HumansTxt        string
	WellKnownPaths   []WellKnownPath
	DiscoveredPaths  []string
	InterestingFiles []string
}

// RobotsTxtResult contains parsed robots.txt data
type RobotsTxtResult struct {
	Found          bool
	AllowedPaths   []string
	DisallowedPath []string // These are often the most interesting!
	Sitemaps       []string
	CrawlDelay     string
	UserAgents     []string
}

// SitemapResult contains URLs from sitemap.xml
type SitemapResult struct {
	URL            string
	LastModified   string
	ChangeFreq     string
	Priority       string
	DiscoveredURLs []string
}

// WellKnownPath represents common security/config files
type WellKnownPath struct {
	Path   string
	Found  bool
	Status int
	Size   int64
}

// SitemapXML represents the XML structure of a sitemap
type SitemapXML struct {
	XMLName xml.Name `xml:"urlset"`
	URLs    []struct {
		Loc        string `xml:"loc"`
		LastMod    string `xml:"lastmod"`
		ChangeFreq string `xml:"changefreq"`
		Priority   string `xml:"priority"`
	} `xml:"url"`
}

// PerformPassiveDiscovery discovers endpoints without active scanning
// 100% passive - only reads publicly documented files
func PerformPassiveDiscovery(baseURL string) (*DiscoveryResult, error) {
	result := &DiscoveryResult{}

	// Ensure baseURL has proper format
	if !strings.HasPrefix(baseURL, "http") {
		baseURL = "https://" + baseURL
	}
	baseURL = strings.TrimSuffix(baseURL, "/")

	log.Printf("[*] Starting passive discovery for %s", baseURL)

	// 1. robots.txt - ALWAYS check this first
	result.RobotsTxt = parseRobotsTxt(baseURL)

	// 2. sitemap.xml and variants
	sitemapURLs := []string{
		baseURL + "/sitemap.xml",
		baseURL + "/sitemap_index.xml",
		baseURL + "/sitemap-index.xml",
		baseURL + "/sitemap1.xml",
	}

	// Add sitemaps found in robots.txt
	sitemapURLs = append(sitemapURLs, result.RobotsTxt.Sitemaps...)

	for _, sitemapURL := range sitemapURLs {
		if sitemap := parseSitemap(sitemapURL); sitemap != nil {
			result.Sitemaps = append(result.Sitemaps, *sitemap)
		}
	}

	// 3. security.txt (RFC 9116) - Security contact information
	result.SecurityTxt = fetchTextFile(baseURL + "/.well-known/security.txt")
	if result.SecurityTxt == "" {
		result.SecurityTxt = fetchTextFile(baseURL + "/security.txt")
	}

	// 4. humans.txt - Website credits
	result.HumansTxt = fetchTextFile(baseURL + "/humans.txt")

	// 5. Well-known URIs (RFC 8615)
	wellKnownPaths := []string{
		"/.well-known/security.txt",
		"/.well-known/change-password",
		"/.well-known/apple-app-site-association",
		"/.well-known/assetlinks.json", // Android app links
		"/.well-known/matrix/server",
		"/.well-known/openid-configuration",
		"/.well-known/acme-challenge",
		"/ads.txt",                // Authorized Digital Sellers
		"/app-ads.txt",            // App ads
		"/crossdomain.xml",        // Flash policy (legacy)
		"/clientaccesspolicy.xml", // Silverlight (legacy)
	}

	for _, path := range wellKnownPaths {
		wellKnown := checkWellKnownPath(baseURL + path)
		result.WellKnownPaths = append(result.WellKnownPaths, wellKnown)
		if wellKnown.Found {
			result.DiscoveredPaths = append(result.DiscoveredPaths, wellKnown.Path)
		}
	}

	// 6. Aggregate all discovered paths
	for _, disallow := range result.RobotsTxt.DisallowedPath {
		if disallow != "" && disallow != "/" {
			result.InterestingFiles = append(result.InterestingFiles, disallow)
		}
	}

	log.Printf("[+] Passive discovery complete: %d paths from robots.txt, %d sitemaps, %d well-known paths",
		len(result.RobotsTxt.DisallowedPath)+len(result.RobotsTxt.AllowedPaths),
		len(result.Sitemaps),
		len(result.WellKnownPaths))

	return result, nil
}

// parseRobotsTxt fetches and parses robots.txt
func parseRobotsTxt(baseURL string) RobotsTxtResult {
	result := RobotsTxtResult{Found: false}

	robotsURL := baseURL + "/robots.txt"
	content := fetchTextFile(robotsURL)
	if content == "" {
		log.Println("[-] robots.txt not found")
		return result
	}

	result.Found = true
	scanner := bufio.NewScanner(strings.NewReader(content))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		directive := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])

		switch directive {
		case "user-agent":
			result.UserAgents = append(result.UserAgents, value)
		case "disallow":
			result.DisallowedPath = append(result.DisallowedPath, value)
		case "allow":
			result.AllowedPaths = append(result.AllowedPaths, value)
		case "sitemap":
			result.Sitemaps = append(result.Sitemaps, value)
		case "crawl-delay":
			result.CrawlDelay = value
		}
	}

	log.Printf("[+] robots.txt parsed: %d disallowed paths, %d sitemaps referenced",
		len(result.DisallowedPath), len(result.Sitemaps))

	return result
}

// parseSitemap fetches and parses a sitemap.xml file
func parseSitemap(sitemapURL string) *SitemapResult {
	client := &http.Client{Timeout: 15 * time.Second}

	req, err := http.NewRequest("GET", sitemapURL, http.NoBody)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", "gomain_analysis/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var sitemap SitemapXML
	if err := xml.Unmarshal(body, &sitemap); err != nil {
		// Might be a sitemap index, not a regular sitemap
		return nil
	}

	result := &SitemapResult{
		URL: sitemapURL,
	}

	for _, url := range sitemap.URLs {
		result.DiscoveredURLs = append(result.DiscoveredURLs, url.Loc)
	}

	log.Printf("[+] Sitemap parsed: %d URLs discovered from %s", len(result.DiscoveredURLs), sitemapURL)
	return result
}

// fetchTextFile retrieves a text file from a URL
func fetchTextFile(url string) string {
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest("GET", url, http.NoBody)
	if err != nil {
		return ""
	}

	req.Header.Set("User-Agent", "gomain_analysis/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	return string(body)
}

// checkWellKnownPath checks if a well-known path exists
func checkWellKnownPath(url string) WellKnownPath {
	result := WellKnownPath{
		Path:  url,
		Found: false,
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	req, err := http.NewRequest("HEAD", url, http.NoBody)
	if err != nil {
		return result
	}

	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	defer func() { _ = resp.Body.Close() }()

	result.Status = resp.StatusCode
	result.Size = resp.ContentLength

	if resp.StatusCode == http.StatusOK {
		result.Found = true
		log.Printf("[+] Well-known path found: %s (Status: %d, Size: %d bytes)", url, result.Status, result.Size)
	}

	return result
}

// ExtractInterestingPaths identifies potentially sensitive paths from robots.txt
func ExtractInterestingPaths(robotsResult RobotsTxtResult) []string {
	interesting := []string{}

	keywords := []string{
		"admin", "login", "api", "v1", "v2", "test", "dev", "staging",
		"backup", "old", "private", "internal", "config", "cgi-bin",
		"console", "dashboard", "panel", "wp-admin", "phpmyadmin",
	}

	for _, path := range robotsResult.DisallowedPath {
		lowerPath := strings.ToLower(path)
		for _, keyword := range keywords {
			if strings.Contains(lowerPath, keyword) {
				interesting = append(interesting, path)
				break
			}
		}
	}

	return interesting
}
