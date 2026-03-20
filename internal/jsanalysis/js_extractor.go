package jsanalysis

import (
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// JSAnalysisResult contains extracted data from JavaScript files
type JSAnalysisResult struct {
	JSFiles          []string
	APIEndpoints     []string
	ExternalDomains  []string
	PotentialSecrets []SecretMatch
	InterestingURLs  []string
	Comments         []string
	SourceMaps       []string
}

// SecretMatch represents a potential secret found in JS
type SecretMatch struct {
	Type    string // "api_key", "token", "password", "aws_key", etc.
	Value   string
	Context string // Surrounding code for context
	File    string // Which JS file it was found in
}

// AnalyzeJavaScript extracts intelligence from JavaScript files
func AnalyzeJavaScript(htmlContent string, baseURL string) (*JSAnalysisResult, error) {
	result := &JSAnalysisResult{}

	log.Println("[*] Analyzing JavaScript files...")

	// 1. Extract all <script src="..."> tags
	scriptRegex := regexp.MustCompile(`<script[^>]*src=["']([^"']+)["']`)
	matches := scriptRegex.FindAllStringSubmatch(htmlContent, -1)

	for _, match := range matches {
		if len(match) > 1 {
			scriptURL := resolveURL(baseURL, match[1])
			result.JSFiles = append(result.JSFiles, scriptURL)
		}
	}

	// 2. Extract inline JavaScript
	inlineScriptRegex := regexp.MustCompile(`(?s)<script[^>]*>(.*?)</script>`)
	inlineMatches := inlineScriptRegex.FindAllStringSubmatch(htmlContent, -1)

	for _, match := range inlineMatches {
		if len(match) > 1 {
			analyzeJSContent(match[1], "inline", result)
		}
	}

	// 3. Download and analyze external JS files (up to 10 to avoid abuse)
	maxFiles := 10
	for i, jsURL := range result.JSFiles {
		if i >= maxFiles {
			break
		}

		content := downloadJS(jsURL)
		if content != "" {
			analyzeJSContent(content, jsURL, result)
		}

		// Be polite - don't hammer the server
		time.Sleep(500 * time.Millisecond)
	}

	// 4. Deduplicate results
	result.APIEndpoints = uniqueStrings(result.APIEndpoints)
	result.ExternalDomains = uniqueStrings(result.ExternalDomains)
	result.InterestingURLs = uniqueStrings(result.InterestingURLs)

	log.Printf("[+] JS analysis complete: %d files, %d API endpoints, %d secrets found",
		len(result.JSFiles), len(result.APIEndpoints), len(result.PotentialSecrets))

	return result, nil
}

// analyzeJSContent performs deep analysis on JavaScript source code
func analyzeJSContent(jsCode, sourceFile string, result *JSAnalysisResult) {
	// 1. Extract API endpoints (common patterns)
	apiPatterns := []*regexp.Regexp{
		regexp.MustCompile(`["'](/api/[^"'\s]+)["']`),                    // /api/...
		regexp.MustCompile(`["'](/v[0-9]/[^"'\s]+)["']`),                 // /v1/..., /v2/...
		regexp.MustCompile(`["'](https?://[^"'\s]+/api[^"'\s]*)["']`),    // Full API URLs
		regexp.MustCompile(`["'](https?://[^"'\s]+/graphql[^"'\s]*)["']`), // GraphQL endpoints
		regexp.MustCompile(`fetch\(["']([^"']+)["']`),                    // fetch() calls
		regexp.MustCompile(`axios\.(get|post|put|delete)\(["']([^"']+)["']`), // axios calls
		regexp.MustCompile(`\$\.ajax\(.*?url:\s*["']([^"']+)["']`),       // jQuery ajax
	}

	for _, pattern := range apiPatterns {
		matches := pattern.FindAllStringSubmatch(jsCode, -1)
		for _, match := range matches {
			if len(match) > 1 {
				endpoint := match[1]
				if endpoint != "" && !strings.Contains(endpoint, "{{") {
					result.APIEndpoints = append(result.APIEndpoints, endpoint)
				}
			}
		}
	}

	// 2. Extract potential secrets/tokens
	secretPatterns := []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{"api_key", regexp.MustCompile(`(?i)api[_-]?key['"]\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]`)},
		{"token", regexp.MustCompile(`(?i)token['"]\s*[:=]\s*['"]([a-zA-Z0-9_\-\.]{20,})['"]`)},
		{"jwt", regexp.MustCompile(`eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`)},
		{"aws_key", regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`)},
		{"aws_secret", regexp.MustCompile(`(?i)aws[_-]?secret['"]\s*[:=]\s*['"]([a-zA-Z0-9/+=]{40})['"]`)},
		{"password", regexp.MustCompile(`(?i)password['"]\s*[:=]\s*['"]([^'"]{8,})['"]`)},
		{"slack_token", regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z]{10,48}`)},
		{"github_token", regexp.MustCompile(`gh[pousr]_[0-9a-zA-Z]{36}`)},
		{"stripe_key", regexp.MustCompile(`(?i)sk_live_[0-9a-zA-Z]{24,}`)},
		{"google_api", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	}

	for _, secretType := range secretPatterns {
		matches := secretType.pattern.FindAllStringSubmatch(jsCode, -1)
		for _, match := range matches {
			if len(match) > 0 {
				value := match[0]
				if len(match) > 1 && match[1] != "" {
					value = match[1]
				}

				// Get context (50 chars before and after)
				index := strings.Index(jsCode, value)
				context := ""
				if index > 0 {
					start := max(0, index-50)
					end := min(len(jsCode), index+len(value)+50)
					context = jsCode[start:end]
				}

				result.PotentialSecrets = append(result.PotentialSecrets, SecretMatch{
					Type:    secretType.name,
					Value:   value,
					Context: context,
					File:    sourceFile,
				})

				log.Printf("[!!!] Potential %s found in %s: %s...", secretType.name, sourceFile, value[:min(20, len(value))])
			}
		}
	}

	// 3. Extract external domains
	domainRegex := regexp.MustCompile(`https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`)
	domainMatches := domainRegex.FindAllStringSubmatch(jsCode, -1)
	for _, match := range domainMatches {
		if len(match) > 1 {
			result.ExternalDomains = append(result.ExternalDomains, match[1])
		}
	}

	// 4. Extract interesting URLs (potential endpoints)
	urlRegex := regexp.MustCompile(`["']([/a-zA-Z0-9._-]+\.(json|xml|txt|log|bak|sql|zip|tar\.gz|config))["']`)
	urlMatches := urlRegex.FindAllStringSubmatch(jsCode, -1)
	for _, match := range urlMatches {
		if len(match) > 1 {
			result.InterestingURLs = append(result.InterestingURLs, match[1])
		}
	}

	// 5. Extract comments (may contain useful info)
	commentRegex := regexp.MustCompile(`(?m)^\s*//(.+)$|/\*(.+?)\*/`)
	commentMatches := commentRegex.FindAllStringSubmatch(jsCode, -1)
	for _, match := range commentMatches {
		if len(match) > 1 {
			comment := strings.TrimSpace(match[1])
			if comment == "" && len(match) > 2 {
				comment = strings.TrimSpace(match[2])
			}
			if len(comment) > 10 && !strings.Contains(comment, "Copyright") {
				result.Comments = append(result.Comments, comment)
			}
		}
	}

	// 6. Check for source maps
	if strings.Contains(jsCode, "sourceMappingURL") {
		sourceMapRegex := regexp.MustCompile(`sourceMappingURL=([^\s]+)`)
		smMatches := sourceMapRegex.FindAllStringSubmatch(jsCode, -1)
		for _, match := range smMatches {
			if len(match) > 1 {
				result.SourceMaps = append(result.SourceMaps, match[1])
				log.Printf("[+] Source map found: %s", match[1])
			}
		}
	}
}

// downloadJS fetches JavaScript content from a URL
func downloadJS(jsURL string) string {
	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	req, err := http.NewRequest("GET", jsURL, http.NoBody)
	if err != nil {
		return ""
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; gomain_analysis/1.0)")
	req.Header.Set("Accept", "application/javascript, */*")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[-] Failed to download JS: %s - %v", jsURL, err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	// Limit download size to 5MB to avoid abuse
	limitedReader := io.LimitReader(resp.Body, 5*1024*1024)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return ""
	}

	return string(body)
}

// resolveURL resolves relative URLs to absolute
func resolveURL(base, relative string) string {
	baseURL, err := url.Parse(base)
	if err != nil {
		return relative
	}

	relURL, err := url.Parse(relative)
	if err != nil {
		return relative
	}

	return baseURL.ResolveReference(relURL).String()
}

// uniqueStrings removes duplicates from a string slice
func uniqueStrings(slice []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

// Helper functions
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// GetCriticalFindings returns only high-severity findings
func (r *JSAnalysisResult) GetCriticalFindings() []SecretMatch {
	critical := []SecretMatch{}

	criticalTypes := map[string]bool{
		"aws_key":       true,
		"aws_secret":    true,
		"jwt":           true,
		"slack_token":   true,
		"github_token":  true,
		"stripe_key":    true,
		"google_api":    true,
	}

	for _, secret := range r.PotentialSecrets {
		if criticalTypes[secret.Type] {
			critical = append(critical, secret)
		}
	}

	return critical
}
