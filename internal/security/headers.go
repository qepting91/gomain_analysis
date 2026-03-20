package security

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// HeaderAnalysis represents security header analysis results
type HeaderAnalysis struct {
	URL                    string
	SecurityScore          int      // 0-100
	MissingHeaders         []string // Critical headers that are missing
	WeakHeaders            []string // Present but misconfigured
	GoodHeaders            []string // Properly configured
	Vulnerabilities        []string // Identified security issues
	HTTPSEnforced          bool
	HSTSPresent            bool
	HSTSMaxAge             string
	CSPPresent             bool
	CSPDirectives          []string
	XFrameOptions          string
	ContentTypeOptionsSet  bool
	ReferrerPolicySet      bool
	PermissionsPolicySet   bool
	CORSWildcard           bool
	ServerHeaderExposed    bool
	ServerVersion          string
	PoweredByExposed       bool
	PoweredByValue         string
	DeprecatedHeadersFound []string
}

// AnalyzeSecurityHeaders performs comprehensive security header analysis
// This is 100% passive - just reads HTTP response headers
func AnalyzeSecurityHeaders(targetURL string) (*HeaderAnalysis, error) {
	analysis := &HeaderAnalysis{
		URL:           targetURL,
		SecurityScore: 100, // Start at perfect, deduct for issues
	}

	// Create HTTP client that follows redirects
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // For testing, we want to connect even with bad certs
			},
		},
	}

	req, err := http.NewRequest("GET", targetURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("User-Agent", "gomain_analysis/1.0 (Security Header Scanner)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch URL: %v", err)
	}
	defer resp.Body.Close()

	// Check HTTPS enforcement
	analysis.HTTPSEnforced = strings.HasPrefix(targetURL, "https://")
	if !analysis.HTTPSEnforced {
		analysis.SecurityScore -= 20
		analysis.Vulnerabilities = append(analysis.Vulnerabilities, "HTTPS not enforced - data transmitted in cleartext")
	}

	headers := resp.Header

	// 1. Strict-Transport-Security (HSTS)
	if hsts := headers.Get("Strict-Transport-Security"); hsts != "" {
		analysis.HSTSPresent = true
		analysis.HSTSMaxAge = hsts
		analysis.GoodHeaders = append(analysis.GoodHeaders, "Strict-Transport-Security")

		// Check for weak HSTS configuration
		if !strings.Contains(hsts, "max-age") {
			analysis.WeakHeaders = append(analysis.WeakHeaders, "HSTS: missing max-age")
			analysis.SecurityScore -= 5
		}
		if !strings.Contains(hsts, "includeSubDomains") {
			analysis.WeakHeaders = append(analysis.WeakHeaders, "HSTS: missing includeSubDomains")
			analysis.SecurityScore -= 3
		}
	} else if analysis.HTTPSEnforced {
		analysis.MissingHeaders = append(analysis.MissingHeaders, "Strict-Transport-Security")
		analysis.Vulnerabilities = append(analysis.Vulnerabilities, "HSTS not set - vulnerable to SSL stripping attacks")
		analysis.SecurityScore -= 15
	}

	// 2. Content-Security-Policy (CSP)
	if csp := headers.Get("Content-Security-Policy"); csp != "" {
		analysis.CSPPresent = true
		analysis.CSPDirectives = strings.Split(csp, ";")
		analysis.GoodHeaders = append(analysis.GoodHeaders, "Content-Security-Policy")

		// Check for unsafe CSP directives
		if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
			analysis.WeakHeaders = append(analysis.WeakHeaders, "CSP: contains unsafe-inline or unsafe-eval")
			analysis.SecurityScore -= 10
		}
		if strings.Contains(csp, "*") && strings.Contains(csp, "default-src") {
			analysis.WeakHeaders = append(analysis.WeakHeaders, "CSP: wildcard in default-src")
			analysis.SecurityScore -= 8
		}
	} else {
		analysis.MissingHeaders = append(analysis.MissingHeaders, "Content-Security-Policy")
		analysis.Vulnerabilities = append(analysis.Vulnerabilities, "CSP not set - vulnerable to XSS and code injection")
		analysis.SecurityScore -= 15
	}

	// 3. X-Frame-Options
	if xfo := headers.Get("X-Frame-Options"); xfo != "" {
		analysis.XFrameOptions = xfo
		analysis.GoodHeaders = append(analysis.GoodHeaders, "X-Frame-Options")

		if !strings.EqualFold(xfo, "DENY") && !strings.EqualFold(xfo, "SAMEORIGIN") {
			analysis.WeakHeaders = append(analysis.WeakHeaders, "X-Frame-Options: weak value")
			analysis.SecurityScore -= 5
		}
	} else {
		analysis.MissingHeaders = append(analysis.MissingHeaders, "X-Frame-Options")
		analysis.Vulnerabilities = append(analysis.Vulnerabilities, "X-Frame-Options not set - vulnerable to clickjacking")
		analysis.SecurityScore -= 10
	}

	// 4. X-Content-Type-Options
	if xcto := headers.Get("X-Content-Type-Options"); xcto == "nosniff" {
		analysis.ContentTypeOptionsSet = true
		analysis.GoodHeaders = append(analysis.GoodHeaders, "X-Content-Type-Options")
	} else {
		analysis.MissingHeaders = append(analysis.MissingHeaders, "X-Content-Type-Options")
		analysis.Vulnerabilities = append(analysis.Vulnerabilities, "X-Content-Type-Options not set - vulnerable to MIME sniffing attacks")
		analysis.SecurityScore -= 8
	}

	// 5. Referrer-Policy
	if rp := headers.Get("Referrer-Policy"); rp != "" {
		analysis.ReferrerPolicySet = true
		analysis.GoodHeaders = append(analysis.GoodHeaders, "Referrer-Policy")
	} else {
		analysis.MissingHeaders = append(analysis.MissingHeaders, "Referrer-Policy")
		analysis.SecurityScore -= 5
	}

	// 6. Permissions-Policy (formerly Feature-Policy)
	if pp := headers.Get("Permissions-Policy"); pp != "" {
		analysis.PermissionsPolicySet = true
		analysis.GoodHeaders = append(analysis.GoodHeaders, "Permissions-Policy")
	} else if fp := headers.Get("Feature-Policy"); fp != "" {
		analysis.PermissionsPolicySet = true
		analysis.GoodHeaders = append(analysis.GoodHeaders, "Feature-Policy (deprecated, use Permissions-Policy)")
	} else {
		analysis.MissingHeaders = append(analysis.MissingHeaders, "Permissions-Policy")
		analysis.SecurityScore -= 5
	}

	// 7. CORS Check for wildcard
	if cors := headers.Get("Access-Control-Allow-Origin"); cors == "*" {
		analysis.CORSWildcard = true
		analysis.Vulnerabilities = append(analysis.Vulnerabilities, "CORS wildcard (*) allows any origin - potential data leakage")
		analysis.SecurityScore -= 10
	}

	// 8. Information Disclosure Headers
	if server := headers.Get("Server"); server != "" {
		analysis.ServerHeaderExposed = true
		analysis.ServerVersion = server
		analysis.Vulnerabilities = append(analysis.Vulnerabilities, fmt.Sprintf("Server header exposed: %s - aids in reconnaissance", server))
		analysis.SecurityScore -= 5
	}

	if poweredBy := headers.Get("X-Powered-By"); poweredBy != "" {
		analysis.PoweredByExposed = true
		analysis.PoweredByValue = poweredBy
		analysis.Vulnerabilities = append(analysis.Vulnerabilities, fmt.Sprintf("X-Powered-By exposed: %s - reveals tech stack", poweredBy))
		analysis.SecurityScore -= 5
	}

	// 9. Deprecated/Dangerous Headers
	deprecatedHeaders := []string{"X-XSS-Protection", "Public-Key-Pins", "Expect-CT"}
	for _, header := range deprecatedHeaders {
		if headers.Get(header) != "" {
			analysis.DeprecatedHeadersFound = append(analysis.DeprecatedHeadersFound, header)
		}
	}

	// Ensure score doesn't go negative
	if analysis.SecurityScore < 0 {
		analysis.SecurityScore = 0
	}

	log.Printf("[+] Security header analysis complete: Score %d/100", analysis.SecurityScore)
	return analysis, nil
}

// GetSecurityGrade returns a letter grade based on score
func (h *HeaderAnalysis) GetSecurityGrade() string {
	switch {
	case h.SecurityScore >= 90:
		return "A"
	case h.SecurityScore >= 80:
		return "B"
	case h.SecurityScore >= 70:
		return "C"
	case h.SecurityScore >= 60:
		return "D"
	default:
		return "F"
	}
}

// GenerateRecommendations provides actionable remediation steps
func (h *HeaderAnalysis) GenerateRecommendations() []string {
	recommendations := []string{}

	if !h.HTTPSEnforced {
		recommendations = append(recommendations, "1. Enforce HTTPS: Redirect all HTTP traffic to HTTPS")
	}

	if !h.HSTSPresent && h.HTTPSEnforced {
		recommendations = append(recommendations, "2. Implement HSTS: Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'")
	}

	if !h.CSPPresent {
		recommendations = append(recommendations, "3. Implement CSP: Start with 'Content-Security-Policy: default-src 'self''")
	}

	if h.XFrameOptions == "" {
		recommendations = append(recommendations, "4. Add X-Frame-Options: Set to 'DENY' or 'SAMEORIGIN'")
	}

	if !h.ContentTypeOptionsSet {
		recommendations = append(recommendations, "5. Add X-Content-Type-Options: Set to 'nosniff'")
	}

	if h.ServerHeaderExposed {
		recommendations = append(recommendations, "6. Remove Server header: Configure web server to suppress version information")
	}

	if h.PoweredByExposed {
		recommendations = append(recommendations, "7. Remove X-Powered-By: Disable in application configuration")
	}

	if h.CORSWildcard {
		recommendations = append(recommendations, "8. Fix CORS: Replace wildcard with specific allowed origins")
	}

	return recommendations
}
