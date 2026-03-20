package report

import (
	"time"
)

// CertData holds structured certificate information
type CertData struct {
	Source    string    `json:"source"`
	ID        int       `json:"id,omitempty"` // Used for crt.sh IDs
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	ValidFrom time.Time `json:"valid_from"`
	ValidTo   time.Time `json:"valid_to"`
	DNSNames  []string  `json:"dns_names"`
}

// GeoData holds structured geolocation information
type GeoData struct {
	IP          string  `json:"ip"`
	City        string  `json:"city"`
	Region      string  `json:"region"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Continent   string  `json:"continent"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	Timezone    string  `json:"timezone"`
}

// WebData holds structured parsed HTML data
type WebData struct {
	Title         string              `json:"title"`
	MetaTags      map[string]string   `json:"meta_tags"`
	Links         []string            `json:"links"`
	ExternalLinks []string            `json:"external_links"`
	InternalLinks []string            `json:"internal_links"`
	Emails        []string            `json:"emails"`
	PhoneNumbers  []string            `json:"phone_numbers"`
	SocialMedia   map[string][]string `json:"social_media"`
	Technologies  []string            `json:"technologies"`
	Scripts       []string            `json:"scripts"`
	StyleSheets   []string            `json:"stylesheets"`
	Forms         []string            `json:"forms"`
	Comments      []string            `json:"comments"`
}

// WaybackSnapshot holds structured wayback data
type WaybackSnapshot struct {
	URL       string `json:"url"`
	Timestamp string `json:"timestamp"`
	Status    string `json:"status"`
}

// DorkResult holds structured Google dork data
type DorkResult struct {
	Query string `json:"query"`
	URL   string `json:"url"`
}

// ReportData is the master struct containing all intelligence gathered
type ReportData struct {
	Domain           string              `json:"domain"`
	ScanTimestamp    time.Time           `json:"scan_timestamp"`
	Certificates     []CertData          `json:"certificates"`
	DNSRecords       []string            `json:"dns_records"`
	ReverseDNS       map[string][]string `json:"reverse_dns"`
	WHOIS            string              `json:"whois"` // Unstructured raw text
	WebAnalysis      *WebData            `json:"web_analysis,omitempty"`
	WaybackSnapshots []WaybackSnapshot   `json:"wayback_snapshots"`
	Dorks            []DorkResult        `json:"dorks"`
	Geolocation      []GeoData           `json:"geolocation"`
	Subdomains       []string            `json:"subdomains,omitempty"`
	MaliciousScore   int                 `json:"malicious_score,omitempty"`
	VT_Tags          []string            `json:"vt_tags,omitempty"`
	BreachedEmails   map[string][]string `json:"breached_emails,omitempty"`
}
