package parser

import (
	"fmt"
	"log"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

type ParsedContent struct {
	Title         string
	MetaTags      map[string]string
	Links         []string
	ExternalLinks []string
	InternalLinks []string
	Emails        []string
	PhoneNumbers  []string
	SocialMedia   map[string][]string
	Technologies  []string
	Scripts       []string
	StyleSheets   []string
	Forms         []string
	Comments      []string
}

func ParseHTMLContent(html string) (*ParsedContent, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML content: %v", err)
	}

	parsed := &ParsedContent{
		MetaTags:    make(map[string]string),
		SocialMedia: make(map[string][]string),
	}

	// Extract title
	parsed.Title = doc.Find("title").Text()

	// Extract meta tags
	doc.Find("meta").Each(func(_ int, s *goquery.Selection) {
		if name, exists := s.Attr("name"); exists {
			if content, exists := s.Attr("content"); exists {
				parsed.MetaTags[name] = content
			}
		}
	})

	// Extract all links and categorize them
	doc.Find("a[href]").Each(func(_ int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if exists {
			parsed.Links = append(parsed.Links, href)

			if strings.Contains(href, "mailto:") {
				email := strings.TrimPrefix(href, "mailto:")
				parsed.Emails = append(parsed.Emails, email)
			} else if strings.Contains(href, "tel:") {
				phone := strings.TrimPrefix(href, "tel:")
				parsed.PhoneNumbers = append(parsed.PhoneNumbers, phone)
			} else if isExternalLink(href) {
				parsed.ExternalLinks = append(parsed.ExternalLinks, href)

				// Detect social media links
				for platform, pattern := range socialMediaPatterns() {
					if strings.Contains(href, pattern) {
						parsed.SocialMedia[platform] = append(parsed.SocialMedia[platform], href)
					}
				}
			} else {
				parsed.InternalLinks = append(parsed.InternalLinks, href)
			}
		}
	})

	// Extract scripts
	doc.Find("script[src]").Each(func(_ int, s *goquery.Selection) {
		if src, exists := s.Attr("src"); exists {
			parsed.Scripts = append(parsed.Scripts, src)
		}
	})

	// Extract stylesheets
	doc.Find("link[rel='stylesheet']").Each(func(_ int, s *goquery.Selection) {
		if href, exists := s.Attr("href"); exists {
			parsed.StyleSheets = append(parsed.StyleSheets, href)
		}
	})

	// Extract forms
	doc.Find("form").Each(func(_ int, s *goquery.Selection) {
		if action, exists := s.Attr("action"); exists {
			parsed.Forms = append(parsed.Forms, action)
		}
	})

	// Extract HTML comments
	doc.Find("*").Contents().Each(func(_ int, s *goquery.Selection) {
		if s.Length() > 0 && s.Get(0).Data == "#comment" {
			parsed.Comments = append(parsed.Comments, strings.TrimSpace(s.Text()))
		}
	})

	// Detect technologies
	parsed.Technologies = detectTechnologies(doc)

	log.Printf("Successfully parsed HTML content: found %d links, %d emails, %d technologies",
		len(parsed.Links), len(parsed.Emails), len(parsed.Technologies))

	return parsed, nil
}

func isExternalLink(href string) bool {
	parsedURL, err := url.Parse(href)
	if err != nil {
		return false
	}
	return parsedURL.Host != ""
}

func socialMediaPatterns() map[string]string {
	return map[string]string{
		"Twitter":   "twitter.com",
		"Facebook":  "facebook.com",
		"LinkedIn":  "linkedin.com",
		"Instagram": "instagram.com",
		"GitHub":    "github.com",
	}
}

func detectTechnologies(doc *goquery.Document) []string {
	var technologies []string

	techSignatures := map[string]string{
		"WordPress": "wp-content",
		"jQuery":    "jquery",
		"React":     "react",
		"Angular":   "ng-",
		"Vue.js":    "vue",
		"Bootstrap": "bootstrap",
	}

	for tech, signature := range techSignatures {
		if doc.Find(fmt.Sprintf("[class*='%s'], [id*='%s'], script[src*='%s']",
			signature, signature, signature)).Length() > 0 {
			technologies = append(technologies, tech)
		}
	}

	return technologies
}
