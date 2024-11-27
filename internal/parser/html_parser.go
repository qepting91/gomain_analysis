package parser

import (
	"fmt"
	"log"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// ParseHTMLContent extracts links and text from the given HTML content
func ParseHTMLContent(html string) ([]string, string, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse HTML content: %v", err)
	}

	var links []string
	doc.Find("a[href]").Each(func(index int, item *goquery.Selection) {
		href, exists := item.Attr("href")
		if exists {
			links = append(links, href)
		}
	})

	textContent := doc.Text()

	log.Printf("Successfully parsed HTML content, extracted %d links", len(links))
	return links, textContent, nil
}
