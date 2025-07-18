package discovery

import (
	"autovulnscan/internal/requester"
	"io"
	"net/url"

	"github.com/PuerkitoBio/goquery"
	"github.com/rs/zerolog/log"
)

// Crawler is responsible for discovering new URLs by crawling the target website.
type Crawler struct {
	baseURL    *url.URL
	userAgents []string
	httpClient *requester.HTTPClient
}

// NewCrawler creates a new Crawler instance.
func NewCrawler(baseURL string, userAgents []string, client *requester.HTTPClient) (*Crawler, error) {
	parsedBaseURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	return &Crawler{
		baseURL:    parsedBaseURL,
		userAgents: userAgents,
		httpClient: client,
	}, nil
}

// ExtractLinks parses the HTML from the reader and extracts all unique, in-scope links.
func (c *Crawler) ExtractLinks(pageURL string, body io.Reader) ([]string, error) {
	doc, err := goquery.NewDocumentFromReader(body)
	if err != nil {
		return nil, err
	}

	foundURLs := make(map[string]struct{})
	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if !exists {
			return
		}

		// Resolve the URL relative to the page it was found on
		resolvedURL, err := c.resolveURL(pageURL, href)
		if err != nil {
			log.Warn().Err(err).Str("href", href).Msg("Failed to resolve URL")
			return
		}
		
		// Check if the URL is within the scope of our target domain
		if c.isInScope(resolvedURL) {
			foundURLs[resolvedURL.String()] = struct{}{}
		}
	})

	// Convert map to slice
	urlSlice := make([]string, 0, len(foundURLs))
	for u := range foundURLs {
		urlSlice = append(urlSlice, u)
	}

	return urlSlice, nil
}

// resolveURL makes an absolute URL from a (possibly relative) href.
func (c *Crawler) resolveURL(baseURLStr, href string) (*url.URL, error) {
	baseURL, err := url.Parse(baseURLStr)
	if err != nil {
		return nil, err
	}
	relativeURL, err := url.Parse(href)
	if err != nil {
		return nil, err
	}
	return baseURL.ResolveReference(relativeURL), nil
}

// isInScope checks if a given URL belongs to the same host as the base URL.
func (c *Crawler) isInScope(u *url.URL) bool {
	return u.Hostname() == c.baseURL.Hostname()
} 