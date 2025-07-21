// Package crawler provides functionalities for crawling websites, including both static and dynamic crawling.
package crawler

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"autovulnscan/internal/config"
	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"
	"autovulnscan/internal/utils"

	"github.com/PuerkitoBio/goquery"
	"github.com/rs/zerolog/log"
	"golang.org/x/time/rate"
)

// Crawler is responsible for fetching web pages and extracting links and parameters from them.
type Crawler struct {
	baseURL        *url.URL
	config         *config.SpiderConfig
	httpClient     *requester.HTTPClient
	limiter        *rate.Limiter
	dynamicCrawler *DynamicCrawler
}

// NewCrawler creates a new Crawler instance.
func NewCrawler(baseURL string, cfg *config.SpiderConfig, client *requester.HTTPClient) (*Crawler, error) {
	parsedBaseURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	limiter := rate.NewLimiter(rate.Limit(cfg.Limit), cfg.Concurrency)
	dynamicCrawler := NewDynamicCrawler(time.Duration(cfg.Timeout) * time.Second)

	return &Crawler{
		baseURL:        parsedBaseURL,
		config:         cfg,
		httpClient:     client,
		limiter:        limiter,
		dynamicCrawler: dynamicCrawler,
	}, nil
}

// Crawl fetches the content of a URL and extracts links and forms.
func (c *Crawler) Crawl(ctx context.Context, crawlURL string) ([]string, []*models.Request, error) {
	log.Debug().Str("url", crawlURL).Msg("Crawling page")

	resp, err := c.httpClient.Get(ctx, crawlURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("bad status code: %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if c.config.DynamicCrawler.Enabled {
		return c.crawlDynamic(ctx, crawlURL, bodyBytes)
	}
	return c.crawlStatic(ctx, crawlURL, bodyBytes)
}

func (c *Crawler) crawlStatic(ctx context.Context, crawlURL string, body []byte) ([]string, []*models.Request, error) {
	log.Debug().Str("url", crawlURL).Int("size", len(body)).Msg("Crawled page successfully")

	// Create two readers from the response body
	var body1, body2 bytes.Buffer
	tee := io.TeeReader(bytes.NewReader(body), &body1)
	if _, err := io.Copy(&body2, tee); err != nil {
		return nil, nil, fmt.Errorf("failed to copy response body: %w", err)
	}

	links := c.extractLinks(&body1, crawlURL)
	requests := extractForms(&body2, crawlURL)

	log.Debug().Str("url", crawlURL).Int("count", len(links)).Msg("Extracted links")
	log.Debug().Str("url", crawlURL).Int("count", len(requests)).Msg("Extracted requests")
	return links, requests, nil
}

func (c *Crawler) crawlDynamic(ctx context.Context, crawlURL string, body []byte) ([]string, []*models.Request, error) {
	htmlContent, err := c.dynamicCrawler.Crawl(ctx, crawlURL)
	if err != nil {
		return nil, nil, fmt.Errorf("dynamic crawl failed: %w", err)
	}

	// Create two readers from the HTML content
	var body1, body2 bytes.Buffer
	tee := io.TeeReader(strings.NewReader(htmlContent), &body1)
	if _, err := io.Copy(&body2, tee); err != nil {
		return nil, nil, fmt.Errorf("failed to copy response body: %w", err)
	}

	links := c.extractLinks(&body1, crawlURL)
	requests := extractForms(&body2, crawlURL)

	log.Debug().Str("url", crawlURL).Int("count", len(links)).Msg("Extracted links (dynamic)")
	log.Debug().Str("url", crawlURL).Int("count", len(requests)).Msg("Extracted requests (dynamic)")
	return links, requests, nil
}

func extractForms(body io.Reader, pageURL string) []*models.Request {
	requests := []*models.Request{}
	doc, err := goquery.NewDocumentFromReader(body)
	if err != nil {
		return requests
	}

	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, _ := s.Attr("action")
		method, _ := s.Attr("method")
		if method == "" {
			method = "GET" // Default to GET
		}

		formURL, err := url.Parse(pageURL)
		if err != nil {
			return
		}
		actionURL, err := formURL.Parse(action)
		if err != nil {
			return
		}

		params := []models.Parameter{}
		s.Find("input, textarea, select").Each(func(j int, input *goquery.Selection) {
			name, _ := input.Attr("name")
			if name != "" {
				// In a real scenario, we might want to fill in values
				params = append(params, models.Parameter{Name: name, Value: "test"})
			}
		})

		// This part of the code is simplified. A real implementation would handle
		// different encodings and methods more robustly.
		req, err := http.NewRequest(strings.ToUpper(method), actionURL.String(), nil)
		if err != nil {
			return
		}

		requests = append(requests, &models.Request{
			Request: req,
			Params:  params,
		})
	})
	return requests
}

// extractLinks parses the HTML body and extracts all valid links.
func (c *Crawler) extractLinks(body io.Reader, pageURL string) []string {
	foundURLs := make(map[string]struct{})
	crawlURL, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}

	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return nil
	}

	jsLinks := c.extractJSLinks(pageURL, bytes.NewReader(bodyBytes))
	for _, link := range jsLinks {
		foundURLs[link] = struct{}{}
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(bodyBytes))
	if err != nil {
		return nil
	}

	processAttr := func(attrValue string) {
		if attrValue == "" {
			return
		}

		resolvedURL := utils.ResolveURL(crawlURL, attrValue)
		if resolvedURL == nil {
			return
		}

		// Check against blacklist
		for _, blacklisted := range c.config.Blacklist {
			if strings.Contains(resolvedURL.Host, blacklisted) {
				return
			}
		}

		normalizedURL := utils.NormalizeURL(resolvedURL)
		if normalizedURL != nil && utils.IsSameHost(c.baseURL, normalizedURL) {
			sanitizedURL := utils.SanitizeURL(normalizedURL)
			if sanitizedURL != nil {
				foundURLs[sanitizedURL.String()] = struct{}{}
			}
		}
	}

	tags := map[string]string{
		"a": "href", "link": "href", "script": "src", "img": "src",
		"iframe": "src", "form": "action",
	}

	for tag, attr := range tags {
		doc.Find(fmt.Sprintf("%s[%s]", tag, attr)).Each(func(i int, s *goquery.Selection) {
			val, _ := s.Attr(attr)
			processAttr(val)
		})
	}

	urls := make([]string, 0, len(foundURLs))
	for u := range foundURLs {
		urls = append(urls, u)
	}
	return urls
}

func (c *Crawler) extractRequests(pageURL string, body string) []*models.Request {
	var requests []*models.Request
	// In a real implementation, this would parse forms and script variables.
	// For now, we will just parse URL query parameters.
	parsedURL, err := url.Parse(pageURL)
	if err != nil {
		return requests
	}

	if len(parsedURL.Query()) > 0 {
		var params []models.Parameter
		for name, values := range parsedURL.Query() {
			for _, value := range values {
				params = append(params, models.Parameter{Name: name, Value: value, Type: "query"})
			}
		}

		req, err := http.NewRequest("GET", pageURL, nil)
		if err == nil {
			requests = append(requests, &models.Request{Request: req, Params: params})
		}
	}
	return requests
}

var jsLinkRegex = regexp.MustCompile(`['"]((?:/[^'"\s]+|https?://[^'"\s]+))['"]`)

func (c *Crawler) extractJSLinks(pageURL string, body io.Reader) []string {
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return nil
	}

	foundURLs := make(map[string]struct{})
	base, _ := url.Parse(pageURL)
	content := string(bodyBytes)

	matches := jsLinkRegex.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			href := match[1]
			resolvedURL := utils.ResolveURL(base, href)
			if resolvedURL == nil {
				continue
			}

			// Check against blacklist
			for _, blacklisted := range c.config.Blacklist {
				if strings.Contains(resolvedURL.Host, blacklisted) {
					continue
				}
			}
			normalizedURL := utils.NormalizeURL(resolvedURL)
			if normalizedURL != nil && utils.IsSameHost(base, normalizedURL) {
				sanitizedURL := utils.SanitizeURL(normalizedURL)
				if sanitizedURL != nil {
					foundURLs[sanitizedURL.String()] = struct{}{}
				}
			}
		}
	}

	urls := make([]string, 0, len(foundURLs))
	for u := range foundURLs {
		urls = append(urls, u)
	}
	return urls
}
