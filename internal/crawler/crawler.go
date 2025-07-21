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

	"autovulnscan/internal/config"
	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"
	"autovulnscan/internal/utils"

	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/chromedp"
	"github.com/rs/zerolog/log"
)

// Crawler is responsible for fetching web pages and extracting links and parameters from them.
type Crawler struct {
	baseURL    *url.URL
	spiderCfg  *config.SpiderConfig
	httpClient *requester.HTTPClient
}

// NewCrawler creates a new Crawler instance for a given target URL.
func NewCrawler(targetURL string, spiderCfg *config.SpiderConfig, client *requester.HTTPClient) (*Crawler, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}
	return &Crawler{
		baseURL:    parsedURL,
		spiderCfg:  spiderCfg,
		httpClient: client,
	}, nil
}

// Crawl fetches a single page and extracts all discoverable, in-scope links.
func (c *Crawler) Crawl(ctx context.Context, pageURL string) (string, []string, error) {
	log.Debug().Str("url", pageURL).Msg("Crawling page")
	if !c.spiderCfg.DynamicCrawler.Enabled {
		return c.staticCrawl(ctx, pageURL)
	}
	return c.dynamicCrawl(ctx, pageURL)
}

func (c *Crawler) dynamicCrawl(ctx context.Context, pageURL string) (string, []string, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", c.spiderCfg.DynamicCrawler.Headless),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	)

	allocCtx, cancel := chromedp.NewExecAllocator(ctx, opts...)
	defer cancel()

	taskCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	var htmlContent string
	err := chromedp.Run(taskCtx,
		chromedp.Navigate(pageURL),
		chromedp.WaitVisible(`body`, chromedp.ByQuery),
		chromedp.OuterHTML("html", &htmlContent),
	)

	if err != nil {
		return "", nil, fmt.Errorf("chromedp failed to crawl %s: %w", pageURL, err)
	}

	links, err := c.extractLinks(pageURL, strings.NewReader(htmlContent))
	if err != nil {
		return htmlContent, nil, err
	}

	return htmlContent, links, nil
}

func (c *Crawler) staticCrawl(ctx context.Context, pageURL string) (string, []string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", pageURL, nil)
	if err != nil {
		return "", nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("bad status code: %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, err
	}
	htmlContent := string(bodyBytes)

	links, err := c.extractLinks(pageURL, strings.NewReader(htmlContent))
	if err != nil {
		return htmlContent, nil, err
	}

	return htmlContent, links, nil
}

// extractLinks parses the HTML content and extracts all links.
func (c *Crawler) extractLinks(pageURL string, body io.Reader) ([]string, error) {
	foundURLs := make(map[string]struct{})
	crawlURL, err := url.Parse(pageURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse page URL for link extraction: %w", err)
	}

	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body for link extraction: %w", err)
	}

	jsLinks := extractJSLinks(pageURL, bytes.NewReader(bodyBytes))
	for _, link := range jsLinks {
		foundURLs[link] = struct{}{}
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML for link extraction: %w", err)
	}

	processAttr := func(attrValue string) {
		if attrValue == "" {
			return
		}

		resolvedURL := utils.ResolveURL(crawlURL, attrValue)
		if resolvedURL != nil && utils.IsSameHost(c.baseURL, resolvedURL) {
			sanitizedURL := utils.SanitizeURL(resolvedURL)
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
	return urls, nil
}

func (c *Crawler) ExtractParameters(pageURL string, body string) []models.ParameterizedURL {
	var pURLs []models.ParameterizedURL
	// In a real implementation, this would parse forms and script variables.
	// For now, we will just parse URL query parameters.
	parsedURL, err := url.Parse(pageURL)
	if err != nil {
		return pURLs
	}

	if len(parsedURL.Query()) > 0 {
		var params []models.Parameter
		for name, values := range parsedURL.Query() {
			for _, value := range values {
				params = append(params, models.Parameter{Name: name, Value: value, Type: "query"})
			}
		}

		pURLs = append(pURLs, models.ParameterizedURL{
			URL:    pageURL,
			Method: "GET",
			Params: params,
		})
	}
	return pURLs
}

var jsLinkRegex = regexp.MustCompile(`['"]((?:/[^'"\s]+|https?://[^'"\s]+))['"]`)

func extractJSLinks(pageURL string, body io.Reader) []string {
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
			if resolvedURL != nil && utils.IsSameHost(base, resolvedURL) {
				sanitizedURL := utils.SanitizeURL(resolvedURL)
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
