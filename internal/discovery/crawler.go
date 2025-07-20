package discovery

import (
	"autovulnscan/internal/config"
	"autovulnscan/internal/requester"
	"autovulnscan/internal/util"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/chromedp"

	// "github.com/chromedp/chromedp/cdp/network"
	"github.com/rs/zerolog/log"
)

// bodyCloser is a helper struct that allows reading from a buffer while ensuring
// the original response body's Closer is called, preventing resource leaks.
type bodyCloser struct {
	io.Reader
	io.Closer
}

// Crawler is responsible for fetching web pages and extracting links from them.
// It can extract links from both HTML tags and JavaScript code.
type Crawler struct {
	httpClient *requester.HTTPClient
	baseURL    *url.URL
	spiderCfg  *config.SpiderConfig
}

// NewCrawler creates a new Crawler instance for a given target URL.
// It requires an HTTP client and a list of user agents to use for requests.
func NewCrawler(targetURL string, spiderCfg *config.SpiderConfig, client *requester.HTTPClient) (*Crawler, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target URL: %w", err)
	}

	// Basic validation
	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return nil, fmt.Errorf("invalid target URL, must be absolute: %s", targetURL)
	}

	return &Crawler{
		httpClient: client,
		baseURL:    parsedURL,
		spiderCfg:  spiderCfg,
	}, nil
}

// Crawl fetches a single page and extracts all discoverable, in-scope links.
// It uses a headless browser (chromedp) to render dynamic content.
func (c *Crawler) Crawl(ctx context.Context, pageURL string) (string, []*url.URL, error) {
	log.Debug().Str("url", pageURL).Msg("Crawling page")
	if !c.spiderCfg.DynamicCrawler.Enabled {
		return c.staticCrawl(ctx, pageURL)
	}

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", c.spiderCfg.DynamicCrawler.Headless),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("no-zygote", true),
	)

	allocCtx, cancel := chromedp.NewExecAllocator(ctx, opts...)
	defer cancel()

	taskCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// Increased timeout for more stability
	timeoutCtx, cancel := context.WithTimeout(taskCtx, 120*time.Second)
	defer cancel()

	var htmlContent string
	var jsURLs []string

	err := chromedp.Run(timeoutCtx,
		chromedp.Navigate(pageURL),
		// Wait for the page to be reasonably loaded before interacting
		chromedp.WaitVisible(`body`, chromedp.ByQuery),
		// Use Poll to wait for the document to be fully loaded
		chromedp.Poll(`document.readyState === "complete"`, nil),
		chromedp.ActionFunc(func(ctx context.Context) error {
			log.Debug().Str("url", pageURL).Msg("Document is fully loaded. Extracting content.")
			return nil
		}),
		chromedp.OuterHTML("html", &htmlContent),
		chromedp.Evaluate(`Array.from(document.querySelectorAll('script[src]')).map(s => s.src)`, &jsURLs),
	)

	if err != nil {
		return "", nil, fmt.Errorf("chromedp failed to crawl %s: %w", pageURL, err)
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse HTML content from %s: %w", pageURL, err)
	}

	var urls []*url.URL
	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if exists {
			absoluteURL, err := c.baseURL.Parse(href)
			if err == nil {
				urls = append(urls, absoluteURL)
			}
		}
	})

	return htmlContent, urls, nil
}

func (c *Crawler) staticCrawl(ctx context.Context, pageURL string) (string, []*url.URL, error) {
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

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse HTML content from %s: %w", pageURL, err)
	}

	var urls []*url.URL
	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if exists {
			absoluteURL, err := c.baseURL.Parse(href)
			if err == nil {
				urls = append(urls, absoluteURL)
			}
		}
	})

	return htmlContent, urls, nil
}

// extractLinks parses the HTML content and extracts all links.
func (c *Crawler) extractLinks(pageURL string, body io.Reader, jsExtractedURLs []string) ([]string, error) {
	foundURLs := make(map[string]struct{})
	crawlURL, err := url.Parse(pageURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse page URL for link extraction: %w", err)
	}

	// Read the body into a byte slice so it can be read multiple times.
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body for link extraction: %w", err)
	}

	// Add URLs extracted from JavaScript execution
	if jsExtractedURLs != nil {
		for _, link := range jsExtractedURLs {
			if link != "" {
				resolvedURL := util.ResolveURL(crawlURL, link)
				if resolvedURL != nil && util.IsSameHost(c.baseURL, resolvedURL) {
					sanitizedURL := util.SanitizeURL(resolvedURL)
					if sanitizedURL != nil {
						foundURLs[sanitizedURL.String()] = struct{}{}
					}
				}
			}
		}
	}

	// Extract from JS first, using a new reader from the byte slice.
	jsLinks := extractJSLinks(pageURL, bytes.NewReader(bodyBytes))
	for _, link := range jsLinks {
		foundURLs[link] = struct{}{}
	}

	// Now, extract from HTML, using another new reader from the same byte slice.
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML for link extraction: %w", err)
	}

	processAttr := func(attrValue string) {
		if attrValue == "" {
			return
		}

		resolvedURL := util.ResolveURL(crawlURL, attrValue)
		if resolvedURL == nil || !util.IsSameHost(c.baseURL, resolvedURL) {
			return
		}

		sanitizedURL := util.SanitizeURL(resolvedURL)
		if sanitizedURL != nil {
			foundURLs[sanitizedURL.String()] = struct{}{}
		}
	}

	// Extract from common tags that contain links
	tags := map[string]string{
		"a":      "href",
		"link":   "href",
		"script": "src",
		"img":    "src",
		"iframe": "src",
		"form":   "action",
		"frame":  "src",
		"embed":  "src",
		"object": "data",
		"source": "src",
		"track":  "src",
		"audio":  "src",
		"video":  "src",
		"input":  "src",
		"area":   "href",
		"base":   "href",
	}

	for tag, attr := range tags {
		doc.Find(fmt.Sprintf("%s[%s]", tag, attr)).Each(func(i int, s *goquery.Selection) {
			val, _ := s.Attr(attr)
			processAttr(val)
		})
	}

	// Extract URLs from inline event handlers
	eventAttributes := []string{
		"onclick", "onmouseover", "onmouseout", "onload", "onerror", "onsubmit",
		"onchange", "onfocus", "onblur", "onkeydown", "onkeyup", "onkeypress",
	}

	doc.Find("*").Each(func(i int, s *goquery.Selection) {
		for _, event := range eventAttributes {
			if val, exists := s.Attr(event); exists {
				// Extract URLs from event handlers
				matches := jsURLRegex.FindAllStringSubmatch(val, -1)
				for _, match := range matches {
					if len(match) > 1 {
						processAttr(match[1])
					}
				}
			}
		}
	})

	// Extract URLs from meta refresh tags
	doc.Find("meta[http-equiv='refresh'][content]").Each(func(i int, s *goquery.Selection) {
		content, _ := s.Attr("content")
		if content != "" {
			parts := strings.Split(strings.ToLower(content), "url=")
			if len(parts) > 1 {
				processAttr(parts[1])
			}
		}
	})

	urls := make([]string, 0, len(foundURLs))
	for u := range foundURLs {
		urls = append(urls, u)
	}

	log.Debug().Str("page", pageURL).Int("count", len(urls)).Strs("urls", urls).Msg("Extracted links from page")
	return urls, nil
}

// Various regex patterns for extracting URLs from JavaScript code
var (
	// jsLinkRegex is a regex to find links in JavaScript code. This is a best-effort approach
	// that looks for string literals that resemble relative or absolute paths.
	jsLinkRegex = regexp.MustCompile(`['"]((?:/[^'"\s]+|https?://[^'"\s]+))['"]`)

	// Additional regex patterns for more comprehensive JavaScript URL extraction
	jsURLRegex   = regexp.MustCompile(`(?:url\s*\(\s*['"]?|href\s*=\s*['"]|src\s*=\s*['"]|action\s*=\s*['"]|data\s*=\s*['"])([^'"\)]+)`)
	jsPathRegex  = regexp.MustCompile(`(?:["'](\/[a-zA-Z0-9_\-\.\/]+)["'])`)
	jsAPIRegex   = regexp.MustCompile(`(?:["'](\/api\/[a-zA-Z0-9_\-\.\/]+)["'])`)
	jsXHRRegex   = regexp.MustCompile(`(?:\.open\s*\(\s*["'](?:GET|POST|PUT|DELETE|PATCH)["']\s*,\s*["']([^"']+)["'])`)
	jsFetchRegex = regexp.MustCompile(`fetch\s*\(\s*["']([^"']+)["']`)
	jsAxiosRegex = regexp.MustCompile(`axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']`)
	jsAjaxRegex  = regexp.MustCompile(`\$\.ajax\s*\(\s*\{[^\}]*url\s*:\s*["']([^"']+)["']`)
)

// extractJSLinks parses a reader's content for JavaScript code and extracts URL-like strings.
// It is designed to find links that are not present in standard HTML `href` or `src` attributes.
func extractJSLinks(pageURL string, body io.Reader) []string {
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return nil
	}

	foundURLs := make(map[string]struct{})
	base, _ := url.Parse(pageURL)
	content := string(bodyBytes)

	// Process with all regex patterns
	regexPatterns := []*regexp.Regexp{
		jsLinkRegex,
		jsURLRegex,
		jsPathRegex,
		jsAPIRegex,
		jsXHRRegex,
		jsFetchRegex,
		jsAxiosRegex,
		jsAjaxRegex,
	}

	for _, regex := range regexPatterns {
		matches := regex.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				href := match[1]
				resolvedURL := util.ResolveURL(base, href)
				if resolvedURL != nil && util.IsSameHost(base, resolvedURL) {
					sanitizedURL := util.SanitizeURL(resolvedURL)
					if sanitizedURL != nil {
						foundURLs[sanitizedURL.String()] = struct{}{}
					}
				}
			}
		}
	}

	// Look for JSON API endpoints
	jsonAPIMatches := regexp.MustCompile(`["'](?:path|endpoint|url)["']\s*:\s*["'](\/[^"']+)["']`).FindAllStringSubmatch(content, -1)
	for _, match := range jsonAPIMatches {
		if len(match) > 1 {
			href := match[1]
			resolvedURL := util.ResolveURL(base, href)
			if resolvedURL != nil && util.IsSameHost(base, resolvedURL) {
				sanitizedURL := util.SanitizeURL(resolvedURL)
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
