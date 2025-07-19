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
func (c *Crawler) Crawl(ctx context.Context, pageURL string) ([]string, io.ReadCloser, error) {
	if !c.spiderCfg.DynamicCrawler.Enabled {
		return c.staticCrawl(ctx, pageURL)
	}

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", c.spiderCfg.DynamicCrawler.Headless),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("disable-web-security", true),
		chromedp.Flag("disable-xss-auditor", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-setuid-sandbox", true),
		chromedp.Flag("allow-running-insecure-content", true),
		chromedp.Flag("disable-webgl", true),
		chromedp.Flag("disable-notifications", true),
		chromedp.WindowSize(1920, 1080), // Larger viewport to capture more content
	)

	allocCtx, cancel := chromedp.NewExecAllocator(ctx, opts...)
	defer cancel()

	// Add logging to see the allocator options
	log.Info().Interface("options", opts).Msg("Chromedp allocator options")

	taskCtx, cancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(log.Printf))
	defer cancel()

	// Create a new context with a timeout for the navigation task
	timeoutCtx, cancel := context.WithTimeout(taskCtx, time.Duration(c.spiderCfg.Timeout)*time.Second)
	defer cancel()

	var htmlContent string
	var jsURLs string
	var networkRequests string

	err := chromedp.Run(timeoutCtx,
		// Set custom user agent
		chromedp.Navigate(pageURL),

		// Wait for the page to load completely with multiple strategies
		chromedp.ActionFunc(func(ctx context.Context) error {
			// Wait for network to be idle
			err := chromedp.WaitReady("body", chromedp.ByQuery).Do(ctx)
			if err != nil {
				log.Warn().Err(err).Msg("Error waiting for body to be ready")
			}
			return nil
		}),

		// Wait for a bit to allow JavaScript to execute
		chromedp.Sleep(2*time.Second),

		// Scroll the page to trigger lazy loading
		chromedp.ActionFunc(func(ctx context.Context) error {
			// Scroll to bottom
			err := chromedp.Evaluate(`window.scrollTo(0, document.body.scrollHeight)`, nil).Do(ctx)
			if err != nil {
				log.Warn().Err(err).Msg("Error scrolling page")
			}
			return nil
		}),

		// Wait a bit more after scrolling
		chromedp.Sleep(1*time.Second),

		// Capture all network requests made by the page
		chromedp.Evaluate(`
			(() => {
				const requests = [];
				if (window.performance && window.performance.getEntries) {
					const entries = window.performance.getEntries();
					for (const entry of entries) {
						if (entry.name && entry.entryType === 'resource') {
							requests.push(entry.name);
						}
					}
				}
				return requests.join('|');
			})()
		`, &networkRequests),

		// Get the final HTML content
		chromedp.OuterHTML("html", &htmlContent),

		// Execute JavaScript to extract all URLs from the page
		chromedp.Evaluate(`
			(() => {
				const urls = [];
				// Extract from a, link, script, img, iframe, form, area, base, embed, object, etc.
				const elements = document.querySelectorAll('a[href], link[href], script[src], img[src], iframe[src], form[action], area[href], base[href], embed[src], object[data], source[src], track[src], input[src], audio[src], video[src]');
				elements.forEach(el => {
					const attr = el.href || el.src || el.action || el.data;
					if (attr) urls.push(attr);
				});
				
				// Extract URLs from inline onclick, onload, etc. event handlers
				const allElements = document.querySelectorAll('*');
				allElements.forEach(el => {
					for (const attr of el.attributes) {
						if (attr.name.startsWith('on') && typeof attr.value === 'string') {
							const matches = attr.value.match(/('|")(https?:\/\/|\/)[^'"]+('|")/g);
							if (matches) {
								matches.forEach(m => urls.push(m.slice(1, -1)));
							}
						}
					}
				});
				
				// Extract URLs from all scripts
				const scripts = document.querySelectorAll('script');
				scripts.forEach(script => {
					if (script.textContent) {
						// Find URL patterns in script content
						const urlMatches = script.textContent.match(/('|")(https?:\/\/|\/)[^'"]+('|")/g);
						if (urlMatches) {
							urlMatches.forEach(m => urls.push(m.slice(1, -1)));
						}
						
						// Find fetch/xhr calls
						const fetchMatches = script.textContent.match(/fetch\s*\(\s*['"]([^'"]+)['"]/g);
						if (fetchMatches) {
							fetchMatches.forEach(m => {
								const url = m.match(/fetch\s*\(\s*['"]([^'"]+)['"]/);
								if (url && url[1]) urls.push(url[1]);
							});
						}
						
						// Find ajax calls
						const ajaxMatches = script.textContent.match(/\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*['"]([^'"]+)['"]/g);
						if (ajaxMatches) {
							ajaxMatches.forEach(m => {
								const url = m.match(/url\s*:\s*['"]([^'"]+)['"]/);
								if (url && url[1]) urls.push(url[1]);
							});
						}
						
						// Find axios calls
						const axiosMatches = script.textContent.match(/axios\s*\.\s*(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]/g);
						if (axiosMatches) {
							axiosMatches.forEach(m => {
								const url = m.match(/axios\s*\.\s*(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]/);
								if (url && url[2]) urls.push(url[2]);
							});
						}
					}
				});
				
				// Extract from meta refresh and location redirects
				const metaRefresh = document.querySelector('meta[http-equiv="refresh"][content]');
				if (metaRefresh) {
					const content = metaRefresh.getAttribute('content');
					const match = content.match(/url=([^;]+)/i);
					if (match && match[1]) urls.push(match[1]);
				}
				
				// Extract URLs from comments
				const iterator = document.createNodeIterator(document, NodeFilter.SHOW_COMMENT);
				let comment;
				while (comment = iterator.nextNode()) {
					const urlMatches = comment.textContent.match(/(?:https?:\/\/|\/)[^\s'"]+/g);
					if (urlMatches) {
						urlMatches.forEach(url => urls.push(url));
					}
				}
				
				// Extract from data-* attributes
				document.querySelectorAll('[data-src], [data-href], [data-url]').forEach(el => {
					if (el.dataset.src) urls.push(el.dataset.src);
					if (el.dataset.href) urls.push(el.dataset.href);
					if (el.dataset.url) urls.push(el.dataset.url);
				});
				
				return Array.from(new Set(urls)).join('|');
			})()
		`, &jsURLs),
	)

	if err != nil {
		return nil, nil, fmt.Errorf("chromedp failed to crawl %s: %w", pageURL, err)
	}

	// Ensure we have content before proceeding
	if htmlContent == "" {
		return nil, nil, fmt.Errorf("chromedp returned empty content for %s", pageURL)
	}

	body := io.NopCloser(strings.NewReader(htmlContent))

	// Process URLs extracted via JavaScript
	jsExtractedURLs := strings.Split(jsURLs, "|")

	// Add network requests to extracted URLs
	if networkRequests != "" {
		networkURLs := strings.Split(networkRequests, "|")
		jsExtractedURLs = append(jsExtractedURLs, networkURLs...)
	}

	// Extract links from HTML content
	links, err := c.extractLinks(pageURL, body, jsExtractedURLs)
	if err != nil {
		// Even if link extraction fails, we should return the body for parameter extraction.
		finalBodyForParamExtraction := io.NopCloser(strings.NewReader(htmlContent))
		return nil, finalBodyForParamExtraction, fmt.Errorf("failed to extract links from %s, but returning body for param analysis: %w", pageURL, err)
	}

	// Re-create a reader for the body to pass to the caller
	finalBody := io.NopCloser(strings.NewReader(htmlContent))
	return links, finalBody, nil
}

// staticCrawl performs a simple HTTP GET request to fetch a page.
// This is used when dynamic crawling is disabled.
func (c *Crawler) staticCrawl(ctx context.Context, pageURL string) ([]string, io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", pageURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request for %s: %w", pageURL, err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch %s: %w", pageURL, err)
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/html") &&
		!strings.Contains(contentType, "application/javascript") &&
		!strings.Contains(contentType, "text/javascript") &&
		!strings.Contains(contentType, "application/json") {
		return []string{}, resp.Body, nil
	}

	var bodyBuf bytes.Buffer
	tee := io.TeeReader(resp.Body, &bodyBuf)

	links, err := c.extractLinks(pageURL, tee, nil)
	if err != nil {
		resp.Body.Close()
		return nil, nil, fmt.Errorf("failed to extract links from static crawl of %s: %w", pageURL, err)
	}

	finalBody := &bodyCloser{Reader: &bodyBuf, Closer: resp.Body}
	return links, finalBody, nil
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
