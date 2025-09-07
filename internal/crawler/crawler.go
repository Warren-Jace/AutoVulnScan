package crawler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"autovulnscan/internal/config"
	"autovulnscan/internal/dedup"
	"compress/gzip"

	"github.com/PuerkitoBio/goquery"
	"github.com/rs/zerolog/log"
)

// Config holds crawler configuration
type Config struct {
	StartURL        string            `json:"start_url"`
	MaxPages        int               `json:"max_pages"`
	Timeout         time.Duration     `json:"timeout"`
	UserAgent       string            `json:"user_agent"`
	MaxDepth        int               `json:"max_depth"`
	Concurrency     int               `json:"concurrency"`
	RateLimit       int               `json:"rate_limit"`
	Delay           time.Duration     `json:"delay"`
	FollowRedirects bool              `json:"follow_redirects"`
	Headers         map[string]string `json:"headers"`
	Cookies         map[string]string `json:"cookies"`
	RespectRobots   bool              `json:"respect_robots"`

	// Similarity deduplication
	SimilarityConfig dedup.SimilarityConfig `json:"similarity_config"`
}

// Helper function to get the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Crawler represents a web crawler instance
type Crawler struct {
	config    Config
	visited   map[string]bool
	visitedMu sync.RWMutex
	results   []string
	resultsMu sync.RWMutex
	client    *http.Client
	rateLimit chan struct{}
	wg        sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc

	// Similarity engine
	similarityEngine *dedup.SimilarityEngine
}

// New creates a new crawler instance
func New(cfg Config) *Crawler {
	// Set defaults
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 5
	}
	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = 3
	}
	if cfg.Delay <= 0 {
		cfg.Delay = 100 * time.Millisecond
	}

	// Create HTTP transport with proxy support
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	// Load global config to get proxy settings
	globalConfig := config.GetGlobalConfig()
	if globalConfig != nil && globalConfig.Proxy.Enabled && globalConfig.Proxy.URL != "" {
		proxyURL, err := url.Parse(globalConfig.Proxy.URL)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
			log.Info().Str("proxy", globalConfig.Proxy.URL).Msg("Using proxy for crawler")
		} else {
			log.Error().Err(err).Str("proxy", globalConfig.Proxy.URL).Msg("Failed to parse proxy URL")
		}
	}

	// Create HTTP client with optimized settings
	client := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: transport,
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Initialize similarity engine
	similarityEngine := dedup.NewSimilarityEngine(cfg.SimilarityConfig)

	return &Crawler{
		config:           cfg,
		visited:          make(map[string]bool),
		results:          make([]string, 0),
		client:           client,
		rateLimit:        make(chan struct{}, cfg.Concurrency),
		ctx:              ctx,
		cancel:           cancel,
		similarityEngine: similarityEngine,
	}
}

// Start begins crawling from the target URL
func (c *Crawler) Start(targetURL string) error {
	log.Info().Str("url", targetURL).Msg("Starting crawler")

	// Validate URL
	if _, err := url.Parse(targetURL); err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Start crawling directly
	return c.crawl(targetURL, 0)
}

// crawl recursively crawls URLs
func (c *Crawler) crawl(urlStr string, depth int) error {
	// Extract actual URL for POST requests
	actualURL := urlStr
	if strings.HasPrefix(urlStr, "POST:") {
		postParts := strings.SplitN(urlStr[5:], "|", 2)
		if len(postParts) == 2 {
			actualURL = postParts[0]
		}
	}

	// Check context cancellation
	select {
	case <-c.ctx.Done():
		return c.ctx.Err()
	default:
	}

	// Check depth limit
	if depth > c.config.MaxDepth {
		fmt.Printf("🔍 DEBUG: Max depth reached for %s (depth: %d)\n", actualURL, depth)
		return nil
	}

	// Check if already visited
	c.visitedMu.RLock()
	if c.visited[urlStr] {
		c.visitedMu.RUnlock()
		fmt.Printf("🔍 DEBUG: Already visited %s\n", actualURL)
		return nil
	}
	c.visitedMu.RUnlock()

	// Mark as visited
	c.visitedMu.Lock()
	c.visited[urlStr] = true
	c.visitedMu.Unlock()

	fmt.Printf("🔍 DEBUG: Crawling %s at depth %d\n", actualURL, depth)

	// Add delay between requests
	if c.config.Delay > 0 {
		time.Sleep(c.config.Delay)
	}

	// Fetch URL
	doc, html, err := c.fetchURL(urlStr)
	if err != nil {
		fmt.Printf("🔍 DEBUG: Failed to fetch %s: %v\n", actualURL, err)
		return nil // Continue with other URLs
	}

	// Debug: Log HTML content length and structure
	log.Debug().Str("url", actualURL).Int("html_length", len(html)).Msg("HTML content fetched")

	// Debug: Count links in HTML
	linkCount := doc.Find("a[href]").Length()
	log.Debug().Str("url", actualURL).Int("link_count", linkCount).Msg("Found anchor tags with href")

	// Direct console output for debugging
	fmt.Printf("🔍 DEBUG: URL: %s\n", actualURL)
	fmt.Printf("🔍 DEBUG: HTML length: %d\n", len(html))
	fmt.Printf("🔍 DEBUG: Found %d anchor tags with href\n", linkCount)

	// Debug: Show HTML structure
	if len(html) > 1000 {
		log.Debug().Str("url", actualURL).Str("html_preview", html[:1000]+"...").Msg("HTML preview")
		fmt.Printf("🔍 DEBUG: HTML preview: %s...\n", html[:200])
	} else {
		log.Debug().Str("url", actualURL).Str("html_content", html).Msg("Full HTML content")
		fmt.Printf("🔍 DEBUG: Full HTML: %s\n", html)
	}

	// Debug: Show page title
	title := doc.Find("title").Text()
	log.Debug().Str("url", actualURL).Str("title", title).Msg("Page title")
	fmt.Printf("🔍 DEBUG: Page title: %s\n", title)

	// Debug: Show all anchor tags
	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		text := strings.TrimSpace(s.Text())
		if exists {
			log.Debug().Str("url", actualURL).Int("index", i).Str("href", href).Str("text", text).Msg("Anchor tag found")
			fmt.Printf("🔍 DEBUG: Link %d: %s -> %s\n", i+1, text, href)
		} else {
			log.Debug().Str("url", actualURL).Int("index", i).Str("text", text).Msg("Anchor tag without href")
			fmt.Printf("🔍 DEBUG: Anchor %d (no href): %s\n", i+1, text)
		}
	})

	// Check similarity deduplication
	if c.similarityEngine != nil {
		shouldFilter, err := c.similarityEngine.ProcessPage(actualURL, html)
		if err != nil {
			log.Debug().Str("url", actualURL).Err(err).Msg("Similarity check failed")
		} else if shouldFilter {
			log.Debug().Str("url", actualURL).Msg("Page filtered due to similarity")
			return nil
		}
	}

	// Add to results
	c.resultsMu.Lock()
	c.results = append(c.results, urlStr)
	c.resultsMu.Unlock()

	// Extract and crawl links
	links := c.extractLinks(doc, actualURL)

	log.Debug().Str("url", actualURL).Int("extracted_links", len(links)).Msg("Link extraction completed")
	fmt.Printf("🔍 DEBUG: Extracted %d links from %s\n", len(links), actualURL)

	// Sequential crawling to avoid deadlock
	for _, link := range links {
		select {
		case <-c.ctx.Done():
			return c.ctx.Err()
		default:
			// Crawl sequentially to avoid deadlock
			if err := c.crawl(link, depth+1); err != nil {
				fmt.Printf("🔍 DEBUG: Error crawling %s: %v\n", link, err)
			}
		}
	}

	return nil
}

// fetchURL fetches a single URL and returns the parsed document and HTML content
func (c *Crawler) fetchURL(urlStr string) (*goquery.Document, string, error) {
	var req *http.Request
	var err error

	// Check if this is a POST request
	if strings.HasPrefix(urlStr, "POST:") {
		// Parse POST URL and parameters
		postParts := strings.SplitN(urlStr[5:], "|", 2)
		if len(postParts) != 2 {
			return nil, "", fmt.Errorf("invalid POST URL format: %s", urlStr)
		}
		postURL := postParts[0]
		paramStr := postParts[1]

		// Create POST request with form data
		req, err = http.NewRequestWithContext(c.ctx, "POST", postURL, strings.NewReader(paramStr))
		if err != nil {
			return nil, "", fmt.Errorf("failed to create POST request: %w", err)
		}

		// Set content type for form data
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		fmt.Printf("🔍 DEBUG: Making POST request to %s with params: %s\n", postURL, paramStr)
	} else {
		// Create GET request
		req, err = http.NewRequestWithContext(c.ctx, "GET", urlStr, nil)
		if err != nil {
			return nil, "", fmt.Errorf("failed to create request: %w", err)
		}

		fmt.Printf("🔍 DEBUG: Making GET request to %s\n", urlStr)
	}

	// Set headers
	if c.config.UserAgent != "" {
		req.Header.Set("User-Agent", c.config.UserAgent)
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate") // 支持gzip压缩
	req.Header.Set("Connection", "keep-alive")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch URL: %w", err)
	}
	defer resp.Body.Close()

	fmt.Printf("🔍 DEBUG: Response status: %s\n", resp.Status)
	fmt.Printf("🔍 DEBUG: Content-Type: %s\n", resp.Header.Get("Content-Type"))
	fmt.Printf("🔍 DEBUG: Content-Encoding: %s\n", resp.Header.Get("Content-Encoding"))

	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("status code error: %d %s", resp.StatusCode, resp.Status)
	}

	// Check content type - allow HTML and image content
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") && !strings.Contains(contentType, "image/") {
		return nil, "", fmt.Errorf("non-HTML and non-image content: %s", contentType)
	}

	// Read HTML content with proper encoding handling
	var html string
	if resp.Header.Get("Content-Encoding") == "gzip" {
		// Handle gzip compression
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, "", fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()

		htmlBytes, err := io.ReadAll(gzReader)
		if err != nil {
			return nil, "", fmt.Errorf("failed to read gzipped response: %w", err)
		}
		html = string(htmlBytes)
		fmt.Printf("🔍 DEBUG: Decompressed gzipped content, length: %d\n", len(html))
	} else {
		// Handle uncompressed content
		htmlBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, "", fmt.Errorf("failed to read response body: %w", err)
		}
		html = string(htmlBytes)
		fmt.Printf("🔍 DEBUG: Read uncompressed content, length: %d\n", len(html))
	}

	// Parse HTML
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse HTML: %w", err)
	}

	return doc, html, nil
}

// extractLinks extracts all links from an HTML document
func (c *Crawler) extractLinks(doc *goquery.Document, baseURL string) []string {
	var links []string
	base, err := url.Parse(baseURL)
	if err != nil {
		log.Debug().Str("base_url", baseURL).Err(err).Msg("Failed to parse base URL")
		return links
	}

	log.Debug().Str("base_url", baseURL).Str("base_host", base.Host).Msg("Extracting links")

	// Debug: Show all anchor tags
	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if !exists {
			log.Debug().Int("index", i).Msg("Anchor tag without href")
			return
		}
		log.Debug().Int("index", i).Str("href", href).Str("text", strings.TrimSpace(s.Text())).Msg("Found anchor tag")
	})

	// Extract links from form[action] and input[formaction] attributes
	doc.Find("form[action], input[formaction]").Each(func(i int, s *goquery.Selection) {
		var action string
		var exists bool

		// Try different attributes based on element type
		if action, exists = s.Attr("action"); !exists {
			if action, exists = s.Attr("formaction"); !exists {
				return
			}
		}

		// Parse URL
		formURL, err := url.Parse(action)
		if err != nil {
			log.Debug().Str("action", action).Err(err).Msg("Failed to parse form action")
			return
		}

		// Resolve relative URL
		resolvedURL := base.ResolveReference(formURL)

		// Filter protocols - only allow http and https
		if resolvedURL.Scheme != "http" && resolvedURL.Scheme != "https" {
			log.Debug().Str("url", resolvedURL.String()).Str("scheme", resolvedURL.Scheme).Msg("Filtered by protocol")
			return
		}

		// Less restrictive domain filtering - only filter obviously external domains
		if resolvedURL.Host != "" && base.Host != "" && 
		   !strings.HasSuffix(resolvedURL.Host, base.Host) && 
		   !strings.HasSuffix(base.Host, resolvedURL.Host) &&
		   !strings.Contains(resolvedURL.Host, base.Host) && 
		   !strings.Contains(base.Host, resolvedURL.Host) {
			log.Debug().Str("url", resolvedURL.String()).Str("url_host", resolvedURL.Host).Str("base_host", base.Host).Msg("Filtered by domain")
			return
		}

		// Less restrictive file extension filtering - only filter obvious non-HTML files
		path := strings.ToLower(resolvedURL.Path)
		if strings.HasSuffix(path, ".pdf") || strings.HasSuffix(path, ".css") ||
			strings.HasSuffix(path, ".xml") || strings.HasSuffix(path, ".zip") ||
			strings.HasSuffix(path, ".tar") || strings.HasSuffix(path, ".gz") ||
			strings.HasSuffix(path, ".exe") || strings.HasSuffix(path, ".dmg") ||
			strings.HasSuffix(path, ".iso") {
			log.Debug().Str("url", resolvedURL.String()).Str("path", path).Msg("Filtered by file extension")
			return
		}

		// Normalize URL
		resolvedURL.Fragment = ""
		cleanJSLinkURL := resolvedURL.String()

		// Deduplicate
		isDuplicate := false
		for _, existing := range links {
			if existing == cleanJSLinkURL {
				log.Debug().Str("url", cleanJSLinkURL).Msg("Duplicate link found")
				isDuplicate = true
				break
			}
		}
		if isDuplicate {
			return
		}

		log.Debug().Str("url", cleanJSLinkURL).Msg("Adding valid form link")
		links = append(links, cleanJSLinkURL)
	})

	// Extract links from meta[refresh] tags
	doc.Find("meta[http-equiv='refresh']").Each(func(i int, s *goquery.Selection) {
		content, exists := s.Attr("content")
		if !exists {
			return
		}

		// Extract URL from content attribute using regex
		urlRegex := regexp.MustCompile(`url=(?:https?:)?//[^\s"'\)]+`)
		matches := urlRegex.FindStringSubmatch(content)
		if len(matches) < 2 {
			log.Debug().Str("content", content).Msg("No URL found in meta refresh")
			return
		}

		metaURL := strings.TrimPrefix(matches[0], "url=")

		// Parse URL
		parsedURL, err := url.Parse(metaURL)
		if err != nil {
			log.Debug().Str("url", metaURL).Err(err).Msg("Failed to parse meta refresh URL")
			return
		}

		// Resolve relative URLs
		resolvedURL := base.ResolveReference(parsedURL)

		// Filter protocols - only allow http and https
		if resolvedURL.Scheme != "http" && resolvedURL.Scheme != "https" {
			log.Debug().Str("url", resolvedURL.String()).Str("scheme", resolvedURL.Scheme).Msg("Filtered by protocol")
			return
		}

		// Less restrictive domain filtering - only filter obviously external domains
		if resolvedURL.Host != "" && base.Host != "" && 
		   !strings.HasSuffix(resolvedURL.Host, base.Host) && 
		   !strings.HasSuffix(base.Host, resolvedURL.Host) &&
		   !strings.Contains(resolvedURL.Host, base.Host) && 
		   !strings.Contains(base.Host, resolvedURL.Host) {
			log.Debug().Str("url", resolvedURL.String()).Str("url_host", resolvedURL.Host).Str("base_host", base.Host).Msg("Filtered by domain")
			return
		}

		// Less restrictive file extension filtering - only filter obvious non-HTML files
		path := strings.ToLower(resolvedURL.Path)
		if strings.HasSuffix(path, ".pdf") || strings.HasSuffix(path, ".css") ||
			strings.HasSuffix(path, ".xml") || strings.HasSuffix(path, ".zip") ||
			strings.HasSuffix(path, ".tar") || strings.HasSuffix(path, ".gz") ||
			strings.HasSuffix(path, ".exe") || strings.HasSuffix(path, ".dmg") ||
			strings.HasSuffix(path, ".iso") {
			log.Debug().Str("url", resolvedURL.String()).Str("path", path).Msg("Filtered by file extension")
			return
		}

		// Normalize URL
		resolvedURL.Fragment = ""
		cleanLinkURL := resolvedURL.String()

		// Deduplicate
		isDuplicate := false
		for _, existing := range links {
			if existing == cleanLinkURL {
				log.Debug().Str("url", cleanLinkURL).Msg("Duplicate link found")
				isDuplicate = true
				break
			}
		}
		if isDuplicate {
			return
		}

		log.Debug().Str("url", cleanLinkURL).Msg("Adding valid meta refresh URL")
		links = append(links, cleanLinkURL)
	})

	// Extract links from button[onclick], input[onclick], and other interactive elements
	doc.Find("button[onclick], input[onclick], select[onchange], textarea[onchange]").Each(func(i int, s *goquery.Selection) {
		var eventAttr string
		var exists bool

		// Try different event attributes based on element type
		if eventAttr, exists = s.Attr("onclick"); exists {
			// Process onclick attribute
		} else if eventAttr, exists = s.Attr("onchange"); exists {
			// Process onchange attribute
		} else {
			return
		}

		// Extract URLs from event attribute using regex
		// Updated regex to capture both absolute and relative URLs, including JavaScript function calls
		urlRegex := regexp.MustCompile(`(?:https?:)?//[^\s"'\)]+|[^\s"'\(\)=\{\}]+\.(?:php|html?|aspx?|jsp|cgi|pl|py)(?:\?[^\s"'\)]*)?|(?:window\.open|loadSomething)\(['"]([^'"\)]+)['"]`)
		eventURLs := urlRegex.FindAllString(eventAttr, -1)

		// Extract URLs from JavaScript function calls
		jsFuncRegex := regexp.MustCompile(`(?:window\.open|loadSomething)\(['"]([^'"\)]+)['"]`)
		jsFuncMatches := jsFuncRegex.FindAllStringSubmatch(eventAttr, -1)
		for _, match := range jsFuncMatches {
			if len(match) > 1 {
				eventURLs = append(eventURLs, match[1])
			}
		}

		for _, eventURL := range eventURLs {
			// Parse URL
			parsedURL, err := url.Parse(eventURL)
			if err != nil {
				log.Debug().Str("url", eventURL).Err(err).Msg("Failed to parse interactive element URL")
				continue
			}

			// Resolve relative URLs
			resolvedURL := base.ResolveReference(parsedURL)

			// Filter protocols - only allow http and https
			if resolvedURL.Scheme != "http" && resolvedURL.Scheme != "https" {
				log.Debug().Str("url", resolvedURL.String()).Str("scheme", resolvedURL.Scheme).Msg("Filtered by protocol")
				continue
			}

			// Less restrictive domain filtering - only filter obviously external domains
		if resolvedURL.Host != "" && base.Host != "" && 
		   !strings.HasSuffix(resolvedURL.Host, base.Host) && 
		   !strings.HasSuffix(base.Host, resolvedURL.Host) &&
		   !strings.Contains(resolvedURL.Host, base.Host) && 
		   !strings.Contains(base.Host, resolvedURL.Host) {
			log.Debug().Str("url", resolvedURL.String()).Str("url_host", resolvedURL.Host).Str("base_host", base.Host).Msg("Filtered by domain")
			continue
		}

			// Less restrictive file extension filtering - only filter obvious non-HTML files
			path := strings.ToLower(resolvedURL.Path)
			if strings.HasSuffix(path, ".pdf") || strings.HasSuffix(path, ".css") ||
				strings.HasSuffix(path, ".xml") || strings.HasSuffix(path, ".zip") ||
				strings.HasSuffix(path, ".tar") || strings.HasSuffix(path, ".gz") ||
				strings.HasSuffix(path, ".exe") || strings.HasSuffix(path, ".dmg") ||
				strings.HasSuffix(path, ".iso") {
				log.Debug().Str("url", resolvedURL.String()).Str("path", path).Msg("Filtered by file extension")
				continue
			}

			// Normalize URL
			resolvedURL.Fragment = ""
			cleanEventURL := resolvedURL.String()

			// Deduplicate
			isDuplicate := false
			for _, existing := range links {
				if existing == cleanEventURL {
					log.Debug().Str("url", cleanEventURL).Msg("Duplicate link found")
					isDuplicate = true
					break
				}
			}
			if isDuplicate {
				continue
			}

			log.Debug().Str("url", cleanEventURL).Msg("Adding valid interactive element URL")
			links = append(links, cleanEventURL)
		}
	})



	// Extract links from iframe[src], embed[src], and object[data] attributes
	doc.Find("iframe[src], embed[src], object[data]").Each(func(i int, s *goquery.Selection) {
		var src string
		var exists bool

		// Try different attributes based on element type
		if src, exists = s.Attr("src"); !exists {
			if src, exists = s.Attr("data"); !exists {
				return
			}
		}

		// Parse URL
		mediaURL, err := url.Parse(src)
		if err != nil {
			log.Debug().Str("src", src).Err(err).Msg("Failed to parse media src/data")
			return
		}

		// Resolve relative URL
		resolvedURL := base.ResolveReference(mediaURL)

		// Filter protocols - only allow http and https
		if resolvedURL.Scheme != "http" && resolvedURL.Scheme != "https" {
			log.Debug().Str("url", resolvedURL.String()).Str("scheme", resolvedURL.Scheme).Msg("Filtered by protocol")
			return
		}

		// Less restrictive domain filtering - only filter obviously external domains
		if resolvedURL.Host != "" && base.Host != "" && 
		   !strings.HasSuffix(resolvedURL.Host, base.Host) && 
		   !strings.HasSuffix(base.Host, resolvedURL.Host) &&
		   !strings.Contains(resolvedURL.Host, base.Host) && 
		   !strings.Contains(base.Host, resolvedURL.Host) {
			log.Debug().Str("url", resolvedURL.String()).Str("url_host", resolvedURL.Host).Str("base_host", base.Host).Msg("Filtered by domain")
			return
		}

		// Less restrictive file extension filtering - only filter obvious non-HTML files
		path := strings.ToLower(resolvedURL.Path)
		if strings.HasSuffix(path, ".pdf") || strings.HasSuffix(path, ".css") ||
			strings.HasSuffix(path, ".xml") || strings.HasSuffix(path, ".zip") ||
			strings.HasSuffix(path, ".tar") || strings.HasSuffix(path, ".gz") ||
			strings.HasSuffix(path, ".exe") || strings.HasSuffix(path, ".dmg") ||
			strings.HasSuffix(path, ".iso") {
			log.Debug().Str("url", resolvedURL.String()).Str("path", path).Msg("Filtered by file extension")
			return
		}

		// Normalize URL
		resolvedURL.Fragment = ""
		cleanMediaURL := resolvedURL.String()

		// Deduplicate
		for _, existing := range links {
			if existing == cleanMediaURL {
				log.Debug().Str("url", cleanMediaURL).Msg("Duplicate link found")
				return
			}
		}

		log.Debug().Str("url", cleanMediaURL).Msg("Adding valid media link")
		links = append(links, cleanMediaURL)
	})

	// Extract links from img[src] attributes
	doc.Find("img[src]").Each(func(i int, s *goquery.Selection) {
		src, exists := s.Attr("src")
		if !exists {
			return
		}

		// Parse URL
		imgURL, err := url.Parse(src)
		if err != nil {
			log.Debug().Str("src", src).Err(err).Msg("Failed to parse img src")
			return
		}

		// Resolve relative URL
		resolvedURL := base.ResolveReference(imgURL)

		// Filter protocols - only allow http and https
		if resolvedURL.Scheme != "http" && resolvedURL.Scheme != "https" {
			log.Debug().Str("url", resolvedURL.String()).Str("scheme", resolvedURL.Scheme).Msg("Filtered by protocol")
			return
		}

		// Filter same domain - allow same host and subdomains
		if !strings.HasPrefix(resolvedURL.Host, base.Host) && !strings.HasPrefix(base.Host, resolvedURL.Host) {
			log.Debug().Str("url", resolvedURL.String()).Str("url_host", resolvedURL.Host).Str("base_host", base.Host).Msg("Filtered by domain")
			return
		}

		// Less restrictive file extension filtering - only filter obvious non-HTML files
		path := strings.ToLower(resolvedURL.Path)
		if strings.HasSuffix(path, ".pdf") || strings.HasSuffix(path, ".css") ||
			strings.HasSuffix(path, ".xml") || strings.HasSuffix(path, ".zip") ||
			strings.HasSuffix(path, ".tar") || strings.HasSuffix(path, ".gz") ||
			strings.HasSuffix(path, ".exe") || strings.HasSuffix(path, ".dmg") ||
			strings.HasSuffix(path, ".iso") {
			log.Debug().Str("url", resolvedURL.String()).Str("path", path).Msg("Filtered by file extension")
			return
		}

		// Normalize URL
		resolvedURL.Fragment = ""
		cleanImgURL := resolvedURL.String()

		// Deduplicate
		for _, existing := range links {
			if existing == cleanImgURL {
				log.Debug().Str("url", cleanImgURL).Msg("Duplicate link found")
				return
			}
		}

		log.Debug().Str("url", cleanImgURL).Msg("Adding valid img link")
		links = append(links, cleanImgURL)
	})

	// Extract links from link[href] attributes
	doc.Find("link[href]").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if !exists {
			return
		}

		// Parse URL
		linkURL, err := url.Parse(href)
		if err != nil {
			log.Debug().Str("href", href).Err(err).Msg("Failed to parse link href")
			return
		}

		// Resolve relative URL
		resolvedURL := base.ResolveReference(linkURL)

		// Filter protocols - only allow http and https
		if resolvedURL.Scheme != "http" && resolvedURL.Scheme != "https" {
			log.Debug().Str("url", resolvedURL.String()).Str("scheme", resolvedURL.Scheme).Msg("Filtered by protocol")
			return
		}

		// Filter same domain - allow same host and subdomains
		if !strings.HasPrefix(resolvedURL.Host, base.Host) && !strings.HasPrefix(base.Host, resolvedURL.Host) {
			log.Debug().Str("url", resolvedURL.String()).Str("url_host", resolvedURL.Host).Str("base_host", base.Host).Msg("Filtered by domain")
			return
		}

		// Less restrictive file extension filtering - only filter obvious non-HTML files
		path := strings.ToLower(resolvedURL.Path)
		if strings.HasSuffix(path, ".pdf") || strings.HasSuffix(path, ".css") ||
			strings.HasSuffix(path, ".xml") || strings.HasSuffix(path, ".zip") ||
			strings.HasSuffix(path, ".tar") || strings.HasSuffix(path, ".gz") ||
			strings.HasSuffix(path, ".exe") || strings.HasSuffix(path, ".dmg") ||
			strings.HasSuffix(path, ".iso") {
			log.Debug().Str("url", resolvedURL.String()).Str("path", path).Msg("Filtered by file extension")
			return
		}

		// Normalize URL
		resolvedURL.Fragment = ""
		cleanLinkURL := resolvedURL.String()

		// Deduplicate
		for _, existing := range links {
			if existing == cleanLinkURL {
				log.Debug().Str("url", cleanLinkURL).Msg("Duplicate link found")
				return
			}
		}

		log.Debug().Str("url", cleanLinkURL).Msg("Adding valid link href")
		links = append(links, cleanLinkURL)
	})

	// Extract links from JavaScript code
	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		scriptContent := s.Text()
		if scriptContent == "" {
			// Try to get script from src attribute
			src, exists := s.Attr("src")
			if !exists {
				return
			}
			// Resolve relative URL
			scriptURL, err := url.Parse(src)
			if err != nil {
				log.Debug().Str("src", src).Err(err).Msg("Failed to parse script src")
				return
			}
			resolvedURL := base.ResolveReference(scriptURL)

			// Filter protocols - only allow http and https
			if resolvedURL.Scheme != "http" && resolvedURL.Scheme != "https" {
				log.Debug().Str("url", resolvedURL.String()).Str("scheme", resolvedURL.Scheme).Msg("Filtered by protocol")
				return
			}

			// Filter same domain - allow same host and subdomains
			if !strings.HasPrefix(resolvedURL.Host, base.Host) && !strings.HasPrefix(base.Host, resolvedURL.Host) {
				log.Debug().Str("url", resolvedURL.String()).Str("url_host", resolvedURL.Host).Str("base_host", base.Host).Msg("Filtered by domain")
				return
			}

			// Less restrictive file extension filtering - only filter obvious non-HTML files
			path := strings.ToLower(resolvedURL.Path)
			if strings.HasSuffix(path, ".pdf") || strings.HasSuffix(path, ".css") ||
				strings.HasSuffix(path, ".xml") || strings.HasSuffix(path, ".zip") ||
				strings.HasSuffix(path, ".tar") || strings.HasSuffix(path, ".gz") ||
				strings.HasSuffix(path, ".exe") || strings.HasSuffix(path, ".dmg") ||
				strings.HasSuffix(path, ".iso") {
				log.Debug().Str("url", resolvedURL.String()).Str("path", path).Msg("Filtered by file extension")
				return
			}

			// Normalize URL
			resolvedURL.Fragment = ""
			cleanFormURL := resolvedURL.String()

			// Deduplicate
			for _, existing := range links {
				if existing == cleanFormURL {
					log.Debug().Str("url", cleanFormURL).Msg("Duplicate link found")
					return
				}
			}

			log.Debug().Str("url", cleanFormURL).Msg("Adding valid script link")
			links = append(links, cleanFormURL)
			return
		}

		// Extract URLs from JavaScript content using regex
		// This is a simple approach and might not catch all URLs
		// Updated regex to capture both absolute and relative URLs, including those in function calls
		// Enhanced to capture URLs in various JavaScript patterns like loadSomething('url'), window.open('url'), etc.
		urlRegex := regexp.MustCompile(`(?:https?:)?//[^\s"']+|['"]([^'"]*\.(?:php|html?|aspx?|jsp|cgi|pl|py)(?:\?[^'"]*)?)['"]|(?:loadSomething|window\.open|location\.href)\(['"]([^'"]*\.(?:php|html?|aspx?|jsp|cgi|pl|py)(?:\?[^'"]*)?)['"]|[^\s"'\(\)=\{\}]+\.(?:php|html?|aspx?|jsp|cgi|pl|py)(?:\?[^\s"']*)?`)
		jsURLs := urlRegex.FindAllString(scriptContent, -1)

		// Debug: Print script content and found URLs
		if len(jsURLs) > 0 {
			fmt.Printf("🔍 DEBUG: Found %d URLs in JavaScript content\n", len(jsURLs))
			for _, url := range jsURLs {
				fmt.Printf("🔍 DEBUG: JS URL: %s\n", url)
			}
		} else {
			// Print a sample of script content for debugging
			sample := scriptContent
			if len(sample) > 200 {
				sample = sample[:200]
			}
			fmt.Printf("🔍 DEBUG: No URLs found in JavaScript content. Sample: %s\n", sample)
		}

		for _, jsURL := range jsURLs {
			// Clean URL by removing quotes and relative path symbols
			cleanJSURL := strings.Trim(jsURL, "'\"")
			cleanJSURL = strings.TrimPrefix(cleanJSURL, "./")
			cleanJSURL = strings.TrimPrefix(cleanJSURL, "/")

			// Parse URL
			parsedURL, err := url.Parse(cleanJSURL)
			if err != nil {
				log.Debug().Str("url", cleanJSURL).Err(err).Msg("Failed to parse JS URL")
				continue
			}

			// Resolve relative URLs
			resolvedURL := base.ResolveReference(parsedURL)

			// Filter protocols - only allow http and https
			if resolvedURL.Scheme != "http" && resolvedURL.Scheme != "https" {
				log.Debug().Str("url", resolvedURL.String()).Str("scheme", resolvedURL.Scheme).Msg("Filtered by protocol")
				continue
			}

			// Filter same domain - allow same host and subdomains
			if !strings.HasPrefix(resolvedURL.Host, base.Host) && !strings.HasPrefix(base.Host, resolvedURL.Host) {
				log.Debug().Str("url", resolvedURL.String()).Str("url_host", resolvedURL.Host).Str("base_host", base.Host).Msg("Filtered by domain")
				continue
			}

			// Less restrictive file extension filtering
			path := strings.ToLower(resolvedURL.Path)
			if strings.HasSuffix(path, ".pdf") ||
				strings.HasSuffix(path, ".css") || strings.HasSuffix(path, ".xml") {
				log.Debug().Str("url", resolvedURL.String()).Str("path", path).Msg("Filtered by file extension")
				continue
			}

			// Normalize URL
			resolvedURL.Fragment = ""
			cleanLinkURL := resolvedURL.String()

			// Deduplicate
			for _, existing := range links {
				if existing == cleanLinkURL {
					log.Debug().Str("url", cleanLinkURL).Msg("Duplicate link found")
					continue
				}
			}

			log.Debug().Str("url", cleanLinkURL).Msg("Adding valid JS link")
			links = append(links, cleanLinkURL)
		}
	})

	// Extract links from HTML comments
	fmt.Printf("🔍 DEBUG: Looking for URLs in HTML comments\n")
	htmlContent, _ := doc.Html()
	// Find HTML comments that might contain URLs
	commentRegex := regexp.MustCompile(`<!--.*?-->`)
	comments := commentRegex.FindAllString(htmlContent, -1)
	
	for _, comment := range comments {
		// Look for URLs in comments
		urlRegex := regexp.MustCompile(`(?:template|href|src|file|path)=["']([^"']+)['"]`)
		urlMatches := urlRegex.FindAllStringSubmatch(comment, -1)
		
		for _, match := range urlMatches {
			if len(match) > 1 {
				commentURL := match[1]
				fmt.Printf("🔍 DEBUG: Found URL in comment: %s\n", commentURL)
				
				// Parse URL
				linkURL, err := url.Parse(commentURL)
				if err != nil {
					log.Debug().Str("comment_url", commentURL).Err(err).Msg("Failed to parse comment URL")
					continue
				}
				
				// Resolve relative URLs
				resolvedURL := base.ResolveReference(linkURL)
				
				log.Debug().Str("comment_url", commentURL).Str("resolved_url", resolvedURL.String()).Msg("Processing comment URL")
				
				// Filter protocols - only allow http and https
				if resolvedURL.Scheme != "http" && resolvedURL.Scheme != "https" {
					log.Debug().Str("url", resolvedURL.String()).Str("scheme", resolvedURL.Scheme).Msg("Filtered by protocol")
					continue
				}
				
				// Less restrictive domain filtering - only filter obviously external domains
				if resolvedURL.Host != "" && base.Host != "" && 
				   !strings.HasSuffix(resolvedURL.Host, base.Host) && 
				   !strings.HasSuffix(base.Host, resolvedURL.Host) &&
				   !strings.Contains(resolvedURL.Host, base.Host) && 
				   !strings.Contains(base.Host, resolvedURL.Host) {
					log.Debug().Str("url", resolvedURL.String()).Str("url_host", resolvedURL.Host).Str("base_host", base.Host).Msg("Filtered by domain")
					continue
				}
				
				// Less restrictive file extension filtering - only filter obvious non-HTML files
				path := strings.ToLower(resolvedURL.Path)
				if strings.HasSuffix(path, ".pdf") || strings.HasSuffix(path, ".css") ||
					strings.HasSuffix(path, ".xml") || strings.HasSuffix(path, ".zip") ||
					strings.HasSuffix(path, ".tar") || strings.HasSuffix(path, ".gz") ||
					strings.HasSuffix(path, ".exe") || strings.HasSuffix(path, ".dmg") ||
					strings.HasSuffix(path, ".iso") {
					log.Debug().Str("url", resolvedURL.String()).Str("path", path).Msg("Filtered by file extension")
					continue
				}
				
				// Normalize URL
				resolvedURL.Fragment = ""
				cleanCommentURL := resolvedURL.String()
				
				// Deduplicate
				isDuplicate := false
				for _, existing := range links {
					if existing == cleanCommentURL {
						log.Debug().Str("url", cleanCommentURL).Msg("Duplicate link found")
						isDuplicate = true
						break
					}
				}
				if isDuplicate {
					continue
				}
				
				log.Debug().Str("url", cleanCommentURL).Msg("Adding valid comment URL")
				links = append(links, cleanCommentURL)
			}
		}
	}

	// Extract links from forms as well
	fmt.Printf("🔍 DEBUG: Looking for forms in page\n")
	// Output the first 500 characters of the HTML to see what we're working with
	fmt.Printf("🔍 DEBUG: HTML content (first 500 chars): %s\n", htmlContent[:min(500, len(htmlContent))])

	// Try different selectors to find forms
	formSelectors := []string{"form[action]", "form", "form[method=post]", "form[method=get]"}
	for _, selector := range formSelectors {
		fmt.Printf("🔍 DEBUG: Trying selector: %s\n", selector)
		doc.Find(selector).Each(func(i int, s *goquery.Selection) {
			fmt.Printf("🔍 DEBUG: Found form with selector %s, index: %d\n", selector, i)
			action, exists := s.Attr("action")
			if !exists {
				fmt.Printf("🔍 DEBUG: Found form without action attribute\n")
				// Try to get the form HTML to see what it looks like
				formHTML, _ := s.Html()
				fmt.Printf("🔍 DEBUG: Form HTML: %s\n", formHTML[:min(200, len(formHTML))])
				return
			}

			// Clean and validate action
			action = strings.TrimSpace(action)
			if action == "" {
				fmt.Printf("🔍 DEBUG: Found form with empty action\n")
				// Try to get the form HTML to see what it looks like
				formHTML, _ := s.Html()
				fmt.Printf("🔍 DEBUG: Form HTML: %s\n", formHTML[:min(200, len(formHTML))])
				return
			}

			// Get form method and inputs
			method, _ := s.Attr("method")
			if method == "" {
				method = "get" // default method
			}
			var params []string
			s.Find("input[name]").Each(func(j int, input *goquery.Selection) {
				name, _ := input.Attr("name")
				value, _ := input.Attr("value")
				if value == "" {
					value = "param_value" // default value
				}
				params = append(params, fmt.Sprintf("%s=%s", name, value))
			})

			// Create URL with parameters
			formURL, err := url.Parse(action)
			if err != nil {
				log.Debug().Str("action", action).Err(err).Msg("Failed to parse form action")
				return
			}

			// Resolve relative URLs
			resolvedURL := base.ResolveReference(formURL)

			// Add parameters for GET forms
			if strings.ToLower(method) == "get" && len(params) > 0 {
				resolvedURL.RawQuery = strings.Join(params, "&")
			}

			log.Debug().Str("form_action", action).Str("method", method).Str("resolved_url", resolvedURL.String()).Msg("Processing form")
			fmt.Printf("🔍 DEBUG: Found form with action: %s, method: %s, params: %v\n", action, method, params)

			// Filter protocols - only allow http and https
			if resolvedURL.Scheme != "http" && resolvedURL.Scheme != "https" {
				log.Debug().Str("url", resolvedURL.String()).Str("scheme", resolvedURL.Scheme).Msg("Filtered by protocol")
				fmt.Printf("🔍 DEBUG: Form filtered by protocol. URL: %s, Scheme: %s\n", resolvedURL.String(), resolvedURL.Scheme)
				return
			}

			// Filter same domain - allow same host and subdomains
			if !strings.HasPrefix(resolvedURL.Host, base.Host) && !strings.HasPrefix(base.Host, resolvedURL.Host) {
				log.Debug().Str("url", resolvedURL.String()).Str("url_host", resolvedURL.Host).Str("base_host", base.Host).Msg("Filtered by domain")
				fmt.Printf("🔍 DEBUG: Form filtered by domain. URL: %s, URL Host: %s, Base Host: %s\n", resolvedURL.String(), resolvedURL.Host, base.Host)
				return
			}

			// Less restrictive file extension filtering - only filter obvious non-HTML files
			path := strings.ToLower(resolvedURL.Path)
			if strings.HasSuffix(path, ".pdf") || strings.HasSuffix(path, ".css") ||
				strings.HasSuffix(path, ".xml") || strings.HasSuffix(path, ".zip") ||
				strings.HasSuffix(path, ".tar") || strings.HasSuffix(path, ".gz") ||
				strings.HasSuffix(path, ".exe") || strings.HasSuffix(path, ".dmg") ||
				strings.HasSuffix(path, ".iso") {
				log.Debug().Str("url", resolvedURL.String()).Str("path", path).Msg("Filtered by file extension")
				fmt.Printf("🔍 DEBUG: Form filtered by file extension. URL: %s, Path: %s\n", resolvedURL.String(), path)
				return
			}

			// Normalize URL
			resolvedURL.Fragment = ""
			cleanFormURL := resolvedURL.String()

			// Deduplicate
			for _, existing := range links {
				if existing == cleanFormURL {
					log.Debug().Str("url", cleanFormURL).Msg("Duplicate link found")
					fmt.Printf("🔍 DEBUG: Form filtered because it's a duplicate. URL: %s\n", cleanFormURL)
					fmt.Printf("🔍 DEBUG: Duplicate found, but continuing to check for POST form\n")
					break
				}
			}

			log.Debug().Str("url", cleanFormURL).Msg("Adding valid form link")
			fmt.Printf("🔍 DEBUG: Adding form URL to links: %s\n", cleanFormURL)
			links = append(links, cleanFormURL)
			fmt.Printf("🔍 DEBUG: Form URL added successfully. Total links: %d\n", len(links))

			// For POST forms, also add the URL with POST parameters as a comment
			fmt.Printf("🔍 DEBUG: Checking if form is POST and has params. Method: %s, Params: %v\n", method, params)
			if strings.ToLower(method) == "post" && len(params) > 0 {
				fmt.Printf("🔍 DEBUG: Form is POST and has params, proceeding to add POST form\n")
				postURL := resolvedURL.String()
				paramStr := strings.Join(params, "&")
				postComment := fmt.Sprintf("POST:%s|%s", postURL, paramStr)

				// Check if POST comment already exists
				fmt.Printf("🔍 DEBUG: Checking if POST comment is duplicate: %s\n", postComment)
				isDuplicate := false
				for _, existing := range links {
					if existing == postComment {
						log.Debug().Str("url", postComment).Msg("Duplicate POST comment found")
						isDuplicate = true
						break
					}
				}

				if !isDuplicate {
					fmt.Printf("🔍 DEBUG: About to add POST form: %s\n", postComment)
					log.Debug().Str("url", postComment).Msg("Adding valid POST form comment")
					fmt.Printf("🔍 DEBUG: Adding POST form: %s\n", postComment)
					links = append(links, postComment)
					fmt.Printf("🔍 DEBUG: POST form added successfully. Total links: %d\n", len(links))
				} else {
					fmt.Printf("🔍 DEBUG: POST form not added because it's a duplicate: %s\n", postComment)
				}
			} else {
				fmt.Printf("🔍 DEBUG: Not adding POST form because no params found. Method: %s, Params: %v\n", method, params)
			}
		})
	}

	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if !exists {
			return
		}

		// Clean and validate href
		href = strings.TrimSpace(href)
		if href == "" || strings.HasPrefix(href, "#") || strings.HasPrefix(href, "mailto:") {
			log.Debug().Str("href", href).Msg("Filtered by content")
			return
		}

		// Handle JavaScript links (e.g., href="javascript:loadSomething('artists.php')")
		if strings.HasPrefix(href, "javascript:") {
			// Extract URLs from JavaScript code using regex - expanded to catch more patterns
			jsRegex := regexp.MustCompile(`(?:window\.open|loadSomething|location\.href|document\.location)\(['"]([^'"]+)['"]`)
			jsMatches := jsRegex.FindAllStringSubmatch(href, -1)

			for _, match := range jsMatches {
				if len(match) > 1 {
					jsURL := match[1]
					fmt.Printf("🔍 DEBUG: Found URL in JavaScript href: %s\n", jsURL)
					// Parse URL
					linkURL, err := url.Parse(jsURL)
					if err != nil {
						log.Debug().Str("js_url", jsURL).Err(err).Msg("Failed to parse JavaScript URL")
						continue
					}

					// Resolve relative URLs
					resolvedURL := base.ResolveReference(linkURL)

					log.Debug().Str("js_url", jsURL).Str("resolved_url", resolvedURL.String()).Msg("Processing JavaScript link")

					// Filter protocols - only allow http and https
					if resolvedURL.Scheme != "http" && resolvedURL.Scheme != "https" {
						log.Debug().Str("url", resolvedURL.String()).Str("scheme", resolvedURL.Scheme).Msg("Filtered by protocol")
						continue
					}

					// Filter same domain - allow same host and subdomains
					if !strings.HasPrefix(resolvedURL.Host, base.Host) && !strings.HasPrefix(base.Host, resolvedURL.Host) {
						log.Debug().Str("url", resolvedURL.String()).Str("url_host", resolvedURL.Host).Str("base_host", base.Host).Msg("Filtered by domain")
						continue
					}

					// Less restrictive file extension filtering - only filter obvious non-HTML files
					path := strings.ToLower(resolvedURL.Path)
					if strings.HasSuffix(path, ".pdf") || strings.HasSuffix(path, ".css") ||
						strings.HasSuffix(path, ".xml") || strings.HasSuffix(path, ".zip") ||
						strings.HasSuffix(path, ".tar") || strings.HasSuffix(path, ".gz") ||
						strings.HasSuffix(path, ".exe") || strings.HasSuffix(path, ".dmg") ||
						strings.HasSuffix(path, ".iso") {
						log.Debug().Str("url", resolvedURL.String()).Str("path", path).Msg("Filtered by file extension")
						continue
					}

					// Normalize URL
					resolvedURL.Fragment = ""
					cleanJSLinkURL := resolvedURL.String()

					// Deduplicate
					isDuplicate := false
					for _, existing := range links {
						if existing == cleanJSLinkURL {
							log.Debug().Str("url", cleanJSLinkURL).Msg("Duplicate link found")
							isDuplicate = true
							break
						}
					}
					if isDuplicate {
						continue
					}

					log.Debug().Str("url", cleanJSLinkURL).Msg("Adding valid JavaScript link")
					links = append(links, cleanJSLinkURL)
				}
			}
			return
		}

		linkURL, err := url.Parse(href)
		if err != nil {
			log.Debug().Str("href", href).Err(err).Msg("Failed to parse link URL")
			return
		}

		// Resolve relative URLs
		resolvedURL := base.ResolveReference(linkURL)

		log.Debug().Str("original_href", href).Str("resolved_url", resolvedURL.String()).Msg("Processing link")

		// Filter protocols - only allow http and https
		if resolvedURL.Scheme != "http" && resolvedURL.Scheme != "https" {
			log.Debug().Str("url", resolvedURL.String()).Str("scheme", resolvedURL.Scheme).Msg("Filtered by protocol")
			return
		}

		// Filter same domain - allow same host and subdomains
		if !strings.HasPrefix(resolvedURL.Host, base.Host) && !strings.HasPrefix(base.Host, resolvedURL.Host) {
			log.Debug().Str("url", resolvedURL.String()).Str("url_host", resolvedURL.Host).Str("base_host", base.Host).Msg("Filtered by domain")
			return
		}

		// Less restrictive file extension filtering - only filter obvious non-HTML files
		path := strings.ToLower(resolvedURL.Path)
		if strings.HasSuffix(path, ".pdf") || strings.HasSuffix(path, ".css") ||
			strings.HasSuffix(path, ".xml") || strings.HasSuffix(path, ".zip") ||
			strings.HasSuffix(path, ".tar") || strings.HasSuffix(path, ".gz") ||
			strings.HasSuffix(path, ".exe") || strings.HasSuffix(path, ".dmg") ||
			strings.HasSuffix(path, ".iso") {
			log.Debug().Str("url", resolvedURL.String()).Str("path", path).Msg("Filtered by file extension")
			return
		}

		// Normalize URL
		resolvedURL.Fragment = ""
		cleanLinkURL := resolvedURL.String()

		// Deduplicate
		for _, existing := range links {
			if existing == cleanLinkURL {
				log.Debug().Str("url", cleanLinkURL).Msg("Duplicate link found")
				return
			}
		}

		log.Debug().Str("url", cleanLinkURL).Msg("Adding valid link")
		links = append(links, cleanLinkURL)
	})

	log.Debug().Int("total_links_found", len(links)).Msg("Link extraction completed")
	return links
}

// GetResults returns all crawled URLs
func (c *Crawler) GetResults() []string {
	c.resultsMu.RLock()
	defer c.resultsMu.RUnlock()

	results := make([]string, len(c.results))
	copy(results, c.results)
	return results
}

// Stop gracefully stops the crawler
func (c *Crawler) Stop() {
	c.cancel()
	c.wg.Wait()
}

// GetStats returns crawler statistics
func (c *Crawler) GetStats() map[string]interface{} {
	c.visitedMu.RLock()
	c.resultsMu.RLock()
	defer c.visitedMu.RUnlock()
	defer c.resultsMu.RUnlock()

	stats := map[string]interface{}{
		"visited_urls": len(c.visited),
		"found_urls":   len(c.results),
		"max_depth":    c.config.MaxDepth,
		"concurrency":  c.config.Concurrency,
	}

	// Add similarity engine stats if available
	if c.similarityEngine != nil {
		similarityStats := c.similarityEngine.GetStats()
		for k, v := range similarityStats {
			stats["similarity_"+k] = v
		}
	}

	return stats
}
