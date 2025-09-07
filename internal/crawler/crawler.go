package crawler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
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
		return nil
	}

	// Check if already visited
	// Use the full urlStr for deduplication to allow different parameters
	visitedKey := urlStr

	c.visitedMu.RLock()
	if c.visited[visitedKey] {
		c.visitedMu.RUnlock()
		return nil
	}
	c.visitedMu.RUnlock()

	// Mark as visited
	c.visitedMu.Lock()
	c.visited[visitedKey] = true
	c.visitedMu.Unlock()

	// Add delay between requests
	if c.config.Delay > 0 {
		time.Sleep(c.config.Delay)
	}

	// Fetch URL
	doc, html, err := c.fetchURL(urlStr)
	if err != nil {
		return nil // Continue with other URLs
	}

	// Debug: Log HTML content length and structure
	log.Debug().Str("url", actualURL).Int("html_length", len(html)).Msg("HTML content fetched")

	// Debug: Count links in HTML
	linkCount := doc.Find("a[href]").Length()
	log.Debug().Str("url", actualURL).Int("link_count", linkCount).Msg("Found anchor tags with href")

	// Debug: Show HTML structure
	if len(html) > 1000 {
		log.Debug().Str("url", actualURL).Str("html_preview", html[:1000]+"...").Msg("HTML preview")
	} else {
		log.Debug().Str("url", actualURL).Str("html_content", html).Msg("Full HTML content")
	}

	// Debug: Show page title
	title := doc.Find("title").Text()
	log.Debug().Str("url", actualURL).Str("title", title).Msg("Page title")

	// Debug: Show all anchor tags
	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		text := strings.TrimSpace(s.Text())
		if exists {
			log.Debug().Str("url", actualURL).Int("index", i).Str("href", href).Str("text", text).Msg("Anchor tag found")
		} else {
			log.Debug().Str("url", actualURL).Int("index", i).Str("text", text).Msg("Anchor tag without href")
		}
	})

	// Check similarity deduplication
	if c.similarityEngine != nil && c.config.SimilarityConfig.Enabled {
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
	// Check if we've reached the maximum number of pages
	if c.config.MaxPages > 0 && len(c.results) >= c.config.MaxPages {
		c.resultsMu.Unlock()
		log.Info().Int("max_pages", c.config.MaxPages).Int("current_pages", len(c.results)).Msg("Reached maximum pages limit, stopping crawler")
		c.cancel() // Cancel context to stop further crawling
		return nil
	}
	c.resultsMu.Unlock()

	// Extract and crawl links
	links := c.extractLinks(doc, actualURL)

	log.Debug().Str("url", actualURL).Int("extracted_links", len(links)).Msg("Link extraction completed")

	// Sequential crawling to avoid deadlock
	for _, link := range links {
		select {
		case <-c.ctx.Done():
			return c.ctx.Err()
		default:
			// Crawl sequentially to avoid deadlock
			if err := c.crawl(link, depth+1); err != nil {
				// Continue with other URLs
			}
		}
	}

	return nil
}

// fetchURL fetches a single URL and returns the parsed document and HTML content
func (c *Crawler) fetchURL(urlStr string) (*goquery.Document, string, error) {
	// Handle file:// protocol for local files
	if strings.HasPrefix(urlStr, "file://") {
		// Extract file path from URL
		filePath := urlStr[7:] // Remove "file://" prefix
		
		// Convert URL path to local file path
		if strings.HasPrefix(filePath, "/") {
			// On Windows, remove leading slash for absolute paths like /C:/path
			if len(filePath) > 2 && filePath[2] == ':' {
				filePath = filePath[1:]
			}
		}
		
		// Read file content
		htmlBytes, err := os.ReadFile(filePath)
		if err != nil {
			return nil, "", fmt.Errorf("failed to read file: %w", err)
		}
		
		html := string(htmlBytes)
		
		// Parse HTML
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse HTML: %w", err)
		}
		
		return doc, html, nil
	}
	
	// Add http:// protocol to URLs without a protocol
	if !strings.Contains(urlStr, "://") {
		urlStr = "http://" + urlStr
	}
	
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
	} else {
		// Create GET request
		req, err = http.NewRequestWithContext(c.ctx, "GET", urlStr, nil)
		if err != nil {
			return nil, "", fmt.Errorf("failed to create request: %w", err)
		}
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

	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("status code error: %d %s", resp.StatusCode, resp.Status)
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
	} else {
		// Handle uncompressed content
		htmlBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, "", fmt.Errorf("failed to read response body: %w", err)
		}
		html = string(htmlBytes)
	}

	// Log content type for debugging
	contentType := resp.Header.Get("Content-Type")
	log.Debug().Str("url", urlStr).Str("content_type", contentType).Msg("Fetched URL content type")

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

		// Less restrictive file extension filtering - only filter obvious non-HTML files, but allow image and media files
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

		// Less restrictive file extension filtering - only filter obvious non-HTML files, but allow image and media files
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

			// Less restrictive file extension filtering - only filter obvious non-HTML files, but allow image and media files
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

		// Less restrictive file extension filtering - only filter obvious non-HTML files, but allow image and media files
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

		// Less restrictive domain filtering - only filter obviously external domains
		if resolvedURL.Host != "" && base.Host != "" && 
		   !strings.HasSuffix(resolvedURL.Host, base.Host) && 
		   !strings.HasSuffix(base.Host, resolvedURL.Host) &&
		   !strings.Contains(resolvedURL.Host, base.Host) && 
		   !strings.Contains(base.Host, resolvedURL.Host) {
			log.Debug().Str("url", resolvedURL.String()).Str("url_host", resolvedURL.Host).Str("base_host", base.Host).Msg("Filtered by domain")
			return
		}

		// Less restrictive file extension filtering - only filter obvious non-HTML files, but allow image and media files
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

		// Less restrictive domain filtering - only filter obviously external domains
		if resolvedURL.Host != "" && base.Host != "" && 
		   !strings.HasSuffix(resolvedURL.Host, base.Host) && 
		   !strings.HasSuffix(base.Host, resolvedURL.Host) &&
		   !strings.Contains(resolvedURL.Host, base.Host) && 
		   !strings.Contains(base.Host, resolvedURL.Host) {
			log.Debug().Str("url", resolvedURL.String()).Str("url_host", resolvedURL.Host).Str("base_host", base.Host).Msg("Filtered by domain")
			return
		}

		// Less restrictive file extension filtering - only filter obvious non-HTML files, but allow image and media files
			path := strings.ToLower(resolvedURL.Path)
			if strings.HasSuffix(path, ".pdf") ||
				strings.HasSuffix(path, ".css") || strings.HasSuffix(path, ".xml") ||
				strings.HasSuffix(path, ".zip") || strings.HasSuffix(path, ".tar") ||
				strings.HasSuffix(path, ".gz") || strings.HasSuffix(path, ".exe") ||
				strings.HasSuffix(path, ".dmg") || strings.HasSuffix(path, ".iso") {
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

	// Extract links from onclick and onClick event attributes
	onclickElements := doc.Find("[onclick], [onClick]")
	
	onclickElements.Each(func(i int, s *goquery.Selection) {
		onclick, exists := s.Attr("onclick")
		if !exists {
			onclick, exists = s.Attr("onClick")
			if !exists {
				return
			}
		}
		
		// Extract URLs from onclick/onClick JavaScript code using regex
		// Extended to capture URLs in various JavaScript patterns like loadSomething('url'), window.open('url'), fetch('url'), axios.get('url'), etc.
		// Also capture URLs with parameters like loadSomething('url', param1, param2)
		jsRegex := regexp.MustCompile(`(?:window\.open|loadSomething|location\.href|document\.location|fetch|axios\.get|axios\.post|axios\.put|axios\.delete|axios\.patch)\(['"]([^'"]+)['"](?:\s*,\s*[^)]*)?\)`)
		jsMatches := jsRegex.FindAllStringSubmatch(onclick, -1)
		
		for _, match := range jsMatches {
			if len(match) > 1 {
				jsURL := match[1]
				
				// Parse URL
				linkURL, err := url.Parse(jsURL)
				if err != nil {
					log.Debug().Str("js_url", jsURL).Err(err).Msg("Failed to parse onclick/onClick URL")
					continue
				}
				
				// Resolve relative URLs, but keep them as relative when base is file://
				var resolvedURL *url.URL
				if base.Scheme == "file" {
					// For local files, keep relative URLs as they are
					resolvedURL = linkURL
				} else {
					// For web URLs, resolve against base
					resolvedURL = base.ResolveReference(linkURL)
				}
				
				log.Debug().Str("js_url", jsURL).Str("resolved_url", resolvedURL.String()).Msg("Processing onclick/onClick link")
				
				// Filter protocols - allow http, https, and empty scheme (for relative URLs)
				if resolvedURL.Scheme != "" && resolvedURL.Scheme != "http" && resolvedURL.Scheme != "https" {
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
				
				// Less restrictive file extension filtering - only filter obvious non-HTML files, but allow image and media files
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
				
				log.Debug().Str("url", cleanJSLinkURL).Msg("Adding valid onclick/onClick link")
				links = append(links, cleanJSLinkURL)
			}
		}
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

			// Less restrictive file extension filtering - only filter obvious non-HTML files, but allow image and media files
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
		// Enhanced to capture URLs in various JavaScript patterns like loadSomething('url'), window.open('url'), fetch('url'), axios.get('url'), etc.
		// Also capture URLs with empty parameters like showimage.php?file=
		// Extended to capture API endpoints and JSON/XML files
		// Also capture URLs with parameters like loadSomething('url', param1, param2)
		urlRegex := regexp.MustCompile(`(?:https?:)?\/\/[^\s"']+|["']([^"']*\.(?:php|html?|aspx?|jsp|cgi|pl|py|json|xml)(?:\?[^"']*)?)["']|(?:loadSomething|window\.open|location\.href|fetch|axios\.get|axios\.post|axios\.put|axios\.delete|axios\.patch)\(["']([^"']*\.(?:php|html?|aspx?|jsp|cgi|pl|py|json|xml)(?:\?[^"']*)?)["'](?:\s*,\s*[^)]*)?|[^\s"'\(\)=\{\}]+\.(?:php|html?|aspx?|jsp|cgi|pl|py|json|xml)(?:\?[\w=&-]*)?`)
		jsURLs := urlRegex.FindAllString(scriptContent, -1)

		// Debug: Log script content and found URLs
		if len(jsURLs) > 0 {
			log.Debug().Int("url_count", len(jsURLs)).Msg("Found URLs in JavaScript content")
			for _, url := range jsURLs {
				log.Debug().Str("js_url", url).Msg("JS URL found")
			}
		} else {
			// Log a sample of script content for debugging
			sample := scriptContent
			if len(sample) > 200 {
				sample = sample[:200]
			}
			log.Debug().Str("sample", sample).Msg("No URLs found in JavaScript content")
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

			// Less restrictive file extension filtering - only filter obvious non-HTML files, but allow image and media files
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
	log.Debug().Msg("Looking for URLs in HTML comments")
	htmlContent, _ := doc.Html()
	// Find HTML comments that might contain URLs
	commentRegex := regexp.MustCompile(`<!--.*?-->`)
	comments := commentRegex.FindAllString(htmlContent, -1)
	
	for _, comment := range comments {
		// Look for URLs in comments with more patterns
		urlRegex := regexp.MustCompile(`(?:(?:template|href|src|file|path)=|url\()\s*["']([^"']+)['"]`)
		urlMatches := urlRegex.FindAllStringSubmatch(comment, -1)
		
		for _, match := range urlMatches {
			if len(match) > 1 {
				commentURL := match[1]
				log.Debug().Str("comment_url", commentURL).Msg("Found URL in comment")
				
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
				
				// Less restrictive file extension filtering - only filter obvious non-HTML files, but allow image and media files
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
	log.Debug().Msg("Looking for forms in page")

	// Try different selectors to find forms
	formSelectors := []string{"form[action]", "form", "form[method=post]", "form[method=get]"}
	for _, selector := range formSelectors {
		log.Debug().Str("selector", selector).Msg("Trying form selector")
		doc.Find(selector).Each(func(i int, s *goquery.Selection) {
			action, exists := s.Attr("action")
			if !exists {
				log.Debug().Msg("Found form without action attribute")
				return
			}

			// Clean and validate action
			action = strings.TrimSpace(action)
			if action == "" {
				log.Debug().Msg("Found form with empty action")
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

			// Handle forms with empty action attribute
			if action == "" {
				action = base.Path
			}

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
					break
				}
			}

			log.Debug().Str("url", cleanFormURL).Msg("Adding valid form link")
			links = append(links, cleanFormURL)

			// For POST forms, also add the URL with POST parameters as a comment
			if strings.ToLower(method) == "post" && len(params) > 0 {
				postURL := resolvedURL.String()
				paramStr := strings.Join(params, "&")
				postComment := fmt.Sprintf("POST:%s|%s", postURL, paramStr)

				// Check if POST comment already exists
				isDuplicate := false
				for _, existing := range links {
					if existing == postComment {
						log.Debug().Str("url", postComment).Msg("Duplicate POST comment found")
						isDuplicate = true
						break
					}
				}

				if !isDuplicate {
					log.Debug().Str("url", postComment).Msg("Adding valid POST form comment")
					links = append(links, postComment)
				}
			}

			// Also add the POST URL without parameters to ensure it's processed
			if strings.ToLower(method) == "post" {
				log.Debug().Str("url", cleanFormURL).Msg("Adding POST form URL for processing")
				links = append(links, cleanFormURL)
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
		// Also capture URLs with parameters like loadSomething('url', param1, param2)
		jsRegex := regexp.MustCompile(`(?:window\.open|loadSomething|location\.href|document\.location|fetch|axios\.get|axios\.post|axios\.put|axios\.delete|axios\.patch)\(['"]([^'"]+)['"](?:\s*,\s*[^)]*)?\)`)
			jsMatches := jsRegex.FindAllStringSubmatch(href, -1)

			for _, match := range jsMatches {
				if len(match) > 1 {
					jsURL := match[1]
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

					// Less restrictive domain filtering - only filter obviously external domains
					if resolvedURL.Host != "" && base.Host != "" && 
					   !strings.HasSuffix(resolvedURL.Host, base.Host) && 
					   !strings.HasSuffix(base.Host, resolvedURL.Host) &&
					   !strings.Contains(resolvedURL.Host, base.Host) && 
					   !strings.Contains(base.Host, resolvedURL.Host) {
						log.Debug().Str("url", resolvedURL.String()).Str("url_host", resolvedURL.Host).Str("base_host", base.Host).Msg("Filtered by domain")
						continue
					}

					// Less restrictive file extension filtering - only filter obvious non-HTML files, but allow image and media files
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

		// Less restrictive file extension filtering - only filter obvious non-HTML files, but allow image and media files
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
