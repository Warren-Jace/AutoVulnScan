package crawler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"autovulnscan/internal/dedup"
	"compress/gzip"

	"github.com/PuerkitoBio/goquery"
	"github.com/rs/zerolog/log"
)

// Config holds crawler configuration
type Config struct {
	MaxPages      int           `json:"max_pages"`
	Timeout       time.Duration `json:"timeout"`
	UserAgent     string        `json:"user_agent"`
	MaxDepth      int           `json:"max_depth"`
	Concurrency   int           `json:"concurrency"`
	Delay         time.Duration `json:"delay"`
	RespectRobots bool          `json:"respect_robots"`

	// Similarity deduplication
	SimilarityConfig dedup.SimilarityConfig `json:"similarity_config"`
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
func New(config Config) *Crawler {
	// Set defaults
	if config.Concurrency <= 0 {
		config.Concurrency = 5
	}
	if config.MaxDepth <= 0 {
		config.MaxDepth = 3
	}
	if config.Delay <= 0 {
		config.Delay = 100 * time.Millisecond
	}

	// Create HTTP client with optimized settings
	client := &http.Client{
		Timeout: config.Timeout,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Initialize similarity engine
	similarityEngine := dedup.NewSimilarityEngine(config.SimilarityConfig)

	return &Crawler{
		config:           config,
		visited:          make(map[string]bool),
		results:          make([]string, 0),
		client:           client,
		rateLimit:        make(chan struct{}, config.Concurrency),
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
	// Check context cancellation
	select {
	case <-c.ctx.Done():
		return c.ctx.Err()
	default:
	}

	// Check depth limit
	if depth > c.config.MaxDepth {
		fmt.Printf("🔍 DEBUG: Max depth reached for %s (depth: %d)\n", urlStr, depth)
		return nil
	}

	// Check if already visited
	c.visitedMu.RLock()
	if c.visited[urlStr] {
		c.visitedMu.RUnlock()
		fmt.Printf("🔍 DEBUG: Already visited %s\n", urlStr)
		return nil
	}
	c.visitedMu.RUnlock()

	// Mark as visited
	c.visitedMu.Lock()
	c.visited[urlStr] = true
	c.visitedMu.Unlock()

	fmt.Printf("🔍 DEBUG: Crawling %s at depth %d\n", urlStr, depth)

	// Add delay between requests
	if c.config.Delay > 0 {
		time.Sleep(c.config.Delay)
	}

	// Fetch URL
	doc, html, err := c.fetchURL(urlStr)
	if err != nil {
		fmt.Printf("🔍 DEBUG: Failed to fetch %s: %v\n", urlStr, err)
		return nil // Continue with other URLs
	}

	// Debug: Log HTML content length and structure
	log.Debug().Str("url", urlStr).Int("html_length", len(html)).Msg("HTML content fetched")

	// Debug: Count links in HTML
	linkCount := doc.Find("a[href]").Length()
	log.Debug().Str("url", urlStr).Int("link_count", linkCount).Msg("Found anchor tags with href")

	// Direct console output for debugging
	fmt.Printf("🔍 DEBUG: URL: %s\n", urlStr)
	fmt.Printf("🔍 DEBUG: HTML length: %d\n", len(html))
	fmt.Printf("🔍 DEBUG: Found %d anchor tags with href\n", linkCount)

	// Debug: Show HTML structure
	if len(html) > 1000 {
		log.Debug().Str("url", urlStr).Str("html_preview", html[:1000]+"...").Msg("HTML preview")
		fmt.Printf("🔍 DEBUG: HTML preview: %s...\n", html[:200])
	} else {
		log.Debug().Str("url", urlStr).Str("html_content", html).Msg("Full HTML content")
		fmt.Printf("🔍 DEBUG: Full HTML: %s\n", html)
	}

	// Debug: Show page title
	title := doc.Find("title").Text()
	log.Debug().Str("url", urlStr).Str("title", title).Msg("Page title")
	fmt.Printf("🔍 DEBUG: Page title: %s\n", title)

	// Debug: Show all anchor tags
	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		text := strings.TrimSpace(s.Text())
		if exists {
			log.Debug().Str("url", urlStr).Int("index", i).Str("href", href).Str("text", text).Msg("Anchor tag found")
			fmt.Printf("🔍 DEBUG: Link %d: %s -> %s\n", i+1, text, href)
		} else {
			log.Debug().Str("url", urlStr).Int("index", i).Str("text", text).Msg("Anchor tag without href")
			fmt.Printf("🔍 DEBUG: Anchor %d (no href): %s\n", i+1, text)
		}
	})

	// Check similarity deduplication
	if c.similarityEngine != nil {
		shouldFilter, err := c.similarityEngine.ProcessPage(urlStr, html)
		if err != nil {
			log.Debug().Str("url", urlStr).Err(err).Msg("Similarity check failed")
		} else if shouldFilter {
			log.Debug().Str("url", urlStr).Msg("Page filtered due to similarity")
			return nil
		}
	}

	// Add to results
	c.resultsMu.Lock()
	c.results = append(c.results, urlStr)
	c.resultsMu.Unlock()

	// Extract and crawl links
	links := c.extractLinks(doc, urlStr)

	log.Debug().Str("url", urlStr).Int("extracted_links", len(links)).Msg("Link extraction completed")
	fmt.Printf("🔍 DEBUG: Extracted %d links from %s\n", len(links), urlStr)

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
	req, err := http.NewRequestWithContext(c.ctx, "GET", urlStr, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	if c.config.UserAgent != "" {
		req.Header.Set("User-Agent", c.config.UserAgent)
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate") // 支持gzip压缩
	req.Header.Set("Connection", "keep-alive")

	fmt.Printf("🔍 DEBUG: Making request to %s\n", urlStr)
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

	// Check content type
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		return nil, "", fmt.Errorf("non-HTML content: %s", contentType)
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

		// Filter same domain - allow same host
		if resolvedURL.Host != base.Host {
			log.Debug().Str("url", resolvedURL.String()).Str("url_host", resolvedURL.Host).Str("base_host", base.Host).Msg("Filtered by domain")
			return
		}

		// Less restrictive file extension filtering
		path := strings.ToLower(resolvedURL.Path)
		if strings.HasSuffix(path, ".pdf") || strings.HasSuffix(path, ".jpg") ||
			strings.HasSuffix(path, ".png") || strings.HasSuffix(path, ".gif") ||
			strings.HasSuffix(path, ".css") || strings.HasSuffix(path, ".js") ||
			strings.HasSuffix(path, ".ico") || strings.HasSuffix(path, ".xml") {
			log.Debug().Str("url", resolvedURL.String()).Str("path", path).Msg("Filtered by file extension")
			return
		}

		// Normalize URL
		resolvedURL.Fragment = ""
		cleanURL := resolvedURL.String()

		// Deduplicate
		for _, existing := range links {
			if existing == cleanURL {
				log.Debug().Str("url", cleanURL).Msg("Duplicate link found")
				return
			}
		}

		log.Debug().Str("url", cleanURL).Msg("Adding valid link")
		links = append(links, cleanURL)
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
