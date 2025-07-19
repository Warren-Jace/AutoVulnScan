package discovery

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/chromedp"
)

type Crawler struct {
	// Configuration
	config *CrawlerConfig

	// URL management
	visitedURLs sync.Map
	urlQueue    chan string

	// Results
	results chan *CrawlResult

	// Statistics
	stats *CrawlerStats

	// Context for cancellation
	ctx context.Context
}

type CrawlerConfig struct {
	// Basic settings
	Concurrency int
	MaxDepth    int
	Timeout     time.Duration

	// Feature flags
	EnableJS       bool
	EnableForms    bool
	FollowRedirect bool

	// Filters
	AllowedDomains []string
	ExcludePaths   []string

	// Custom headers
	Headers map[string]string
}

type CrawlResult struct {
	URL         string
	Method      string
	Parameters  map[string]string
	StatusCode  int
	ContentType string
	Title       string
	Links       []string
}

type CrawlerStats struct {
	sync.Mutex
	TotalURLs     int
	SuccessURLs   int
	FailedURLs    int
	SkippedURLs   int
	StartTime     time.Time
	ProcessedTime time.Duration
}

// NewCrawler creates a new crawler instance
func NewCrawler(config *CrawlerConfig) *Crawler {
	return &Crawler{
		config:   config,
		urlQueue: make(chan string, 10000),
		results:  make(chan *CrawlResult, 1000),
		stats:    &CrawlerStats{StartTime: time.Now()},
		ctx:      context.Background(),
	}
}

// Start begins the crawling process
func (c *Crawler) Start(seedURLs []string) error {
	// Initialize URL queue with seed URLs
	for _, url := range seedURLs {
		c.urlQueue <- url
	}

	// Start worker pool
	var wg sync.WaitGroup
	for i := 0; i < c.config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.worker()
		}()
	}

	// Wait for all workers to finish
	wg.Wait()
	return nil
}

// worker processes URLs from the queue
func (c *Crawler) worker() {
	for url := range c.urlQueue {
		if c.shouldSkip(url) {
			continue
		}

		// Mark URL as visited
		c.visitedURLs.Store(url, true)

		// Process URL
		result := c.processURL(url)
		if result != nil {
			c.results <- result

			// Extract and queue new URLs
			for _, link := range result.Links {
				if !c.isVisited(link) {
					c.urlQueue <- link
				}
			}
		}
	}
}

// processURL handles a single URL
func (c *Crawler) processURL(targetURL string) *CrawlResult {
	result := &CrawlResult{
		URL:        targetURL,
		Parameters: make(map[string]string),
	}

	// Process with different strategies
	if c.config.EnableJS {
		c.processWithChrome(result)
	} else {
		c.processWithGoQuery(result)
	}

	// Extract parameters from URL
	if u, err := url.Parse(targetURL); err == nil {
		query := u.Query()
		for key := range query {
			result.Parameters[key] = query.Get(key)
		}
	}

	return result
}

// processWithChrome handles JavaScript-enabled crawling
func (c *Crawler) processWithChrome(result *CrawlResult) {
	ctx, cancel := chromedp.NewContext(c.ctx)
	defer cancel()

	// Set timeout
	ctx, cancel = context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	// Navigate and wait for network idle
	var links []string
	err := chromedp.Run(ctx,
		chromedp.Navigate(result.URL),
		chromedp.WaitReady("body"),
		chromedp.Evaluate(`
			Array.from(document.querySelectorAll('a')).map(a => a.href)
		`, &links),
	)

	if err == nil {
		result.Links = links
	}
}

// processWithGoQuery handles static HTML crawling
func (c *Crawler) processWithGoQuery(result *CrawlResult) {
	// Create HTTP client with custom settings
	client := &http.Client{
		Timeout: c.config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !c.config.FollowRedirect {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// Create request
	req, err := http.NewRequest("GET", result.URL, nil)
	if err != nil {
		return
	}

	// Add custom headers
	for key, value := range c.config.Headers {
		req.Header.Set(key, value)
	}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Parse HTML
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return
	}

	// Extract links
	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		if href, exists := s.Attr("href"); exists {
			result.Links = append(result.Links, href)
		}
	})

	// Extract form actions
	if c.config.EnableForms {
		doc.Find("form").Each(func(i int, s *goquery.Selection) {
			if action, exists := s.Attr("action"); exists {
				result.Links = append(result.Links, action)
			}
		})
	}
}

// shouldSkip determines if a URL should be skipped
func (c *Crawler) shouldSkip(url string) bool {
	// Check if URL was already visited
	if c.isVisited(url) {
		return true
	}

	// Check domain restrictions
	if len(c.config.AllowedDomains) > 0 {
		allowed := false
		for _, domain := range c.config.AllowedDomains {
			if strings.Contains(url, domain) {
				allowed = true
				break
			}
		}
		if !allowed {
			return true
		}
	}

	// Check excluded paths
	for _, pattern := range c.config.ExcludePaths {
		if matched, _ := regexp.MatchString(pattern, url); matched {
			return true
		}
	}

	return false
}

// isVisited checks if a URL was already processed
func (c *Crawler) isVisited(url string) bool {
	_, visited := c.visitedURLs.Load(url)
	return visited
}

// GetResults returns the channel for crawl results
func (c *Crawler) GetResults() <-chan *CrawlResult {
	return c.results
}

// GetStats returns current crawler statistics
func (c *Crawler) GetStats() *CrawlerStats {
	c.stats.Lock()
	defer c.stats.Unlock()
	c.stats.ProcessedTime = time.Since(c.stats.StartTime)
	return c.stats
}
