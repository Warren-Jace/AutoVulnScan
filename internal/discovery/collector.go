// Package discovery contains all the logic related to the discovery phase of the scan.
// This includes crawling, link extraction, and parameter analysis.
package discovery

import (
	"autovulnscan/internal/util"
	"context"
	"net/url"
	"sync"

	"github.com/go-redis/redis/v8"
	"github.com/rs/zerolog/log"
)

// URLCollector handles the storage and deduplication of discovered URLs.
// It uses Redis for persistence across scans and an in-memory cache for session-specific speed.
type URLCollector struct {
	redisClient   *redis.Client
	memoryCache   map[string]struct{}
	crawledURLs   []string
	urlSignatures map[string]string // Maps URL signatures to canonical URLs
	mu            sync.RWMutex
	redisKey      string
}

// NewURLCollector creates and returns a new URLCollector.
func NewURLCollector(redisClient *redis.Client, redisKey string) *URLCollector {
	return &URLCollector{
		redisClient:   redisClient,
		memoryCache:   make(map[string]struct{}),
		crawledURLs:   make([]string, 0),
		urlSignatures: make(map[string]string),
		redisKey:      redisKey,
	}
}

// Add adds a URL to the collector. It returns true if the URL was new and added.
// It first checks the in-memory cache, then Redis, to ensure deduplication.
func (c *URLCollector) Add(ctx context.Context, url string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check in-memory cache first, which is the session's source of truth
	if _, exists := c.memoryCache[url]; exists {
		return false, nil
	}

	// Check if the URL is structurally similar to already collected URLs
	parsedURL, err := parseURL(url)
	if err != nil {
		log.Warn().Err(err).Str("url", url).Msg("Failed to parse URL for signature generation")
	} else {
		signature := util.GenerateURLSignature(parsedURL)
		if existingURL, exists := c.urlSignatures[signature]; exists {
			log.Debug().Str("url", url).Str("existing", existingURL).Str("signature", signature).Msg("URL is structurally similar to an existing URL, skipping")
			return false, nil
		}

		// Store the URL signature
		c.urlSignatures[signature] = url
	}

	// Then try to add to Redis if available
	if c.redisClient != nil {
		added, err := c.redisClient.SAdd(ctx, c.redisKey, url).Result()
		if err != nil {
			log.Warn().Err(err).Msg("Failed to add URL to Redis, falling back to in-memory only for this URL.")
			// Fallback to in-memory only for this operation, but don't disable redisClient globally
		} else if added == 0 {
			// The URL was already in Redis but not in our session cache.
			// This can happen if resuming a previous scan.
			// We add it to the memory cache to prevent re-processing in this session.
			c.memoryCache[url] = struct{}{}
			return false, nil
		}
	}

	// If the URL is new to both Redis (or Redis is down) and the memory cache,
	// add it to the memory cache and the list of URLs crawled in this session.
	c.memoryCache[url] = struct{}{}
	c.crawledURLs = append(c.crawledURLs, url)
	return true, nil
}

// Has checks if a URL has already been collected.
// It checks the in-memory cache first for performance, then falls back to Redis.
func (c *URLCollector) Has(ctx context.Context, url string) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Check in-memory cache first for speed
	if _, exists := c.memoryCache[url]; exists {
		return true, nil
	}

	// Then check Redis if available
	if c.redisClient != nil {
		exists, err := c.redisClient.SIsMember(ctx, c.redisKey, url).Result()
		if err != nil {
			log.Warn().Err(err).Msg("Failed to check URL in Redis, assuming not present.")
			// If Redis check fails, we assume it's not there and rely on memory cache.
			return false, nil
		}
		if exists {
			// If found in Redis, add it to the memory cache for faster lookups next time.
			// This requires upgrading the lock.
			c.mu.RUnlock()
			c.mu.Lock()
			c.memoryCache[url] = struct{}{}
			c.mu.Unlock()
			c.mu.RLock()
		}
		return exists, nil
	}

	return false, nil
}

// GetCrawledURLs returns a slice of all unique URLs crawled during the current session.
func (c *URLCollector) GetCrawledURLs() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Create a copy to ensure the returned slice is safe from concurrent modification.
	urls := make([]string, len(c.crawledURLs))
	copy(urls, c.crawledURLs)
	return urls
}

// parseURL is a helper function to safely parse URLs
func parseURL(urlStr string) (*url.URL, error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	return parsedURL, nil
}
