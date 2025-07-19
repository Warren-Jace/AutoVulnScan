package discovery

import (
	"autovulnscan/internal/requester"
	"autovulnscan/internal/util"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// SitemapURL represents a URL entry in a sitemap.xml file
type SitemapURL struct {
	Loc        string `xml:"loc"`
	LastMod    string `xml:"lastmod,omitempty"`
	ChangeFreq string `xml:"changefreq,omitempty"`
	Priority   string `xml:"priority,omitempty"`
}

// Sitemap represents a sitemap.xml file
type Sitemap struct {
	URLs []SitemapURL `xml:"url"`
}

// SitemapIndex represents a sitemap index file
type SitemapIndex struct {
	Sitemaps []struct {
		Loc string `xml:"loc"`
	} `xml:"sitemap"`
}

// SourceExtractor is responsible for extracting URLs from various sources like
// sitemap.xml, robots.txt, etc.
type SourceExtractor struct {
	httpClient *requester.HTTPClient
	baseURL    *url.URL
}

// NewSourceExtractor creates a new SourceExtractor instance
func NewSourceExtractor(baseURL *url.URL, client *requester.HTTPClient) *SourceExtractor {
	return &SourceExtractor{
		httpClient: client,
		baseURL:    baseURL,
	}
}

// ExtractFromSitemap extracts URLs from the sitemap.xml file
func (s *SourceExtractor) ExtractFromSitemap(ctx context.Context) ([]string, error) {
	foundURLs := make(map[string]struct{})

	// Construct potential sitemap URLs
	sitemapURLs := []string{
		fmt.Sprintf("%s://%s/sitemap.xml", s.baseURL.Scheme, s.baseURL.Host),
		fmt.Sprintf("%s://%s/sitemap_index.xml", s.baseURL.Scheme, s.baseURL.Host),
		fmt.Sprintf("%s://%s/sitemap-index.xml", s.baseURL.Scheme, s.baseURL.Host),
		fmt.Sprintf("%s://%s/sitemapindex.xml", s.baseURL.Scheme, s.baseURL.Host),
		fmt.Sprintf("%s://%s/wp-sitemap.xml", s.baseURL.Scheme, s.baseURL.Host), // WordPress
		fmt.Sprintf("%s://%s/sitemap.php", s.baseURL.Scheme, s.baseURL.Host),
		fmt.Sprintf("%s://%s/sitemap", s.baseURL.Scheme, s.baseURL.Host),
	}

	for _, sitemapURL := range sitemapURLs {
		urls, err := s.processSitemap(ctx, sitemapURL)
		if err != nil {
			log.Debug().Err(err).Str("url", sitemapURL).Msg("Failed to process sitemap")
			continue
		}

		for _, u := range urls {
			foundURLs[u] = struct{}{}
		}
	}

	// Convert map to slice
	result := make([]string, 0, len(foundURLs))
	for u := range foundURLs {
		result = append(result, u)
	}

	log.Info().Int("count", len(result)).Msg("Extracted URLs from sitemap")
	return result, nil
}

// processSitemap fetches and processes a sitemap file
func (s *SourceExtractor) processSitemap(ctx context.Context, sitemapURL string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", sitemapURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for sitemap %s: %w", sitemapURL, err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch sitemap %s: %w", sitemapURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sitemap %s returned status code %d", sitemapURL, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read sitemap body: %w", err)
	}

	foundURLs := make(map[string]struct{})

	var sitemapIndex SitemapIndex
	if err := xml.Unmarshal(body, &sitemapIndex); err == nil && len(sitemapIndex.Sitemaps) > 0 {
		log.Debug().Int("count", len(sitemapIndex.Sitemaps)).Msg("Found sitemap index")
		for _, subSitemap := range sitemapIndex.Sitemaps {
			subURLs, err := s.processSitemap(ctx, subSitemap.Loc)
			if err != nil {
				log.Debug().Err(err).Str("url", subSitemap.Loc).Msg("Failed to process sub-sitemap")
				continue
			}
			for _, u := range subURLs {
				foundURLs[u] = struct{}{}
			}
		}
	} else {
		var sitemap Sitemap
		if err := xml.Unmarshal(body, &sitemap); err != nil {
			return nil, fmt.Errorf("failed to parse sitemap XML: %w", err)
		}

		for _, sitemapURL := range sitemap.URLs {
			parsedURL, err := url.Parse(sitemapURL.Loc)
			if err != nil {
				log.Debug().Err(err).Str("url", sitemapURL.Loc).Msg("Failed to parse URL from sitemap")
				continue
			}
			if util.IsSameHost(s.baseURL, parsedURL) {
				foundURLs[sitemapURL.Loc] = struct{}{}
			}
		}
	}

	result := make([]string, 0, len(foundURLs))
	for u := range foundURLs {
		result = append(result, u)
	}
	return result, nil
}

// ExtractFromRobotsTxt extracts URLs from the robots.txt file
func (s *SourceExtractor) ExtractFromRobotsTxt(ctx context.Context) ([]string, error) {
	robotsURL := fmt.Sprintf("%s://%s/robots.txt", s.baseURL.Scheme, s.baseURL.Host)

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", robotsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for robots.txt: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch robots.txt: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("robots.txt returned status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read robots.txt body: %w", err)
	}

	foundURLs := make(map[string]struct{})

	// Extract paths from Allow and Disallow directives
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Look for Allow, Disallow, and Sitemap directives
		if strings.HasPrefix(strings.ToLower(line), "allow:") ||
			strings.HasPrefix(strings.ToLower(line), "disallow:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}

			path := strings.TrimSpace(parts[1])
			if path == "" || path == "/" {
				continue
			}

			// Convert path to full URL
			fullURL := fmt.Sprintf("%s://%s%s", s.baseURL.Scheme, s.baseURL.Host, path)
			foundURLs[fullURL] = struct{}{}
		} else if strings.HasPrefix(strings.ToLower(line), "sitemap:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}

			sitemapURL := strings.TrimSpace(parts[1])
			sitemapURLs, err := s.processSitemap(ctx, sitemapURL)
			if err != nil {
				log.Debug().Err(err).Str("url", sitemapURL).Msg("Failed to process sitemap from robots.txt")
				continue
			}

			for _, u := range sitemapURLs {
				foundURLs[u] = struct{}{}
			}
		}
	}

	// Extract common directories from robots.txt
	commonDirsRegex := regexp.MustCompile(`(?i)(?:Disallow|Allow):\s*(/.+?)(?:\s|$)`)
	matches := commonDirsRegex.FindAllStringSubmatch(string(body), -1)
	for _, match := range matches {
		if len(match) > 1 {
			path := match[1]
			if path != "/" && !strings.Contains(path, "*") && !strings.Contains(path, "$") {
				// Convert path to full URL
				fullURL := fmt.Sprintf("%s://%s%s", s.baseURL.Scheme, s.baseURL.Host, path)
				foundURLs[fullURL] = struct{}{}
			}
		}
	}

	// Convert map to slice
	result := make([]string, 0, len(foundURLs))
	for u := range foundURLs {
		result = append(result, u)
	}

	log.Info().Int("count", len(result)).Msg("Extracted URLs from robots.txt")
	return result, nil
}
