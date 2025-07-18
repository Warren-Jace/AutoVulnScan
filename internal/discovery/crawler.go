package discovery

import (
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

	"github.com/PuerkitoBio/goquery"
	"github.com/rs/zerolog/log"
)

// bodyCloser is a helper struct that combines a reader (like bytes.Buffer)
// with a closer (like the original http.Response.Body.Close)
// to ensure the underlying connection is properly closed.
type bodyCloser struct {
	io.Reader
	io.Closer
}

// Crawler fetches web pages and extracts links.
type Crawler struct {
	httpClient *requester.HTTPClient
	baseURL    *url.URL
}

// NewCrawler creates a new Crawler instance.
func NewCrawler(targetURL string, userAgents []string, client *requester.HTTPClient) (*Crawler, error) {
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
	}, nil
}

// Crawl fetches a single URL and extracts all discoverable, in-scope links.
// It returns a slice of found URLs and the response body, which MUST be closed by the caller.
func (c *Crawler) Crawl(ctx context.Context, pageURL string) ([]string, io.ReadCloser, error) {
	crawlURL, err := url.Parse(pageURL)
	if err != nil {
		log.Error().Err(err).Str("url", pageURL).Msg("Failed to parse page URL during crawl")
		return nil, nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", pageURL, nil)
	if err != nil {
		log.Error().Err(err).Str("url", pageURL).Msg("Failed to create request")
		return nil, nil, err
	}

	// The User-Agent is now handled by the custom HTTPClient's Do method.
	// No need to set it here.

	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Warn().Err(err).Str("url", pageURL).Msg("Failed to fetch URL")
		return nil, nil, err
	}
	// DO NOT close resp.Body here. The caller is responsible for it.

	if resp.StatusCode >= 400 {
		resp.Body.Close() // Close the body on error
		msg := fmt.Sprintf("Request failed with status code: %d", resp.StatusCode)
		log.Warn().Int("status_code", resp.StatusCode).Str("url", pageURL).Msg(msg)
		return nil, nil, fmt.Errorf(msg)
	}

	// Make sure we are only parsing HTML content, but pass the body on regardless
	// so the caller can decide what to do with non-html content types.
	contentType := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/html") {
		log.Debug().Str("url", pageURL).Str("content_type", contentType).Msg("Skipping non-HTML content for link extraction")
		// Return the body so other tools can potentially use it, but no links were extracted.
		return []string{}, resp.Body, nil
	}

	foundURLs := make(map[string]struct{})

	// TeeReader allows us to read the body for link extraction AND pass the original body on.
	// This is important because reading the body consumes it.
	var bodyBuf bytes.Buffer
	tee := io.TeeReader(resp.Body, &bodyBuf)

	// Extract links from JavaScript
	jsLinks := extractJSLinks(pageURL, &bodyBuf)
	for _, link := range jsLinks {
		foundURLs[link] = struct{}{}
	}

	doc, err := goquery.NewDocumentFromReader(tee)
	if err != nil {
		resp.Body.Close() // Close the original body on parsing error
		log.Warn().Err(err).Str("url", pageURL).Msg("Failed to parse HTML content")
		return nil, nil, err
	}

	// After goquery has read from the tee, the buffer is filled.
	// We return a new ReadCloser that reads from the buffer but closes the original response body.
	finalBody := &bodyCloser{Reader: &bodyBuf, Closer: resp.Body}

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

	log.Debug().Str("crawled_url", pageURL).Int("found_urls", len(urls)).Msg("Crawling complete")
	return urls, finalBody, nil
}

var (
	// Regex to find links in JavaScript code. This is a best-effort approach.
	// It looks for string literals that look like relative or absolute paths.
	jsLinkRegex = regexp.MustCompile(`['"](/[^'"\s]+|https?://[^'"\s]+)['"]`)
)

func extractJSLinks(pageURL string, body io.Reader) []string {
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return nil
	}

	foundURLs := make(map[string]struct{})
	base, _ := url.Parse(pageURL)

	matches := jsLinkRegex.FindAllStringSubmatch(string(bodyBytes), -1)
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

	urls := make([]string, 0, len(foundURLs))
	for u := range foundURLs {
		urls = append(urls, u)
	}
	return urls
}
