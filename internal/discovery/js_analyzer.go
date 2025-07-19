package discovery

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"regexp"
	"strings"

	"github.com/dop251/goja"
)

// JSAnalyzer handles JavaScript content analysis
type JSAnalyzer struct {
	vm *goja.Runtime
}

// NewJSAnalyzer creates a new JSAnalyzer instance
func NewJSAnalyzer() *JSAnalyzer {
	return &JSAnalyzer{
		vm: goja.New(),
	}
}

// ExtractURLs extracts URLs from JavaScript content
func (a *JSAnalyzer) ExtractURLs(content string, baseURL *url.URL) []string {
	urls := make(map[string]struct{})

	// Extract URLs from string literals
	a.extractFromStrings(content, baseURL, urls)

	// Extract URLs from common patterns
	a.extractFromPatterns(content, baseURL, urls)

	// Extract URLs from JSON-like objects
	a.extractFromJSON(content, baseURL, urls)

	// Convert map to slice
	result := make([]string, 0, len(urls))
	for u := range urls {
		result = append(result, u)
	}

	return result
}

// Common patterns for URL extraction
var (
	urlPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(https?://[^\s'"]+)`),                    // HTTP(S) URLs
		regexp.MustCompile(`(?i)(ws[s]?://[^\s'"]+)`),                    // WebSocket URLs
		regexp.MustCompile(`['"]([/][^'"]*?)['"]\s*`),                    // Relative paths
		regexp.MustCompile(`url\(['"]?([^'"]+)['"]?\)`),                  // CSS url() function
		regexp.MustCompile(`(?i)src\s*=\s*['"]([^'"]+)['"]`),             // src attributes
		regexp.MustCompile(`(?i)href\s*=\s*['"]([^'"]+)['"]`),            // href attributes
		regexp.MustCompile(`(?i)action\s*=\s*['"]([^'"]+)['"]`),          // form actions
		regexp.MustCompile(`(?i)endpoint['"]\s*:\s*['"]([^'"]+)['"]`),    // API endpoints
		regexp.MustCompile(`(?i)fetch\(['"]([^'"]+)['"]\)`),              // fetch calls
		regexp.MustCompile(`(?i)\.get\(['"]([^'"]+)['"]\)`),              // AJAX get
		regexp.MustCompile(`(?i)\.post\(['"]([^'"]+)['"]\)`),             // AJAX post
		regexp.MustCompile(`(?i)\.ajax\(\{[^}]*url:\s*['"]([^'"]+)['"]`), // jQuery ajax
	}

	// Common API endpoint patterns
	apiPatterns = []string{
		"/api/",
		"/v1/",
		"/v2/",
		"/rest/",
		"/graphql",
		"/query",
		"/service/",
	}
)

// extractFromStrings extracts URLs from string literals
func (a *JSAnalyzer) extractFromStrings(content string, baseURL *url.URL, urls map[string]struct{}) {
	// First pass: extract string literals
	stringLiterals := regexp.MustCompile(`(['"])((?:(?!\1)[^\\]|\\[\s\S])*?)\1`).FindAllStringSubmatch(content, -1)

	for _, match := range stringLiterals {
		if len(match) > 2 {
			str := match[2]
			// Check if it looks like a URL or path
			if strings.HasPrefix(str, "http") || strings.HasPrefix(str, "/") {
				if u := resolveURL(baseURL, str); u != "" {
					urls[u] = struct{}{}
				}
			}
		}
	}
}

// extractFromPatterns extracts URLs using regex patterns
func (a *JSAnalyzer) extractFromPatterns(content string, baseURL *url.URL, urls map[string]struct{}) {
	for _, pattern := range urlPatterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				if u := resolveURL(baseURL, match[1]); u != "" {
					urls[u] = struct{}{}
				}
			}
		}
	}

	// Look for API endpoints
	for _, pattern := range apiPatterns {
		if idx := strings.Index(content, pattern); idx != -1 {
			// Extract the full path
			start := idx
			for start > 0 && content[start-1] != '"' && content[start-1] != '\'' {
				start--
			}
			end := idx + len(pattern)
			for end < len(content) && content[end] != '"' && content[end] != '\'' && content[end] != ' ' {
				end++
			}
			if path := content[start:end]; path != "" {
				if u := resolveURL(baseURL, path); u != "" {
					urls[u] = struct{}{}
				}
			}
		}
	}
}

// extractFromJSON extracts URLs from JSON-like objects
func (a *JSAnalyzer) extractFromJSON(content string, baseURL *url.URL, urls map[string]struct{}) {
	// Find JSON-like objects
	jsonPattern := regexp.MustCompile(`\{[^{}]*\}`)
	matches := jsonPattern.FindAllString(content, -1)

	for _, match := range matches {
		var obj interface{}
		if err := json.NewDecoder(bytes.NewReader([]byte(match))).Decode(&obj); err == nil {
			a.extractURLsFromJSON(obj, baseURL, urls)
		}
	}
}

// extractURLsFromJSON recursively extracts URLs from JSON objects
func (a *JSAnalyzer) extractURLsFromJSON(obj interface{}, baseURL *url.URL, urls map[string]struct{}) {
	switch v := obj.(type) {
	case map[string]interface{}:
		for _, val := range v {
			a.extractURLsFromJSON(val, baseURL, urls)
		}
	case []interface{}:
		for _, val := range v {
			a.extractURLsFromJSON(val, baseURL, urls)
		}
	case string:
		if strings.HasPrefix(v, "http") || strings.HasPrefix(v, "/") {
			if u := resolveURL(baseURL, v); u != "" {
				urls[u] = struct{}{}
			}
		}
	}
}

// resolveURL resolves a URL against a base URL
func resolveURL(base *url.URL, ref string) string {
	if base == nil {
		return ""
	}

	// Clean the reference
	ref = strings.TrimSpace(ref)
	ref = strings.Trim(ref, "'\"")

	// Parse the reference
	refURL, err := url.Parse(ref)
	if err != nil {
		return ""
	}

	// Resolve against base
	resolvedURL := base.ResolveReference(refURL)

	// Validate the result
	if resolvedURL.Scheme != "http" && resolvedURL.Scheme != "https" {
		return ""
	}

	return resolvedURL.String()
}

// AnalyzeJSFile analyzes a JavaScript file and extracts URLs
func (a *JSAnalyzer) AnalyzeJSFile(reader io.Reader, baseURL *url.URL) ([]string, error) {
	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	return a.ExtractURLs(string(content), baseURL), nil
}
