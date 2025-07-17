package util

import (
	"net/url"
	"strings"

	"github.com/rs/zerolog/log"
)

// ResolveURL resolves a potentially relative URL against a base URL.
func ResolveURL(base *url.URL, href string) *url.URL {
	// Trim leading/trailing whitespace and control characters from the href
	href = strings.TrimSpace(href)

	// Ignore empty, javascript, mailto, or anchor links
	if href == "" || strings.HasPrefix(href, "javascript:") || strings.HasPrefix(href, "mailto:") || strings.HasPrefix(href, "#") {
		return nil
	}

	// Parse the href
	rel, err := url.Parse(href)
	if err != nil {
		log.Debug().Str("href", href).Err(err).Msg("Failed to parse href")
		return nil
	}

	// Resolve the reference
	resolvedURL := base.ResolveReference(rel)
	return resolvedURL
}

// IsSameHost checks if a given URL is on the same host as the base URL.
// It also allows subdomains of the base host.
func IsSameHost(base *url.URL, target *url.URL) bool {
	if target == nil {
		return false
	}
	baseHost := base.Hostname()
	targetHost := target.Hostname()

	// Direct match or subdomain match
	return targetHost == baseHost || strings.HasSuffix(targetHost, "."+baseHost)
}

// SanitizeURL removes fragments and standardizes the URL.
func SanitizeURL(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}
	// Create a copy to modify
	sanitized := *u
	sanitized.Fragment = "" // Remove fragment
	return &sanitized
}

// NormalizeURL takes a string, sanitizes it, and returns the canonical string representation.
func NormalizeURL(base *url.URL, href string) string {
	resolved := ResolveURL(base, href)
	if resolved == nil {
		return ""
	}
	sanitized := SanitizeURL(resolved)
	if sanitized == nil {
		return ""
	}
	return sanitized.String()
} 