// Package utils provides various utility functions used across the application.
package utils

import (
	"html"
	"net/url"
	"strings"
)

// ResolveURL resolves a relative URL against a base URL.
func ResolveURL(base *url.URL, href string) *url.URL {
	if strings.HasPrefix(href, "#") {
		return nil
	}
	resolved, err := base.Parse(href)
	if err != nil {
		return nil
	}
	return resolved
}

// IsSameHost checks if two URLs belong to the same host.
func IsSameHost(base, target *url.URL) bool {
	return base.Host == target.Host
}

// SanitizeURL removes the fragment from a URL.
func SanitizeURL(u *url.URL) *url.URL {
	u.Fragment = ""
	return u
}

// NormalizeURL decodes HTML entities and cleans up a URL.
func NormalizeURL(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}
	u.Path = html.UnescapeString(u.Path)
	u.RawQuery = html.UnescapeString(u.RawQuery)
	return u
}

// RandomString generates a random string of a given length.
func RandomString(length int) string {
	// This is a placeholder. A real implementation should use crypto/rand.
	return "random"
}
