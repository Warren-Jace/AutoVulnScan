// Package utils provides utility functions used across the AutoVulnScan application.
package utils

import (
	"math/rand"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

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
	log.Debug().Str("base", base.String()).Str("href", href).Str("resolved", resolvedURL.String()).Msg("URL Resolved")
	return resolvedURL
}

// IsSameHost checks if a given URL is on the same host as the base URL.
// It allows for direct host matches and any subdomains of the base host.
func IsSameHost(base *url.URL, target *url.URL) bool {
	if target == nil {
		return false
	}
	baseHost := base.Hostname()
	targetHost := target.Hostname()

	if targetHost == baseHost {
		return true
	}

	isSame := strings.HasSuffix(targetHost, "."+baseHost)
	log.Debug().Str("base_host", baseHost).Str("target_host", targetHost).Bool("is_same", isSame).Msg("Host comparison")
	return isSame
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

// Common URL patterns for normalization
var (
	// Patterns for common URL parameters that don't affect content
	trackingParamRegex = regexp.MustCompile(`(?i)^(utm_|fbclid|gclid|msclkid|dclid|zanpid|icid|mc_|yclid|_hsenc|_hsmi|ref_|source|mkt_tok|hmb_|cmpid|partnerid|campaign|referral|coupon)`)

	// Pattern for numeric IDs in URLs
	numericIDRegex = regexp.MustCompile(`/\d+(/|$)`)

	// Pattern for UUIDs and other common ID formats
	uuidRegex = regexp.MustCompile(`/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(/|$)`)

	// Pattern for hexadecimal hashes
	hashRegex = regexp.MustCompile(`/[0-9a-f]{32}(/|$)|/[0-9a-f]{40}(/|$)|/[0-9a-f]{64}(/|$)`)
)

// CanonicalizeURL creates a canonical representation of a URL for deduplication.
// It removes tracking parameters, normalizes paths, and standardizes the URL format.
func CanonicalizeURL(u *url.URL) string {
	if u == nil {
		return ""
	}

	// Create a copy to modify
	canonical := *u

	// Remove tracking parameters
	if canonical.RawQuery != "" {
		query := canonical.Query()
		filteredQuery := make(url.Values)

		// Keep only non-tracking parameters
		for key, values := range query {
			if !trackingParamRegex.MatchString(key) {
				filteredQuery[key] = values
			}
		}

		// Sort parameters for consistent ordering
		sortedKeys := make([]string, 0, len(filteredQuery))
		for key := range filteredQuery {
			sortedKeys = append(sortedKeys, key)
		}
		sort.Strings(sortedKeys)

		// Rebuild query string with sorted parameters
		var queryBuilder strings.Builder
		for i, key := range sortedKeys {
			if i > 0 {
				queryBuilder.WriteString("&")
			}
			queryBuilder.WriteString(key)
			queryBuilder.WriteString("=")
			queryBuilder.WriteString(filteredQuery.Get(key))
		}

		canonical.RawQuery = queryBuilder.String()
	}

	// Remove fragment
	canonical.Fragment = ""

	// Ensure path ends with trailing slash for consistency
	if !strings.HasSuffix(canonical.Path, "/") {
		canonical.Path += "/"
	}

	// Normalize common patterns in path
	canonical.Path = numericIDRegex.ReplaceAllString(canonical.Path, "/{id}/")
	canonical.Path = uuidRegex.ReplaceAllString(canonical.Path, "/{uuid}/")
	canonical.Path = hashRegex.ReplaceAllString(canonical.Path, "/{hash}/")

	// Force lowercase for host
	canonical.Host = strings.ToLower(canonical.Host)

	return canonical.String()
}

// GenerateURLSignature creates a signature for a URL that represents its structure
// rather than its exact value. This is useful for identifying structurally similar URLs.
func GenerateURLSignature(u *url.URL) string {
	if u == nil {
		return ""
	}

	// Create a signature based on the URL structure
	var signature strings.Builder

	// Add scheme and host
	signature.WriteString(u.Scheme)
	signature.WriteString("://")
	signature.WriteString(strings.ToLower(u.Host))

	// Process path - replace numeric and UUID segments
	path := u.Path
	path = numericIDRegex.ReplaceAllString(path, "/{id}/")
	path = uuidRegex.ReplaceAllString(path, "/{uuid}/")
	path = hashRegex.ReplaceAllString(path, "/{hash}/")
	signature.WriteString(path)

	// Add a marker for query parameters if they exist
	if len(u.Query()) > 0 {
		signature.WriteString("?{params}")
	}

	return signature.String()
}

// URLSimilarity determines if two URLs are structurally similar
// Returns a similarity score between 0 (completely different) and 1 (identical)
func URLSimilarity(url1, url2 *url.URL) float64 {
	if url1 == nil || url2 == nil {
		return 0
	}

	// Different hosts means completely different URLs
	if url1.Host != url2.Host {
		return 0
	}

	// Generate signatures for both URLs
	sig1 := GenerateURLSignature(url1)
	sig2 := GenerateURLSignature(url2)

	// If signatures match, they're structurally identical
	if sig1 == sig2 {
		return 1
	}

	// Otherwise, compare path structures
	pathParts1 := strings.Split(strings.Trim(url1.Path, "/"), "/")
	pathParts2 := strings.Split(strings.Trim(url2.Path, "/"), "/")

	// Calculate Jaccard similarity of path parts
	intersection := 0
	union := len(pathParts1) + len(pathParts2)

	// Find intersection
	pathMap := make(map[string]bool)
	for _, part := range pathParts1 {
		pathMap[part] = true
	}

	for _, part := range pathParts2 {
		if pathMap[part] {
			intersection++
		}
	}

	union -= intersection // Correct for double-counting in the intersection

	if union == 0 {
		return 0 // Avoid division by zero
	}

	return float64(intersection) / float64(union)
}

// IsInScope checks if a given URL is within the defined scope and not in the blacklist.
func IsInScope(target *url.URL, scope []string, blacklist []string) bool {
	if target == nil {
		return false
	}
	targetHost := target.Hostname()

	// Check blacklist first
	for _, blacklistedDomain := range blacklist {
		if strings.HasSuffix(targetHost, blacklistedDomain) {
			return false
		}
	}

	// Check scope
	for _, allowedDomain := range scope {
		if strings.HasSuffix(targetHost, allowedDomain) {
			return true
		}
	}

	return false
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var src = rand.NewSource(time.Now().UnixNano())

// RandomString generates a random string of a given length. It is a highly
// efficient implementation to avoid performance bottlenecks.
func RandomString(n int) string {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters.
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}
	return string(b)
}
