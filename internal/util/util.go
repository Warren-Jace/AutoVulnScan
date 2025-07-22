// Package util provides utility functions for the AutoVulnScan application.
package util

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"autovulnscan/internal/models"

	"github.com/chromedp/chromedp"
)

// GetAllocContext creates a new chromedp execution allocator context with the specified options.
func GetAllocContext(headless bool, proxy, userAgent string) (context.Context, context.CancelFunc) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", headless),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.UserAgent(userAgent),
	)
	if proxy != "" {
		opts = append(opts, chromedp.ProxyServer(proxy))
	}
	return chromedp.NewExecAllocator(context.Background(), opts...)
}

// IsInScope checks if a given URL is within the scope defined by the configuration.
func IsInScope(u *url.URL, scopeDomains []string, blacklistPatterns []string) bool {
	hostname := u.Hostname()

	// Check against blacklist patterns
	for _, pattern := range blacklistPatterns {
		if matched, _ := regexp.MatchString(pattern, u.String()); matched {
			return false
		}
	}

	// Check against scope domains
	for _, domain := range scopeDomains {
		if strings.HasSuffix(hostname, domain) {
			return true
		}
	}

	return false
}

// ExtractParameters finds all potential parameters in a given string content.
// This is a simplified implementation and can be greatly improved.
func ExtractParameters(content string) []models.Parameter {
	// A simple regex to find patterns like name="param_name" or name='param_name'
	// This does not cover all cases and is not context-aware.
	re := regexp.MustCompile(`(?i)(name|id|for)=["']([^"']+)["']`)
	matches := re.FindAllStringSubmatch(content, -1)

	params := make([]models.Parameter, 0)
	seen := make(map[string]struct{})

	for _, match := range matches {
		if len(match) > 2 {
			paramName := match[2]
			if _, ok := seen[paramName]; !ok {
				params = append(params, models.Parameter{Name: paramName})
				seen[paramName] = struct{}{}
			}
		}
	}
	return params
}
