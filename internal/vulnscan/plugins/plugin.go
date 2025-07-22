// Package plugins defines the interface for vulnerability scanning plugins.
package plugins

import (
	"context"
	"time"

	"autovulnscan/internal/models"
)

// Vulnerability represents a security vulnerability found by a plugin.
type Vulnerability struct {
	Type          string    `json:"type"`
	URL           string    `json:"url"`
	Payload       string    `json:"payload"`
	Param         string    `json:"param"`
	Method        string    `json:"method"`
	VulnerableURL string    `json:"vulnerable_url"`
	Timestamp     time.Time `json:"timestamp"`
}

// Plugin is the interface that all vulnerability scanning plugins must implement.
type Plugin interface {
	// Type returns the type of the plugin (e.g., "xss", "sqli").
	Type() string
	// Scan performs the vulnerability scan on a given parameterized URL.
	Scan(ctx context.Context, pURL models.ParameterizedURL) ([]Vulnerability, error)
}
