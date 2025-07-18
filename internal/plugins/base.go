package plugins

import (
	"autovulnscan/internal/discovery"
	"context"
	"time"
)

// Vulnerability represents a security issue found by a plugin.
type Vulnerability struct {
	Type      string    `json:"type"`
	URL       string    `json:"url"`
	Payload   string    `json:"payload"`
	Timestamp time.Time `json:"timestamp"`
}

// Plugin defines the interface for all vulnerability scanning plugins.
type Plugin interface {
	// Scan takes a parameterized URL and checks it for a specific type of vulnerability.
	// It returns a slice of vulnerabilities found.
	Scan(ctx context.Context, pURL discovery.ParameterizedURL) ([]Vulnerability, error)

	// Type returns the type of the plugin (e.g., "sqli", "xss").
	// This will be used for matching against the configuration.
	Type() string
}
