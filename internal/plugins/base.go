// Package plugins defines the interface for all vulnerability scanning plugins
// and the data structures they use.
package plugins

import (
	"autovulnscan/internal/discovery"
	"context"
	"time"
)

// Vulnerability represents a single, confirmed security vulnerability.
// It contains all the necessary information for reporting and analysis.
type Vulnerability struct {
	Type                 string    `json:"type"`
	URL                  string    `json:"url"`
	Payload              string    `json:"payload"`
	Timestamp            time.Time `json:"timestamp"`
	Method               string    `json:"method"`
	Parameter            string    `json:"parameter"`
	VulnerabilityAddress string    `json:"vulnerability_address"` // A reproducible request string
}

// Plugin defines the interface for all vulnerability scanning plugins.
// Each plugin is responsible for scanning for a specific type of vulnerability.
type Plugin interface {
	// Type returns the plugin's name (e.g., "sqli", "xss").
	Type() string

	// Scan takes a parameterized URL and checks it for a specific type of vulnerability.
	// It returns a slice of vulnerabilities found.
	Scan(ctx context.Context, pURL discovery.ParameterizedURL) ([]Vulnerability, error)
}
