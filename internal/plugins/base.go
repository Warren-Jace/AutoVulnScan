package plugins

import (
	"autovulnscan/internal/discovery"
	"context"
)

// Vulnerability represents a single security finding.
type Vulnerability struct {
	Type        string                 `json:"type"`        // e.g., "SQLi", "XSS"
	URL         string                 `json:"url"`         // The URL where the vulnerability was found
	Method      string                 `json:"method"`      // The HTTP method used ("GET", "POST")
	Parameter   discovery.Parameter    `json:"parameter"`   // The parameter that was found to be vulnerable
	Payload     string                 `json:"payload"`     // The payload that triggered the vulnerability
	Evidence    string                 `json:"evidence"`    // Evidence of the vulnerability (e.g., error message, reflection)
	Confidence  string                 `json:"confidence"`  // e.g., "High", "Medium", "Low"
}

// Plugin is the interface that all vulnerability scanning plugins must implement.
type Plugin interface {
	// Scan takes a parameterized URL and checks it for a specific type of vulnerability.
	// It returns a slice of vulnerabilities found.
	Scan(ctx context.Context, pURL discovery.ParameterizedURL) ([]Vulnerability, error)

	// Type returns the type of the plugin (e.g., "sqli", "xss").
	// This will be used for matching against the configuration.
	Type() string
} 