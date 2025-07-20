// Package plugins defines the interface for vulnerability scanning plugins.
package plugins

import (
	"autovulnscan/internal/models"
	"context"
	"time"
)

// Plugin is the interface that all vulnerability scanning plugins must implement.
type Plugin interface {
	// Type returns the type of the plugin (e.g., "sqli", "xss").
	Type() string
	// Scan performs the vulnerability scan on a given request.
	// It returns a slice of vulnerabilities found, or an error if the scan fails.
	Scan(ctx context.Context, pURL models.ParameterizedURL) ([]Vulnerability, error)
}

// BasePlugin provides a basic implementation of the Plugin interface.
type BasePlugin struct {
	name        string
	description string
}

// Type returns the name of the plugin.
func (p *BasePlugin) Type() string {
	return p.name
}

// Vulnerability represents a detected security vulnerability.
type Vulnerability struct {
	Type          string    `json:"type"`
	URL           string    `json:"url"`
	Param         string    `json:"param"`
	Payload       string    `json:"payload"`
	Method        string    `json:"method"`
	VulnerableURL string    `json:"vulnerable_url"`
	Timestamp     time.Time `json:"timestamp"`
}
