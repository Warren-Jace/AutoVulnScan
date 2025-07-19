// Package plugins defines the interface for vulnerability scanning plugins.
package plugins

import (
	"context"
	"time"

	"autovulnscan/internal/discovery"
)

// Plugin is the interface that all vulnerability scanning plugins must implement.
type Plugin interface {
	Scan(ctx context.Context, pURL discovery.ParameterizedURL) ([]Vulnerability, error)
	Type() string
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

// Vulnerability represents a single discovered vulnerability.
type Vulnerability struct {
	Name                 string    `json:"name"`
	Type                 string    `json:"type"`
	URL                  string    `json:"url"`
	Payload              string    `json:"payload"`
	Method               string    `json:"method"`
	Parameter            string    `json:"parameter"`
	VulnerabilityAddress string    `json:"vulnerability_address"`
	Reproduction         string    `json:"reproduction"`
	Timestamp            time.Time `json:"timestamp"`
}
