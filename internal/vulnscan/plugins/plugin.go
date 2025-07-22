// Package plugins defines the interface for vulnerability scanning plugins.
package plugins

import (
	"context"
	"time"

	"autovulnscan/internal/models"
)

type PluginInfo struct {
	Name        string
	Description string
	Author      string
	Version     string
}

func cloneRequest(r *models.Request) *models.Request {
	// a deep copy of the request
	r2 := new(models.Request)
	*r2 = *r
	r2.Request = r.Request.Clone(context.Background())
	r2.Params = make([]models.Parameter, len(r.Params))
	copy(r2.Params, r.Params)

	return r2
}

// Vulnerability represents a single found vulnerability.
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
