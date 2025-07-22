// Package vulnscan provides the core vulnerability scanning engine.
package vulnscan

import (
	"autovulnscan/internal/requester"
)

// Engine is the vulnerability scanning engine.
type Engine struct {
	plugins    []Plugin
	httpClient *requester.HTTPClient
}

// NewEngine creates a new scanning engine.
func NewEngine(client *requester.HTTPClient) (*Engine, error) {
	engine := &Engine{
		httpClient: client,
		plugins:    GetPlugins(),
	}
	return engine, nil
}
