// Package vulnscan provides the core vulnerability scanning engine.
package vulnscan

import (
	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"
	"autovulnscan/internal/vulnscan/plugins"
	"context"
	"sync"

	"github.com/rs/zerolog/log"
)

// Engine is the vulnerability scanning engine.
type Engine struct {
	plugins    []plugins.Plugin
	httpClient *requester.HTTPClient
}

// NewEngine creates a new scanning engine.
func NewEngine(client *requester.HTTPClient) (*Engine, error) {
	engine := &Engine{
		httpClient: client,
	}
	engine.registerPlugins()
	return engine, nil
}

// registerPlugins discovers and registers all available plugins.
func (e *Engine) registerPlugins() {
	// In a real-world scenario, you might auto-discover plugins.
	// For now, we'll manually register them.
	sqliPlugin, err := plugins.NewSQLiPlugin(e.httpClient, "config/payloads/sqli.json")
	if err != nil {
		log.Error().Err(err).Msg("Failed to initialize SQLi plugin")
	} else {
		e.plugins = append(e.plugins, sqliPlugin)
		log.Info().Str("plugin", sqliPlugin.Type()).Msg("Plugin registered")
	}

	xssPlugin, err := plugins.NewXSSPlugin(e.httpClient, "config/payloads/xss.json")
	if err != nil {
		log.Error().Err(err).Msg("Failed to initialize XSS plugin")
	} else {
		e.plugins = append(e.plugins, xssPlugin)
		log.Info().Str("plugin", xssPlugin.Type()).Msg("Plugin registered")
	}
}

// StartScan runs the scanning process for a given parameterized URL.
func (e *Engine) StartScan(ctx context.Context, pURL models.ParameterizedURL) []plugins.Vulnerability {
	var vulnerabilities []plugins.Vulnerability
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, plugin := range e.plugins {
		wg.Add(1)
		go func(p plugins.Plugin) {
			defer wg.Done()
			vulns, err := p.Scan(ctx, pURL)
			if err != nil {
				log.Warn().Err(err).Str("plugin", p.Type()).Str("url", pURL.URL).Msg("Plugin scan failed")
				return
			}

			mu.Lock()
			vulnerabilities = append(vulnerabilities, vulns...)
			mu.Unlock()
		}(plugin)
	}

	wg.Wait()
	return vulnerabilities
}
