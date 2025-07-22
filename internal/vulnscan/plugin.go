// Package vulnscan provides the core vulnerability scanning engine and plugin interfaces.
package vulnscan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"autovulnscan/internal/models"
)

// Plugin is the interface for all vulnerability scanning plugins.
type Plugin interface {
	// Info returns basic information about the plugin.
	Info() PluginInfo
	// Scan performs the vulnerability scan.
	Scan(ctx context.Context, req *models.Request, payloads []string) ([]*Vulnerability, error)
}

// PluginInfo contains metadata about a plugin.
type PluginInfo struct {
	Name        string
	Description string
	Author      string
	Version     string
}

// Vulnerability represents a single found vulnerability.
type Vulnerability struct {
	Type          string    `json:"type"`
	URL           string    `json:"url"`
	Method        string    `json:"method"`
	Param         string    `json:"param"`
	Payload       string    `json:"payload"`
	VulnerableURL string    `json:"vulnerable_url"`
	Timestamp     time.Time `json:"timestamp"`
}

type Payload struct {
	Value       string `json:"value"`
	Description string `json:"description"`
}

// LoadPayloads loads vulnerability payloads from a JSON file.
func LoadPayloads(pluginName string) ([]string, error) {
	payloadFile := filepath.Join("config", "payloads", fmt.Sprintf("%s.json", pluginName))
	data, err := os.ReadFile(payloadFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read payload file %s: %w", payloadFile, err)
	}

	var payloadFileContent struct {
		Payloads []Payload `json:"payloads"`
	}
	if err := json.Unmarshal(data, &payloadFileContent); err != nil {
		// Fallback for simple string array format for backward compatibility
		var payloads []string
		if err2 := json.Unmarshal(data, &payloads); err2 == nil {
			return payloads, nil
		}
		return nil, fmt.Errorf("failed to unmarshal payloads from %s: %w", payloadFile, err)
	}

	var payloads []string
	for _, p := range payloadFileContent.Payloads {
		payloads = append(payloads, p.Value)
	}

	return payloads, nil
} 