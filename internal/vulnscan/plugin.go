// Package vulnscan provides the core vulnerability scanning engine and plugin interfaces.
package vulnscan

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"autovulnscan/internal/models"
)

// Plugin is the interface that all vulnerability scanning plugins must implement.
type Plugin interface {
	// Type returns the type of the plugin (e.g., "sqli", "xss").
	Type() string
	// Scan performs the vulnerability scan on the given parameterized URL.
	Scan(ctx context.Context, pURL models.ParameterizedURL, aiPayloads []string) ([]Vulnerability, error)
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

func loadPayloads(file string) ([]models.Payload, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var data json.RawMessage
	if err := json.NewDecoder(f).Decode(&data); err != nil {
		return nil, err
	}

	var payloadStruct struct {
		Payloads []models.Payload `json:"payloads"`
	}
	if err := json.Unmarshal(data, &payloadStruct); err == nil && payloadStruct.Payloads != nil {
		return payloadStruct.Payloads, nil
	}

	var payloads []models.Payload
	if err := json.Unmarshal(data, &payloads); err != nil {
		return nil, err
	}
	return payloads, nil
} 