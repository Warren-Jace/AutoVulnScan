package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"

	"github.com/rs/zerolog/log"
)

// SQLiPlugin checks for SQL Injection vulnerabilities.
type SQLiPlugin struct {
	httpClient    *requester.HTTPClient
	payloads      []models.Payload
	errorPatterns []string
}

// NewSQLiPlugin creates a new SQLiPlugin.
func NewSQLiPlugin(client *requester.HTTPClient, payloadFile string) (*SQLiPlugin, error) {
	payloads, err := loadSQLiPayloads(payloadFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load SQLi payloads: %w", err)
	}

	return &SQLiPlugin{
		httpClient: client,
		payloads:   payloads,
		errorPatterns: []string{
			"you have an error in your sql syntax",
			"unclosed quotation mark",
			"supplied argument is not a valid mysql result resource",
			"sql server",
			"microsoft ole db provider for odbc drivers error",
			"invalid querystring",
			"odbc driver error",
			"oracle error",
			"db2 sql error",
			"postgresql error",
			"sqlite error",
		},
	}, nil
}

// Type returns the plugin type.
func (p *SQLiPlugin) Type() string {
	return "sqli"
}

// Scan performs the SQLi scan.
func (p *SQLiPlugin) Scan(ctx context.Context, pURL models.ParameterizedURL) ([]Vulnerability, error) {
	var vulnerabilities []Vulnerability

	for _, param := range pURL.Params {
		for _, payload := range p.payloads {
			// Create a new request with the payload
			req, err := p.httpClient.NewRequest("GET", pURL.URL, nil) // Simplified to GET for now
			if err != nil {
				continue
			}

			q := req.URL.Query()
			q.Set(param.Name, payload.Value)
			req.URL.RawQuery = q.Encode()

			// Send the request
			resp, err := p.httpClient.Do(req.WithContext(ctx))
			if err != nil {
				log.Warn().Err(err).Str("url", req.URL.String()).Msg("Failed to send SQLi test request")
				continue
			}
			defer resp.Body.Close()

			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				continue
			}

			// Check for errors in the response body
			for _, pattern := range p.errorPatterns {
				if strings.Contains(strings.ToLower(string(bodyBytes)), pattern) {
					vuln := Vulnerability{
						Type:          p.Type(),
						URL:           pURL.URL,
						Payload:       payload.Value,
						Param:         param.Name,
						Method:        "GET", // Explicitly setting GET
						VulnerableURL: req.URL.String(),
						Timestamp:     time.Now(),
					}
					vulnerabilities = append(vulnerabilities, vuln)
					break // Found a pattern, move to next payload
				}
			}
		}
	}
	return vulnerabilities, nil
}

func loadSQLiPayloads(file string) ([]models.Payload, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var data struct {
		Payloads []models.Payload `json:"payloads"`
	}
	if err := json.NewDecoder(f).Decode(&data); err != nil {
		return nil, err
	}
	return data.Payloads, nil
}
