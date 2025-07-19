package plugins

import (
	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/rs/zerolog/log"
)

// SQLiPayloads holds the data loaded from the sqli.json file.
type SQLiPayloads struct {
	Name          string    `json:"name"`
	Payloads      []Payload `json:"payloads"`
	ErrorPatterns []string  `json:"error_patterns"`
}

// Payload represents a single attack string.
type Payload struct {
	Value       string `json:"value"`
	Description string `json:"description"`
}

// SQLiPlugin is the plugin for detecting SQL injection vulnerabilities.
type SQLiPlugin struct {
	httpClient *requester.HTTPClient
	payloads   *SQLiPayloads
}

// NewSQLiPlugin creates a new SQLiPlugin instance.
func NewSQLiPlugin(client *requester.HTTPClient, payloadFile string) (*SQLiPlugin, error) {
	jsonFile, err := os.Open(payloadFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqli payload file: %w", err)
	}
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)
	var payloads SQLiPayloads
	if err := json.Unmarshal(byteValue, &payloads); err != nil {
		return nil, fmt.Errorf("failed to unmarshal sqli payloads: %w", err)
	}

	return &SQLiPlugin{
		httpClient: client,
		payloads:   &payloads,
	}, nil
}

// Type returns the plugin type.
func (p *SQLiPlugin) Type() string {
	return "sqli"
}

// Scan performs the SQL Injection scan on a given parameterized URL.
func (p *SQLiPlugin) Scan(ctx context.Context, pURL models.ParameterizedURL) ([]Vulnerability, error) {
	var vulnerabilities []Vulnerability

	for _, param := range pURL.Params {
		// Fetch the original response once per parameter to use as a baseline.
		originalReq, err := p.httpClient.BuildRequest(pURL, param.Name, "") // Empty payload for baseline
		if err != nil {
			log.Warn().Err(err).Msg("Failed to build original request for baseline comparison")
			continue
		}
		originalResp, err := p.httpClient.Do(originalReq.Request)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to fetch original response for baseline comparison")
			continue
		}
		originalBody, _ := requester.ReadBody(originalResp)

	paramPayloadLoop:
		for _, payload := range p.payloads.Payloads {
			req, err := p.httpClient.BuildRequest(pURL, param.Name, payload.Value)
			if err != nil {
				continue
			}

			resp, err := p.httpClient.Do(req.Request)
			if err != nil {
				continue
			}

			if p.isVulnerable(resp, originalBody) {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					Type:          p.Type(),
					URL:           pURL.URL,
					Param:         param.Name,
					Payload:       payload.Value,
					Method:        pURL.Method,
					VulnerableURL: req.URL.String(),
					Timestamp:     time.Now(),
				})
				log.Info().Str("type", "SQLi").Str("url", pURL.URL).Str("param", param.Name).Msg(color.RedString("Vulnerability Found!"))
				break paramPayloadLoop // Found vulnerability for this param, move to the next.
			}
		}
	}
	return vulnerabilities, nil
}

// isVulnerable checks if the response indicates a SQL injection vulnerability.
func (p *SQLiPlugin) isVulnerable(resp *http.Response, originalBody string) bool {
	body, err := requester.ReadBody(resp)
	if err != nil {
		return false
	}

	// 1. Check for common SQL error patterns
	for _, pattern := range p.payloads.ErrorPatterns {
		if strings.Contains(strings.ToLower(body), strings.ToLower(pattern)) {
			return true
		}
	}

	// 2. Compare response body lengths (simple but effective)
	if len(body) != len(originalBody) {
		// This is a weak signal, but can be effective for boolean-based blind SQLi
		// A more advanced check would be to use a similarity algorithm.
		bodySimilarity := p.calculateBodySimilarity(originalBody, body)
		if bodySimilarity < 0.95 { // Threshold for significant difference
			return true
		}
	}

	// 3. Check for time-based blind SQLi by measuring response time
	// Note: This requires payloads designed for time-based attacks.
	// For now, we'll assume the client timeout handles this implicitly,
	// but a more explicit check could be added here.

	return false
}

// calculateBodySimilarity calculates the similarity between two response bodies.
// This is a placeholder for a more advanced similarity algorithm like Levenshtein distance.
func (p *SQLiPlugin) calculateBodySimilarity(s1, s2 string) float64 {
	if len(s1) == 0 && len(s2) == 0 {
		return 1.0
	}
	if len(s1) == 0 || len(s2) == 0 {
		return 0.0
	}

	// Simple length-based similarity for now.
	// A more sophisticated algorithm could be used here.
	return 1.0 - (float64(abs(len(s1)-len(s2))) / float64(max(len(s1), len(s2))))
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
