package vulnscan

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"

	"github.com/rs/zerolog/log"
)

// SQLiPlugin is the plugin for detecting SQL injection vulnerabilities.
type SQLiPlugin struct {
	httpClient *requester.HTTPClient
	payloads   []models.Payload
	errorPatterns []string
}

// NewSQLiPlugin creates a new SQLiPlugin instance.
func NewSQLiPlugin(client *requester.HTTPClient, payloadFile string) (*SQLiPlugin, error) {
	payloads, err := loadPayloads(payloadFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load SQLi payloads: %w", err)
	}
	// In a real implementation, error patterns would also come from the config.
	errorPatterns := []string{"you have an error in your sql syntax", "warning: mysql"}
	return &SQLiPlugin{httpClient: client, payloads: payloads, errorPatterns: errorPatterns}, nil
}

// Type returns the plugin type.
func (p *SQLiPlugin) Type() string {
	return "sqli"
}

// Scan performs the SQL injection scan on a given parameterized URL.
func (p *SQLiPlugin) Scan(ctx context.Context, pURL models.ParameterizedURL, aiPayloads []string) ([]Vulnerability, error) {
	var vulnerabilities []Vulnerability
	allPayloads := p.payloads
	if len(aiPayloads) > 0 {
		for _, pl := range aiPayloads {
			allPayloads = append(allPayloads, models.Payload{Value: pl})
		}
	}

	for _, param := range pURL.Params {
		originalReq, err := p.httpClient.BuildRequest(pURL, param.Name, "")
		if err != nil {
			continue
		}
		originalResp, err := p.httpClient.Do(originalReq.Request)
		if err != nil {
			continue
		}
		originalBody, _ := requester.ReadBody(originalResp)

		for _, payload := range allPayloads {
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
				log.Info().Str("type", "SQLi").Str("url", pURL.URL).Str("param", param.Name).Msg("Vulnerability Found!")
				goto NextParam
			}
		}
	NextParam:
	}
	return vulnerabilities, nil
}

// isVulnerable checks if the response indicates a SQL injection vulnerability.
func (p *SQLiPlugin) isVulnerable(resp *http.Response, originalBody string) bool {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	bodyStr := string(body)

	for _, pattern := range p.errorPatterns {
		if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(pattern)) {
			return true
		}
	}

	// Add more checks here, like boolean-based and time-based.
	return false
} 