package plugins

import (
	"autovulnscan/internal/discovery"
	"autovulnscan/internal/requester"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
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

// Scan performs the SQLi scan on a given parameterized URL.
func (p *SQLiPlugin) Scan(ctx context.Context, pURL discovery.ParameterizedURL) ([]Vulnerability, error) {
	vulnerabilities := make([]Vulnerability, 0)

	for _, param := range pURL.Params {
		vulnerableFoundForParam := false
		for _, payload := range p.payloads.Payloads {
			if vulnerableFoundForParam {
				break // Skip to the next parameter
			}

			reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			var req *http.Request
			var err error

			if pURL.Method == "GET" {
				// Build GET request
				targetURL, _ := url.Parse(pURL.URL)
				q := targetURL.Query()
				q.Set(param.Name, payload.Value)
				targetURL.RawQuery = q.Encode()
				req, err = http.NewRequestWithContext(reqCtx, "GET", targetURL.String(), nil)
			} else if pURL.Method == "POST" {
				// Build POST request
				formData := url.Values{}
				formData.Set(param.Name, payload.Value)
				req, err = http.NewRequestWithContext(reqCtx, "POST", pURL.URL, strings.NewReader(formData.Encode()))
				if err == nil {
					req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				}
			}

			if err != nil {
				log.Warn().Err(err).Msg("Failed to build request for SQLi scan")
				continue
			}

			resp, err := p.httpClient.Do(req)
			if err != nil {
				log.Warn().Err(err).Str("url", pURL.URL).Msg("Request failed during SQLi scan")
				continue
			}

			bodyBytes, _ := ioutil.ReadAll(resp.Body)
			resp.Body.Close()

			bodyString := string(bodyBytes)
			for _, pattern := range p.payloads.ErrorPatterns {
				if strings.Contains(strings.ToLower(bodyString), strings.ToLower(pattern)) {
					vuln := Vulnerability{
						Type:      p.Type(),
						URL:       pURL.URL,
						Payload:   payload.Value,
						Timestamp: time.Now(),
					}
					vulnerabilities = append(vulnerabilities, vuln)
					vulnerableFoundForParam = true

					c := color.New(color.FgHiRed, color.Bold)
					c.Printf("[!!!] SQL Injection Vulnerability Found!\n")
					log.Warn().
						Str("type", "SQLi").
						Str("url", pURL.URL).
						Str("param", param.Name).
						Str("payload", payload.Value).
						Msg("Potential SQL Injection vulnerability found!")

					break // Found a pattern, no need to check others for this payload
				}
			}
		}
	}

	return vulnerabilities, nil
}
