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

	"github.com/rs/zerolog/log"
)

// SQLiPayloads holds the data loaded from the sqli.json file.
type SQLiPayloads struct {
	Name          string   `json:"name"`
	Payloads      []Payload `json:"payloads"`
	ErrorPatterns []string `json:"error_patterns"`
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

// Scan performs the SQL injection scan on a given parameterized URL.
func (p *SQLiPlugin) Scan(ctx context.Context, pURL discovery.ParameterizedURL) ([]Vulnerability, error) {
	vulnerabilities := make([]Vulnerability, 0)

	for _, param := range pURL.Params {
		for _, payload := range p.payloads.Payloads {
			// Create a new context with a timeout for each request.
			reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			var req *http.Request
			var err error

			if pURL.Method == "GET" {
				req, err = p.buildGETRequest(reqCtx, pURL.URL, param, payload.Value)
			} else if pURL.Method == "POST" {
				req, err = p.buildPOSTRequest(reqCtx, pURL.URL, param, payload.Value)
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
			resp.Body.Close() // Close body after reading

			bodyString := string(bodyBytes)
			for _, pattern := range p.payloads.ErrorPatterns {
				if strings.Contains(strings.ToLower(bodyString), strings.ToLower(pattern)) {
					vuln := Vulnerability{
						Type:       p.Type(),
						URL:        pURL.URL,
						Method:     pURL.Method,
						Parameter:  param,
						Payload:    payload.Value,
						Evidence:   pattern,
						Confidence: "High",
					}
					vulnerabilities = append(vulnerabilities, vuln)
					log.Warn().Str("type", "SQLi").Str("url", pURL.URL).Str("param", param.Name).Msg("Potential SQL Injection vulnerability found!")
					// Move to the next parameter after finding a vulnerability
					goto NextParam
				}
			}
		}
	NextParam:
	}

	return vulnerabilities, nil
}

func (p *SQLiPlugin) buildGETRequest(ctx context.Context, baseURL string, paramToTest discovery.Parameter, payload string) (*http.Request, error) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	
	q := parsedURL.Query()
	q.Set(paramToTest.Name, payload)
	parsedURL.RawQuery = q.Encode()
	
	return http.NewRequestWithContext(ctx, "GET", parsedURL.String(), nil)
}

func (p *SQLiPlugin) buildPOSTRequest(ctx context.Context, baseURL string, paramToTest discovery.Parameter, payload string) (*http.Request, error) {
	formData := url.Values{}
	formData.Set(paramToTest.Name, payload)
	
	req, err := http.NewRequestWithContext(ctx, "POST", baseURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
} 