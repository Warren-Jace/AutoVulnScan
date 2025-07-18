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
func (p *SQLiPlugin) Scan(ctx context.Context, pURL discovery.ParameterizedURL, payloads []string) ([]Vulnerability, error) {
	vulnerabilities := make([]Vulnerability, 0)

	// Determine which payloads to use
	var payloadsToTest []string
	if len(payloads) > 0 {
		payloadsToTest = payloads
	} else {
		for _, p := range p.payloads.Payloads {
			payloadsToTest = append(payloadsToTest, p.Value)
		}
	}

	for _, param := range pURL.Params {
		for _, payload := range payloadsToTest {
			// Create a new context with a timeout for each request.
			reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			var req *http.Request
			var err error

			if pURL.Method == "GET" {
				req, err = p.buildGETRequest(reqCtx, pURL.URL, param, payload)
			} else if pURL.Method == "POST" {
				req, err = p.buildPOSTRequest(reqCtx, pURL.URL, pURL.Params, param, payload)
			}

			if err != nil {
				log.Warn().Err(err).Msg("Failed to build request for SQLi scan")
				continue
			}

			// --- Start of new boolean-based detection logic ---
			// 1. Get original response
			originalReq, err := p.httpClient.CloneRequest(req)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to clone original request for SQLi scan")
				continue
			}
			originalResp, err := p.httpClient.Do(originalReq)
			if err != nil {
				log.Warn().Err(err).Str("url", pURL.URL).Msg("Original request failed during SQLi scan")
				continue
			}
			originalBodyBytes, _ := ioutil.ReadAll(originalResp.Body)
			originalResp.Body.Close()

			// 2. Test with a "true" condition
			truePayload := payload + " AND 1=1--" // Common boolean true
			var trueReq *http.Request
			if pURL.Method == "GET" {
				trueReq, _ = p.buildGETRequest(reqCtx, pURL.URL, param, truePayload)
			} else {
				trueReq, _ = p.buildPOSTRequest(reqCtx, pURL.URL, pURL.Params, param, truePayload)
			}
			trueResp, err := p.httpClient.Do(trueReq)
			if err != nil {
				continue
			}
			trueBodyBytes, _ := ioutil.ReadAll(trueResp.Body)
			trueResp.Body.Close()

			// 3. Test with a "false" condition
			falsePayload := payload + " AND 1=2--" // Common boolean false
			var falseReq *http.Request
			if pURL.Method == "GET" {
				falseReq, _ = p.buildGETRequest(reqCtx, pURL.URL, param, falsePayload)
			} else {
				falseReq, _ = p.buildPOSTRequest(reqCtx, pURL.URL, pURL.Params, param, falsePayload)
			}
			falseResp, err := p.httpClient.Do(falseReq)
			if err != nil {
				continue
			}
			falseBodyBytes, _ := ioutil.ReadAll(falseResp.Body)
			falseResp.Body.Close()

			// 4. Compare lengths (a simple heuristic for content change)
			if len(trueBodyBytes) != len(originalBodyBytes) && len(falseBodyBytes) == len(originalBodyBytes) {
				vuln := Vulnerability{
					Type:       p.Type(),
					URL:        pURL.URL,
					Method:     pURL.Method,
					Parameter:  param,
					Payload:    payload,
					Evidence:   "Boolean-based blind SQLi detected based on content length.",
					Confidence: "Medium", // Content length is a heuristic, so confidence is medium
				}
				vulnerabilities = append(vulnerabilities, vuln)
				log.Warn().Str("type", "SQLi").Str("url", pURL.URL).Str("param", param.Name).Msg("Potential SQL Injection vulnerability found!")
				goto NextParam
			}
			// --- End of new boolean-based detection logic ---

			// Keep the old error-based check as a fallback
			bodyString := string(originalBodyBytes)
			for _, pattern := range p.payloads.ErrorPatterns {
				if strings.Contains(strings.ToLower(bodyString), strings.ToLower(pattern)) {
					vuln := Vulnerability{
						Type:       p.Type(),
						URL:        pURL.URL,
						Method:     pURL.Method,
						Parameter:  param,
						Payload:    payload,
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
	q.Set(paramToTest.Name, payload) // Inject the payload
	parsedURL.RawQuery = q.Encode()

	return http.NewRequestWithContext(ctx, "GET", parsedURL.String(), nil)
}

func (p *SQLiPlugin) buildPOSTRequest(ctx context.Context, baseURL string, allParams []discovery.Parameter, paramToTest discovery.Parameter, payload string) (*http.Request, error) {
	formData := url.Values{}
	// Set the payload for the parameter being tested
	formData.Set(paramToTest.Name, payload)

	// Add all other parameters with their original values
	for _, p := range allParams {
		if p.Name != paramToTest.Name {
			formData.Set(p.Name, p.Value)
		}
	}

	req, err := http.NewRequestWithContext(ctx, "POST", baseURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
} 