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

// XSSPayloads holds the data loaded from the xss.json file.
type XSSPayloads struct {
	Name     string    `json:"name"`
	Payloads []Payload `json:"payloads"`
}

// XSSPlugin is the plugin for detecting Cross-Site Scripting vulnerabilities.
type XSSPlugin struct {
	httpClient *requester.HTTPClient
	payloads   *XSSPayloads
}

// NewXSSPlugin creates a new XSSPlugin instance.
func NewXSSPlugin(client *requester.HTTPClient, payloadFile string) (*XSSPlugin, error) {
	jsonFile, err := os.Open(payloadFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open xss payload file: %w", err)
	}
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)
	var payloads XSSPayloads
	if err := json.Unmarshal(byteValue, &payloads); err != nil {
		return nil, fmt.Errorf("failed to unmarshal xss payloads: %w", err)
	}

	return &XSSPlugin{
		httpClient: client,
		payloads:   &payloads,
	}, nil
}

// Type returns the plugin type.
func (p *XSSPlugin) Type() string {
	return "xss"
}

// Scan performs the XSS scan on a given parameterized URL.
func (p *XSSPlugin) Scan(ctx context.Context, pURL discovery.ParameterizedURL) ([]Vulnerability, error) {
	vulnerabilities := make([]Vulnerability, 0)

	for _, param := range pURL.Params {
		// Use a unique string for each parameter-payload pair to avoid false positives
		// where one injection reflects in a place intended for another.
		for _, payload := range p.payloads.Payloads {
			// A simple unique marker for this specific test
			uniqueMarker := strings.Replace(payload.Value, "'AutoVulnScanXSS'", "'AVS-XSS-TEST'", 1)
			
			reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			var req *http.Request
			var err error

			if pURL.Method == "GET" {
				req, err = p.buildGETRequest(reqCtx, pURL.URL, param, uniqueMarker)
			} else if pURL.Method == "POST" {
				req, err = p.buildPOSTRequest(reqCtx, pURL.URL, param, uniqueMarker)
			}

			if err != nil {
				log.Warn().Err(err).Msg("Failed to build request for XSS scan")
				continue
			}

			resp, err := p.httpClient.Do(req)
			if err != nil {
				log.Warn().Err(err).Str("url", pURL.URL).Msg("Request failed during XSS scan")
				continue
			}

			bodyBytes, _ := ioutil.ReadAll(resp.Body)
			resp.Body.Close()

			bodyString := string(bodyBytes)
			if strings.Contains(bodyString, uniqueMarker) {
				vuln := Vulnerability{
					Type:       p.Type(),
					URL:        pURL.URL,
					Method:     pURL.Method,
					Parameter:  param,
					Payload:    payload.Value, // Report the original payload for clarity
					Evidence:   fmt.Sprintf("Payload reflected in response: %s", uniqueMarker),
					Confidence: "High",
				}
				vulnerabilities = append(vulnerabilities, vuln)
				log.Warn().Str("type", "XSS").Str("url", pURL.URL).Str("param", param.Name).Msg("Potential XSS vulnerability found!")
				goto NextParam
			}
		}
	NextParam:
	}

	return vulnerabilities, nil
}

func (p *XSSPlugin) buildGETRequest(ctx context.Context, baseURL string, paramToTest discovery.Parameter, payload string) (*http.Request, error) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	q := parsedURL.Query()
	q.Set(paramToTest.Name, payload)
	parsedURL.RawQuery = q.Encode()
	return http.NewRequestWithContext(ctx, "GET", parsedURL.String(), nil)
}

func (p *XSSPlugin) buildPOSTRequest(ctx context.Context, baseURL string, paramToTest discovery.Parameter, payload string) (*http.Request, error) {
	formData := url.Values{}
	formData.Set(paramToTest.Name, payload)
	req, err := http.NewRequestWithContext(ctx, "POST", baseURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
} 