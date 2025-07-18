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
		vulnerableFoundForParam := false
		for _, payload := range p.payloads.Payloads {
			if vulnerableFoundForParam {
				break // Skip to the next parameter if a vulnerability has been found for this one
			}

			uniqueMarker := strings.Replace(payload.Value, "'AutoVulnScanXSS'", "'AVS-XSS-TEST'", 1)

			reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			var req *http.Request
			var err error

			targetURL, err := url.Parse(pURL.URL)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to parse URL for XSS scan")
				continue
			}

			if pURL.Method == "GET" {
				q := targetURL.Query()
				q.Set(param.Name, uniqueMarker)
				targetURL.RawQuery = q.Encode()
				req, err = http.NewRequestWithContext(reqCtx, "GET", targetURL.String(), nil)
			} else if pURL.Method == "POST" {
				formData := url.Values{}
				formData.Set(param.Name, uniqueMarker)
				req, err = http.NewRequestWithContext(reqCtx, "POST", pURL.URL, strings.NewReader(formData.Encode()))
				if err == nil {
					req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				}
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
					Type:      p.Type(),
					URL:       pURL.URL,
					Payload:   payload.Value,
					Timestamp: time.Now(),
				}
				vulnerabilities = append(vulnerabilities, vuln)
				vulnerableFoundForParam = true // Mark as found and continue to the next payload for this param

				c := color.New(color.FgRed, color.Bold)
				c.Printf("[!!] XSS Vulnerability Found!\n")
				log.Warn().
					Str("type", "XSS").
					Str("url", pURL.URL).
					Str("param", param.Name).
					Str("payload", payload.Value).
					Msg("Potential XSS vulnerability found!")
			}
		}
	}

	return vulnerabilities, nil
}
