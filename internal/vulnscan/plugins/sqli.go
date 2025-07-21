package plugins

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"autovulnscan/internal/models"
	"autovulnscan/internal/vulnscan"
	"github.com/rs/zerolog/log"
)

func init() {
	vulnscan.RegisterPlugin(&SQLiPlugin{})
}

// SQLiPlugin is a plugin for detecting SQL Injection vulnerabilities.
type SQLiPlugin struct{}

// Info returns basic information about the SQLi plugin.
func (p *SQLiPlugin) Info() vulnscan.PluginInfo {
	return vulnscan.PluginInfo{
		Name:        "sqli",
		Description: "SQL Injection (SQLi) Plugin",
		Author:      "w8ay",
		Version:     "1.1", // Updated version
	}
}

var sqlErrorPatterns = []string{
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
}

// Scan performs the SQLi scan.
func (p *SQLiPlugin) Scan(ctx context.Context, req *models.Request, payloads []string) ([]*vulnscan.Vulnerability, error) {
	log.Debug().Str("plugin", "sqli").Str("url", req.URL.String()).Msg("Starting scan")
	var vulnerabilities []*vulnscan.Vulnerability

	for _, param := range req.Params {
		for _, payload := range payloads {
			testReq, err := p.createTestRequest(req, param.Name, payload)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to create test request")
				continue
			}

			// Send the request
			resp, err := http.DefaultClient.Do(testReq.Request)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to send test request")
				continue
			}
			defer resp.Body.Close()

			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to read response body")
				continue
			}

			// Check for errors in the response body
			for _, pattern := range sqlErrorPatterns {
				if strings.Contains(strings.ToLower(string(bodyBytes)), pattern) {
					log.Info().Str("plugin", "sqli").Str("url", req.URL.String()).Str("payload", payload).Msg("Vulnerability found!")
					vuln := &vulnscan.Vulnerability{
						Type:          p.Info().Name,
						URL:           req.URL.String(),
						Method:        req.Method,
						Param:         param.Name,
						Payload:       payload,
						Timestamp:     time.Now(),
						VulnerableURL: testReq.URL.String(),
					}
					vulnerabilities = append(vulnerabilities, vuln)
					break // Move to the next payload
				}
			}
		}
	}

	log.Debug().Str("plugin", "sqli").Str("url", req.URL.String()).Int("count", len(vulnerabilities)).Msg("Scan finished")
	return vulnerabilities, nil
}

func (p *SQLiPlugin) createTestRequest(originalReq *models.Request, paramName, payload string) (*models.Request, error) {
	newReq := &models.Request{
		Request: originalReq.Request.Clone(context.Background()),
		Params:  make([]models.Parameter, len(originalReq.Params)),
	}
	copy(newReq.Params, originalReq.Params)

	q := newReq.Request.URL.Query()
	for i, p := range newReq.Params {
		if p.Name == paramName {
			newReq.Params[i].Value = payload
			q.Set(p.Name, payload)
		}
	}
	newReq.Request.URL.RawQuery = q.Encode()

	// Handle POST requests
	if newReq.Request.Method == "POST" {
		form := url.Values{}
		for _, p := range newReq.Params {
			form.Add(p.Name, p.Value)
		}
		newReq.Request.Body = io.NopCloser(bytes.NewBufferString(form.Encode()))
		newReq.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	return newReq, nil
} 