package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"

	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/rs/zerolog/log"
)

// XSSPlugin checks for Cross-Site Scripting vulnerabilities.
type XSSPlugin struct {
	httpClient *requester.HTTPClient
	payloads   []models.Payload
}

// NewXSSPlugin creates a new XSSPlugin.
func NewXSSPlugin(client *requester.HTTPClient, payloadFile string) (*XSSPlugin, error) {
	payloads, err := loadPayloads(payloadFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load XSS payloads: %w", err)
	}
	return &XSSPlugin{httpClient: client, payloads: payloads}, nil
}

// Type returns the plugin type.
func (p *XSSPlugin) Type() string {
	return "xss"
}

// Scan performs the XSS scan.
func (p *XSSPlugin) Scan(ctx context.Context, pURL models.ParameterizedURL) ([]Vulnerability, error) {
	var vulnerabilities []Vulnerability

	for _, param := range pURL.Params {
		for _, payload := range p.payloads {
			vulnerable, err := p.checkVulnerability(ctx, pURL.URL, param.Name, payload.Value)
			if err != nil {
				log.Warn().Err(err).Str("url", pURL.URL).Str("param", param.Name).Msg("Error checking XSS vulnerability")
				continue
			}

			if vulnerable {
				vuln := Vulnerability{
					Type:          p.Type(),
					URL:           pURL.URL,
					Payload:       payload.Value,
					Param:         param.Name,
					Method:        "GET", // Explicitly setting GET
					VulnerableURL: p.httpClient.BuildURL(pURL.URL, param.Name, payload.Value),
					Timestamp:     time.Now(),
				}
				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}
	return vulnerabilities, nil
}

func (p *XSSPlugin) checkVulnerability(ctx context.Context, baseURL, param, payload string) (bool, error) {
	// Create a new browser context for each check
	allocCtx, cancel := chromedp.NewExecAllocator(ctx, append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("ignore-certificate-errors", true),
	)...)
	defer cancel()

	taskCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	var alertTriggered bool
	chromedp.ListenTarget(taskCtx, func(ev interface{}) {
		if _, ok := ev.(*runtime.EventJavascriptDialogOpening); ok {
			alertTriggered = true
		}
	})

	fullURL := p.httpClient.BuildURL(baseURL, param, payload)
	err := chromedp.Run(taskCtx,
		chromedp.Navigate(fullURL),
		chromedp.Sleep(2*time.Second), // Wait for potential JS execution
	)

	if err != nil {
		return false, err
	}

	return alertTriggered, nil
}

func loadPayloads(file string) ([]models.Payload, error) {
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
