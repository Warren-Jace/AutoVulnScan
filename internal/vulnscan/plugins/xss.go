package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"

	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"

	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/rs/zerolog/log"
)

// XSSPlugin checks for Cross-Site Scripting vulnerabilities.
type XSSPlugin struct {
	httpClient *requester.HTTPClient
	info       PluginInfo
}

// NewXSSPlugin creates a new XSSPlugin.
func NewXSSPlugin(client *requester.HTTPClient) *XSSPlugin {
	return &XSSPlugin{
		httpClient: client,
		info: PluginInfo{
			Name:        "xss",
			Description: "Checks for Cross-Site Scripting vulnerabilities.",
			Author:      "AutoVulnScan",
			Version:     "0.1.0",
		},
	}
}

// Info returns basic information about the plugin.
func (p *XSSPlugin) Info() PluginInfo {
	return p.info
}

// Scan performs the XSS scan.
func (p *XSSPlugin) Scan(ctx context.Context, req *models.Request, payloads []string) ([]*Vulnerability, error) {
	var vulnerabilities []*Vulnerability

	for _, param := range req.Params {
		for _, payload := range payloads {
			vuln, err := p.testPayload(ctx, req, param.Name, payload)
			if err != nil {
				log.Warn().Err(err).Str("url", req.URL.String()).Msg("XSS test failed")
				continue
			}
			if vuln != nil {
				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}

	return vulnerabilities, nil
}

// testPayload tests a single payload on a specific parameter.
func (p *XSSPlugin) testPayload(ctx context.Context, originalReq *models.Request, paramName, payload string) (*Vulnerability, error) {
	newReq := cloneRequest(originalReq)

	// Inject payload
	if newReq.Request.Method == "POST" {
		bodyBytes, _ := io.ReadAll(newReq.Request.Body)
		newReq.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		form, _ := url.ParseQuery(string(bodyBytes))
		form.Set(paramName, payload)
		newReq.Request.Body = io.NopCloser(strings.NewReader(form.Encode()))
		newReq.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		q := newReq.Request.URL.Query()
		q.Set(paramName, payload)
		newReq.Request.URL.RawQuery = q.Encode()
	}

	// First, check for reflected XSS in the response body
	resp, err := p.httpClient.Do(newReq.Request.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if strings.Contains(string(body), payload) {
		// Potential reflected XSS, verify with DOM analysis
		if p.verifyWithDOM(ctx, newReq) {
			return &Vulnerability{
				Type:          p.info.Name,
				URL:           originalReq.URL.String(),
				Payload:       payload,
				Param:         paramName,
				Method:        originalReq.Method,
				VulnerableURL: newReq.URL.String(),
			}, nil
		}
	}

	return nil, nil
}

// verifyWithDOM uses a headless browser to confirm if a reflected payload is executable.
func (p *XSSPlugin) verifyWithDOM(ctx context.Context, req *models.Request) bool {
	allocCtx, cancel := chromedp.NewExecAllocator(ctx, append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("ignore-certificate-errors", true),
	)...)
	defer cancel()

	taskCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	var alertTriggered bool
	chromedp.ListenTarget(taskCtx, func(ev interface{}) {
		if _, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			alertTriggered = true
		}
	})

	var err error
	if req.Method == "POST" {
		// For POST requests, we need to submit a form in the browser.
		// This requires a page with a form that can be used for submission.
		// For simplicity, we'll navigate to the original URL and then execute a script to post.
		err = p.postWithChrome(taskCtx, req)
	} else {
		// For GET requests, we can just navigate to the URL with the payload.
		err = chromedp.Run(taskCtx, chromedp.Navigate(req.URL.String()))
	}

	if err != nil {
		log.Error().Err(err).Msg("Failed to verify XSS with DOM")
		return false
	}

	return alertTriggered
}

func (p *XSSPlugin) postWithChrome(ctx context.Context, req *models.Request) error {
	// Read body
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return err
	}
	req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // Restore body
	formValues, err := url.ParseQuery(string(bodyBytes))
	if err != nil {
		return err
	}

	// Convert form values to a JSON string for injection
	formJSON, err := json.Marshal(formValues)
	if err != nil {
		return err
	}

	// JavaScript to create and submit a form
	script := fmt.Sprintf(`
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = '%s';
        const fields = %s;
        for (const key in fields) {
            if (fields.hasOwnProperty(key)) {
                const hiddenField = document.createElement('input');
                hiddenField.type = 'hidden';
                hiddenField.name = key;
                hiddenField.value = fields[key][0];
                form.appendChild(hiddenField);
            }
        }
        document.body.appendChild(form);
        form.submit();
    `, req.URL.String(), string(formJSON))

	return chromedp.Run(ctx,
		// Navigate to a blank page to have a DOM context
		chromedp.Navigate("about:blank"),
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, _, err := runtime.Evaluate(script).Do(ctx)
			return err
		}),
	)
}

// isReflected checks if the payload is reflected in the response.
func isReflected(body []byte, payload string) (bool, error) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	// A simple check to see if the payload is anywhere in the HTML
	return strings.Contains(doc.Text(), payload), nil
}
