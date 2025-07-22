package plugins

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"autovulnscan/internal/models"
	"autovulnscan/internal/utils"
	"autovulnscan/internal/vulnscan"

	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/rs/zerolog/log"
)

const (
	xssCheckElementID = "autovulnscan-xss-check"
)

func init() {
	vulnscan.RegisterPlugin(&XSSPlugin{})
}

// XSSPlugin is a plugin for detecting Cross-Site Scripting vulnerabilities.
type XSSPlugin struct{}

// Info returns basic information about the XSS plugin.
func (p *XSSPlugin) Info() vulnscan.PluginInfo {
	return vulnscan.PluginInfo{
		Name:        "xss",
		Description: "Cross-Site Scripting (XSS) Plugin",
		Author:      "w8ay",
		Version:     "1.0",
	}
}

// Scan performs the XSS scan.
func (p *XSSPlugin) Scan(ctx context.Context, req *models.Request, payloads []string) ([]*vulnscan.Vulnerability, error) {
	log.Debug().Str("plugin", "xss").Str("url", req.URL.String()).Msg("Starting scan")
	var vulnerabilities []*vulnscan.Vulnerability

	// Create a map of parameter names to a unique random string for this scan
	paramToRandomStr := make(map[string]string)
	for _, param := range req.Params {
		paramToRandomStr[param.Name] = utils.RandomString(10)
	}

	// First, check which parameters are reflected in the DOM
	vulnerableParams := p.checkDOMContext(ctx, req, paramToRandomStr)
	if len(vulnerableParams) == 0 {
		return nil, nil // No reflected parameters, no need to test payloads
	}

	log.Debug().Str("plugin", "xss").Strs("params", vulnerableParams).Msg("Found reflected parameters")

	// Now, test payloads on the reflected parameters
	for _, paramName := range vulnerableParams {
		for _, payload := range payloads {
			// Create a new request with the payload for the specific parameter
			testReq, err := p.createTestRequest(req, paramName, payload)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to create test request")
				continue
			}

			if p.isVulnerable(ctx, testReq) {
				log.Info().Str("plugin", "xss").Str("url", req.URL.String()).Str("param", paramName).Str("payload", payload).Msg("Vulnerability confirmed!")
				vuln := &vulnscan.Vulnerability{
					Type:          p.Info().Name,
					URL:           req.URL.String(),
					Method:        req.Method,
					Param:         paramName,
					Payload:       payload,
					Timestamp:     time.Now(),
					VulnerableURL: testReq.URL.String(), // The URL with the payload
				}
				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}

	log.Debug().Str("plugin", "xss").Str("url", req.URL.String()).Int("count", len(vulnerabilities)).Msg("Scan finished")
	return vulnerabilities, nil
}

func (p *XSSPlugin) isVulnerable(ctx context.Context, req *models.Request) bool {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
	)
	allocCtx, cancel := chromedp.NewExecAllocator(ctx, opts...)
	defer cancel()

	taskCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	var consoleMessages []string
	listenForConsoleMessages(taskCtx, &consoleMessages)

	err := chromedp.Run(taskCtx,
		chromedp.Navigate(req.URL.String()),
		chromedp.Poll("document.readyState === 'complete'", nil),
	)

	if err != nil {
		log.Debug().Err(err).Msg("Failed to execute vulnerability check")
		return false
	}

	for _, msg := range consoleMessages {
		if strings.Contains(msg, "AutoVulnScanXSS") {
			return true
		}
	}

	return false
}

func (p *XSSPlugin) createTestRequest(originalReq *models.Request, paramName, payload string) (*models.Request, error) {
	var newReq *models.Request
	isPost := originalReq.Method == "POST"

	if isPost {
		// Clone the original request to avoid modifying it
		clone, err := http.NewRequest(originalReq.Method, originalReq.URL.String(), nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create new request: %w", err)
		}
		clone.Header = originalReq.Header.Clone()

		form := url.Values{}
		if originalReq.Body != nil {
			bodyBytes, readErr := io.ReadAll(originalReq.Body)
			if readErr != nil {
				return nil, fmt.Errorf("failed to read original request body: %w", readErr)
			}
			// Restore the original body so it can be read again
			originalReq.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

			parsedForm, parseErr := url.ParseQuery(string(bodyBytes))
			if parseErr != nil {
				// If body is not form-urlencoded, treat it as a single parameter
				log.Warn().Msg("Could not parse POST body as form, treating as single value")
			} else {
				for key, values := range parsedForm {
					for _, value := range values {
						form.Add(key, value)
					}
				}
			}
		}

		form.Set(paramName, payload)
		clone.Body = io.NopCloser(strings.NewReader(form.Encode()))
		clone.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		clone.ContentLength = int64(len(form.Encode()))

		newReq = &models.Request{
			Request: clone,
		}
	} else {
		newURL, _ := url.Parse(originalReq.URL.String())
		q := newURL.Query()
		q.Set(paramName, payload)
		newURL.RawQuery = q.Encode()

		cloneReq := originalReq.Request.Clone(context.Background())
		cloneReq.URL = newURL

		newReq = &models.Request{
			Request: cloneReq,
		}
	}

	return newReq, nil
}

// checkDOMContext uses a headless browser to check if a payload is executed in the DOM.
func (p *XSSPlugin) checkDOMContext(ctx context.Context, req *models.Request, paramToIdentifier map[string]string) []string {
	var foundVulnerabilities []string

	// Create a new headless browser instance
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
	)
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()
	taskCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// Capture the original request body if it's a POST request
	if req.Method == "POST" && req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			log.Error().Err(err).Msg("Failed to read original request body")
			return nil
		}
		// Restore the body for subsequent reads
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	for param, identifier := range paramToIdentifier {
		var alertTriggered bool
		listenForAlert(taskCtx, &alertTriggered)

		err := chromedp.Run(taskCtx,
			chromedp.ActionFunc(func(ctx context.Context) error {
				// Navigate to a blank page first to avoid issues with existing contexts
				if err := chromedp.Run(ctx, chromedp.Navigate("about:blank")); err != nil {
					return err
				}

				// If it's a POST request, submit the form
				if req.Method == "POST" {
					formSelector := "form" // A simple fallback
					// This logic can be improved to find the correct form
					return submitFormWithPayload(ctx, req.URL.String(), formSelector, param, identifier)
				}

				// For GET requests, navigate to the URL with the payload
				targetURL, _ := url.Parse(req.URL.String())
				q := targetURL.Query()
				q.Set(param, identifier)
				targetURL.RawQuery = q.Encode()

				log.Debug().Str("url", targetURL.String()).Msg("Testing URL for DOM XSS")
				return chromedp.Run(ctx, chromedp.Navigate(targetURL.String()))
			}),
		)

		if err != nil {
			log.Error().Err(err).Str("param", param).Msg("Error checking for XSS")
			continue
		}

		if alertTriggered {
			foundVulnerabilities = append(foundVulnerabilities, param)
		}
	}

	return foundVulnerabilities
}

// listenForAlert sets up a listener for alert dialogs.
func listenForAlert(ctx context.Context, triggered *bool) {
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		if _, ok := ev.(*runtime.EventExceptionThrown); ok {
			// This is a simple way to detect alerts, but it's not perfect.
			// A more robust solution would be to inspect the exception details.
			*triggered = true
		}
	})
}

// submitFormWithPayload submits a form with a given payload.
func submitFormWithPayload(ctx context.Context, targetURL string, formSelector, paramName, payload string) error {
	return chromedp.Run(ctx,
		chromedp.Navigate(targetURL),
		chromedp.WaitVisible(formSelector, chromedp.ByQuery),
		chromedp.SetValue(fmt.Sprintf("[name=%s]", paramName), payload, chromedp.ByQuery),
		chromedp.Submit(formSelector, chromedp.ByQuery),
	)
}

func listenForConsoleMessages(ctx context.Context, messages *[]string) {
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		if msg, ok := ev.(*runtime.EventConsoleAPICalled); ok {
			for _, arg := range msg.Args {
				*messages = append(*messages, string(arg.Value))
			}
		}
	})
} 