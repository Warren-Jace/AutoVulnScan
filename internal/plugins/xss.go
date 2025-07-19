// Package plugins contains the individual vulnerability scanning plugins.
package plugins

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/rs/zerolog/log"

	"autovulnscan/internal/discovery"
	"autovulnscan/internal/requester"
	"html"
)

// XSSPlugin is the plugin for detecting Cross-Site Scripting vulnerabilities.
type XSSPlugin struct {
	BasePlugin
	httpClient *requester.HTTPClient
	payloads   []XSSPayload
}

// XSSPayload defines a payload and the method to verify its success.
type XSSPayload struct {
	Payload           string
	VerificationType  string // "dom" or "console"
	VerificationToken string
	InjectionContext  string // e.g., "html_tag", "html_attr", "js_string"
}

// NewXSSPlugin creates a new XSSPlugin instance.
func NewXSSPlugin(client *requester.HTTPClient, payloadFile string) (*XSSPlugin, error) {
	// A comprehensive list of context-aware, non-malicious payloads.
	// Each payload has a specific verification method (DOM or console).
	payloads := []XSSPayload{
		// 1. Basic HTML Tag Injection (Semantic DOM Check)
		{
			Payload:           `<avs-xss-test id="avstoken_html_tag"></avs-xss-test>`,
			VerificationType:  "dom",
			VerificationToken: "#avstoken_html_tag",
			InjectionContext:  "HTML Tag",
		},
		// 2. HTML Attribute Breakout (for unquoted attributes)
		{
			Payload:           `onmouseover=console.log('avstoken_attr_unquoted')`,
			VerificationType:  "console",
			VerificationToken: "avstoken_attr_unquoted",
			InjectionContext:  "HTML Attribute (Unquoted)",
		},
		// 3. HTML Attribute Breakout (for quoted attributes)
		{
			Payload:           `"><img src=x onerror=console.log('avstoken_attr_quoted')>`,
			VerificationType:  "console",
			VerificationToken: "avstoken_attr_quoted",
			InjectionContext:  "HTML Attribute (Quoted)",
		},
		// 4. JavaScript String Breakout (Single Quote)
		{
			Payload:           `'-console.log('avstoken_js_sq')-'`,
			VerificationType:  "console",
			VerificationToken: "avstoken_js_sq",
			InjectionContext:  "JavaScript String (Single Quote)",
		},
		// 5. JavaScript String Breakout (Double Quote)
		{
			Payload:           `"-console.log('avstoken_js_dq')-"`,
			VerificationType:  "console",
			VerificationToken: "avstoken_js_dq",
			InjectionContext:  "JavaScript String (Double Quote)",
		},
		// 6. HTML Comment Breakout
		{
			Payload:           `--><img src=x onerror=console.log('avstoken_comment')>`,
			VerificationType:  "console",
			VerificationToken: "avstoken_comment",
			InjectionContext:  "HTML Comment",
		},
		// 7. Textarea Breakout
		{
			Payload:           `</textarea><script>console.log('avstoken_textarea')</script>`,
			VerificationType:  "console",
			VerificationToken: "avstoken_textarea",
			InjectionContext:  "Textarea",
		},
		// 8. SVG-based payload (alternative to simple tags)
		{
			Payload:           `<svg/onload=console.log('avstoken_svg')>`,
			VerificationType:  "console",
			VerificationToken: "avstoken_svg",
			InjectionContext:  "HTML Tag (SVG)",
		},
	}

	return &XSSPlugin{
		BasePlugin: BasePlugin{
			name:        "xss",
			description: "Tests for Cross-Site Scripting vulnerabilities by injecting context-aware payloads and verifying execution in a headless browser.",
		},
		httpClient: client,
		payloads:   payloads,
	}, nil
}

// Scan performs the XSS scan for a given parameterized URL.
func (p *XSSPlugin) Scan(ctx context.Context, pURL discovery.ParameterizedURL) ([]Vulnerability, error) {
	var vulnerabilities []Vulnerability

	for _, payload := range p.payloads {
		for i := range pURL.Params {

			// Test with the original payload
			if vuln := p.testPayload(ctx, pURL, payload, pURL.Params[i].Name, payload.Payload); vuln != nil {
				vulnerabilities = append(vulnerabilities, *vuln)
				continue // Move to the next parameter if a vulnerability is found
			}

			// Test with the HTML-encoded payload
			encodedPayload := html.EscapeString(payload.Payload)
			if vuln := p.testPayload(ctx, pURL, payload, pURL.Params[i].Name, encodedPayload); vuln != nil {
				vulnerabilities = append(vulnerabilities, *vuln)
			}
		}
	}
	return vulnerabilities, nil
}

// testPayload runs a single payload test against a URL parameter.
func (p *XSSPlugin) testPayload(ctx context.Context, pURL discovery.ParameterizedURL, payload XSSPayload, paramName, finalPayload string) *Vulnerability {
	testURL, err := p.httpClient.BuildURLWithPayload(pURL.URL, paramName, finalPayload)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to build URL with payload")
		return nil
	}

	// Allocate a new context for chromedp
	allocCtx, cancel := chromedp.NewContext(ctx)
	defer cancel()

	// Create a context with a timeout
	taskCtx, cancel := context.WithTimeout(allocCtx, 30*time.Second)
	defer cancel()

	var found bool

	// Listen for console.log events
	listenCtx, cancelListen := context.WithCancel(taskCtx)
	defer cancelListen()
	chromedp.ListenTarget(listenCtx, func(ev interface{}) {
		if ev, ok := ev.(*runtime.EventConsoleAPICalled); ok {
			for _, arg := range ev.Args {
				if strings.Contains(string(arg.Value), payload.VerificationToken) {
					found = true
					cancelListen() // Stop listening once found
				}
			}
		}
	})

	err = chromedp.Run(taskCtx,
		chromedp.Navigate(testURL),
		chromedp.ActionFunc(func(ctx context.Context) error {
			if payload.VerificationType == "dom" {
				var nodes []*cdp.Node
				err := chromedp.Run(ctx, chromedp.Nodes(payload.VerificationToken, &nodes, chromedp.AtLeast(1)))
				if err == nil && len(nodes) > 0 {
					found = true
				}
			}
			// For console type, the listener will handle it. We just need to wait a bit.
			time.Sleep(2 * time.Second)
			return nil
		}),
	)

	if err != nil && err != context.Canceled {
		log.Debug().Err(err).Str("url", testURL).Msg("Chromedp run failed")
	}

	if found {
		return &Vulnerability{
			Name:                 p.name,
			Type:                 p.Type(),
			URL:                  pURL.URL,
			Payload:              finalPayload, // Use the payload that actually worked
			Method:               pURL.Method,
			Parameter:            paramName,
			VulnerabilityAddress: testURL,
			Reproduction:         fmt.Sprintf("Vulnerability confirmed with token '%s' via %s check.", payload.VerificationToken, payload.VerificationType),
			Timestamp:            time.Now(),
		}
	}
	return nil
}
