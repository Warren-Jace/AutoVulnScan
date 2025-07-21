package plugins

import (
	"context"
	"fmt"
	"io"
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

	return newReq, nil
}

// checkDOMContext uses a headless browser to check if a payload is executed in the DOM.
func (p *XSSPlugin) checkDOMContext(ctx context.Context, req *models.Request, paramToIdentifier map[string]string) []string {
	var vulnerableParams []string

	// This function is now only used to find reflected parameters, not to confirm vulnerabilities.
	// A more robust implementation might use different techniques here.
	// For now, we'll keep the existing console log check for this purpose.

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

	var err error
	if req.Method == "POST" {
		bodyBytes, readErr := io.ReadAll(req.Body)
		if readErr != nil {
			log.Warn().Err(readErr).Msg("Failed to read request body for XSS check")
			return nil
		}
		req.Body.Close()
		postData := string(bodyBytes)
		postData = strings.ReplaceAll(postData, "`", "\\`")

		script := fmt.Sprintf(`
            (async () => {
                const response = await fetch('%s', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: `+"`%s`"+`
                });
                const html = await response.text();
                document.open();
                document.write(html);
                document.close();
            })();
        `, req.URL.String(), postData)
		err = chromedp.Run(taskCtx,
			chromedp.Navigate("about:blank"),
			chromedp.Evaluate(script, nil, func(p *runtime.EvaluateParams) *runtime.EvaluateParams {
				return p.WithAwaitPromise(true)
			}),
			chromedp.Poll("document.readyState === 'complete'", nil),
		)
	} else { // Default to GET
		err = chromedp.Run(taskCtx,
			chromedp.Navigate(req.URL.String()),
			chromedp.Poll("document.readyState === 'complete'", nil),
		)
	}

	if err != nil {
		log.Debug().Err(err).Msg("Failed to execute DOM context check")
		return nil
	}

	for param, identifier := range paramToIdentifier {
		for _, msg := range consoleMessages {
			if strings.Contains(msg, identifier) {
				vulnerableParams = append(vulnerableParams, param)
				break
			}
		}
	}

	return vulnerableParams
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