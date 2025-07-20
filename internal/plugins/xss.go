// Package plugins contains the individual vulnerability scanning plugins.
package plugins

import (
	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"
	"autovulnscan/internal/util"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/fatih/color"
	"github.com/rs/zerolog/log"
)

// XSSPlugin is responsible for detecting Cross-Site Scripting vulnerabilities.
type XSSPlugin struct {
	client   *requester.HTTPClient
	payloads []models.Payload
}

// NewXSSPlugin creates a new XSSPlugin.
func NewXSSPlugin(client *requester.HTTPClient, payloadFile string) (*XSSPlugin, error) {
	payloads, err := loadPayloads(payloadFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load XSS payloads: %w", err)
	}
	return &XSSPlugin{client: client, payloads: payloads}, nil
}

// Type returns the type of the plugin.
func (p *XSSPlugin) Type() string {
	return "xss"
}

// Scan performs the XSS scan on a given parameterized URL.
func (p *XSSPlugin) Scan(ctx context.Context, pURL models.ParameterizedURL) ([]Vulnerability, error) {
	var vulnerabilities []Vulnerability

	for _, payload := range p.payloads {
		paramPayloads := make(map[string]string)
		paramToRandomStr := make(map[string]string)

		for _, param := range pURL.Params {
			randomStr := util.RandomString(10)
			paramToRandomStr[param.Name] = randomStr
			// Inject the random string into the payload for detection
			finalPayload := strings.ReplaceAll(payload.Value, "alert('AutoVulnScanXSS')", fmt.Sprintf("console.log('%s')", randomStr))
			paramPayloads[param.Name] = finalPayload
		}

		req, err := p.client.BuildRequestWithPayloads(pURL, paramPayloads)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to build request for XSS scan")
			continue
		}

		vulnerableParams := p.checkDOMContext(ctx, req, paramToRandomStr)

		for _, vp := range vulnerableParams {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:          p.Type(),
				URL:           pURL.URL,
				Param:         vp,
				Payload:       paramPayloads[vp],
				Method:        pURL.Method,
				VulnerableURL: req.URL.String(),
				Timestamp:     time.Now(),
			})
			log.Info().Str("type", "XSS").Str("url", pURL.URL).Str("param", vp).Msg(color.RedString("Vulnerability Found!"))
		}
	}

	return vulnerabilities, nil
}

// checkDOMContext uses a headless browser to check if a payload is executed in the DOM.
func (p *XSSPlugin) checkDOMContext(ctx context.Context, req *requester.Request, paramToRandomStr map[string]string) []string {
	var vulnerableParams []string

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

	for param, randomStr := range paramToRandomStr {
		for _, msg := range consoleMessages {
			if strings.Contains(msg, randomStr) {
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

func loadPayloads(file string) ([]models.Payload, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var payloads []models.Payload
	if err := json.NewDecoder(f).Decode(&payloads); err != nil {
		return nil, err
	}
	return payloads, nil
}
