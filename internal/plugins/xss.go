// Package plugins contains the individual vulnerability scanning plugins.
package plugins

import (
	"autovulnscan/internal/requester"
	"autovulnscan/internal/util"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"os"

	"autovulnscan/internal/models"

	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/fatih/color"
	"github.com/rs/zerolog/log"
)

// XSSPlugin is responsible for detecting Cross-Site Scripting vulnerabilities.
type XSSPlugin struct {
	client   *requester.HTTPClient
	payloads []string
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
	paramPayloads := make(map[string]string)
	paramToRandomStr := make(map[string]string)

	for _, param := range pURL.Params {
		randomStr := util.RandomString(10)
		paramToRandomStr[param.Name] = randomStr
		// Use a simple but effective payload that writes the random string to the console.
		paramPayloads[param.Name] = fmt.Sprintf(`" autofocus onfocus="console.log('%s')"`, randomStr)
	}

	req, err := p.client.BuildRequestWithPayloads(pURL, paramPayloads)
	if err != nil {
		return nil, fmt.Errorf("failed to build request with grouped payloads: %w", err)
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

	err := chromedp.Run(taskCtx,
		chromedp.Navigate(req.URL.String()),
		chromedp.Sleep(2*time.Second),
	)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to navigate to page for DOM context check")
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

func loadPayloads(file string) ([]string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var data struct {
		Payloads []string `json:"payloads"`
	}
	if err := json.NewDecoder(f).Decode(&data); err != nil {
		return nil, err
	}
	return data.Payloads, nil
}
