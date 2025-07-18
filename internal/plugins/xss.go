package plugins

import (
	"autovulnscan/internal/browser"
	"autovulnscan/internal/discovery"
	"autovulnscan/internal/requester"
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/net/html"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
)

// XSSPayloads holds the data loaded from the xss.json file.
type XSSPayloads struct {
	Name     string    `json:"name"`
	Payloads []Payload `json:"payloads"`
}

// XSSPlugin is the plugin for detecting Cross-Site Scripting vulnerabilities.
type XSSPlugin struct {
	browserService *browser.BrowserService
	httpClient     *requester.HTTPClient // The HTTP client is needed again to fetch page source
	payloads       *XSSPayloads
}

// NewXSSPlugin creates a new XSSPlugin instance.
func NewXSSPlugin(bs *browser.BrowserService, client *requester.HTTPClient, payloadFile string) (*XSSPlugin, error) {
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
		browserService: bs,
		httpClient:     client,
		payloads:       &payloads,
	}, nil
}

// Type returns the plugin type.
func (p *XSSPlugin) Type() string {
	return "xss"
}

const xssHookScript = `<script>
    window.__xss_was_triggered = false;
    const originalAlert = window.alert;
    const originalConfirm = window.confirm;
    const originalPrompt = window.prompt;
    window.alert = function() { window.__xss_was_triggered = true; return originalAlert.apply(this, arguments); };
    window.confirm = function() { window.__xss_was_triggered = true; return originalConfirm.apply(this, arguments); };
    window.prompt = function() { window.__xss_was_triggered = true; return originalPrompt.apply(this, arguments); };
</script>`

// Scan performs the XSS scan by injecting a script hook and checking for its execution in a headless browser.
func (p *XSSPlugin) Scan(ctx context.Context, pURL discovery.ParameterizedURL, payloads []string) ([]Vulnerability, error) {
	vulnerabilities := make([]Vulnerability, 0)

	// DEBUG: Use a known-good, simple payload to isolate detection logic issues.
	payloadsToTest := []string{"<script>alert(1)</script>"}
	/*
		if len(payloads) > 0 {
			payloadsToTest = payloads
		} else {
			for _, p := range p.payloads.Payloads {
				payloadsToTest = append(payloadsToTest, p.Value)
			}
		}
	*/

	for _, param := range pURL.Params {
		for _, payload := range payloadsToTest {
			req, err := p.buildRequest(ctx, pURL, param, payload)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to build request for XSS scan")
				continue
			}

			resp, err := p.httpClient.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				continue
			}

			bodyBytes, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				continue
			}

			// Inject our hook script into the HTML using a proper HTML parser
			modifiedHTML, err := p.injectHook(string(bodyBytes))
			if err != nil {
				log.Warn().Err(err).Msg("Failed to inject XSS hook script")
				continue
			}

			// DEBUG: Log the exact HTML being sent to the browser for analysis.
			log.Debug().Str("url", pURL.URL).Str("param", param.Name).Str("payload", payload).Str("html", modifiedHTML).Msg("HTML content being sent to browser for XSS check")

			found, err := p.browserService.CheckXSSFromHTML(modifiedHTML)
			if err != nil {
				log.Error().Err(err).Msg("Error during XSS check in browser")
				continue
			}

			if found {
				vuln := Vulnerability{
					Type:       p.Type(),
					URL:        pURL.URL,
					Method:     pURL.Method,
					Parameter:  param,
					Payload:    payload,
					Evidence:   "A JavaScript dialog function (alert, prompt, confirm) was successfully hooked.",
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

// injectHook parses the HTML, finds the head tag, and prepends the hook script.
func (p *XSSPlugin) injectHook(htmlString string) (string, error) {
	doc, err := html.Parse(strings.NewReader(htmlString))
	if err != nil {
		return "", err
	}

	var headNode *html.Node
	var findHead func(*html.Node)
	findHead = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "head" {
			headNode = n
			return
		}
		for c := n.FirstChild; c != nil && headNode == nil; c = c.NextSibling {
			findHead(c)
		}
	}
	findHead(doc)

	if headNode != nil {
		scriptNode, err := html.Parse(strings.NewReader(xssHookScript))
		if err == nil && scriptNode.FirstChild != nil && scriptNode.FirstChild.LastChild != nil {
			// The parsed script is a full document, we need to get the actual <script> tag from its body.
			scriptTag := scriptNode.FirstChild.LastChild.FirstChild
			if scriptTag != nil {
				// Detach from old parent
				scriptTag.Parent.RemoveChild(scriptTag)
				// Prepend to new parent
				headNode.InsertBefore(scriptTag, headNode.FirstChild)
			}
		}
	} else {
		// If no head tag, prepend to the body or html tag as a fallback.
		// For simplicity, we'll just prepend to the whole document string.
		return xssHookScript + htmlString, nil
	}

	var b strings.Builder
	if err := html.Render(&b, doc); err != nil {
		return "", err
	}
	return b.String(), nil
}

func (p *XSSPlugin) buildRequest(ctx context.Context, pURL discovery.ParameterizedURL, paramToTest discovery.Parameter, payload string) (*http.Request, error) {
	var req *http.Request
	var err error

	if pURL.Method == "GET" {
		parsedURL, _ := url.Parse(pURL.URL)
		q := parsedURL.Query()
		q.Set(paramToTest.Name, payload)
		parsedURL.RawQuery = q.Encode()
		req, err = http.NewRequestWithContext(ctx, "GET", parsedURL.String(), nil)
	} else if pURL.Method == "POST" {
		formData := url.Values{}
		formData.Set(paramToTest.Name, payload)
		for _, p := range pURL.Params {
			if p.Name != paramToTest.Name {
				formData.Set(p.Name, p.Value)
			}
		}
		req, err = http.NewRequestWithContext(ctx, "POST", pURL.URL, strings.NewReader(formData.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	} else {
		err = fmt.Errorf("unsupported method: %s", pURL.Method)
	}

	return req, err
} 