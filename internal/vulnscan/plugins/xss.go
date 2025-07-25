// Package plugins 包含了各种具体的漏洞扫描插件实现。
package plugins

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"autovulnscan/internal/browser"
	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"
	"autovulnscan/internal/vulnscan"

	"github.com/rs/zerolog/log"
)

// XSSPlugin 实现了用于检测跨站脚本（XSS）漏洞的插件。
// 它能够检测反射型XSS，并通过一个可选的浏览器服务来验证DOM-based XSS。
type XSSPlugin struct {
	payloads       []models.Payload
	browserService *browser.BrowserService
}

func init() {
	// 自动注册XSS插件
	vulnscan.GetRegistry().Register(&XSSPlugin{})
}

// Name 返回插件的名称。
func (p *XSSPlugin) Name() string {
	return "xss"
}

// SetBrowserService 允许外部（如扫描引擎）注入一个浏览器服务实例。
// 这是一种依赖注入的实现，使得插件可以利用共享的浏览器资源。
func (p *XSSPlugin) SetBrowserService(service *browser.BrowserService) {
	p.browserService = service
}

// Scan 是插件的核心逻辑，负责对给定的请求执行XSS扫描。
func (p *XSSPlugin) Scan(client *requester.HTTPClient, req *models.Request) ([]*vulnscan.Vulnerability, error) {
	// 注意：BrowserService应该在创建引擎时注入。
	// 如果没有注入，DOM验证将被跳过。
	if p.browserService == nil {
		log.Warn().Msg("XSS插件未配置浏览器服务，DOM验证将被跳过。")
	}

	var vulnerabilities []*vulnscan.Vulnerability
	for _, param := range req.Params {
		for _, payload := range p.payloads {
			vuln, err := p.testPayload(client, req, param.Name, payload.Value)
			if err != nil {
				log.Warn().Err(err).Str("url", req.URL).Msg("XSS payload test failed")
				continue
			}
			if vuln != nil {
				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}
	return vulnerabilities, nil
}

// testPayload 测试单个XSS payload在特定参数上的效果。
// 它会检查payload是否在响应体中被反射，并可选地使用浏览器进行验证。
func (p *XSSPlugin) testPayload(client *requester.HTTPClient, originalReq *models.Request, paramName, payload string) (*vulnscan.Vulnerability, error) {
	var reqToTest *http.Request
	var err error
	targetURL := originalReq.URL

	// 为每个payload创建一个全新的请求
	if originalReq.Method == "POST" {
		form := make(url.Values)
		for _, p := range originalReq.Params {
			if p.Name == paramName {
				form.Set(p.Name, payload)
			} else {
				form.Set(p.Name, p.Value)
			}
		}
		reqToTest, err = http.NewRequest("POST", targetURL, strings.NewReader(form.Encode()))
		if err == nil {
			reqToTest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	} else { // GET
		parsedURL, _ := url.Parse(targetURL)
		q := parsedURL.Query()
		q.Set(paramName, payload)
		parsedURL.RawQuery = q.Encode()
		reqToTest, err = http.NewRequest("GET", parsedURL.String(), nil)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// 发送请求
	resp, err := client.Do(reqToTest)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// 转储请求和响应
	reqDump, err := httputil.DumpRequestOut(reqToTest, true)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to dump request")
	}

	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to dump response")
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// 检查响应中是否反射了payload
	if strings.Contains(string(bodyBytes), payload) {
		// 如果配置了浏览器服务，进行DOM验证
		if p.browserService != nil {
			isVuln, err := p.browserService.VerifyXSS(context.Background(), reqToTest.URL.String(), payload)
			if err != nil {
				log.Warn().Err(err).Str("url", reqToTest.URL.String()).Msg("XSS DOM verification failed")
			}
			if !isVuln {
				return nil, nil // DOM验证未通过
			}
		}

		return &vulnscan.Vulnerability{
			Type:         p.Name(),
			URL:          originalReq.URL,
			Method:       originalReq.Method,
			Param:        paramName,
			Payload:      payload,
			Timestamp:    time.Now(),
			RequestDump:  string(reqDump),
			ResponseDump: string(respDump),
		}, nil
	}

	return nil, nil
}

// detectReflection 检测payload是否在响应体中被反射。
func (p *XSSPlugin) detectReflection(body []byte, payload string) bool {
	bodyStr := string(body)

	// 1. 直接字符串匹配
	if strings.Contains(bodyStr, payload) {
		return true
	}

	// 2. 检查HTML实体编码后的反射
	encodedPayload := strings.Replace(payload, "<", "&lt;", -1)
	encodedPayload = strings.Replace(encodedPayload, ">", "&gt;", -1)
	if strings.Contains(bodyStr, encodedPayload) {
		return true
	}

	// 3. 检查URL编码后的反射
	if strings.Contains(bodyStr, url.QueryEscape(payload)) {
		return true
	}

	return false
}
