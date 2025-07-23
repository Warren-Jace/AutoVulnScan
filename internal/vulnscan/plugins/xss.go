// Package plugins 包含了所有具体的漏洞扫描插件实现。
package plugins

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"

	"autovulnscan/internal/browser"
	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"
	"autovulnscan/internal/vulnscan"

	"github.com/rs/zerolog/log"
)

// XSSPlugin 实现了用于检测反射型跨站脚本（XSS）漏洞的插件。
type XSSPlugin struct {
	browserService  *browser.BrowserService
	reflectionRegex *regexp.Regexp
	payloads        []models.Payload
}

// init 函数会在包初始化时被调用，用于自动注册插件。
func init() {
	payloads, err := vulnscan.LoadPayloads("xss")
	if err != nil {
		log.Fatal().Err(err).Msg("无法加载XSS payloads，插件将无法运行")
	}
	vulnscan.RegisterPlugin(&XSSPlugin{
		reflectionRegex: regexp.MustCompile(`(?i)<script[^>]*>.*?</script>|javascript:|on\w+\s*=|<img[^>]*src\s*=|<iframe[^>]*src\s*=`),
		payloads:        payloads,
	})
}

// Info 返回插件的元数据。
func (p *XSSPlugin) Info() vulnscan.PluginInfo {
	return vulnscan.PluginInfo{
		Name:        "xss",
		Description: "检测反射型跨站脚本（XSS）漏洞。",
		Author:      "AutoVulnScan Team",
		Version:     "1.0",
	}
}

// SetBrowserService 允许外部注入一个共享的 BrowserService 实例。
func (p *XSSPlugin) SetBrowserService(service *browser.BrowserService) {
	p.browserService = service
}

// Scan 对给定的HTTP请求执行XSS扫描。
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

// testPayload 在特定参数上测试单个XSS payload。
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
		parsedURL, errParse := url.Parse(targetURL)
		if errParse != nil {
			return nil, errParse
		}
		q := parsedURL.Query()
		for _, p := range originalReq.Params {
			if p.Name != paramName {
				q.Set(p.Name, p.Value)
			}
		}
		q.Set(paramName, payload)
		parsedURL.RawQuery = q.Encode()
		reqToTest, err = http.NewRequest("GET", parsedURL.String(), nil)
	}

	if err != nil {
		return nil, fmt.Errorf("创建XSS测试请求失败: %w", err)
	}
	if originalReq.Headers != nil {
		reqToTest.Header = originalReq.Headers.Clone()
	}

	// ---- START DEBUG LOGGING ----
	dump, err := httputil.DumpRequestOut(reqToTest, true)
	if err != nil {
		log.Debug().Err(err).Msg("Could not dump request")
	} else {
		log.Debug().Str("plugin", "xss").Msgf("Raw XSS Request:\n%s", string(dump))
	}
	// ---- END DEBUG LOGGING ----

	log.Debug().
		Str("plugin", "xss").
		Str("method", reqToTest.Method).
		Str("url", reqToTest.URL.String()).
		Msg("Sending XSS test request")

	resp, err := client.Do(reqToTest)
	if err != nil {
		log.Error().Err(err).Str("plugin", "xss").Msg("Request failed")
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// ---- START DEBUG LOGGING ----
	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		log.Debug().Err(err).Msg("Could not dump response")
	} else {
		log.Debug().Str("plugin", "xss").Msgf("Raw XSS Response:\n%s", string(respDump))
	}
	// ---- END DEBUG LOGGING ----

	if p.detectReflection(body, payload) {
		log.Info().
			Str("plugin", "xss").
			Str("payload", payload).
			Str("url", originalReq.URL).
			Msg("Payload reflection found in response")
		// 如果检测到反射，并且浏览器服务可用，则进行DOM验证
		if p.browserService != nil {
			verified, err := p.browserService.CheckXSSFromHTML(string(body))
			if err != nil {
				log.Warn().Err(err).Msg("XSS DOM验证时出错")
			}
			if !verified {
				log.Info().Str("url", originalReq.URL).Str("param", paramName).Msg("XSS反射被发现，但DOM验证未触发。可能是一个误报或非典型的XSS。")
				return nil, nil // DOM验证失败，确认为误报
			}
			log.Info().Str("url", originalReq.URL).Str("param", paramName).Msg("XSS通过DOM验证！")
		}

		return &vulnscan.Vulnerability{
			Type:          p.Info().Name,
			URL:           originalReq.URL,
			Payload:       payload,
			Param:         paramName,
			Method:        originalReq.Method,
			VulnerableURL: reqToTest.URL.String(),
			Timestamp:     time.Now(),
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
