// Package plugins 包含了所有具体的漏洞扫描插件实现。
package plugins

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
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
	// 自动注册XSS插件
	vulnscan.RegisterPlugin(&XSSPlugin{})
}

// SetPayloads 设置插件的攻击载荷。
func (p *XSSPlugin) SetPayloads(payloads []models.Payload) {
	p.payloads = payloads
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
		hashSet := make(map[string]struct{})

		for _, payload := range p.payloads {
			vuln, shortHash, err := p.testPayloadWithHash(client, req, param.Name, payload.Value)
			if err != nil {
				log.Warn().Err(err).Str("url", req.URL).Msg("XSS payload test failed")
				continue
			}

			if vuln != nil {
				vulnerabilities = append(vulnerabilities, vuln)
			}
			hashSet[shortHash] = struct{}{}
		}

		// 检查是否所有payload响应一致（可能被WAF拦截）
		if len(hashSet) == 1 && len(p.payloads) > 1 {
			log.Warn().Str("param", param.Name).Msg("所有payload响应内容一致，可能被WAF/限流/黑名单拦截或目标站点无效！")
		}
	}

	return vulnerabilities, nil
}

// getResponseInfo 获取响应信息并计算hash
func (p *XSSPlugin) getResponseInfo(resp *http.Response) (*models.ResponseInfo, error) {
	if resp == nil {
		return nil, fmt.Errorf("http响应为空")
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %w", err)
	}
	defer resp.Body.Close()

	hash := sha256.Sum256(body)
	shortHash := hex.EncodeToString(hash[:4]) // 使用4字节作为短hash

	return &models.ResponseInfo{
		Body:       body,
		StatusCode: resp.StatusCode,
		Hash:       shortHash,
	}, nil
}

// buildHTTPRequest 构建HTTP请求
func (p *XSSPlugin) buildHTTPRequest(originalReq *models.Request, paramName, paramValue string) (*http.Request, error) {
	var req *http.Request
	var err error

	if originalReq.Method == "POST" {
		form := make(url.Values)
		for _, param := range originalReq.Params {
			if param.Name == paramName {
				form.Set(param.Name, paramValue)
			} else {
				form.Set(param.Name, param.Value)
			}
		}

		req, err = http.NewRequest("POST", originalReq.URL, strings.NewReader(form.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	} else {
		parsedURL, parseErr := url.Parse(originalReq.URL)
		if parseErr != nil {
			return nil, parseErr
		}

		query := parsedURL.Query()
		for _, param := range originalReq.Params {
			if param.Name == paramName {
				query.Set(param.Name, paramValue)
			} else {
				query.Set(param.Name, param.Value)
			}
		}

		parsedURL.RawQuery = query.Encode()
		req, err = http.NewRequest("GET", parsedURL.String(), nil)
	}

	if err != nil {
		return nil, fmt.Errorf("创建XSS测试请求失败: %w", err)
	}

	// 复制原始请求头
	if originalReq.Headers != nil {
		req.Header = originalReq.Headers.Clone()
	}

	return req, nil
}

// logRequestDebug 记录请求调试信息
func (p *XSSPlugin) logRequestDebug(req *http.Request, payload string) {
	if dump, err := httputil.DumpRequestOut(req, true); err == nil {
		log.Debug().Str("plugin", "xss").Msgf("Raw XSS Request:\n%s", string(dump))
	}

	log.Debug().
		Str("plugin", "xss").
		Str("method", req.Method).
		Str("url", req.URL.String()).
		Str("payload", payload).
		Msg("Sending XSS test request")
}

// logResponseDebug 记录响应调试信息
func (p *XSSPlugin) logResponseDebug(info *models.ResponseInfo) {
	if info == nil {
		log.Debug().Str("plugin", "xss").Msg("Response info is nil")
		return
	}
	previewLen := 100
	preview := string(info.Body)
	if len(preview) > previewLen {
		preview = preview[:previewLen] + "..."
	}

	log.Debug().
		Str("plugin", "xss").
		Int("status", info.StatusCode).
		Int("bodyLen", len(info.Body)).
		Str("bodyPreview", preview).
		Str("respHash", info.Hash).
		Msg("HTTP response received")
}

// logComparisonDebug 记录响应对比调试信息
func (p *XSSPlugin) logComparisonDebug(paramName, payload string, baseInfo, testInfo *models.ResponseInfo) {
	if baseInfo == nil || testInfo == nil {
		log.Debug().Str("plugin", "xss").Msg("Base or test info is nil for comparison")
		return
	}
	log.Debug().
		Str("plugin", "xss").
		Str("param", paramName).
		Str("payload", payload).
		Int("baseLen", len(baseInfo.Body)).
		Str("baseHash", baseInfo.Hash).
		Int("baseStatus", baseInfo.StatusCode).
		Int("testLen", len(testInfo.Body)).
		Str("testHash", testInfo.Hash).
		Int("testStatus", testInfo.StatusCode).
		Msg("Comparing XSS response details")
}

// detectReflection 检测payload是否在响应体中被反射
func (p *XSSPlugin) detectReflection(body []byte, payload string) bool {
	bodyStr := string(body)

	// 检查函数列表，按优先级排序
	checks := []func(string, string) bool{
		p.checkDirectReflection,
		p.checkHTMLEncodedReflection,
		p.checkURLEncodedReflection,
	}

	for _, check := range checks {
		if check(bodyStr, payload) {
			return true
		}
	}

	return false
}

// checkDirectReflection 检查直接字符串匹配
func (p *XSSPlugin) checkDirectReflection(bodyStr, payload string) bool {
	return strings.Contains(bodyStr, payload)
}

// checkHTMLEncodedReflection 检查HTML实体编码后的反射
func (p *XSSPlugin) checkHTMLEncodedReflection(bodyStr, payload string) bool {
	encodedPayload := strings.NewReplacer(
		"<", "&lt;",
		">", "&gt;",
		"&", "&amp;",
		"\"", "&quot;",
		"'", "&#39;",
	).Replace(payload)

	return strings.Contains(bodyStr, encodedPayload)
}

// checkURLEncodedReflection 检查URL编码后的反射
func (p *XSSPlugin) checkURLEncodedReflection(bodyStr, payload string) bool {
	return strings.Contains(bodyStr, url.QueryEscape(payload))
}

// hasSignificantDifference 检查两个响应是否有显著差异
func (p *XSSPlugin) hasSignificantDifference(base, test *models.ResponseInfo) bool {
	if base == nil || test == nil {
		return false
	}
	// 状态码不同
	if base.StatusCode != test.StatusCode {
		return true
	}

	// 内容hash不同
	if base.Hash != test.Hash {
		return true
	}

	// 响应长度差异检查
	lenDiff := len(test.Body) - len(base.Body)
	if lenDiff < 0 {
		lenDiff = -lenDiff
	}

	// 如果长度差异超过5%或者超过500字节，认为有显著差异
	threshold := len(base.Body) / 20 // 5%
	if threshold < 500 {
		threshold = 500
	}

	return lenDiff > threshold
}

// performDOMVerification 执行DOM验证
func (p *XSSPlugin) performDOMVerification(body []byte, originalReq *models.Request, paramName string) bool {
	if p.browserService == nil {
		return true // 没有浏览器服务时，跳过DOM验证
	}

	verified, err := p.browserService.VerifyXSS(context.Background(), originalReq.URL, "some_payload")
	if err != nil {
		log.Warn().Err(err).Msg("XSS DOM验证时出错")
		return true // 验证出错时，假设漏洞存在
	}

	if !verified {
		log.Info().
			Str("url", originalReq.URL).
			Str("param", paramName).
			Msg("XSS反射被发现，但DOM验证未触发。可能是一个误报或非典型的XSS。")
		return false
	}

	log.Info().
		Str("url", originalReq.URL).
		Str("param", paramName).
		Msg("XSS通过DOM验证！")
	return true
}

// createVulnerability 创建漏洞对象
func (p *XSSPlugin) createVulnerability(originalReq *models.Request, paramName, payload string, testReq *http.Request) *vulnscan.Vulnerability {
	return &vulnscan.Vulnerability{
		Type:          p.Info().Name,
		URL:           originalReq.URL,
		Payload:       payload,
		Param:         paramName,
		Method:        originalReq.Method,
		VulnerableURL: testReq.URL.String(),
		Timestamp:     time.Now(),
	}
}

// testPayloadWithHash 返回短hash用于一致性检测
func (p *XSSPlugin) testPayloadWithHash(client *requester.HTTPClient, originalReq *models.Request, paramName, payload string) (*vulnscan.Vulnerability, string, error) {
	// 1. 获取基线响应
	baseReq, err := p.buildHTTPRequest(originalReq, paramName, "")
	if err != nil {
		return nil, "", err
	}

	// 设置原始参数值
	for _, param := range originalReq.Params {
		if param.Name == paramName {
			baseReq, err = p.buildHTTPRequest(originalReq, paramName, param.Value)
			if err != nil {
				return nil, "", err
			}
			break
		}
	}

	baseResp, err := client.Do(baseReq)
	if err != nil {
		return nil, "", fmt.Errorf("获取基线响应失败: %w", err)
	}

	baseInfo, err := p.getResponseInfo(baseResp)
	if err != nil {
		return nil, "", fmt.Errorf("读取基线响应失败: %w", err)
	}

	// 2. 构造并发送payload请求
	testReq, err := p.buildHTTPRequest(originalReq, paramName, payload)
	if err != nil {
		return nil, "", err
	}

	p.logRequestDebug(testReq, payload)

	testResp, err := client.Do(testReq)
	if err != nil {
		log.Error().Err(err).Str("plugin", "xss").Msg("Request failed")
		return nil, "", err
	}

	testInfo, err := p.getResponseInfo(testResp)
	if err != nil {
		return nil, "", fmt.Errorf("读取测试响应失败: %w", err)
	}

	p.logResponseDebug(testInfo)
	p.logComparisonDebug(paramName, payload, baseInfo, testInfo)

	// 3. 检查XSS反射或响应差异
	hasReflection := p.detectReflection(testInfo.Body, payload)
	hasDifference := p.hasSignificantDifference(baseInfo, testInfo)

	if hasReflection || hasDifference {
		log.Warn().
			Str("plugin", "xss").
			Str("url", originalReq.URL).
			Str("param", paramName).
			Str("payload", payload).
			Bool("hasReflection", hasReflection).
			Bool("hasDifference", hasDifference).
			Int("baseLen", len(baseInfo.Body)).
			Str("baseHash", baseInfo.Hash).
			Int("baseStatus", baseInfo.StatusCode).
			Int("testLen", len(testInfo.Body)).
			Str("testHash", testInfo.Hash).
			Int("testStatus", testInfo.StatusCode).
			Msg("XSS reflection or response difference detected, indicating a potential XSS vulnerability.")

		// 4. 执行DOM验证
		if !p.performDOMVerification(testInfo.Body, originalReq, paramName) {
			return nil, testInfo.Hash, nil // DOM验证失败，确认为误报
		}

		return p.createVulnerability(originalReq, paramName, payload, testReq), testInfo.Hash, nil
	}

	return nil, testInfo.Hash, nil
}
