// Package plugins 包含了所有具体的漏洞扫描插件实现。
package plugins

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"
	"autovulnscan/internal/vulnscan"
	"encoding/hex"

	"github.com/rs/zerolog/log"
)

// SQLiPlugin 实现了用于检测基于错误的SQL注入漏洞的插件。
type SQLiPlugin struct {
	errorPatterns []string
	payloads      []models.Payload
}

// init 函数会在包初始化时被调用，用于自动注册插件。
func init() {
	payloads, err := vulnscan.LoadPayloads("sqli")
	if err != nil {
		log.Fatal().Err(err).Msg("无法加载SQLi payloads，插件将无法运行")
	}
	vulnscan.RegisterPlugin(&SQLiPlugin{
		errorPatterns: []string{
			"you have an error in your sql syntax",
			"unclosed quotation mark",
			"supplied argument is not a valid mysql result resource",
			"sql server",
			"microsoft ole db provider for odbc drivers error",
			"invalid querystring",
			"odbc driver error",
			"oracle error",
			"db2 sql error",
			"postgresql error",
			"sqlite error",
		},
		payloads: payloads,
	})
}

// Info 返回插件的元数据。
func (p *SQLiPlugin) Info() vulnscan.PluginInfo {
	return vulnscan.PluginInfo{
		Name:        "sqli",
		Description: "检测基于错误的SQL注入漏洞。",
		Author:      "AutoVulnScan Team",
		Version:     "1.0",
	}
}

// Scan 对给定的HTTP请求执行SQL注入扫描。
func (p *SQLiPlugin) Scan(client *requester.HTTPClient, req *models.Request) ([]*vulnscan.Vulnerability, error) {
	var vulnerabilities []*vulnscan.Vulnerability

	for _, param := range req.Params {
		hashSet := make(map[string]struct{})

		for _, payload := range p.payloads {
			vuln, shortHash, err := p.testPayloadWithHash(client, req, param.Name, payload.Value)
			if err != nil {
				log.Warn().Err(err).Str("url", req.URL).Msg("SQLi payload test failed")
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

// responseInfo 封装响应信息
type responseInfo struct {
	body       []byte
	statusCode int
	hash       string
}

// getResponseInfo 获取响应信息并计算hash
func (p *SQLiPlugin) getResponseInfo(resp *http.Response) (*responseInfo, error) {
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(body)
	shortHash := hex.EncodeToString(hash[:4]) // 使用4字节作为短hash

	return &responseInfo{
		body:       body,
		statusCode: resp.StatusCode,
		hash:       shortHash,
	}, nil
}

// buildHTTPRequest 构建HTTP请求
func (p *SQLiPlugin) buildHTTPRequest(originalReq *models.Request, paramName, paramValue string) (*http.Request, error) {
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
		return nil, fmt.Errorf("创建HTTP请求失败: %w", err)
	}

	// 复制原始请求头
	if originalReq.Headers != nil {
		req.Header = originalReq.Headers.Clone()
	}

	return req, nil
}

// logRequestDebug 记录请求调试信息
func (p *SQLiPlugin) logRequestDebug(req *http.Request, payload string) {
	if dump, err := httputil.DumpRequestOut(req, true); err == nil {
		log.Debug().Str("plugin", "sqli").Msgf("Raw SQLi Request:\n%s", string(dump))
	}

	log.Debug().
		Str("plugin", "sqli").
		Str("method", req.Method).
		Str("url", req.URL.String()).
		Str("payload", payload).
		Msg("Sending SQLi test request")
}

// logResponseDebug 记录响应调试信息
func (p *SQLiPlugin) logResponseDebug(resp *http.Response, info *responseInfo) {
	if dump, err := httputil.DumpResponse(resp, false); err == nil {
		log.Debug().Str("plugin", "sqli").Msgf("Raw SQLi Response:\n%s", string(dump))
	}

	previewLen := 100
	preview := string(info.body)
	if len(preview) > previewLen {
		preview = preview[:previewLen] + "..."
	}

	log.Debug().
		Str("plugin", "sqli").
		Int("status", info.statusCode).
		Int("bodyLen", len(info.body)).
		Str("bodyPreview", preview).
		Str("respHash", info.hash).
		Msg("HTTP response received")
}

// checkErrorPatterns 检查响应中是否包含SQL错误模式
func (p *SQLiPlugin) checkErrorPatterns(body []byte) string {
	bodyLower := strings.ToLower(string(body))
	for _, pattern := range p.errorPatterns {
		if strings.Contains(bodyLower, pattern) {
			return pattern
		}
	}
	return ""
}

// createVulnerability 创建漏洞对象
func (p *SQLiPlugin) createVulnerability(originalReq *models.Request, paramName, payload string, testReq *http.Request) *vulnscan.Vulnerability {
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
func (p *SQLiPlugin) testPayloadWithHash(client *requester.HTTPClient, originalReq *models.Request, paramName, payload string) (*vulnscan.Vulnerability, string, error) {
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
		log.Error().Err(err).Str("plugin", "sqli").Msg("Request failed")
		return nil, "", err
	}

	testInfo, err := p.getResponseInfo(testResp)
	if err != nil {
		return nil, "", fmt.Errorf("读取测试响应失败: %w", err)
	}

	p.logResponseDebug(testResp, testInfo)

	// 3. 检查SQL错误模式
	if pattern := p.checkErrorPatterns(testInfo.body); pattern != "" {
		log.Warn().
			Str("plugin", "sqli").
			Str("url", originalReq.URL).
			Str("param", paramName).
			Str("payload", payload).
			Str("pattern", pattern).
			Msg("SQLi error pattern found in response")

		return p.createVulnerability(originalReq, paramName, payload, testReq), testInfo.hash, nil
	}

	// 4. 检查响应差异
	if p.hasSignificantDifference(baseInfo, testInfo) {
		log.Warn().
			Str("plugin", "sqli").
			Str("url", originalReq.URL).
			Str("param", paramName).
			Str("payload", payload).
			Int("baseLen", len(baseInfo.body)).
			Str("baseHash", baseInfo.hash).
			Int("baseStatus", baseInfo.statusCode).
			Int("testLen", len(testInfo.body)).
			Str("testHash", testInfo.hash).
			Int("testStatus", testInfo.statusCode).
			Msg("Response changed after payload injection, indicating potential SQL injection")

		return p.createVulnerability(originalReq, paramName, payload, testReq), testInfo.hash, nil
	}

	return nil, testInfo.hash, nil
}

// hasSignificantDifference 检查两个响应是否有显著差异
func (p *SQLiPlugin) hasSignificantDifference(base, test *responseInfo) bool {
	// 状态码不同
	if base.statusCode != test.statusCode {
		return true
	}

	// 内容hash不同
	if base.hash != test.hash {
		return true
	}

	// 响应长度差异超过阈值（可选的额外检查）
	lenDiff := len(test.body) - len(base.body)
	if lenDiff < 0 {
		lenDiff = -lenDiff
	}

	// 如果长度差异超过10%或者超过1000字节，认为有显著差异
	threshold := len(base.body) / 10
	if threshold < 1000 {
		threshold = 1000
	}

	return lenDiff > threshold
}
