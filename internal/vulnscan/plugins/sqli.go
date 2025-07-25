// Package plugins 包含了各种具体的漏洞扫描插件实现。
package plugins

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"

	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"
	"autovulnscan/internal/vulnscan"

	"github.com/rs/zerolog/log"
)

// SQLiPlugin 实现了用于检测SQL注入漏洞的插件。
type SQLiPlugin struct {
	payloads         []models.Payload
	errorPatterns    []*regexp.Regexp
	timeBasedPayload string
	timeThreshold    time.Duration
}

func init() {
	// 在包初始化时，自动将此插件注册到全局注册表中。
	// 这种模式使得添加新插件非常方便，只需要创建新的插件文件并在init中注册即可。
	vulnscan.GetRegistry().Register(&SQLiPlugin{})
}

// Name 返回插件的名称。
func (p *SQLiPlugin) Name() string {
	return "sqli"
}

// Scan 是插件的核心逻辑，负责对给定的请求执行SQL注入扫描。
func (p *SQLiPlugin) Scan(client *requester.HTTPClient, req *models.Request) ([]*vulnscan.Vulnerability, error) {
	var vulnerabilities []*vulnscan.Vulnerability

	for _, param := range req.Params {
		for _, payload := range p.payloads {
			vuln, err := p.testPayload(client, req, param.Name, payload.Value)
			if err != nil {
				log.Warn().Err(err).Str("url", req.URL).Msg("SQLi payload test failed")
				continue
			}
			if vuln != nil {
				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}

	return vulnerabilities, nil
}

// testPayload 测试单个payload对单个参数的效果。
// 这是实际发送HTTP请求并分析响应的地方。
func (p *SQLiPlugin) testPayload(client *requester.HTTPClient, originalReq *models.Request, paramName, payload string) (*vulnscan.Vulnerability, error) {
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
	} else { // GET a
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

	// 检查响应中是否有SQL错误信息
	for _, pattern := range p.errorPatterns {
		if pattern.Match(bodyBytes) {
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
	}

	return nil, nil
}

// isErrorBasedSQLi 检查响应体是否匹配已知的SQL错误模式。
func (p *SQLiPlugin) isErrorBasedSQLi(body string) bool {
	// 检查响应体中是否包含已知的SQL错误模式
	// 例如："you have an error in your sql syntax", "unclosed quotation mark" 等
	// 这里需要根据实际的payloads和错误模式来判断
	// 为了简化，这里只保留一个示例，实际需要更复杂的模式匹配
	return false // 示例：如果响应体包含 "you have an error in your sql syntax"，则认为存在SQL注入
}

// isTimeBasedSQLi 检查响应时间是否超过了设定的阈值，以判断是否存在时间盲注。
func (p *SQLiPlugin) isTimeBasedSQLi(duration time.Duration) bool {
	// 检查响应时间是否超过设定的阈值
	// 例如，如果阈值是1秒，则如果响应时间超过1秒，则认为存在时间盲注
	// 这里只保留一个示例，实际需要更复杂的逻辑
	return false // 示例：如果响应时间超过1秒，则认为存在时间盲注
}

// loadPayloads 从JSON文件中加载用于SQL注入的payloads。
// 这使得payloads可以独立于代码进行管理和更新。
func (p *SQLiPlugin) loadPayloads() error {
	// 从JSON文件加载payloads
	// 例如：从 "payloads.json" 文件中读取
	// 这里只保留一个示例，实际需要更复杂的文件读取逻辑
	return nil // 示例：从 "payloads.json" 文件中读取payloads
}
