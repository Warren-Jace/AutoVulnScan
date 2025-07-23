// Package plugins 包含了所有具体的漏洞扫描插件实现。
package plugins

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"
	"autovulnscan/internal/vulnscan"

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
		for _, payload := range p.payloads {
			vuln, err := p.testPayload(client, req, param.Name, payload.Value)
			if err != nil {
				log.Warn().Err(err).Str("url", req.URL.String()).Msg("SQLi payload test failed")
				continue
			}
			if vuln != nil {
				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}

	return vulnerabilities, nil
}

// testPayload 在特定参数上测试单个SQL注入payload。
func (p *SQLiPlugin) testPayload(client *requester.HTTPClient, originalReq *models.Request, paramName, payload string) (*vulnscan.Vulnerability, error) {
	var reqToTest *http.Request
	var err error

	// 为每个payload创建一个全新的请求，以避免body被消耗的问题
	if originalReq.Method == "POST" {
		form := make(url.Values)
		for _, p := range originalReq.Params {
			if p.Name == paramName {
				form.Set(p.Name, payload)
			} else {
				form.Set(p.Name, p.Value)
			}
		}
		reqToTest, err = http.NewRequest("POST", originalReq.URL.String(), strings.NewReader(form.Encode()))
		if err == nil {
			reqToTest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	} else { // 默认为GET请求
		newURL, err := url.Parse(originalReq.URL.String())
		if err != nil {
			return nil, err
		}
		q := newURL.Query()
		q.Set(paramName, payload)
		newURL.RawQuery = q.Encode()
		reqToTest, err = http.NewRequest("GET", newURL.String(), nil)
	}

	if err != nil {
		return nil, fmt.Errorf("创建测试请求失败: %w", err)
	}

	// 复制原始请求的头信息
	reqToTest.Header = originalReq.Header.Clone()

	log.Debug().
		Str("plugin", "sqli").
		Str("method", reqToTest.Method).
		Str("url", reqToTest.URL.String()).
		Msg("Sending SQLi test request")

	resp, err := client.Do(reqToTest)
	if err != nil {
		log.Error().Err(err).Str("plugin", "sqli").Msg("Request failed")
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	log.Debug().
		Str("plugin", "sqli").
		Int("status_code", resp.StatusCode).
		Int("body_size", len(body)).
		Msg("Received response for SQLi test")

	responseText := strings.ToLower(string(body))
	for _, pattern := range p.errorPatterns {
		if strings.Contains(responseText, pattern) {
			log.Info().
				Str("plugin", "sqli").
				Str("pattern", pattern).
				Str("url", originalReq.URL.String()).
				Msg("SQLi pattern found in response")

			return &vulnscan.Vulnerability{
				Type:          p.Info().Name,
				URL:           originalReq.URL.String(),
				Payload:       payload,
				Param:         paramName,
				Method:        originalReq.Method,
				VulnerableURL: reqToTest.URL.String(),
				Timestamp:     time.Now(),
			}, nil
		}
	}

	return nil, nil
}
