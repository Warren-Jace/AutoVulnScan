// Package plugins 包含了所有具体的漏洞扫描插件实现。
package plugins

import (
	"bytes"
	"io"
	"net/url"
	"strings"
	"time"

	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"
	"autovulnscan/internal/util"
	"autovulnscan/internal/vulnscan"

	"github.com/rs/zerolog/log"
)

// SQLiPlugin 实现了用于检测基于错误的SQL注入漏洞的插件。
type SQLiPlugin struct {
	errorPatterns []string
}

// init 函数会在包初始化时被调用，用于自动注册插件。
func init() {
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
	payloads, err := vulnscan.LoadPayloads("sqli")
	if err != nil {
		return nil, err
	}

	for _, param := range req.Params {
		for _, payload := range payloads {
			vuln, err := p.testPayload(client, req, param.Name, payload)
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
	newReq := util.CloneRequest(originalReq)

	if newReq.Request.Method == "POST" {
		bodyBytes, _ := io.ReadAll(newReq.Request.Body)
		newReq.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		form, _ := url.ParseQuery(string(bodyBytes))
		form.Set(paramName, payload)

		newReq.Request.Body = io.NopCloser(strings.NewReader(form.Encode()))
		newReq.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		q := newReq.Request.URL.Query()
		q.Set(paramName, payload)
		newReq.Request.URL.RawQuery = q.Encode()
	}

	resp, err := client.Do(newReq.Request)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	responseText := strings.ToLower(string(body))
	for _, pattern := range p.errorPatterns {
		if strings.Contains(responseText, pattern) {
			return &vulnscan.Vulnerability{
				Type:          p.Info().Name,
				URL:           originalReq.URL.String(),
				Payload:       payload,
				Param:         paramName,
				Method:        originalReq.Method,
				VulnerableURL: newReq.Request.URL.String(),
				Timestamp:     time.Now(),
			}, nil
		}
	}

	return nil, nil
}
