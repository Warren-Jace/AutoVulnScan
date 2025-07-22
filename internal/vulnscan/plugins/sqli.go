package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"

	"bytes"

	"github.com/rs/zerolog/log"
)

// SQLiPlugin checks for SQL Injection vulnerabilities.
type SQLiPlugin struct {
	httpClient    *requester.HTTPClient
	payloads      []models.Payload
	errorPatterns []string
}

// NewSQLiPlugin creates a new SQLiPlugin.
func NewSQLiPlugin(client *requester.HTTPClient, payloadFile string) (*SQLiPlugin, error) {
	payloads, err := loadSQLiPayloads(payloadFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load SQLi payloads: %w", err)
	}

	return &SQLiPlugin{
		httpClient: client,
		payloads:   payloads,
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
	}, nil
}

// Type returns the plugin type.
func (p *SQLiPlugin) Type() string {
	return "sqli"
}

// Scan performs the SQLi scan.
func (p *SQLiPlugin) Scan(ctx context.Context, req *models.Request, payloads []string) ([]*Vulnerability, error) {
	var vulnerabilities []*Vulnerability

	for _, param := range req.Params {
		for _, payload := range payloads {
			// 在每个参数上测试每个payload
			vuln, err := p.testPayload(ctx, req, param.Name, payload)
			if err != nil {
				log.Warn().Err(err).Str("url", req.URL.String()).Msg("SQLi test failed")
				continue
			}
			if vuln != nil {
				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}

	return vulnerabilities, nil
}

// testPayload tests a single payload on a specific parameter.
func (p *SQLiPlugin) testPayload(ctx context.Context, originalReq *models.Request, paramName, payload string) (*Vulnerability, error) {
	// 克隆原始请求以避免修改
	newReq := cloneRequest(originalReq)

	// 根据请求方法（GET/POST）将payload注入到参数中
	if newReq.Request.Method == "POST" {
		// 如果是POST请求，需要处理表单数据
		bodyBytes, _ := io.ReadAll(newReq.Request.Body)
		newReq.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // 重新赋值Body
		form, _ := url.ParseQuery(string(bodyBytes))
		form.Set(paramName, payload)
		newReq.Request.Body = io.NopCloser(strings.NewReader(form.Encode()))
		newReq.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		// 如果是GET请求，直接修改查询参数
		q := newReq.Request.URL.Query()
		q.Set(paramName, payload)
		newReq.Request.URL.RawQuery = q.Encode()
	}

	// 发送带有payload的请求
	resp, err := p.httpClient.Do(newReq.Request.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// 检查响应体中是否包含数据库错误信息
	for _, pattern := range p.errorPatterns {
		if strings.Contains(strings.ToLower(string(body)), pattern) {
			// 如果找到错误信息，说明可能存在SQL注入漏洞
			return &Vulnerability{
				Type:          p.Type(),
				URL:           originalReq.URL.String(),
				Payload:       payload,
				Param:         paramName,
				Method:        originalReq.Method,
				VulnerableURL: newReq.Request.URL.String(),
			}, nil
		}
	}

	// 未发现漏洞
	return nil, nil
}

func loadSQLiPayloads(file string) ([]models.Payload, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var data struct {
		Payloads []models.Payload `json:"payloads"`
	}
	if err := json.NewDecoder(f).Decode(&data); err != nil {
		return nil, err
	}
	return data.Payloads, nil
}
