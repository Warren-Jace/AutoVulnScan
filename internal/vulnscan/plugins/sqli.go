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

// SQLiPlugin 用于检测SQL注入漏洞
// 通过注入SQL payload并分析响应中的数据库错误信息来识别SQL注入漏洞
type SQLiPlugin struct {
	httpClient    *requester.HTTPClient // HTTP客户端，用于发送测试请求
	payloads      []models.Payload      // SQL注入测试payload列表
	errorPatterns []string              // 数据库错误信息匹配模式列表
}

// NewSQLiPlugin 创建一个新的SQL注入插件实例
// 从指定文件加载SQL注入payload，并初始化数据库错误匹配模式
// 参数:
//   - client: HTTP客户端实例，用于发送扫描请求
//   - payloadFile: SQL注入payload配置文件路径
//
// 返回:
//   - *SQLiPlugin: 初始化完成的SQL注入插件实例
//   - error: 初始化过程中的错误（如文件读取失败）
func NewSQLiPlugin(client *requester.HTTPClient, payloadFile string) (*SQLiPlugin, error) {
	// 从文件加载SQL注入payload
	payloads, err := loadSQLiPayloads(payloadFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load SQLi payloads: %w", err)
	}

	return &SQLiPlugin{
		httpClient: client,
		payloads:   payloads,
		// 预定义的数据库错误信息匹配模式
		// 这些模式用于识别不同数据库系统的错误响应
		errorPatterns: []string{
			"you have an error in your sql syntax",                   // MySQL语法错误
			"unclosed quotation mark",                                // SQL Server引号未闭合错误
			"supplied argument is not a valid mysql result resource", // MySQL资源错误
			"sql server", // SQL Server通用错误
			"microsoft ole db provider for odbc drivers error", // ODBC驱动错误
			"invalid querystring",                              // 无效查询字符串
			"odbc driver error",                                // ODBC驱动错误
			"oracle error",                                     // Oracle数据库错误
			"db2 sql error",                                    // DB2数据库错误
			"postgresql error",                                 // PostgreSQL数据库错误
			"sqlite error",                                     // SQLite数据库错误
		},
	}, nil
}

// Type 返回插件类型标识符
// 实现Plugin接口的Type方法
// 返回:
//   - string: 插件类型标识符"sqli"
func (p *SQLiPlugin) Type() string {
	return "sqli"
}

// Scan 执行SQL注入漏洞扫描
// 遍历所有参数和payload组合，测试每个可能的SQL注入点
// 参数:
//   - ctx: 上下文对象，用于控制扫描超时和取消
//   - req: 要扫描的HTTP请求对象
//   - payloads: SQL注入测试payload列表
//
// 返回:
//   - []*Vulnerability: 发现的SQL注入漏洞列表
//   - error: 扫描过程中的错误
func (p *SQLiPlugin) Scan(ctx context.Context, req *models.Request, payloads []string) ([]*Vulnerability, error) {
	var vulnerabilities []*Vulnerability

	// 遍历请求中的所有参数
	for _, param := range req.Params {
		// 对每个参数测试所有SQL注入payload
		for _, payload := range payloads {
			// 在每个参数上测试每个payload
			vuln, err := p.testPayload(ctx, req, param.Name, payload)
			if err != nil {
				// 记录测试失败的警告，但继续测试其他payload
				log.Warn().Err(err).Str("url", req.URL.String()).Msg("SQLi test failed")
				continue
			}
			// 如果发现漏洞，添加到结果列表
			if vuln != nil {
				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}

	return vulnerabilities, nil
}

// testPayload 在特定参数上测试单个SQL注入payload
// 通过修改参数值注入SQL payload，然后分析响应中是否包含数据库错误信息
// 参数:
//   - ctx: 上下文对象
//   - originalReq: 原始HTTP请求
//   - paramName: 要测试的参数名称
//   - payload: 要注入的SQL payload
//
// 返回:
//   - *Vulnerability: 如果发现漏洞则返回漏洞信息，否则返回nil
//   - error: 测试过程中的错误
func (p *SQLiPlugin) testPayload(ctx context.Context, originalReq *models.Request, paramName, payload string) (*Vulnerability, error) {
	// 克隆原始请求以避免修改原始数据
	newReq := cloneRequest(originalReq)

	// 根据请求方法（GET/POST）将payload注入到参数中
	if newReq.Request.Method == "POST" {
		// 如果是POST请求，需要处理表单数据
		bodyBytes, _ := io.ReadAll(newReq.Request.Body)
		newReq.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // 重新赋值Body以供后续使用

		// 解析表单数据并设置payload
		form, _ := url.ParseQuery(string(bodyBytes))
		form.Set(paramName, payload) // 将指定参数的值设置为SQL注入payload

		// 重新构造请求体
		newReq.Request.Body = io.NopCloser(strings.NewReader(form.Encode()))
		newReq.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		// 如果是GET请求，直接修改URL查询参数
		q := newReq.Request.URL.Query()
		q.Set(paramName, payload) // 将指定查询参数的值设置为SQL注入payload
		newReq.Request.URL.RawQuery = q.Encode()
	}

	// 发送带有SQL注入payload的请求
	resp, err := p.httpClient.Do(newReq.Request.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 读取响应体内容
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// 检查响应体中是否包含数据库错误信息
	// 将响应内容转换为小写以进行大小写不敏感的匹配
	responseText := strings.ToLower(string(body))

	for _, pattern := range p.errorPatterns {
		if strings.Contains(responseText, pattern) {
			// 如果找到匹配的数据库错误信息，说明可能存在SQL注入漏洞
			return &Vulnerability{
				Type:          p.Type(),                    // 漏洞类型：sqli
				URL:           originalReq.URL.String(),    // 原始URL
				Payload:       payload,                     // 触发漏洞的SQL payload
				Param:         paramName,                   // 存在漏洞的参数名
				Method:        originalReq.Method,          // HTTP请求方法
				VulnerableURL: newReq.Request.URL.String(), // 包含payload的完整URL
			}, nil
		}
	}

	// 未发现SQL注入漏洞
	return nil, nil
}

// loadSQLiPayloads 从JSON文件中加载SQL注入payload
// 解析包含SQL注入测试payload的配置文件
// 参数:
//   - file: payload配置文件的路径
//
// 返回:
//   - []models.Payload: 解析出的payload列表
//   - error: 文件读取或解析过程中的错误
func loadSQLiPayloads(file string) ([]models.Payload, error) {
	// 打开payload配置文件
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// 定义用于解析JSON的数据结构
	var data struct {
		Payloads []models.Payload `json:"payloads"` // payload数组
	}

	// 解析JSON文件内容
	if err := json.NewDecoder(f).Decode(&data); err != nil {
		return nil, err
	}

	return data.Payloads, nil
}
