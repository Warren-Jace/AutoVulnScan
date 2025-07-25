// Package vulnscan 包含了漏洞扫描引擎的核心逻辑和插件系统。
package vulnscan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"autovulnscan/internal/models"
	"autovulnscan/internal/requester" // 引入 requester 包
)

// Plugin 是所有漏洞扫描插件都必须实现的接口。
// 它定义了一个插件的基本行为：接收一个HTTP请求，并返回发现的漏洞。
type Plugin interface {
	// Name 返回插件的唯一名称，例如 "xss", "sqli"。
	Name() string
	// Scan 对给定的HTTP请求执行漏洞扫描。
	// 它应该返回一个包含所有发现的漏洞的切片，或者在发生错误时返回一个error。
	Scan(client *requester.HTTPClient, req *models.Request) ([]*Vulnerability, error)
}

// PluginInfo 包含了插件的元数据信息。
type PluginInfo struct {
	Name        string // 插件的唯一名称，用于标识和日志记录。
	Description string // 对插件功能的简要描述。
	Author      string // 插件的作者。
	Version     string // 插件的版本号。
}

// Vulnerability 代表一个被发现的安全漏洞。
// 它包含了关于漏洞的详细信息，如类型、URL、参数、使用的payload，以及用于验证的完整请求和响应。
type Vulnerability struct {
	Type         string    `json:"type"`          // 漏洞类型，例如 "xss", "sqli"。
	URL          string    `json:"url"`           // 存在漏洞的原始URL。
	Method       string    `json:"method"`        // 触发漏洞的HTTP请求方法 (GET, POST, etc.)。
	Param        string    `json:"param"`         // 存在漏洞的参数名称。
	Payload      string    `json:"payload"`       // 用于触发漏洞的攻击载荷。
	Timestamp    time.Time `json:"timestamp"`     // 漏洞发现的时间戳。
	RequestDump  string    `json:"request_dump"`  // 完整的HTTP请求报文。
	ResponseDump string    `json:"response_dump"` // 完整的HTTP响应报文。
}

// NewVulnerability 创建并返回一个新的Vulnerability实例。
// 它会自动设置当前时间为漏洞发现的时间戳。
func NewVulnerability(vulnType, url, method, param, payload, requestDump, responseDump string) *Vulnerability {
	return &Vulnerability{
		Type:         vulnType,
		URL:          url,
		Method:       method,
		Param:        param,
		Payload:      payload,
		Timestamp:    time.Now(),
		RequestDump:  requestDump,
		ResponseDump: responseDump,
	}
}

// LoadPayloads 从插件专属的JSON文件中加载攻击载荷。
//
// JSON文件应包含一个对象数组，每个对象都有 "value" 和 "description" 字段。
// 例如:
// [
//
//	{"value": "<script>alert(1)</script>", "description": "Basic XSS payload"},
//	...
//
// ]
//
// 参数:
//
//	pluginName (string): 插件的名称，用于定位对应的payload文件 (例如 "xss" -> "config/payloads/xss.json")。
//
// 返回:
//
//	[]models.Payload: 从文件中解析出的攻击载荷结构体切片。
//	error: 如果文件读取或解析失败，则返回错误。
func LoadPayloads(pluginName string) ([]models.Payload, error) {
	payloadFile := filepath.Join("config", "payloads", fmt.Sprintf("%s.json", pluginName))

	data, err := os.ReadFile(payloadFile)
	if err != nil {
		return nil, fmt.Errorf("读取payload文件 %s 失败: %w", payloadFile, err)
	}

	var payloads []models.Payload
	if err := json.Unmarshal(data, &payloads); err != nil {
		// 尝试解析旧的 {"payloads": [...]} 格式以保持向后兼容
		var oldFormat struct {
			Payloads []models.Payload `json:"payloads"`
		}
		if err2 := json.Unmarshal(data, &oldFormat); err2 == nil {
			return oldFormat.Payloads, nil
		}
		return nil, fmt.Errorf("无法从 %s 解析payloads：JSON格式无效: %w", payloadFile, err)
	}

	return payloads, nil
}
