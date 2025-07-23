// Package vulnscan 提供了核心的漏洞扫描引擎和插件管理机制。
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

// Plugin 是所有漏洞扫描插件必须实现的接口。
// 它定义了插件的基本行为：提供元数据信息和执行扫描逻辑。
type Plugin interface {
	// Info 返回插件的基本信息。
	Info() PluginInfo

	// Scan 对给定的HTTP请求执行漏洞扫描。
	//
	// 参数:
	//   client (*requester.HTTPClient): 用于发送HTTP请求的客户端。
	//   req (*models.Request): 要扫描的目标HTTP请求。
	//
	// 返回:
	//   []*Vulnerability: 发现的漏洞列表。
	//   error: 扫描过程中发生的错误。
	Scan(client *requester.HTTPClient, req *models.Request) ([]*Vulnerability, error)
}

// PluginInfo 包含了插件的元数据信息。
type PluginInfo struct {
	Name        string // 插件的唯一名称，用于标识和日志记录。
	Description string // 对插件功能的简要描述。
	Author      string // 插件的作者。
	Version     string // 插件的版本号。
}

// Vulnerability 代表一个被发现的、具体的安全漏洞。
// 它包含了用于生成报告的所有必要信息。
type Vulnerability struct {
	Type          string    `json:"type"`           // 漏洞类型，例如 "xss", "sqli"。
	URL           string    `json:"url"`            // 存在漏洞的原始URL。
	Method        string    `json:"method"`         // 触发漏洞的HTTP请求方法 (GET, POST, etc.)。
	Param         string    `json:"param"`          // 存在漏洞的参数名称。
	Payload       string    `json:"payload"`        // 成功触发漏洞的攻击载荷。
	VulnerableURL string    `json:"vulnerable_url"` // 包含攻击载荷的完整可复现URL。
	Timestamp     time.Time `json:"timestamp"`      // 漏洞被发现的时间戳。
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
