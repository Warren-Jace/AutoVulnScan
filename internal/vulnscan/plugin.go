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
// 此函数支持两种JSON格式:
//  1. 结构化格式: 一个包含 "payloads" 键的JSON对象，其值为一个对象数组，每个对象都有 "value" 和 "description"。
//     [
//     {"value": "<script>alert(1)</script>", "description": "Basic XSS payload"},
//     ...
//     ]
//  2. 简单格式: 一个简单的字符串数组（为保持向后兼容）。
//     ["<script>alert(1)</script>", "<b>test</b>"]
//
// 参数:
//
//	pluginName (string): 插件的名称，用于定位对应的payload文件 (例如 "xss" -> "config/payloads/xss.json")。
//
// 返回:
//
//	[]string: 从文件中解析出的攻击载荷字符串切片。
//	error: 如果文件读取或解析失败，则返回错误。
func LoadPayloads(pluginName string) ([]string, error) {
	payloadFile := filepath.Join("config", "payloads", fmt.Sprintf("%s.json", pluginName))

	data, err := os.ReadFile(payloadFile)
	if err != nil {
		return nil, fmt.Errorf("读取payload文件 %s 失败: %w", payloadFile, err)
	}

	// 尝试解析结构化格式
	var structuredPayloads struct {
		Payloads []models.Payload `json:"payloads"`
	}
	if err := json.Unmarshal(data, &structuredPayloads); err == nil && len(structuredPayloads.Payloads) > 0 {
		var payloads []string
		for _, p := range structuredPayloads.Payloads {
			payloads = append(payloads, p.Value)
		}
		return payloads, nil
	}

	// 如果结构化解析失败或结果为空，则尝试解析简单的字符串数组格式
	var simplePayloads []string
	if err := json.Unmarshal(data, &simplePayloads); err == nil {
		return simplePayloads, nil
	}

	return nil, fmt.Errorf("无法从 %s 解析payloads：文件格式无效", payloadFile)
}
