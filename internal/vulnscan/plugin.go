// Package vulnscan 提供了核心的漏洞扫描引擎和插件管理机制。
package vulnscan

import (
	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"
	"time"
)

// Plugin 插件接口
// 所有漏洞插件都应实现该接口
// Scan 返回发现的漏洞列表
// Info 返回插件元信息
type Plugin interface {
	Info() PluginInfo
	Scan(client *requester.HTTPClient, req *models.Request) ([]*Vulnerability, error)
}

// PluginInfo 插件元信息
type PluginInfo struct {
	Name        string
	Description string
	Author      string
	Version     string
}

// Vulnerability 漏洞结构体
type Vulnerability struct {
	Type          string    // 漏洞类型（如sqli/xss）
	URL           string    // 目标URL
	Payload       string    // 使用的payload
	Param         string    // 漏洞参数名
	Method        string    // 请求方法
	VulnerableURL string    // 可复现漏洞的完整URL
	Timestamp     time.Time // 检测时间
}
