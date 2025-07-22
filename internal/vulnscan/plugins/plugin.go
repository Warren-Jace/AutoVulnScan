// plugins包定义了漏洞扫描插件的接口规范
package plugins

import (
	"context"
	"time"

	"autovulnscan/internal/models"
)

// PluginInfo 包含插件的元数据信息
// 用于描述插件的基本属性，便于插件管理和用户识别
type PluginInfo struct {
	Name        string // 插件名称，用于唯一标识插件
	Description string // 插件功能描述，说明插件检测的漏洞类型和原理
	Author      string // 插件作者信息
	Version     string // 插件版本号，用于版本控制和兼容性管理
}

// cloneRequest 创建给定请求的深拷贝
// 用于在插件扫描过程中避免修改原始请求对象，确保并发安全
// 参数:
//   - r: 要克隆的原始请求对象
//
// 返回:
//   - *models.Request: 克隆后的请求对象副本
func cloneRequest(r *models.Request) *models.Request {
	// Create a deep copy of the request
	// 创建请求的深拷贝，避免插件修改原始请求影响其他插件
	r2 := new(models.Request)                           // 创建新的请求对象
	*r2 = *r                                            // 复制基本字段
	r2.Request = r.Request.Clone(context.Background())  // 深拷贝HTTP请求对象
	r2.Params = make([]models.Parameter, len(r.Params)) // 创建新的参数切片
	copy(r2.Params, r.Params)                           // 复制所有参数

	return r2
}

// Vulnerability 表示发现的单个漏洞
// 包含漏洞的完整信息，用于生成扫描报告和后续分析
type Vulnerability struct {
	Type          string    `json:"type"`           // 漏洞类型，如"xss"、"sqli"等
	URL           string    `json:"url"`            // 存在漏洞的原始URL地址
	Payload       string    `json:"payload"`        // 触发漏洞的攻击载荷
	Param         string    `json:"param"`          // 存在漏洞的参数名称
	Method        string    `json:"method"`         // HTTP请求方法（GET、POST等）
	VulnerableURL string    `json:"vulnerable_url"` // 包含payload的完整漏洞URL
	Timestamp     time.Time `json:"timestamp"`      // 漏洞发现的时间戳
}

// Plugin 是所有漏洞扫描插件必须实现的接口
// 定义了插件的基本行为规范，确保插件的一致性和可互换性
type Plugin interface {
	// Type 返回插件的类型标识符
	// 用于区分不同类型的漏洞检测插件，如XSS、SQL注入等
	// 返回:
	//   - string: 插件类型字符串，应使用小写字母和下划线
	Type() string

	// Scan 对给定的参数化URL执行漏洞扫描
	// 这是插件的核心功能，负责检测特定类型的安全漏洞
	// 参数:
	//   - ctx: 上下文对象，用于控制扫描超时和取消操作
	//   - pURL: 参数化URL对象，包含要扫描的URL和参数信息
	// 返回:
	//   - []Vulnerability: 发现的漏洞列表，如果没有发现漏洞则返回空切片
	//   - error: 扫描过程中发生的错误，如网络错误、解析错误等
	Scan(ctx context.Context, pURL models.ParameterizedURL) ([]Vulnerability, error)
}
