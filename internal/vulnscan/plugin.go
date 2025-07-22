// vulnscan包提供核心漏洞扫描引擎和插件接口
package vulnscan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"autovulnscan/internal/models"
)

// Plugin 是所有漏洞扫描插件必须实现的接口
// 定义了插件的基本行为：提供信息和执行扫描
type Plugin interface {
	// Info 返回插件的基本信息，包括名称、描述、作者和版本
	Info() PluginInfo

	// Scan 执行漏洞扫描，接收请求和payload列表，返回发现的漏洞
	// 参数:
	//   - ctx: 上下文，用于控制扫描超时和取消
	//   - req: 要扫描的HTTP请求
	//   - payloads: 用于测试的payload列表
	// 返回:
	//   - []*Vulnerability: 发现的漏洞列表
	//   - error: 扫描过程中的错误
	Scan(ctx context.Context, req *models.Request, payloads []string) ([]*Vulnerability, error)
}

// PluginInfo 包含插件的元数据信息
// 用于描述插件的基本属性和版本信息
type PluginInfo struct {
	Name        string // 插件名称，用于标识和日志记录
	Description string // 插件描述，说明插件的功能和用途
	Author      string // 插件作者信息
	Version     string // 插件版本号，用于版本管理和兼容性检查
}

// Vulnerability 表示发现的单个漏洞
// 包含漏洞的详细信息，用于报告和分析
type Vulnerability struct {
	Type          string    `json:"type"`           // 漏洞类型，如XSS、SQL注入等
	URL           string    `json:"url"`            // 存在漏洞的原始URL
	Method        string    `json:"method"`         // HTTP请求方法（GET、POST等）
	Param         string    `json:"param"`          // 存在漏洞的参数名称
	Payload       string    `json:"payload"`        // 触发漏洞的payload
	VulnerableURL string    `json:"vulnerable_url"` // 包含payload的完整漏洞URL
	Timestamp     time.Time `json:"timestamp"`      // 漏洞发现时间戳
}

// Payload 表示单个攻击载荷及其元数据
// 用于结构化存储和管理测试payload
type Payload struct {
	Value       string `json:"value"`       // payload的实际内容
	Description string `json:"description"` // payload的描述信息，说明其用途和原理
}

// LoadPayloads 从JSON文件中加载漏洞测试payload
// 支持两种格式：结构化格式（包含描述）和简单字符串数组格式（向后兼容）
// 参数:
//   - pluginName: 插件名称，用于构造payload文件路径
//
// 返回:
//   - []string: payload字符串列表
//   - error: 加载过程中的错误
func LoadPayloads(pluginName string) ([]string, error) {
	// 构造payload文件路径：config/payloads/{pluginName}.json
	payloadFile := filepath.Join("config", "payloads", fmt.Sprintf("%s.json", pluginName))

	// 读取payload文件内容
	data, err := os.ReadFile(payloadFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read payload file %s: %w", payloadFile, err)
	}

	// 定义结构化payload文件格式
	var payloadFileContent struct {
		Payloads []Payload `json:"payloads"` // payload对象数组
	}

	// 尝试解析结构化格式
	if err := json.Unmarshal(data, &payloadFileContent); err != nil {
		// 如果结构化格式解析失败，尝试简单字符串数组格式（向后兼容）
		var payloads []string
		if err2 := json.Unmarshal(data, &payloads); err2 == nil {
			return payloads, nil
		}
		return nil, fmt.Errorf("failed to unmarshal payloads from %s: %w", payloadFile, err)
	}

	// 从结构化格式中提取payload值
	var payloads []string
	for _, p := range payloadFileContent.Payloads {
		payloads = append(payloads, p.Value)
	}

	return payloads, nil
}
