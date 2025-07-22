// vulnscan包提供核心漏洞扫描引擎
package vulnscan

import (
	"autovulnscan/internal/requester"
)

// Engine 是漏洞扫描引擎，负责协调各种扫描插件执行漏洞检测
type Engine struct {
	plugins    []Plugin              // 已加载的扫描插件列表
	httpClient *requester.HTTPClient // HTTP客户端，用于发送扫描请求
}

// NewEngine 创建一个新的扫描引擎实例
// 参数:
//   - client: HTTP客户端实例，用于网络请求
//
// 返回:
//   - *Engine: 扫描引擎实例
//   - error: 创建过程中的错误信息
func NewEngine(client *requester.HTTPClient) (*Engine, error) {
	// 初始化扫描引擎
	engine := &Engine{
		httpClient: client,       // 设置HTTP客户端
		plugins:    GetPlugins(), // 加载所有已注册的扫描插件
	}
	return engine, nil
}
