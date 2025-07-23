// Package vulnscan 提供了核心的漏洞扫描引擎和插件管理机制。
package vulnscan

import (
	"sync"

	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"
)

// Engine 是漏洞扫描引擎，负责协调各种扫描插件对目标请求执行漏洞检测。
type Engine struct {
	plugins    []Plugin              // 已加载的所有扫描插件的列表。
	httpClient *requester.HTTPClient // 用于发送扫描请求的HTTP客户端。
}

// NewEngine 创建一个新的扫描引擎实例。
// 它会加载所有在插件注册表中注册的插件。
//
// 参数:
//
//	client: 一个 requester.HTTPClient 实例，用于所有插件的网络请求。
//
// 返回:
//
//	*Engine: 一个初始化完成的扫描引擎实例。
//	error: 如果创建过程中出现错误，则返回错误信息。
func NewEngine(client *requester.HTTPClient) (*Engine, error) {
	engine := &Engine{
		httpClient: client,
		plugins:    GetPlugins(), // 从插件注册表加载所有已注册的插件。
	}
	return engine, nil
}

// Execute 方法负责对单个目标请求执行所有已加载的漏洞扫描插件。
// 它使用并发的方式运行所有插件，以提高扫描效率。
//
// 参数:
//
//	req (*models.Request): 需要被扫描的目标请求，包含了URL、方法、参数等信息。
//
// 返回:
//
//	[]*Vulnerability: 一个包含了所有被发现的漏洞的切片。
func (e *Engine) Execute(req *models.Request) []*Vulnerability {
	var vulnerabilities []*Vulnerability
	var wg sync.WaitGroup
	vulnChan := make(chan *Vulnerability, len(e.plugins))

	for _, plugin := range e.plugins {
		wg.Add(1)
		go func(p Plugin) {
			defer wg.Done()
			// 调用插件的 Scan 方法执行扫描。
			if vulns, err := p.Scan(e.httpClient, req); err == nil {
				for _, v := range vulns {
					vulnChan <- v
				}
			}
		}(plugin)
	}

	// 等待所有插件执行完毕。
	wg.Wait()
	close(vulnChan)

	// 从channel中收集所有发现的漏洞。
	for v := range vulnChan {
		vulnerabilities = append(vulnerabilities, v)
	}

	return vulnerabilities
}
