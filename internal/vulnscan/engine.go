// Package vulnscan 提供了核心的漏洞扫描引擎和插件管理机制。
package vulnscan

import (
	"sync"

	"autovulnscan/internal/browser"
	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"
)

// Engine 是漏洞扫描引擎，负责协调各种扫描插件对目标请求执行漏洞检测。
type Engine struct {
	plugins        []Plugin
	httpClient     *requester.HTTPClient
	browserService *browser.BrowserService
}

// NewEngine 创建一个新的扫描引擎实例。
// 它会加载所有在插件注册表中注册的插件。
func NewEngine(client *requester.HTTPClient, browserService *browser.BrowserService) (*Engine, error) {
	engine := &Engine{
		httpClient:     client,
		browserService: browserService,
		plugins:        GetPlugins(),
	}

	// 注入依赖
	engine.injectDependencies()

	return engine, nil
}

// injectDependencies 负责向需要外部服务的插件注入依赖。
func (e *Engine) injectDependencies() {
	for _, p := range e.plugins {
		// 使用类型断言检查插件是否需要浏览器服务
		if xssPlugin, ok := p.(interface{ SetBrowserService(*browser.BrowserService) }); ok {
			xssPlugin.SetBrowserService(e.browserService)
		}
	}
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
