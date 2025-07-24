// Package vulnscan 提供了核心的漏洞扫描引擎和插件管理机制。
package vulnscan

import (
	"fmt"
	"sync"
	"time"

	"autovulnscan/internal/browser"
	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"

	"github.com/rs/zerolog/log"
)

// Engine 是漏洞扫描引擎，负责协调各种扫描插件对目标请求执行漏洞检测。
type Engine struct {
	plugins           []Plugin
	httpClient        *requester.HTTPClient
	browserService    *browser.BrowserService
	vulnerabilityChan chan *Vulnerability
}

// NewEngine 创建一个新的扫描引擎实例。
// 它会加载所有在插件注册表中注册的插件。
func NewEngine(client *requester.HTTPClient, browserService *browser.BrowserService) (*Engine, error) {
	plugins := GetPlugins()
	if len(plugins) == 0 {
		log.Warn().Msg("没有找到任何已注册的扫描插件")
	}

	engine := &Engine{
		httpClient:        client,
		browserService:    browserService,
		plugins:           plugins,
		vulnerabilityChan: make(chan *Vulnerability, 100),
	}

	// 注入依赖
	if err := engine.injectDependencies(); err != nil {
		log.Error().Err(err).Msg("依赖注入失败")
		return nil, fmt.Errorf("依赖注入失败: %w", err)
	}

	log.Info().Int("pluginCount", len(engine.plugins)).Msg("扫描引擎初始化完成")
	return engine, nil
}

// VulnerabilityChan 返回一个只读的漏洞通道
func (e *Engine) VulnerabilityChan() <-chan *Vulnerability {
	return e.vulnerabilityChan
}

// Close a vulnerability channel
func (e *Engine) Close() {
	if e.vulnerabilityChan != nil {
		close(e.vulnerabilityChan)
		log.Debug().Msg("漏洞通道已关闭")
	}
}

// pluginDependencyInjector 定义了需要依赖注入的插件接口
type pluginDependencyInjector interface {
	SetBrowserService(*browser.BrowserService)
}

// injectDependencies 负责向需要外部服务的插件注入依赖。
func (e *Engine) injectDependencies() error {
	injectedCount := 0

	for i, plugin := range e.plugins {
		if plugin == nil {
			log.Warn().Int("index", i).Msg("发现空插件，跳过")
			continue
		}

		// 记录插件信息
		info := plugin.Info()
		log.Debug().
			Str("name", info.Name).
			Str("version", info.Version).
			Str("author", info.Author).
			Msg("正在处理插件")

		// 检查是否需要浏览器服务注入
		if injector, ok := plugin.(pluginDependencyInjector); ok {
			if e.browserService != nil {
				injector.SetBrowserService(e.browserService)
				injectedCount++
				log.Debug().
					Str("plugin", info.Name).
					Msg("已注入浏览器服务")
			} else {
				log.Warn().
					Str("plugin", info.Name).
					Msg("插件需要浏览器服务，但服务未提供")
			}
		}
	}

	log.Info().
		Int("totalPlugins", len(e.plugins)).
		Int("injectedCount", injectedCount).
		Msg("依赖注入完成")

	return nil
}

// pluginResult 封装插件执行结果
type pluginResult struct {
	pluginName      string
	vulnerabilities []*Vulnerability
	err             error
	duration        time.Duration
}

// executePlugin 执行单个插件的扫描
func (e *Engine) executePlugin(plugin Plugin, req *models.Request) pluginResult {
	startTime := time.Now()
	info := plugin.Info()

	log.Debug().
		Str("plugin", info.Name).
		Str("url", req.URL).
		Str("method", req.Method).
		Msg("开始执行插件扫描")

	vulns, err := plugin.Scan(e.httpClient, req)
	duration := time.Since(startTime)

	result := pluginResult{
		pluginName:      info.Name,
		vulnerabilities: vulns,
		err:             err,
		duration:        duration,
	}

	if err != nil {
		log.Error().
			Err(err).
			Str("plugin", info.Name).
			Str("url", req.URL).
			Dur("duration", duration).
			Msg("插件扫描失败")
	} else {
		log.Debug().
			Str("plugin", info.Name).
			Str("url", req.URL).
			Int("vulnCount", len(vulns)).
			Dur("duration", duration).
			Msg("插件扫描完成")
	}

	return result
}

// sendVulnerabilities 发送漏洞到通道
func (e *Engine) sendVulnerabilities(results []pluginResult) {
	totalVulns := 0
	successfulPlugins := 0
	failedPlugins := 0

	for _, result := range results {
		if result.err != nil {
			failedPlugins++
			continue
		}

		successfulPlugins++
		for _, vuln := range result.vulnerabilities {
			if vuln != nil {
				select {
				case e.vulnerabilityChan <- vuln:
					totalVulns++
				default:
					log.Warn().
						Str("plugin", result.pluginName).
						Msg("漏洞通道已满，丢弃漏洞")
				}
			}
		}
	}

	log.Info().
		Int("totalVulns", totalVulns).
		Int("successfulPlugins", successfulPlugins).
		Int("failedPlugins", failedPlugins).
		Msg("漏洞发送完成")
}

// validateRequest 验证请求的有效性
func (e *Engine) validateRequest(req *models.Request) error {
	if req == nil {
		return fmt.Errorf("请求对象为空")
	}

	if req.URL == "" {
		return fmt.Errorf("请求URL为空")
	}

	if req.Method == "" {
		log.Warn().Str("url", req.URL).Msg("请求方法为空，默认使用GET")
		req.Method = "GET"
	}

	return nil
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
func (e *Engine) Execute(req *models.Request) {
	startTime := time.Now()

	// 验证请求
	if err := e.validateRequest(req); err != nil {
		log.Error().Err(err).Msg("请求验证失败")
		return
	}

	// 检查是否有可用的插件
	if len(e.plugins) == 0 {
		log.Warn().Str("url", req.URL).Msg("没有可用的扫描插件")
		return
	}

	log.Info().
		Str("url", req.URL).
		Str("method", req.Method).
		Int("pluginCount", len(e.plugins)).
		Int("paramCount", len(req.Params)).
		Msg("开始执行漏洞扫描")

	// 创建结果收集器
	results := make([]pluginResult, len(e.plugins))
	var wg sync.WaitGroup

	// 并发执行所有插件
	for i, plugin := range e.plugins {
		if plugin == nil {
			log.Warn().Int("index", i).Msg("跳过空插件")
			continue
		}

		wg.Add(1)
		go func(index int, p Plugin) {
			defer func() {
				wg.Done()
				// 恢复panic，避免单个插件崩溃影响整体扫描
				if r := recover(); r != nil {
					log.Error().
						Interface("panic", r).
						Str("plugin", p.Info().Name).
						Str("url", req.URL).
						Msg("插件执行时发生panic")
				}
			}()

			results[index] = e.executePlugin(p, req)
		}(i, plugin)
	}

	// 等待所有插件完成
	wg.Wait()

	// 发送漏洞到通道
	e.sendVulnerabilities(results)

	totalDuration := time.Since(startTime)
	log.Info().
		Str("url", req.URL).
		Dur("totalDuration", totalDuration).
		Msg("漏洞扫描执行完成")
}
