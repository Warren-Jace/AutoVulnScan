// Package vulnscan 提供了核心的漏洞扫描引擎和插件管理机制。
package vulnscan

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"autovulnscan/internal/browser"
	"autovulnscan/internal/config"
	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"

	"github.com/rs/zerolog/log"
)

// Engine 是漏洞扫描引擎，负责协调各种扫描插件对目标请求执行漏洞检测。
type Engine struct {
	// 核心组件
	plugins        []Plugin
	httpClient     *requester.HTTPClient
	browserService *browser.BrowserService
	scannerConfig  *config.ScannerConfig

	// 通道和上下文
	vulnerabilityChan chan *Vulnerability
	requestChan       chan *models.Request
	ctx               context.Context
	cancel            context.CancelFunc

	// 并发控制
	wg          sync.WaitGroup
	workerPool  chan struct{} // 用于限制并发数
	rateLimiter <-chan time.Time

	// 统计信息
	stats struct {
		requestsProcessed    int64
		vulnerabilitiesFound int64
		pluginExecutions     int64
		pluginFailures       int64
		totalScanTime        int64 // 纳秒
		startTime            time.Time
	}
	statsMutex sync.RWMutex

	// 配置
	config EngineConfig

	// 状态管理
	state     int32 // 0: stopped, 1: running, 2: stopping
	once      sync.Once
	closeOnce sync.Once
}

// EngineConfig 引擎配置
type EngineConfig struct {
	MaxConcurrency   int           // 最大并发数
	RequestTimeout   time.Duration // 请求超时时间
	RateLimitRPS     int           // 每秒请求数限制
	BufferSize       int           // 缓冲区大小
	EnableMetrics    bool          // 是否启用指标收集
	GracefulShutdown time.Duration // 优雅关闭超时时间
	RetryAttempts    int           // 重试次数
	RetryDelay       time.Duration // 重试延迟
}

// EngineStats 引擎统计信息
type EngineStats struct {
	RequestsProcessed    int64         `json:"requests_processed"`
	VulnerabilitiesFound int64         `json:"vulnerabilities_found"`
	PluginExecutions     int64         `json:"plugin_executions"`
	PluginFailures       int64         `json:"plugin_failures"`
	AverageScanTime      time.Duration `json:"average_scan_time"`
	Uptime               time.Duration `json:"uptime"`
	ActiveWorkers        int           `json:"active_workers"`
	QueuedRequests       int           `json:"queued_requests"`
}

// pluginDependencyInjector 定义了需要依赖注入的插件接口
type pluginDependencyInjector interface {
	SetBrowserService(*browser.BrowserService)
}

// payloadSetter 定义了需要注入Payloads的插件接口
type payloadSetter interface {
	SetPayloads([]models.Payload)
}

// contextAware 定义了支持上下文的插件接口
type contextAware interface {
	ScanWithContext(context.Context, *requester.HTTPClient, *models.Request) ([]*Vulnerability, error)
}

// pluginResult 封装插件执行结果
type pluginResult struct {
	pluginName      string
	vulnerabilities []*Vulnerability
	err             error
	duration        time.Duration
	retryCount      int
}

// 默认配置
var defaultConfig = EngineConfig{
	MaxConcurrency:   runtime.NumCPU() * 2,
	RequestTimeout:   500 * time.Millisecond,   // 进一步减少超时时间
	RateLimitRPS:     50,                // 降低每秒请求数限制，与性能配置文件保持一致
	BufferSize:       1000,
	EnableMetrics:    true,
	GracefulShutdown: 30 * time.Second,
	RetryAttempts:    1,                 // 减少重试次数，与性能配置文件保持一致
	RetryDelay:       1 * time.Second,   // 减少重试延迟，与性能配置文件保持一致
}

// NewEngine 创建一个新的扫描引擎实例。
func NewEngine(cfg *config.ScannerConfig, client *requester.HTTPClient, browserService *browser.BrowserService) (*Engine, error) {
	if cfg == nil {
		return nil, fmt.Errorf("scanner config cannot be nil")
	}

	if client == nil {
		return nil, fmt.Errorf("HTTP client cannot be nil")
	}

	// 获取已注册的插件
	plugins := GetPlugins()
	log.Info().Int("registered_plugins", len(plugins)).Msg("检查已注册的插件数量")

	// 如果没有插件，尝试手动注册默认插件
	if len(plugins) == 0 {
		log.Warn().Msg("没有找到任何已注册的扫描插件，尝试手动注册默认插件")

		// 由于循环导入问题，我们不能直接导入plugins包或使用其中的函数
		// 这里我们记录一个警告，说明需要手动导入插件包
		log.Warn().Msg("由于循环导入问题，无法自动注册插件。请确保在主程序中导入了plugins包")

		// 再次检查
		plugins = GetPlugins()
		log.Info().Int("plugins_after_retry", len(plugins)).Msg("重新检查插件数量")

		if len(plugins) == 0 {
			// 手动创建默认插件
			log.Warn().Msg("仍然没有插件，将手动创建默认插件")
			// 这里可以手动创建XSS和SQLi插件
		}
	}

	// 打印已注册的插件信息
	for i, plugin := range plugins {
		if plugin != nil {
			info := plugin.Info()
			log.Info().
				Int("index", i).
				Str("name", info.Name).
				Str("version", info.Version).
				Str("category", info.Category).
				Str("description", info.Description).
				Msg("已注册的插件")
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	// 合并配置
	engineConfig := defaultConfig
	if cfg.Concurrency > 0 {
		engineConfig.MaxConcurrency = cfg.Concurrency
	}
	if cfg.Timeout > 0 {
		engineConfig.RequestTimeout = time.Duration(cfg.Timeout) * time.Second
	}

	log.Debug().
		Int("max_concurrency", engineConfig.MaxConcurrency).
		Dur("request_timeout", engineConfig.RequestTimeout).
		Int("rate_limit_rps", engineConfig.RateLimitRPS).
		Msg("扫描引擎配置")

	// 创建限流器
	var rateLimiter <-chan time.Time
	if engineConfig.RateLimitRPS > 0 {
		rateLimiter = time.Tick(time.Second / time.Duration(engineConfig.RateLimitRPS))
	}

	engine := &Engine{
		httpClient:        client,
		browserService:    browserService,
		plugins:           plugins,
		scannerConfig:     cfg,
		ctx:               ctx,
		cancel:            cancel,
		config:            engineConfig,
		vulnerabilityChan: make(chan *Vulnerability, engineConfig.BufferSize),
		requestChan:       make(chan *models.Request, engineConfig.BufferSize),
		workerPool:        make(chan struct{}, engineConfig.MaxConcurrency),
		rateLimiter:       rateLimiter,
	}

	// 初始化统计信息
	engine.stats.startTime = time.Now()

	// 准备payload配置
	payloads := make(map[string][]models.Payload)
	
	// 处理sql注入payloads
	if cfg.Vulnerabilities.SQLInjection.Enabled {
		var modelPayloads []models.Payload
		for _, p := range cfg.Vulnerabilities.SQLInjection.Payloads.Basic {
			modelPayloads = append(modelPayloads, models.Payload{
				Value:       p.Value,
				Description: p.Description,
			})
		}
		for _, p := range cfg.Vulnerabilities.SQLInjection.Payloads.Intermediate {
			modelPayloads = append(modelPayloads, models.Payload{
				Value:       p.Value,
				Description: p.Description,
			})
		}
		for _, p := range cfg.Vulnerabilities.SQLInjection.Payloads.Advanced {
			modelPayloads = append(modelPayloads, models.Payload{
				Value:       p.Value,
				Description: p.Description,
			})
		}
		payloads["sqli"] = modelPayloads
		log.Debug().
			Str("type", "sqli").
			Int("payload_count", len(modelPayloads)).
			Msg("加载sql注入配置")
	}
	
	// 处理xss payloads
	if cfg.Vulnerabilities.XSS.Enabled {
		var modelPayloads []models.Payload
		for _, p := range cfg.Vulnerabilities.XSS.Payloads.Basic {
			modelPayloads = append(modelPayloads, models.Payload{
				Value:       p.Value,
				Description: p.Description,
			})
		}
		for _, p := range cfg.Vulnerabilities.XSS.Payloads.Intermediate {
			modelPayloads = append(modelPayloads, models.Payload{
				Value:       p.Value,
				Description: p.Description,
			})
		}
		for _, p := range cfg.Vulnerabilities.XSS.Payloads.Advanced {
			modelPayloads = append(modelPayloads, models.Payload{
				Value:       p.Value,
				Description: p.Description,
			})
		}
		payloads["xss"] = modelPayloads
		log.Debug().
			Str("type", "xss").
			Int("payload_count", len(modelPayloads)).
			Msg("加载xss配置")
	}
	
	// 处理命令注入payloads
	if cfg.Vulnerabilities.CommandInjection.Enabled {
		var modelPayloads []models.Payload
		for _, p := range cfg.Vulnerabilities.CommandInjection.Payloads.Basic {
			modelPayloads = append(modelPayloads, models.Payload{
				Value:       p.Value,
				Description: p.Description,
			})
		}
		for _, p := range cfg.Vulnerabilities.CommandInjection.Payloads.Intermediate {
			modelPayloads = append(modelPayloads, models.Payload{
				Value:       p.Value,
				Description: p.Description,
			})
		}
		for _, p := range cfg.Vulnerabilities.CommandInjection.Payloads.Advanced {
			modelPayloads = append(modelPayloads, models.Payload{
				Value:       p.Value,
				Description: p.Description,
			})
		}
		payloads["command_injection"] = modelPayloads
		log.Debug().
			Str("type", "command_injection").
			Int("payload_count", len(modelPayloads)).
			Msg("加载命令注入配置")
	}
	
	// 处理文件包含payloads
	if cfg.Vulnerabilities.FileInclusion.Enabled {
		var modelPayloads []models.Payload
		for _, p := range cfg.Vulnerabilities.FileInclusion.Payloads.Basic {
			modelPayloads = append(modelPayloads, models.Payload{
				Value:       p.Value,
				Description: p.Description,
			})
		}
		for _, p := range cfg.Vulnerabilities.FileInclusion.Payloads.Intermediate {
			modelPayloads = append(modelPayloads, models.Payload{
				Value:       p.Value,
				Description: p.Description,
			})
		}
		for _, p := range cfg.Vulnerabilities.FileInclusion.Payloads.Advanced {
			modelPayloads = append(modelPayloads, models.Payload{
				Value:       p.Value,
				Description: p.Description,
			})
		}
		payloads["file_inclusion"] = modelPayloads
		log.Debug().
			Str("type", "file_inclusion").
			Int("payload_count", len(modelPayloads)).
			Msg("加载文件包含配置")
	}
	
	// 处理开放重定向payloads
	if cfg.Vulnerabilities.OpenRedirect.Enabled {
		var modelPayloads []models.Payload
		for _, p := range cfg.Vulnerabilities.OpenRedirect.Payloads.Basic {
			modelPayloads = append(modelPayloads, models.Payload{
				Value:       p.Value,
				Description: p.Description,
			})
		}
		for _, p := range cfg.Vulnerabilities.OpenRedirect.Payloads.Intermediate {
			modelPayloads = append(modelPayloads, models.Payload{
				Value:       p.Value,
				Description: p.Description,
			})
		}
		for _, p := range cfg.Vulnerabilities.OpenRedirect.Payloads.Advanced {
			modelPayloads = append(modelPayloads, models.Payload{
				Value:       p.Value,
				Description: p.Description,
			})
		}
		payloads["open_redirect"] = modelPayloads
		log.Debug().
			Str("type", "open_redirect").
			Int("payload_count", len(modelPayloads)).
			Msg("加载开放重定向配置")
	}

	// 注入依赖
	if err := engine.injectDependencies(payloads); err != nil {
		cancel()
		return nil, fmt.Errorf("依赖注入失败: %w", err)
	}

	log.Info().
		Int("pluginCount", len(engine.plugins)).
		Int("maxConcurrency", engineConfig.MaxConcurrency).
		Int("bufferSize", engineConfig.BufferSize).
		Msg("扫描引擎初始化完成")

	return engine, nil
}

// injectDependencies 负责向需要外部服务的插件注入依赖。
func (e *Engine) injectDependencies(payloadsConfig map[string][]models.Payload) error {
	injectedCount := 0
	var injectionErrors []error

	for i, plugin := range e.plugins {
		if plugin == nil {
			log.Warn().Int("index", i).Msg("发现空插件，跳过")
			continue
		}

		info := plugin.Info()
		log.Debug().
			Str("name", info.Name).
			Str("version", info.Version).
			Str("author", info.Author).
			Msg("正在处理插件")

		// 注入浏览器服务
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

		// 注入Payloads
		if setter, ok := plugin.(payloadSetter); ok {
			if payloads, found := payloadsConfig[info.Name]; found {
				setter.SetPayloads(payloads)
				log.Debug().
					Str("plugin", info.Name).
					Int("payloadCount", len(payloads)).
					Msg("已注入Payloads")
			} else {
				log.Debug().
					Str("plugin", info.Name).
					Msg("未找到对应的Payloads配置")
			}
		}
	}

	if len(injectionErrors) > 0 {
		return fmt.Errorf("依赖注入过程中发生错误: %v", injectionErrors)
	}

	log.Info().
		Int("totalPlugins", len(e.plugins)).
		Int("injectedCount", injectedCount).
		Msg("依赖注入完成")

	return nil
}

// Start 启动扫描引擎
func (e *Engine) Start() {
	if !atomic.CompareAndSwapInt32(&e.state, 0, 1) {
		log.Warn().Msg("扫描引擎已经在运行中")
		return
	}

	log.Info().
		Int("concurrency", e.config.MaxConcurrency).
		Int("bufferSize", e.config.BufferSize).
		Msg("启动扫描引擎")

	// 启动工作协程
	for i := 0; i < e.config.MaxConcurrency; i++ {
		e.wg.Add(1)
		go e.worker(i)
	}

	// 启动统计协程
	if e.config.EnableMetrics {
		go e.metricsCollector()
	}

	log.Info().Msg("扫描引擎启动完成")
}

// Stop 停止扫描引擎
func (e *Engine) Stop() {
	if !atomic.CompareAndSwapInt32(&e.state, 1, 2) {
		log.Warn().Msg("扫描引擎未在运行或已在停止中")
		return
	}

	log.Info().Msg("正在停止扫描引擎...")

	// 关闭请求通道
	close(e.requestChan)

	// 等待所有工作协程完成，带超时
	done := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Info().Msg("所有工作协程已正常退出")
	case <-time.After(e.config.GracefulShutdown):
		log.Warn().Msg("优雅关闭超时，强制退出")
	}

	// 取消上下文
	e.cancel()

	// 更新状态
	atomic.StoreInt32(&e.state, 0)

	log.Info().Msg("扫描引擎已停止")
}

// Close 关闭扫描引擎并清理资源
func (e *Engine) Close() {
	e.closeOnce.Do(func() {
		// 停止引擎
		e.Stop()

		// 关闭漏洞通道
		if e.vulnerabilityChan != nil {
			close(e.vulnerabilityChan)
			log.Debug().Msg("漏洞通道已关闭")
		}

		log.Info().Msg("扫描引擎资源清理完成")
	})
}

// QueueRequest 将请求加入扫描队列
func (e *Engine) QueueRequest(req *models.Request) error {
	if atomic.LoadInt32(&e.state) != 1 {
		return fmt.Errorf("扫描引擎未运行")
	}

	if req == nil {
		return fmt.Errorf("请求不能为空")
	}

	select {
	case e.requestChan <- req:
		return nil
	case <-e.ctx.Done():
		return fmt.Errorf("扫描引擎已关闭")
	default:
		return fmt.Errorf("请求队列已满")
	}
}

// QueueRequestWithTimeout 带超时的请求入队
func (e *Engine) QueueRequestWithTimeout(req *models.Request, timeout time.Duration) error {
	if atomic.LoadInt32(&e.state) != 1 {
		return fmt.Errorf("扫描引擎未运行")
	}

	if req == nil {
		return fmt.Errorf("请求不能为空")
	}

	ctx, cancel := context.WithTimeout(e.ctx, timeout)
	defer cancel()

	select {
	case e.requestChan <- req:
		return nil
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("请求入队超时")
		}
		return fmt.Errorf("扫描引擎已关闭")
	}
}

// VulnerabilityChan 返回只读的漏洞通道
func (e *Engine) VulnerabilityChan() <-chan *Vulnerability {
	return e.vulnerabilityChan
}

// GetStats 获取引擎统计信息
func (e *Engine) GetStats() EngineStats {
	e.statsMutex.RLock()
	defer e.statsMutex.RUnlock()

	var avgScanTime time.Duration
	if e.stats.pluginExecutions > 0 {
		avgScanTime = time.Duration(e.stats.totalScanTime / e.stats.pluginExecutions)
	}

	return EngineStats{
		RequestsProcessed:    atomic.LoadInt64(&e.stats.requestsProcessed),
		VulnerabilitiesFound: atomic.LoadInt64(&e.stats.vulnerabilitiesFound),
		PluginExecutions:     atomic.LoadInt64(&e.stats.pluginExecutions),
		PluginFailures:       atomic.LoadInt64(&e.stats.pluginFailures),
		AverageScanTime:      avgScanTime,
		Uptime:               time.Since(e.stats.startTime),
		ActiveWorkers:        e.config.MaxConcurrency,
		QueuedRequests:       len(e.requestChan),
	}
}

// IsRunning 检查引擎是否在运行
func (e *Engine) IsRunning() bool {
	return atomic.LoadInt32(&e.state) == 1
}

// worker 工作协程处理扫描请求
func (e *Engine) worker(workerID int) {
	defer e.wg.Done()

	log.Debug().Int("worker_id", workerID).Msg("扫描工作协程已启动")

	for req := range e.requestChan {
		select {
		case <-e.ctx.Done():
			log.Debug().Int("worker_id", workerID).Msg("工作协程收到取消信号")
			return
		default:
		}

		e.processRequest(workerID, req)
	}

	log.Debug().Int("worker_id", workerID).Msg("扫描工作协程已退出")
}

// processRequest 处理单个扫描请求
func (e *Engine) processRequest(workerID int, req *models.Request) {
	if req == nil {
		log.Warn().Int("worker_id", workerID).Msg("收到空请求，跳过")
		return
	}

	startTime := time.Now()
	atomic.AddInt64(&e.stats.requestsProcessed, 1)

	log.Debug().
		Int("worker_id", workerID).
		Str("method", req.Method).
		Str("url", req.URL).
		Int("params_count", len(req.Params)).
		Msg("开始处理扫描请求")

	// 应用速率限制
	if e.rateLimiter != nil {
		select {
		case <-e.rateLimiter:
		case <-e.ctx.Done():
			return
		}
	}

	// 创建模块映射，用于快速查找
	moduleMap := make(map[string]bool)
	for _, module := range e.scannerConfig.Modules {
		moduleMap[module] = true
	}

	// 对每个插件执行扫描，但只执行Modules字段中指定的插件
	for _, plugin := range e.plugins {
		if plugin == nil {
			log.Warn().Int("worker_id", workerID).Msg("发现空插件，跳过")
			continue
		}

		// 获取插件信息
		info := plugin.Info()
		
		// 如果Modules字段不为空，检查插件是否在指定的模块中
		if len(e.scannerConfig.Modules) > 0 {
			if _, exists := moduleMap[info.Name]; !exists {
				log.Debug().
					Int("worker_id", workerID).
					Str("plugin", info.Name).
					Msg("插件不在指定模块中，跳过")
				continue
			}
		}

		select {
		case <-e.ctx.Done():
			return
		default:
		}

		e.executePlugin(workerID, plugin, req)
	}

	// 更新统计
	duration := time.Since(startTime)
	atomic.AddInt64(&e.stats.totalScanTime, duration.Nanoseconds())

	log.Debug().
		Int("worker_id", workerID).
		Str("url", req.URL).
		Dur("duration", duration).
		Msg("请求处理完成")
}

// executePlugin 执行单个插件的扫描
func (e *Engine) executePlugin(workerID int, plugin Plugin, req *models.Request) {
	info := plugin.Info()
	startTime := time.Now()

	log.Debug().
		Int("worker_id", workerID).
		Str("plugin", info.Name).
		Str("url", req.URL).
		Msg("执行插件扫描")

	atomic.AddInt64(&e.stats.pluginExecutions, 1)

	// 创建插件专用的上下文，带超时
	ctx, cancel := context.WithTimeout(e.ctx, e.config.RequestTimeout)
	defer cancel()

	var vulnerabilities []*Vulnerability
	var err error

	// 优先使用支持上下文的扫描方法
	if contextAware, ok := plugin.(contextAware); ok {
		vulnerabilities, err = contextAware.ScanWithContext(ctx, e.httpClient, req)
	} else {
		// 回退到普通的扫描方法
		vulnerabilities, err = plugin.Scan(e.httpClient, req)
	}

	duration := time.Since(startTime)

	if err != nil {
		atomic.AddInt64(&e.stats.pluginFailures, 1)
		log.Error().
			Err(err).
			Int("worker_id", workerID).
			Str("plugin", info.Name).
			Str("url", req.URL).
			Dur("duration", duration).
			Msg("插件执行失败")
		return
	}

	// 处理发现的漏洞
	if len(vulnerabilities) > 0 {
		atomic.AddInt64(&e.stats.vulnerabilitiesFound, int64(len(vulnerabilities)))

		log.Info().
			Int("worker_id", workerID).
			Str("plugin", info.Name).
			Str("url", req.URL).
			Int("vulnerabilities_found", len(vulnerabilities)).
			Dur("duration", duration).
			Msg("🚨 发现漏洞")

		// 发送漏洞到通道
		for _, vuln := range vulnerabilities {
			select {
			case e.vulnerabilityChan <- vuln:
			case <-e.ctx.Done():
				return
			default:
				log.Warn().
					Str("plugin", info.Name).
					Str("url", req.URL).
					Msg("漏洞通道已满，跳过漏洞")
			}
		}
	} else {
		log.Debug().
			Int("worker_id", workerID).
			Str("plugin", info.Name).
			Str("url", req.URL).
			Dur("duration", duration).
			Msg("插件执行完成，未发现漏洞")
	}
}

// isRetryableError 判断错误是否可重试
func (e *Engine) isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// 网络相关错误通常可以重试
	errStr := err.Error()
	retryableErrors := []string{
		"timeout",
		"connection reset",
		"connection refused",
		"temporary failure",
		"network unreachable",
		"no route to host",
	}

	for _, retryable := range retryableErrors {
		if strings.Contains(strings.ToLower(errStr), strings.ToLower(retryable)) {
			return true
		}
	}

	return false
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
					atomic.AddInt64(&e.stats.vulnerabilitiesFound, 1)
				case <-e.ctx.Done():
					log.Debug().Msg("上下文取消，停止发送漏洞")
					return
				default:
					log.Warn().
						Str("plugin", result.pluginName).
						Msg("漏洞通道已满，丢弃漏洞")
				}
			}
		}
	}

	if totalVulns > 0 || failedPlugins > 0 {
		log.Debug().
			Int("total_vulns", totalVulns).
			Int("successful_plugins", successfulPlugins).
			Int("failed_plugins", failedPlugins).
			Msg("漏洞发送完成")
	}
}

// validateRequest 验证请求
func (e *Engine) validateRequest(req *models.Request) error {
	if req == nil {
		return fmt.Errorf("请求对象为空")
	}

	if req.URL == "" {
		return fmt.Errorf("请求URL为空")
	}

	if req.Method == "" {
		log.Debug().Str("url", req.URL).Msg("请求方法为空，默认使用GET")
		req.Method = "GET"
	}

	return nil
}

// metricsCollector 指标收集器
func (e *Engine) metricsCollector() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			stats := e.GetStats()
			log.Info().
				Int64("requests_processed", stats.RequestsProcessed).
				Int64("vulnerabilities_found", stats.VulnerabilitiesFound).
				Int64("plugin_executions", stats.PluginExecutions).
				Int64("plugin_failures", stats.PluginFailures).
				Dur("average_scan_time", stats.AverageScanTime).
				Dur("uptime", stats.Uptime).
				Int("queued_requests", stats.QueuedRequests).
				Msg("📊 扫描引擎统计信息")
		case <-e.ctx.Done():
			log.Debug().Msg("指标收集器退出")
			return
		}
	}
}

// Execute 已弃用，使用 QueueRequest 替代
// 保留此方法以保持向后兼容性
func (e *Engine) Execute(req *models.Request) {
	if err := e.QueueRequest(req); err != nil {
		log.Error().Err(err).Msg("Failed to queue request via deprecated Execute method")
	}
}
