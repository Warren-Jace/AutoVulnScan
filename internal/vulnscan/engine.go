// Package vulnscan 提供了核心的漏洞扫描引擎和插件管理机制。
package vulnscan

import (
	"context"
	"fmt"
	"runtime"
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
	plugins           []Plugin
	httpClient        *requester.HTTPClient
	browserService    *browser.BrowserService
	scannerConfig     *config.ScannerConfig

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
		requestsProcessed   int64
		vulnerabilitiesFound int64
		pluginExecutions    int64
		pluginFailures      int64
		totalScanTime       int64 // 纳秒
		startTime           time.Time
	}
	statsMutex sync.RWMutex

	// 配置
	config EngineConfig

	// 状态管理
	state      int32 // 0: stopped, 1: running, 2: stopping
	once       sync.Once
	closeOnce  sync.Once
}

// EngineConfig 引擎配置
type EngineConfig struct {
	MaxConcurrency    int           // 最大并发数
	RequestTimeout    time.Duration // 请求超时时间
	RateLimitRPS      int           // 每秒请求数限制
	BufferSize        int           // 缓冲区大小
	EnableMetrics     bool          // 是否启用指标收集
	GracefulShutdown  time.Duration // 优雅关闭超时时间
	RetryAttempts     int           // 重试次数
	RetryDelay        time.Duration // 重试延迟
}

// EngineStats 引擎统计信息
type EngineStats struct {
	RequestsProcessed     int64         `json:"requests_processed"`
	VulnerabilitiesFound  int64         `json:"vulnerabilities_found"`
	PluginExecutions      int64         `json:"plugin_executions"`
	PluginFailures        int64         `json:"plugin_failures"`
	AverageScanTime       time.Duration `json:"average_scan_time"`
	Uptime                time.Duration `json:"uptime"`
	ActiveWorkers         int           `json:"active_workers"`
	QueuedRequests        int           `json:"queued_requests"`
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
	RequestTimeout:   30 * time.Second,
	RateLimitRPS:     100,
	BufferSize:       1000,
	EnableMetrics:    true,
	GracefulShutdown: 30 * time.Second,
	RetryAttempts:    3,
	RetryDelay:       time.Second,
}

// NewEngine 创建一个新的扫描引擎实例。
func NewEngine(cfg *config.ScannerConfig, client *requester.HTTPClient, browserService *browser.BrowserService) (*Engine, error) {
	if cfg == nil {
		return nil, fmt.Errorf("scanner config cannot be nil")
	}

	if client == nil {
		return nil, fmt.Errorf("HTTP client cannot be nil")
	}

	plugins := GetPlugins()
	if len(plugins) == 0 {
		log.Warn().Msg("没有找到任何已注册的扫描插件")
	}

	ctx, cancel := context.WithCancel(context.Background())

	// 合并配置
	engineConfig := defaultConfig
	if cfg.Concurrency > 0 {
		engineConfig.MaxConcurrency = cfg.Concurrency
	}
	if cfg.Timeout > 0 {
		engineConfig.RequestTimeout = cfg.Timeout
	}

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
	for _, vulnConfig := range cfg.Vulnerabilities {
		var modelPayloads []models.Payload
		for _, p := range vulnConfig.Payloads {
			modelPayloads = append(modelPayloads, models.Payload{
				Value:       p.Value,
				Description: p.Description,
			})
		}
		payloads[vulnConfig.Type] = modelPayloads
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

// worker 工作协程
func (e *Engine) worker(id int) {
	defer e.wg.Done()
	
	log.Debug().Int("worker_id", id).Msg("扫描工作协程已启动")
	
	for {
		select {
		case req, ok := <-e.requestChan:
			if !ok {
				log.Debug().Int("worker_id", id).Msg("请求通道已关闭，工作协程退出")
				return
			}
			
			// 限流
			if e.rateLimiter != nil {
				<-e.rateLimiter
			}
			
			// 获取工作槽位
			e.workerPool <- struct{}{}
			
			// 处理请求
			e.processRequest(req, id)
			
			// 释放工作槽位
			<-e.workerPool
			
		case <-e.ctx.Done():
			log.Debug().Int("worker_id", id).Msg("上下文取消，工作协程退出")
			return
		}
	}
}

// processRequest 处理单个请求
func (e *Engine) processRequest(req *models.Request, workerID int) {
	startTime := time.Now()
	
	// 验证请求
	if err := e.validateRequest(req); err != nil {
		log.Error().
			Err(err).
			Int("worker_id", workerID).
			Msg("请求验证失败")
		return
	}

	atomic.AddInt64(&e.stats.requestsProcessed, 1)

	log.Debug().
		Str("url", req.URL).
		Str("method", req.Method).
		Int("worker_id", workerID).
		Int("plugin_count", len(e.plugins)).
		Msg("开始处理请求")

	// 执行扫描
	results := e.executePlugins(req, workerID)
	
	// 发送结果
	e.sendVulnerabilities(results)

	duration := time.Since(startTime)
	atomic.AddInt64(&e.stats.totalScanTime, int64(duration))

	log.Debug().
		Str("url", req.URL).
		Int("worker_id", workerID).
		Dur("duration", duration).
		Int("results", len(results)).
		Msg("请求处理完成")
}

// executePlugins 执行所有插件
func (e *Engine) executePlugins(req *models.Request, workerID int) []pluginResult {
	if len(e.plugins) == 0 {
		return nil
	}

	var wg sync.WaitGroup
	resultsChan := make(chan pluginResult, len(e.plugins))

	// 为每个插件创建带超时的上下文
	ctx, cancel := context.WithTimeout(e.ctx, e.config.RequestTimeout)
	defer cancel()

	for _, plugin := range e.plugins {
		if plugin == nil {
			continue
		}

		wg.Add(1)
		go func(p Plugin) {
			defer func() {
				if r := recover(); r != nil {
					log.Error().
						Interface("panic", r).
						Str("plugin", p.Info().Name).
						Str("url", req.URL).
						Int("worker_id", workerID).
						Msg("插件执行时发生panic")
					
					resultsChan <- pluginResult{
						pluginName: p.Info().Name,
						err:        fmt.Errorf("plugin panic: %v", r),
					}
				}
				wg.Done()
			}()

			result := e.executePluginWithRetry(ctx, p, req, workerID)
			resultsChan <- result
		}(plugin)
	}

	wg.Wait()
	close(resultsChan)

	var results []pluginResult
	for result := range resultsChan {
		results = append(results, result)
	}

	return results
}

// executePluginWithRetry 带重试的插件执行
func (e *Engine) executePluginWithRetry(ctx context.Context, plugin Plugin, req *models.Request, workerID int) pluginResult {
	info := plugin.Info()
	var lastErr error
	
	for attempt := 0; attempt <= e.config.RetryAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(e.config.RetryDelay):
			case <-ctx.Done():
				return pluginResult{
					pluginName: info.Name,
					err:        ctx.Err(),
					retryCount: attempt,
				}
			}
		}

		result := e.executePlugin(ctx, plugin, req, workerID)
		result.retryCount = attempt

		// 如果成功或者是不可重试的错误，直接返回
		if result.err == nil || !e.isRetryableError(result.err) {
			return result
		}

		lastErr = result.err
		log.Debug().
			Err(result.err).
			Str("plugin", info.Name).
			Int("attempt", attempt+1).
			Int("worker_id", workerID).
			Msg("插件执行失败，准备重试")
	}

	atomic.AddInt64(&e.stats.pluginFailures, 1)
	return pluginResult{
		pluginName: info.Name,
		err:        fmt.Errorf("插件执行失败，已重试%d次: %w", e.config.RetryAttempts, lastErr),
		retryCount: e.config.RetryAttempts,
	}
}

// executePlugin 执行单个插件
func (e *Engine) executePlugin(ctx context.Context, plugin Plugin, req *models.Request, workerID int) pluginResult {
	startTime := time.Now()
	info := plugin.Info()

	atomic.AddInt64(&e.stats.pluginExecutions, 1)

	log.Debug().
		Str("plugin", info.Name).
		Str("url", req.URL).
		Int("worker_id", workerID).
		Msg("开始执行插件")

	var vulns []*Vulnerability
	var err error

	// 检查插件是否支持上下文
	if contextAwarePlugin, ok := plugin.(contextAware); ok {
		vulns, err = contextAwarePlugin.ScanWithContext(ctx, e.httpClient, req)
	} else {
		// 使用传统接口，但在goroutine中执行以支持超时
		done := make(chan struct{})
		go func() {
			defer close(done)
			vulns, err = plugin.Scan(e.httpClient, req)
		}()

		select {
		case <-done:
			// 正常完成
		case <-ctx.Done():
			err = ctx.Err()
		}
	}

	duration := time.Since(startTime)

	result := pluginResult{
		pluginName:      info.Name,
		vulnerabilities: vulns,
		err:             err,
		duration:        duration,
	}

	if err != nil {
		log.Debug().
			Err(err).
			Str("plugin", info.Name).
			Str("url", req.URL).
			Int("worker_id", workerID).
			Dur("duration", duration).
			Msg("插件执行失败")
	} else {
		log.Debug().
			Str("plugin", info.Name).
			Str("url", req.URL).
			Int("worker_id", workerID).
			Int("vuln_count", len(vulns)).
			Dur("duration", duration).
			Msg("插件执行完成")
	}

	return result
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
		if contains(errStr, retryable) {
			return true
		}
	}

	return false
}

// contains 检查字符串是否包含子字符串（不区分大小写）
func contains(s, substr string) bool {
	return len(s) >= len(substr) && 
		   (s == substr || 
		    (len(s) > len(substr) && 
		     (s[:len(substr)] == substr || 
		      s[len(s)-len(substr):] == substr || 
		      indexIgnoreCase(s, substr) >= 0)))
}

// indexIgnoreCase 不区分大小写的字符串查找
func indexIgnoreCase(s, substr string) int {
	s = toLower(s)
	substr = toLower(substr)
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// toLower 简单的转小写函数
func toLower(s string) string {
	result := make([]byte, len(s))
	for i, b := range []byte(s) {
		if b >= 'A' && b <= 'Z' {
			result[i] = b + 32
		} else {
			result[i] = b
		}
	}
	return string(result)
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
