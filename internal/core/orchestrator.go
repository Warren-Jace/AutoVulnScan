// Package core contains the main orchestrator for the AutoVulnScan application.
package core

import (
	"bytes"
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"autovulnscan/internal/ai"
	"autovulnscan/internal/config"
	"autovulnscan/internal/crawler"
	"autovulnscan/internal/dedup"
	"autovulnscan/internal/models"
	"autovulnscan/internal/output"
	"autovulnscan/internal/requester"
	"autovulnscan/internal/vulnscan"
	_ "autovulnscan/internal/vulnscan/plugins"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/html"
)

// 常量定义
const (
	// 默认相似度阈值
	defaultDOMThreshold     = 0.85 // DOM结构相似度阈值85%
	defaultContentThreshold = 0.80 // 内容相似度阈值80%
	defaultFormThreshold    = 0.90 // 表单相似度阈值90%
	defaultURLThreshold     = 0.75 // URL模式相似度阈值75%

	// 重试配置
	defaultMaxRetries = 3
	defaultRetryDelay = 2 * time.Second

	// 统计输出间隔
	statsInterval = 30 * time.Second
	adjustInterval = 5 * time.Minute

	// 任务队列缓冲大小倍数
	queueBufferMultiplier = 4

	// URL最大长度限制
	maxURLLength = 2048

	// 域名统计调整间隔
	minAdjustmentInterval = 10 * time.Minute
)

// PageStructure 页面结构信息
// 用于分析和比较页面的结构特征，支持相似度检测
type PageStructure struct {
	DOMHash     string            `json:"dom_hash"`     // DOM结构哈希值
	TextHash    string            `json:"text_hash"`    // 文本内容哈希值
	FormFields  map[string]string `json:"form_fields"`  // 表单字段映射 (哈希->动作)
	InputCount  int               `json:"input_count"`  // 输入字段数量
	LinkCount   int               `json:"link_count"`   // 链接数量
	ScriptCount int               `json:"script_count"` // 脚本数量
	Title       string            `json:"title"`        // 页面标题
}

// URLPattern URL模式结构
// 用于识别和去重相似的URL模式
type URLPattern struct {
	BaseURL    string   `json:"base_url"`    // 基础URL
	ParamNames []string `json:"param_names"` // 参数名列表
	Pattern    string   `json:"pattern"`     // URL模式字符串
}

// SimilarityConfig 相似度配置
// 控制页面相似度检测的各种阈值和行为
type SimilarityConfig struct {
	DOMThreshold     float64 `json:"dom_threshold"`     // DOM结构相似度阈值
	ContentThreshold float64 `json:"content_threshold"` // 内容相似度阈值
	FormThreshold    float64 `json:"form_threshold"`    // 表单相似度阈值
	URLThreshold     float64 `json:"url_threshold"`     // URL模式相似度阈值
	AutoAdjust       bool    `json:"auto_adjust"`       // 是否自动调整阈值
}

// DomainStatistics 域名统计信息
// 用于动态调整阈值和监控爬取效果
type DomainStatistics struct {
	TotalPages        int       `json:"total_pages"`        // 总页面数
	UniqueForms       int       `json:"unique_forms"`       // 唯一表单数
	AverageSimilarity float64   `json:"average_similarity"` // 平均相似度
	LastAdjustment    time.Time `json:"last_adjustment"`    // 最后调整时间
}

// FormStructure 表单结构
// 用于分析和比较表单的结构特征
type FormStructure struct {
	Fields []string `json:"fields"` // 字段名列表
	Types  []string `json:"types"`  // 字段类型列表
	Action string   `json:"action"` // 表单提交地址
	Method string   `json:"method"` // 表单提交方法
	Hash   string   `json:"hash"`   // 结构哈希值
}

// RetryConfig 重试配置
// 控制网络请求和扫描的重试行为
type RetryConfig struct {
	MaxRetries int           `json:"max_retries"` // 最大重试次数
	RetryDelay time.Duration `json:"retry_delay"` // 重试间隔时间
}

// Statistics 统计信息结构
// 用于跟踪和监控扫描进度
type Statistics struct {
	URLsProcessed        int64 `json:"urls_processed"`        // 已处理的URL数量
	RequestsScanned      int64 `json:"requests_scanned"`      // 已扫描的请求数量
	VulnerabilitiesFound int64 `json:"vulnerabilities_found"` // 发现的漏洞数量
	DuplicatesSkipped    int64 `json:"duplicates_skipped"`    // 跳过的重复内容数量
	SimilarPagesSkipped  int64 `json:"similar_pages_skipped"` // 跳过的相似页面数量
}

// Orchestrator 负责协调爬虫、扫描和报告的主流程控制器
// 这是整个系统的核心组件，管理所有子模块的协调工作
type Orchestrator struct {
	// 基础配置和组件
	config       *config.Settings      // 全局配置文件
	targetURL    string                // 目标URL
	crawler      *crawler.Crawler      // 爬虫实例
	plugins      []vulnscan.Plugin     // 漏洞扫描插件列表
	deduplicator *dedup.Deduplicator   // 去重模块
	aiAnalyzer   *ai.AIAnalyzer        // AI 分析器
	httpClient   *requester.HTTPClient // HTTP客户端
	payloads     map[string][]string   // 预加载的payloads（按插件名分类）

	// 上下文控制
	ctx    context.Context    // 主上下文
	cancel context.CancelFunc // 取消函数

	// 统计信息
	stats Statistics // 运行时统计数据

	// 重试配置
	retryConfig RetryConfig // 错误重试机制配置

	// 相似度爬虫相关
	similarityConfig SimilarityConfig             // 相似度配置
	pageStructures   sync.Map                     // 页面结构缓存 URL -> PageStructure
	urlPatterns      sync.Map                     // URL模式缓存 Pattern -> URLPattern
	formStructures   sync.Map                     // 表单结构缓存 FormHash -> FormStructure
	requestDedup     sync.Map                     // 用于请求去重
	domainStats      map[string]*DomainStatistics // 域名统计信息
	domainStatsMutex sync.RWMutex                 // 域名统计锁

	// 内部状态
	isInitialized bool       // 初始化状态标志
	startTime     time.Time  // 开始时间
	mu            sync.Mutex // 内部状态锁
}

// NewOrchestrator 创建新的编排器实例
// 初始化所有必要的组件和配置
func NewOrchestrator(cfg *config.Settings, targetURL string) (*Orchestrator, error) {
	if cfg == nil {
		return nil, fmt.Errorf("配置不能为空")
	}

	if targetURL == "" {
		return nil, fmt.Errorf("目标URL不能为空")
	}

	// 验证目标URL格式
	if _, err := url.Parse(targetURL); err != nil {
		return nil, fmt.Errorf("无效的目标URL: %w", err)
	}

	// 创建带超时的上下文
	ctx, cancel := context.WithCancel(context.Background())

	// 初始化 HTTP 客户端
	httpClient := requester.NewHTTPClient(cfg.Spider.Timeout, cfg.Spider.UserAgents)
	if httpClient == nil {
		cancel()
		return nil, fmt.Errorf("HTTP客户端初始化失败")
	}

	// 初始化爬虫
	cr, err := crawler.NewCrawler(targetURL, cfg, httpClient)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("初始化爬虫失败: %w", err)
	}

	// 初始化插件列表
	plugins := vulnscan.GetPlugins()
	if len(plugins) == 0 {
		log.Warn().Msg("未找到可用的漏洞扫描插件")
	}

	// 初始化去重模块
	deduplicator := dedup.NewDeduplicator()
	if deduplicator == nil {
		cancel()
		return nil, fmt.Errorf("去重模块初始化失败")
	}

	// 初始化 AI 分析器（可选）
	var aiAnalyzer *ai.AIAnalyzer
	if cfg.AIModule.Enabled {
		aiAnalyzer, err = ai.NewAIAnalyzer(cfg.AIModule.APIKey, cfg.AIModule.Model, "")
		if err != nil {
			log.Warn().Err(err).Msg("AI 分析器初始化失败，将继续使用传统扫描方式")
			// AI初始化失败不应该导致整个系统失败
		}
	}

	// 创建编排器实例
	o := &Orchestrator{
		config:       cfg,
		targetURL:    targetURL,
		crawler:      cr,
		plugins:      plugins,
		deduplicator: deduplicator,
		aiAnalyzer:   aiAnalyzer,
		httpClient:   httpClient,
		payloads:     make(map[string][]string),
		ctx:          ctx,
		cancel:       cancel,
		domainStats:  make(map[string]*DomainStatistics),
		retryConfig: RetryConfig{
			MaxRetries: defaultMaxRetries,
			RetryDelay: defaultRetryDelay,
		},
		startTime: time.Now(),
	}

	// 初始化相似度配置
	o.initSimilarityConfig()

	// 预加载所有插件的payloads
	if err := o.loadAllPayloads(); err != nil {
		log.Warn().Err(err).Msg("部分插件payload加载失败")
		// payload加载失败不应该导致整个系统失败
	}

	o.isInitialized = true
	log.Info().Str("target", targetURL).Msg("编排器初始化完成")

	return o, nil
}

// initSimilarityConfig 初始化相似度配置
// 设置各种相似度检测的默认阈值
func (o *Orchestrator) initSimilarityConfig() {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.similarityConfig = SimilarityConfig{
		DOMThreshold:     defaultDOMThreshold,
		ContentThreshold: defaultContentThreshold,
		FormThreshold:    defaultFormThreshold,
		URLThreshold:     defaultURLThreshold,
		AutoAdjust:       true,
	}

	log.Debug().
		Float64("dom_threshold", o.similarityConfig.DOMThreshold).
		Float64("content_threshold", o.similarityConfig.ContentThreshold).
		Float64("form_threshold", o.similarityConfig.FormThreshold).
		Float64("url_threshold", o.similarityConfig.URLThreshold).
		Msg("相似度配置初始化完成")
}

// loadAllPayloads 预加载所有插件的payloads
// 提前加载所有payload以提高扫描效率
func (o *Orchestrator) loadAllPayloads() error {
	if !o.isInitialized {
		return fmt.Errorf("编排器未初始化")
	}

	var loadErrors []string
	successCount := 0

	log.Info().Int("plugin_count", len(o.plugins)).Msg("开始加载插件payloads")

	for _, p := range o.plugins {
		pluginName := p.Info().Name
		if pluginName == "" {
			log.Warn().Msg("发现无名插件，跳过")
			continue
		}

		payloads, err := vulnscan.LoadPayloads(pluginName)
		if err != nil {
			errMsg := fmt.Sprintf("plugin %s: %v", pluginName, err)
			loadErrors = append(loadErrors, errMsg)
			log.Warn().Err(err).Str("plugin", pluginName).Msg("插件payload加载失败")
			continue
		}

		if len(payloads) == 0 {
			log.Warn().Str("plugin", pluginName).Msg("插件没有可用的payloads")
			o.payloads[pluginName] = []string{} // 设置空切片避免nil检查
		} else {
			o.payloads[pluginName] = payloads
			successCount++
			log.Debug().
				Str("plugin", pluginName).
				Int("count", len(payloads)).
				Msg("插件payloads加载成功")
		}
	}

	// 如果所有插件都加载失败，返回错误
	if len(loadErrors) > 0 && successCount == 0 {
		return fmt.Errorf("所有插件payload加载失败: %s", strings.Join(loadErrors, "; "))
	}

	log.Info().
		Int("success_count", successCount).
		Int("error_count", len(loadErrors)).
		Msg("插件payloads加载完成")

	return nil
}

// Start 启动主流程，包含爬取、扫描和报告
// 这是编排器的主要入口点，协调所有子系统的工作
func (o *Orchestrator) Start(reporter *output.Reporter) {
	if !o.isInitialized {
		log.Error().Msg("编排器未正确初始化")
		return
	}

	if reporter == nil {
		log.Error().Msg("报告器不能为空")
		return
	}

	log.Info().
    Str("target", o.targetURL).
    Int("concurrency", o.config.Spider.Concurrency).
    Int("max_depth", o.config.Spider.MaxDepth).
    Msg("开始启动高级相似度爬虫...")

defer func() {
    o.cancel()
    log.Info().
        Dur("total_time", time.Since(o.startTime)). // 修复：Duration -> Dur
        Msg("编排器执行完成")
}()

	// 启动统计信息定期输出
	statsTicker := time.NewTicker(statsInterval)
	defer statsTicker.Stop()
	go o.printStats(statsTicker.C)

	// 启动阈值自动调整（如果启用）
	if o.similarityConfig.AutoAdjust {
		adjustTicker := time.NewTicker(adjustInterval)
		defer adjustTicker.Stop()
		go o.autoAdjustThresholds(adjustTicker.C)
	}

	// 创建任务队列和工作协程
	var wg sync.WaitGroup
	queueSize := o.config.Spider.Concurrency * queueBufferMultiplier
	taskQueue := make(chan models.Task, queueSize)

	// 启动工作协程池
	for i := 0; i < o.config.Spider.Concurrency; i++ {
		go o.worker(i, taskQueue, &wg, reporter)
	}

	// 添加初始任务
	wg.Add(1)
	select {
	case taskQueue <- models.Task{URL: o.targetURL, Depth: 0}:
		log.Info().Str("url", o.targetURL).Msg("初始任务已加入队列")
	case <-o.ctx.Done():
		wg.Done()
		log.Warn().Msg("上下文已取消，跳过初始任务")
	}

	// 等待所有任务完成
	wg.Wait()
	close(taskQueue)

	// 输出最终统计信息
	o.printFinalStats()
	log.Info().Msg("编排器关闭完成")
}

// printStats 定期输出统计信息
// 提供实时的扫描进度反馈
func (o *Orchestrator) printStats(ticker <-chan time.Time) {
    for {
        select {
        case <-ticker:
            urls := atomic.LoadInt64(&o.stats.URLsProcessed)
            requests := atomic.LoadInt64(&o.stats.RequestsScanned)
            vulns := atomic.LoadInt64(&o.stats.VulnerabilitiesFound)
            dups := atomic.LoadInt64(&o.stats.DuplicatesSkipped)
            similar := atomic.LoadInt64(&o.stats.SimilarPagesSkipped)

            log.Info().
                Int64("urls_processed", urls).
                Int64("requests_scanned", requests).
                Int64("vulnerabilities_found", vulns).
                Int64("duplicates_skipped", dups).
                Int64("similar_pages_skipped", similar).
                Dur("elapsed", time.Since(o.startTime)). // 修复：Duration -> Dur
                Msg("进度更新")

        case <-o.ctx.Done():
            log.Debug().Msg("统计输出协程退出")
            return
        }
    }
}
// printFinalStats 输出最终统计信息
// 在扫描完成后提供详细的统计报告
func (o *Orchestrator) printFinalStats() {
    urls := atomic.LoadInt64(&o.stats.URLsProcessed)
    requests := atomic.LoadInt64(&o.stats.RequestsScanned)
    vulns := atomic.LoadInt64(&o.stats.VulnerabilitiesFound)
    dups := atomic.LoadInt64(&o.stats.DuplicatesSkipped)
    similar := atomic.LoadInt64(&o.stats.SimilarPagesSkipped)
    totalTime := time.Since(o.startTime)

    log.Info().
        Int64("total_urls_processed", urls).
        Int64("total_requests_scanned", requests).
        Int64("total_vulnerabilities_found", vulns).
        Int64("total_duplicates_skipped", dups).
        Int64("total_similar_pages_skipped", similar).
        Dur("total_execution_time", totalTime). // 修复：Duration -> Dur
        Msg("最终统计信息")

    // 计算效率指标
    if totalTime.Seconds() > 0 {
        urlsPerSecond := float64(urls) / totalTime.Seconds()
        requestsPerSecond := float64(requests) / totalTime.Seconds()

        log.Info().
            Float64("urls_per_second", urlsPerSecond).
            Float64("requests_per_second", requestsPerSecond).
            Msg("性能指标")
    }

    // 输出域名统计
    o.domainStatsMutex.RLock()
    defer o.domainStatsMutex.RUnlock()

    for domain, stats := range o.domainStats {
        log.Info().
            Str("domain", domain).
            Int("total_pages", stats.TotalPages).
            Int("unique_forms", stats.UniqueForms).
            Float64("avg_similarity", stats.AverageSimilarity).
            Msg("域名统计")
    }
}

// autoAdjustThresholds 自动调整相似度阈值
// 根据域名统计信息动态优化相似度检测参数
func (o *Orchestrator) autoAdjustThresholds(ticker <-chan time.Time) {
	for {
		select {
		case <-ticker:
			o.performThresholdAdjustment()

		case <-o.ctx.Done():
			log.Debug().Msg("阈值调整协程退出")
			return
		}
	}
}

// performThresholdAdjustment 执行阈值调整逻辑
func (o *Orchestrator) performThresholdAdjustment() {
	o.domainStatsMutex.Lock()
	defer o.domainStatsMutex.Unlock()

	adjustmentCount := 0

	for domain, stats := range o.domainStats {
		// 检查是否需要调整（避免频繁调整）
		if time.Since(stats.LastAdjustment) < minAdjustmentInterval {
			continue
		}

		// 根据平均相似度调整阈值
		oldDOMThreshold := o.similarityConfig.DOMThreshold
		oldContentThreshold := o.similarityConfig.ContentThreshold

		if stats.AverageSimilarity > 0.9 {
			// 页面相似度很高，提高阈值以减少重复爬取
			o.similarityConfig.DOMThreshold = 0.90
			o.similarityConfig.ContentThreshold = 0.85
		} else if stats.AverageSimilarity < 0.5 {
			// 页面差异较大，降低阈值以爬取更多页面
			o.similarityConfig.DOMThreshold = 0.75
			o.similarityConfig.ContentThreshold = 0.70
		} else {
			// 中等相似度，使用默认值
			o.similarityConfig.DOMThreshold = defaultDOMThreshold
			o.similarityConfig.ContentThreshold = defaultContentThreshold
		}

		// 记录调整
		if oldDOMThreshold != o.similarityConfig.DOMThreshold ||
			oldContentThreshold != o.similarityConfig.ContentThreshold {

			stats.LastAdjustment = time.Now()
			adjustmentCount++

			log.Debug().
				Str("domain", domain).
				Float64("avg_similarity", stats.AverageSimilarity).
				Float64("old_dom_threshold", oldDOMThreshold).
				Float64("new_dom_threshold", o.similarityConfig.DOMThreshold).
				Float64("old_content_threshold", oldContentThreshold).
				Float64("new_content_threshold", o.similarityConfig.ContentThreshold).
				Msg("相似度阈值已调整")
		}
	}

	if adjustmentCount > 0 {
		log.Info().Int("adjustments", adjustmentCount).Msg("完成阈值自动调整")
	}
}

// worker 工作协程，不断从任务队列中取任务处理
// 这是并发处理的核心，每个worker独立处理任务
func (o *Orchestrator) worker(id int, taskQueue chan models.Task, wg *sync.WaitGroup, reporter *output.Reporter) {
	log.Debug().Int("worker_id", id).Msg("工作协程启动")
	defer log.Debug().Int("worker_id", id).Msg("工作协程结束")

	for {
		select {
		case task, ok := <-taskQueue:
			if !ok {
				// 通道已关闭，退出工作协程
				log.Debug().Int("worker_id", id).Msg("任务队列已关闭，工作协程退出")
				return
			}

			// 处理任务
			o.processTask(task, taskQueue, wg, reporter, id)

		case <-o.ctx.Done():
			log.Debug().Int("worker_id", id).Msg("工作协程被取消")
			return
		}
	}
}

// processTask 处理单个任务
func (o *Orchestrator) processTask(task models.Task, taskQueue chan models.Task, wg *sync.WaitGroup, reporter *output.Reporter, workerID int) {
	defer wg.Done()

	// 检查任务类型并处理
	if task.Request != nil {
		// 扫描任务
		o.handleScanTask(task, reporter, workerID)
	} else {
		// 爬取任务
		o.handleCrawlTask(task, taskQueue, wg, reporter)
	}
}

// handleScanTask 处理扫描任务
func (o *Orchestrator) handleScanTask(task models.Task, reporter *output.Reporter, workerID int) {
	log.Debug().
		Int("worker_id", workerID).
		Str("url", task.Request.URL.String()).
		Msg("执行扫描任务")

	// 生成请求唯一标识符进行去重
	requestKey := o.generateRequestKey(task.Request)
	if _, exists := o.requestDedup.LoadOrStore(requestKey, true); exists {
		log.Debug().
			Str("url", task.Request.URL.String()).
			Msg("跳过重复请求")
		return
	}

	// 记录参数URL
	reporter.LogParamURL(task.Request)

	// 执行扫描
	vulnerabilityCount := o.scanRequestWithRetry(o.ctx, task.Request, reporter)
	if vulnerabilityCount > 0 {
		atomic.AddInt64(&o.stats.VulnerabilitiesFound, int64(vulnerabilityCount))
	}

	atomic.AddInt64(&o.stats.RequestsScanned, 1)
}

// generateRequestKey 生成请求的唯一标识符用于去重
// 基于HTTP方法、URL和参数名生成唯一键
func (o *Orchestrator) generateRequestKey(req *models.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}

	var keyBuilder strings.Builder
	keyBuilder.WriteString(req.Method)
	keyBuilder.WriteString(":")
	keyBuilder.WriteString(req.URL.String())

	// 添加参数名（不包含值，避免值变化导致的重复扫描）
	if len(req.Params) > 0 {
		keyBuilder.WriteString("?")
		paramNames := make([]string, 0, len(req.Params))
		for _, param := range req.Params {
			paramNames = append(paramNames, param.Name)
		}
		sort.Strings(paramNames) // 确保顺序一致性
		keyBuilder.WriteString(strings.Join(paramNames, "&"))
	}

	return keyBuilder.String()
}

// handleCrawlTask 处理爬取任务，包括深度检查、相似度分析、链接和请求发现
// 这是爬虫逻辑的核心，实现智能去重和相似度检测
func (o *Orchestrator) handleCrawlTask(task models.Task, taskQueue chan models.Task, wg *sync.WaitGroup, reporter *output.Reporter) {
	// 检查爬取深度
	if task.Depth >= o.config.Spider.MaxDepth {
		log.Debug().
			Str("url", task.URL).
			Int("depth", task.Depth).
			Int("max_depth", o.config.Spider.MaxDepth).
			Msg("已达到最大深度，停止爬取")
		return
	}

	// 1. URL模式检查 - 快速去重相似URL模式
	if o.isURLPatternDuplicate(task.URL) {
		log.Debug().Str("url", task.URL).Msg("跳过重复URL模式")
		atomic.AddInt64(&o.stats.SimilarPagesSkipped, 1)
		return
	}

	// 2. 获取页面内容
	bodyBytes, err := o.fetchURLWithRetry(task.URL)
	if err != nil {
		log.Error().
			Err(err).
			Str("url", task.URL).
			Msg("重试后仍无法获取URL内容")
		return
	}

	// 3. 分析页面结构
	pageStructure, err := o.analyzePageStructure(task.URL, bodyBytes)
	if err != nil {
		log.Error().
			Err(err).
			Str("url", task.URL).
			Msg("页面结构分析失败")
		return
	}

	// 4. 相似度检查 - 基于页面结构的智能去重
	if o.isSimilarPage(pageStructure) {
		log.Debug().Str("url", task.URL).Msg("跳过相似页面")
		atomic.AddInt64(&o.stats.SimilarPagesSkipped, 1)
		return
	}

	// 5. 传统去重检查（作为备份机制）
	isUnique, err := o.deduplicator.IsUnique(task.URL, bytes.NewReader(bodyBytes))
	if err != nil {
		log.Error().
			Err(err).
			Str("url", task.URL).
			Msg("去重检查失败")
		return
	}
	if !isUnique {
		log.Debug().Str("url", task.URL).Msg("跳过重复内容")
		reporter.LogDeDuplicateURL(task.URL)
		atomic.AddInt64(&o.stats.DuplicatesSkipped, 1)
		return
	}
	// 6. 存储页面结构并更新统计信息
	o.pageStructures.Store(task.URL, pageStructure)
	o.updateDomainStatistics(task.URL, pageStructure)

	// 7. 爬取和解析页面内容
	links, requests, err := o.crawler.Crawl(o.ctx, task.URL, bodyBytes)
	if err != nil {
		log.Error().
			Err(err).
			Str("url", task.URL).
			Msg("页面爬取失败")
		return
	}

	// 记录成功处理的URL
	reporter.LogURL(task.URL)
	atomic.AddInt64(&o.stats.URLsProcessed, 1)

	// 8. 过滤和验证新发现的链接和请求
	validLinks := o.filterValidLinks(links)
	validRequests := o.filterValidRequests(requests)

	// 9. 优先处理结构差异较大的表单请求
	validRequests = o.prioritizeUniqueFormRequests(validRequests)

	// 10. 将新任务加入队列
	o.enqueueNewTasks(validLinks, validRequests, task.Depth, taskQueue, wg)
}

// enqueueNewTasks 将新发现的任务加入队列
func (o *Orchestrator) enqueueNewTasks(links []string, requests []*models.Request, currentDepth int, taskQueue chan models.Task, wg *sync.WaitGroup) {
	totalTasks := len(links) + len(requests)
	if totalTasks == 0 {
		return
	}

	wg.Add(totalTasks)

	// 添加链接爬取任务
	for _, link := range links {
		select {
		case taskQueue <- models.Task{URL: link, Depth: currentDepth + 1}:
			log.Debug().
				Str("url", link).
				Int("depth", currentDepth+1).
				Msg("链接任务已加入队列")
		case <-o.ctx.Done():
			wg.Done()
			log.Debug().Msg("上下文已取消，停止添加链接任务")
			return
		}
	}

	// 添加请求扫描任务
	for _, req := range requests {
		select {
		case taskQueue <- models.Task{Request: req}:
			log.Debug().
				Str("url", req.URL.String()).
				Str("method", req.Method).
				Msg("扫描任务已加入队列")
		case <-o.ctx.Done():
			wg.Done()
			log.Debug().Msg("上下文已取消，停止添加扫描任务")
			return
		}
	}
}

// analyzePageStructure 分析页面结构
// 提取页面的各种结构特征用于相似度比较
func (o *Orchestrator) analyzePageStructure(pageURL string, bodyBytes []byte) (*PageStructure, error) {
	if len(bodyBytes) == 0 {
		return nil, fmt.Errorf("页面内容为空")
	}

	// 解析HTML文档
	doc, err := html.Parse(bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("HTML解析失败: %w", err)
	}

	// 初始化页面结构
	structure := &PageStructure{
		FormFields: make(map[string]string),
	}

	// 分析DOM结构 - 提取页面的结构骨架
	structure.DOMHash = o.calculateDOMHash(doc)

	// 分析文本内容 - 提取页面的文本特征
	structure.TextHash = o.calculateTextHash(bodyBytes)

	// 分析表单结构 - 识别交互元素
	o.analyzeFormStructure(doc, structure)

	// 统计各种元素数量
	o.countElements(doc, structure)

	// 提取页面标题
	structure.Title = o.extractTitle(doc)

	log.Debug().
		Str("url", pageURL).
		Str("dom_hash", structure.DOMHash[:8]+"...").
		Str("text_hash", structure.TextHash[:8]+"...").
		Int("input_count", structure.InputCount).
		Int("link_count", structure.LinkCount).
		Int("script_count", structure.ScriptCount).
		Str("title", structure.Title).
		Msg("页面结构分析完成")

	return structure, nil
}

// calculateDOMHash 计算DOM结构哈希
// 生成页面DOM结构的唯一标识符
func (o *Orchestrator) calculateDOMHash(node *html.Node) string {
	if node == nil {
		return ""
	}

	var domStructure strings.Builder
	o.traverseDOM(node, &domStructure, 0)

	hash := md5.Sum([]byte(domStructure.String()))
	return fmt.Sprintf("%x", hash)
}

// traverseDOM 遍历DOM结构
// 递归遍历DOM树，提取结构信息
func (o *Orchestrator) traverseDOM(node *html.Node, builder *strings.Builder, depth int) {
	if node == nil || builder == nil {
		return
	}

	// 限制遍历深度，避免过深的DOM结构影响性能
	const maxDepth = 20
	if depth > maxDepth {
		return
	}

	if node.Type == html.ElementNode {
		// 添加缩进表示层级
		builder.WriteString(strings.Repeat("  ", depth))
		builder.WriteString(node.Data)

		// 包含重要属性（class, id, name等）
		for _, attr := range node.Attr {
			if o.isImportantAttribute(attr.Key) {
				builder.WriteString(fmt.Sprintf("[%s=%s]", attr.Key, attr.Val))
			}
		}
		builder.WriteString("\n")
	}

	// 递归处理子节点
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		o.traverseDOM(child, builder, depth+1)
	}
}

// isImportantAttribute 判断是否为重要属性
func (o *Orchestrator) isImportantAttribute(attrKey string) bool {
	importantAttrs := []string{"class", "id", "name", "type", "role"}
	for _, attr := range importantAttrs {
		if attr == attrKey {
			return true
		}
	}
	return false
}

// calculateTextHash 计算文本内容哈希
// 提取并哈希化页面的纯文本内容
func (o *Orchestrator) calculateTextHash(bodyBytes []byte) string {
	if len(bodyBytes) == 0 {
		return ""
	}

	// 提取纯文本内容
	text := string(bodyBytes)

	// 移除HTML标签
	htmlTagRegex := regexp.MustCompile(`<[^>]*>`)
	text = htmlTagRegex.ReplaceAllString(text, "")

	// 移除多余空白字符
	whitespaceRegex := regexp.MustCompile(`\s+`)
	text = whitespaceRegex.ReplaceAllString(text, " ")
	text = strings.TrimSpace(text)

	// 如果文本过长，只取前1000个字符进行哈希
	const maxTextLength = 1000
	if len(text) > maxTextLength {
		text = text[:maxTextLength]
	}

	hash := md5.Sum([]byte(text))
	return fmt.Sprintf("%x", hash)
}

// analyzeFormStructure 分析表单结构
// 递归分析HTML中的表单元素
func (o *Orchestrator) analyzeFormStructure(node *html.Node, structure *PageStructure) {
	if node == nil || structure == nil {
		return
	}

	if node.Type == html.ElementNode {
		switch node.Data {
		case "form":
			// 提取表单结构
			formStruct := o.extractFormStructure(node)
			if formStruct != nil && formStruct.Hash != "" {
				structure.FormFields[formStruct.Hash] = formStruct.Action
			}
		case "input", "textarea", "select":
			// 统计输入字段
			structure.InputCount++
		}
	}

	// 递归处理子节点
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		o.analyzeFormStructure(child, structure)
	}
}

// extractFormStructure 提取表单结构
// 分析单个表单的详细结构信息
func (o *Orchestrator) extractFormStructure(formNode *html.Node) *FormStructure {
	if formNode == nil {
		return nil
	}

	form := &FormStructure{
		Fields: make([]string, 0),
		Types:  make([]string, 0),
	}

	// 提取表单属性
	for _, attr := range formNode.Attr {
		switch attr.Key {
		case "action":
			form.Action = attr.Val
		case "method":
			form.Method = strings.ToUpper(attr.Val)
		}
	}

	// 设置默认值
	if form.Method == "" {
		form.Method = "GET"
	}

	// 提取表单字段
	o.extractFormFields(formNode, form)

	// 计算表单哈希
	if len(form.Fields) > 0 {
		form.Hash = o.calculateFormHash(form)
	}

	return form
}

// extractFormFields 提取表单字段
// 递归提取表单中的所有输入字段
func (o *Orchestrator) extractFormFields(node *html.Node, form *FormStructure) {
	if node == nil || form == nil {
		return
	}

	if node.Type == html.ElementNode {
		switch node.Data {
		case "input", "textarea", "select":
			var name, fieldType string
			for _, attr := range node.Attr {
				switch attr.Key {
				case "name":
					name = attr.Val
				case "type":
					fieldType = attr.Val
				}
			}

			// 只记录有名称的字段
			if name != "" {
				form.Fields = append(form.Fields, name)
				if fieldType == "" {
					fieldType = "text" // 默认类型
				}
				form.Types = append(form.Types, fieldType)
			}
		}
	}

	// 递归处理子节点
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		o.extractFormFields(child, form)
	}
}

// calculateFormHash 计算表单结构哈希
// 基于表单字段生成唯一标识符
func (o *Orchestrator) calculateFormHash(form *FormStructure) string {
	if form == nil || len(form.Fields) == 0 {
		return ""
	}

	var hashBuilder strings.Builder

	// 排序字段名以确保一致性
	sortedFields := make([]string, len(form.Fields))
	copy(sortedFields, form.Fields)
	sort.Strings(sortedFields)

	// 构建哈希字符串
	hashBuilder.WriteString(form.Method)
	hashBuilder.WriteString(":")
	for _, field := range sortedFields {
		hashBuilder.WriteString(field)
		hashBuilder.WriteString(",")
	}

	hash := md5.Sum([]byte(hashBuilder.String()))
	return fmt.Sprintf("%x", hash)
}

// countElements 统计页面元素
// 统计页面中各种类型元素的数量
func (o *Orchestrator) countElements(node *html.Node, structure *PageStructure) {
	if node == nil || structure == nil {
		return
	}

	if node.Type == html.ElementNode {
		switch node.Data {
		case "a":
			structure.LinkCount++
		case "script":
			structure.ScriptCount++
		}
	}

	// 递归处理子节点
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		o.countElements(child, structure)
	}
}

// extractTitle 提取页面标题
// 递归查找并提取HTML文档的title标签内容
func (o *Orchestrator) extractTitle(node *html.Node) string {
	if node == nil {
		return ""
	}

	if node.Type == html.ElementNode && node.Data == "title" {
		if node.FirstChild != nil && node.FirstChild.Type == html.TextNode {
			title := strings.TrimSpace(node.FirstChild.Data)
			// 限制标题长度
			const maxTitleLength = 100
			if len(title) > maxTitleLength {
				title = title[:maxTitleLength] + "..."
			}
			return title
		}
	}

	// 递归查找子节点
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if title := o.extractTitle(child); title != "" {
			return title
		}
	}

	return ""
}

// isURLPatternDuplicate 检查URL模式是否重复
// 通过URL模式识别来避免爬取相似的URL
func (o *Orchestrator) isURLPatternDuplicate(targetURL string) bool {
	if targetURL == "" {
		return true
	}

	pattern := o.extractURLPattern(targetURL)
	if pattern == "" {
		return false
	}

	// 使用LoadOrStore进行原子操作
	_, exists := o.urlPatterns.LoadOrStore(pattern, URLPattern{
		BaseURL: targetURL,
		Pattern: pattern,
	})

	if exists {
		log.Debug().
			Str("url", targetURL).
			Str("pattern", pattern).
			Msg("发现重复URL模式")
	}

	return exists
}

// extractURLPattern 提取URL模式
// 将URL中的动态部分替换为占位符，生成URL模式
func (o *Orchestrator) extractURLPattern(targetURL string) string {
	if targetURL == "" {
		return ""
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		log.Debug().Err(err).Str("url", targetURL).Msg("URL解析失败")
		return ""
	}

	// 处理查询参数
	query := parsedURL.Query()
	var paramNames []string

	for key, values := range query {
		paramNames = append(paramNames, key)
		// 将数字值替换为占位符
		for i, value := range values {
			if o.isNumericValue(value) {
				values[i] = "{num}"
			} else if o.isUUIDValue(value) {
				values[i] = "{uuid}"
			} else if len(value) > 20 {
				values[i] = "{long}"
			}
		}
		query[key] = values
	}

	// 对参数名排序以确保一致性
	sort.Strings(paramNames)
	parsedURL.RawQuery = query.Encode()

	return parsedURL.String()
}

// isNumericValue 判断值是否为数字
func (o *Orchestrator) isNumericValue(value string) bool {
	_, err := strconv.Atoi(value)
	return err == nil
}

// isUUIDValue 判断值是否为UUID格式
func (o *Orchestrator) isUUIDValue(value string) bool {
	uuidRegex := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	return uuidRegex.MatchString(value)
}

// isSimilarPage 检查页面是否相似
// 通过多维度相似度计算判断页面是否应该跳过
func (o *Orchestrator) isSimilarPage(newStructure *PageStructure) bool {
	if newStructure == nil {
		return false
	}

	var maxSimilarity float64
	comparisonCount := 0

	// 遍历已存储的页面结构进行比较
	o.pageStructures.Range(func(key, value interface{}) bool {
		existingStructure, ok := value.(*PageStructure)
		if !ok {
			return true // 继续遍历
		}

		comparisonCount++

		// 计算多维度相似度
		domSimilarity := o.calculateDOMSimilarity(newStructure.DOMHash, existingStructure.DOMHash)
		contentSimilarity := o.calculateContentSimilarity(newStructure.TextHash, existingStructure.TextHash)
		formSimilarity := o.calculateFormSimilarity(newStructure.FormFields, existingStructure.FormFields)

		// 结构特征相似度
		structuralSimilarity := o.calculateStructuralSimilarity(newStructure, existingStructure)

		// 加权综合相似度计算
		overallSimilarity := (domSimilarity*0.3 + contentSimilarity*0.3 + formSimilarity*0.2 + structuralSimilarity*0.2)

		if overallSimilarity > maxSimilarity {
			maxSimilarity = overallSimilarity
		}

		// 如果已经找到高相似度页面，可以提前退出
		if maxSimilarity > 0.95 {
			return false // 停止遍历
		}

		return true // 继续遍历
	})

	// 记录相似度检查结果
	log.Debug().
		Float64("max_similarity", maxSimilarity).
		Float64("threshold", o.similarityConfig.DOMThreshold).
		Int("comparisons", comparisonCount).
		Bool("is_similar", maxSimilarity > o.similarityConfig.DOMThreshold).
		Msg("页面相似度检查完成")

	return maxSimilarity > o.similarityConfig.DOMThreshold
}

// calculateDOMSimilarity 计算DOM结构相似度
func (o *Orchestrator) calculateDOMSimilarity(hash1, hash2 string) float64 {
	if hash1 == "" || hash2 == "" {
		return 0.0
	}

	if hash1 == hash2 {
		return 1.0
	}

	// 使用字符级别的相似度计算
	return o.calculateHashSimilarity(hash1, hash2)
}

// calculateContentSimilarity 计算内容相似度
func (o *Orchestrator) calculateContentSimilarity(hash1, hash2 string) float64 {
	if hash1 == "" || hash2 == "" {
		return 0.0
	}

	if hash1 == hash2 {
		return 1.0
	}

	return o.calculateHashSimilarity(hash1, hash2)
}

// calculateFormSimilarity 计算表单相似度
// 使用Jaccard相似度计算表单字段的相似性
func (o *Orchestrator) calculateFormSimilarity(forms1, forms2 map[string]string) float64 {
	if len(forms1) == 0 && len(forms2) == 0 {
		return 1.0 // 都没有表单，认为相似
	}

	if len(forms1) == 0 || len(forms2) == 0 {
		return 0.0 // 一个有表单一个没有，不相似
	}

	// 计算表单字段的交集和并集
	intersection := 0
	union := len(forms1)

	for hash1 := range forms1 {
		if _, exists := forms2[hash1]; exists {
			intersection++
		}
	}

	for hash2 := range forms2 {
		if _, exists := forms1[hash2]; !exists {
			union++
		}
	}

	if union == 0 {
		return 1.0
	}

	return float64(intersection) / float64(union)
}

// calculateStructuralSimilarity 计算结构相似度
// 基于页面元素数量计算结构相似性
func (o *Orchestrator) calculateStructuralSimilarity(struct1, struct2 *PageStructure) float64 {
	if struct1 == nil || struct2 == nil {
		return 0.0
	}

	// 计算各种元素数量的相似度
	inputSimilarity := o.calculateCountSimilarity(struct1.InputCount, struct2.InputCount)
	linkSimilarity := o.calculateCountSimilarity(struct1.LinkCount, struct2.LinkCount)
	scriptSimilarity := o.calculateCountSimilarity(struct1.ScriptCount, struct2.ScriptCount)

	// 标题相似度
	titleSimilarity := o.calculateStringSimilarity(struct1.Title, struct2.Title)

	// 加权平均
	return (inputSimilarity*0.3 + linkSimilarity*0.3 + scriptSimilarity*0.2 + titleSimilarity*0.2)
}

// calculateCountSimilarity 计算数量相似度
func (o *Orchestrator) calculateCountSimilarity(count1, count2 int) float64 {
	if count1 == 0 && count2 == 0 {
		return 1.0
	}

	maxCount := count1
	minCount := count2
	if count2 > count1 {
		maxCount = count2
		minCount = count1
	}

	if maxCount == 0 {
		return 1.0
	}

	return float64(minCount) / float64(maxCount)
}

// calculateStringSimilarity 计算字符串相似度
func (o *Orchestrator) calculateStringSimilarity(str1, str2 string) float64 {
	if str1 == str2 {
		return 1.0
	}

	if str1 == "" || str2 == "" {
		return 0.0
	}

	// 简单的字符串相似度计算（可以使用更复杂的算法如编辑距离）
	shorter := str1
	longer := str2
	if len(str1) > len(str2) {
		shorter = str2
		longer = str1
	}

	if len(longer) == 0 {
		return 1.0
	}

	// 计算公共前缀长度
	commonPrefix := 0
	for i := 0; i < len(shorter) && i < len(longer); i++ {
		if shorter[i] == longer[i] {
			commonPrefix++
		} else {
			break
		}
	}

	return float64(commonPrefix) / float64(len(longer))
}

// calculateHashSimilarity 计算哈希相似度
// 基于字符匹配度计算哈希值的相似性
func (o *Orchestrator) calculateHashSimilarity(hash1, hash2 string) float64 {
	if len(hash1) != len(hash2) {
		return 0.0
	}

	if len(hash1) == 0 {
		return 1.0
	}

	matches := 0
	for i := 0; i < len(hash1); i++ {
		if hash1[i] == hash2[i] {
			matches++
		}
	}

	return float64(matches) / float64(len(hash1))
}

// updateDomainStatistics 更新域名统计信息
// 收集和维护每个域名的统计数据用于阈值调整
func (o *Orchestrator) updateDomainStatistics(pageURL string, structure *PageStructure) {
	if pageURL == "" || structure == nil {
		return
	}

	parsedURL, err := url.Parse(pageURL)
	if err != nil {
		log.Debug().Err(err).Str("url", pageURL).Msg("URL解析失败，跳过统计更新")
		return
	}

	domain := parsedURL.Host
	if domain == "" {
		return
	}

	o.domainStatsMutex.Lock()
	defer o.domainStatsMutex.Unlock()

	stats, exists := o.domainStats[domain]
	if !exists {
		stats = &DomainStatistics{
			LastAdjustment: time.Now(),
		}
		o.domainStats[domain] = stats
	}

	// 更新统计信息
	stats.TotalPages++
	stats.UniqueForms += len(structure.FormFields)

	// 更新平均相似度（简化计算）
	if stats.TotalPages > 1 {
		// 这里可以实现更精确的平均相似度计算
		// 当前使用简化的递增平均算法
		newSimilarity := 0.5 // 假设的相似度值
		stats.AverageSimilarity = (stats.AverageSimilarity*float64(stats.TotalPages-1) + newSimilarity) / float64(stats.TotalPages)
	} else {
		stats.AverageSimilarity = 0.5
	}

	log.Debug().
		Str("domain", domain).
		Int("total_pages", stats.TotalPages).
		Int("unique_forms", stats.UniqueForms).
		Float64("avg_similarity", stats.AverageSimilarity).
		Msg("域名统计已更新")
}

// prioritizeUniqueFormRequests 优先处理结构差异较大的表单请求
// 根据表单唯一性对请求进行排序，优先处理独特的表单
func (o *Orchestrator) prioritizeUniqueFormRequests(requests []*models.Request) []*models.Request {
	if len(requests) <= 1 {
		return requests
	}

	log.Debug().Int("request_count", len(requests)).Msg("开始表单请求优先级排序")

	// 按表单唯一性分数排序
	sort.Slice(requests, func(i, j int) bool {
		scoreI := o.calculateFormUniquenessScore(requests[i])
		scoreJ := o.calculateFormUniquenessScore(requests[j])
		return scoreI > scoreJ // 分数高的排在前面
	})

	log.Debug().Int("sorted_count", len(requests)).Msg("表单请求优先级排序完成")
	return requests
}

// calculateFormUniquenessScore 计算表单唯一性分数
// 分数越高表示表单越独特，应该优先处理
func (o *Orchestrator) calculateFormUniquenessScore(req *models.Request) float64 {
	if req == nil || len(req.Params) == 0 {
		return 0.0
	}

	// 创建表单结构哈希
	var formBuilder strings.Builder
	paramNames := make([]string, 0, len(req.Params))

	for _, param := range req.Params {
		if param.Name != "" {
			paramNames = append(paramNames, param.Name)
		}
	}

	if len(paramNames) == 0 {
		return 0.0
	}

	// 排序以确保一致性
	sort.Strings(paramNames)
	for _, name := range paramNames {
		formBuilder.WriteString(name)
		formBuilder.WriteString(":")
	}

	formHash := fmt.Sprintf("%x", md5.Sum([]byte(formBuilder.String())))

	// 检查是否已存在相似表单
	similarityCount := 0
	o.formStructures.Range(func(key, value interface{}) bool {
		existingHash, ok := key.(string)
		if !ok {
			return true
		}

		similarity := o.calculateHashSimilarity(formHash, existingHash)
		if similarity > o.similarityConfig.FormThreshold {
			similarityCount++
		}
		return true
	})

	// 存储表单结构
	o.formStructures.Store(formHash, true)

	// 计算唯一性分数（相似表单越少，分数越高）
	uniquenessScore := 1.0 / (1.0 + float64(similarityCount))

	log.Debug().
		Str("form_hash", formHash[:8]+"...").
		Int("similar_count", similarityCount).
		Float64("uniqueness_score", uniquenessScore).
		Msg("表单唯一性分数计算完成")

	return uniquenessScore
}

// fetchURLWithRetry 带重试机制的URL获取
// 实现智能重试逻辑，处理网络异常和临时错误
func (o *Orchestrator) fetchURLWithRetry(url string) ([]byte, error) {
    if url == "" {
        return nil, fmt.Errorf("URL不能为空")
    }

    var lastErr error
    startTime := time.Now()

    for attempt := 0; attempt <= o.retryConfig.MaxRetries; attempt++ {
        // 添加重试延迟（除了第一次尝试）
        if attempt > 0 {
            log.Debug().
                Str("url", url).
                Int("attempt", attempt).
                Int("max_retries", o.retryConfig.MaxRetries).
                Dur("delay", o.retryConfig.RetryDelay).
                Msg("重试URL获取")

            select {
            case <-time.After(o.retryConfig.RetryDelay):
            case <-o.ctx.Done():
                return nil, fmt.Errorf("上下文已取消: %w", o.ctx.Err())
            }
        }

        // 执行HTTP请求
        resp, err := o.httpClient.Get(o.ctx, url, nil)
        if err != nil {
            lastErr = fmt.Errorf("HTTP请求失败: %w", err)
            
            // 检查是否为可重试的错误
            if !o.isRetryableError(err) {
                log.Debug().
                    Err(err).
                    Str("url", url).
                    Msg("不可重试的错误，停止重试")
                break
            }
            continue
        }

        // 检查HTTP状态码
        if resp.StatusCode >= 400 {
            resp.Body.Close()
            lastErr = fmt.Errorf("HTTP状态码错误: %d", resp.StatusCode)
            
            // 4xx错误通常不需要重试
            if resp.StatusCode >= 400 && resp.StatusCode < 500 {
                break
            }
            continue
        }

        // 读取响应体
        bodyBytes, err := io.ReadAll(resp.Body)
        resp.Body.Close()

        if err != nil {
            lastErr = fmt.Errorf("读取响应体失败: %w", err)
            continue
        }

        // 检查响应体大小
        const maxBodySize = 10 * 1024 * 1024 // 10MB
        if len(bodyBytes) > maxBodySize {
            log.Warn().
                Str("url", url).
                Int("size", len(bodyBytes)).
                Msg("响应体过大，可能影响性能")
        }

        log.Debug().
            Str("url", url).
            Int("attempt", attempt+1).
            Int("size", len(bodyBytes)).
            Dur("elapsed", time.Since(startTime)). // 修复：Duration -> Dur
            Msg("URL获取成功")

        return bodyBytes, nil
    }

    return nil, fmt.Errorf("重试%d次后仍然失败: %w", o.retryConfig.MaxRetries+1, lastErr)
}

// isRetryableError 判断错误是否可重试
// 分析错误类型，决定是否值得重试
func (o *Orchestrator) isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := strings.ToLower(err.Error())
	
	// 定义可重试的错误模式
	retryablePatterns := []string{
		"timeout",
		"connection reset",
		"connection refused",
		"temporary failure",
		"server closed",
		"network is unreachable",
		"no route to host",
		"connection timed out",
		"i/o timeout",
		"broken pipe",
		"connection aborted",
	}

	for _, pattern := range retryablePatterns {
		if strings.Contains(errStr, pattern) {
			log.Debug().
				Err(err).
				Str("pattern", pattern).
				Msg("检测到可重试错误")
			return true
		}
	}

	return false
}

// filterValidLinks 过滤有效的链接
// 移除无效、过长或指向静态资源的链接
func (o *Orchestrator) filterValidLinks(links []string) []string {
	if len(links) == 0 {
		return links
	}

	validLinks := make([]string, 0, len(links))
	filteredCount := 0

	for _, link := range links {
		// 基本验证
		if link == "" {
			filteredCount++
			continue
		}

		// 长度检查
		if len(link) > maxURLLength {
			log.Debug().
				Str("url", link[:50]+"...").
				Int("length", len(link)).
				Msg("链接过长，已过滤")
			filteredCount++
			continue
		}

		// 静态资源检查
		if o.isStaticResource(link) {
			log.Debug().Str("url", link).Msg("静态资源链接，已过滤")
			filteredCount++
			continue
		}

		// URL格式验证
		if _, err := url.Parse(link); err != nil {
			log.Debug().
				Err(err).
				Str("url", link).
				Msg("无效URL格式，已过滤")
			filteredCount++
			continue
		}

		validLinks = append(validLinks, link)
	}

	log.Debug().
		Int("total_links", len(links)).
		Int("valid_links", len(validLinks)).
		Int("filtered_count", filteredCount).
		Msg("链接过滤完成")

	return validLinks
}

// filterValidRequests 过滤有效的请求
// 移除无效的HTTP请求
func (o *Orchestrator) filterValidRequests(requests []*models.Request) []*models.Request {
	if len(requests) == 0 {
		return requests
	}

	validRequests := make([]*models.Request, 0, len(requests))
	filteredCount := 0

	for _, req := range requests {
		// 基本验证
		if req == nil || req.URL == nil {
			filteredCount++
			continue
		}

		// URL长度检查
		if len(req.URL.String()) > maxURLLength {
			log.Debug().
				Str("url", req.URL.String()[:50]+"...").
				Msg("请求URL过长，已过滤")
			filteredCount++
			continue
		}

		// 静态资源检查
		if o.isStaticResource(req.URL.String()) {
			log.Debug().
				Str("url", req.URL.String()).
				Msg("静态资源请求，已过滤")
			filteredCount++
			continue
		}

		// HTTP方法验证
		if !o.isValidHTTPMethod(req.Method) {
			log.Debug().
				Str("method", req.Method).
				Str("url", req.URL.String()).
				Msg("无效HTTP方法，已过滤")
			filteredCount++
			continue
		}

		validRequests = append(validRequests, req)
	}

	log.Debug().
		Int("total_requests", len(requests)).
		Int("valid_requests", len(validRequests)).
		Int("filtered_count", filteredCount).
		Msg("请求过滤完成")

	return validRequests
}

// isStaticResource 判断是否为静态资源
// 检查URL是否指向静态文件
func (o *Orchestrator) isStaticResource(url string) bool {
	if url == "" {
		return false
	}

	// 定义静态资源扩展名
	staticExtensions := []string{
		// 样式和脚本
		".css", ".js", ".scss", ".sass", ".less",
		// 图片
		".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".bmp", ".tiff",
		// 字体
		".woff", ".woff2", ".ttf", ".eot", ".otf",
		// 文档
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		// 压缩文件
		".zip", ".tar", ".gz", ".rar", ".7z",
		// 媒体文件
		".mp4", ".mp3", ".avi", ".mov", ".wmv", ".flv", ".mkv", ".webm",
		".wav", ".aac", ".ogg", ".m4a",
		// 其他
		".xml", ".json", ".txt", ".csv",
	}

	urlLower := strings.ToLower(url)
	
	for _, ext := range staticExtensions {
		if strings.HasSuffix(urlLower, ext) {
			return true
		}
	}

	// 检查常见的静态资源路径模式
	staticPaths := []string{
		"/static/", "/assets/", "/public/", "/resources/",
		"/css/", "/js/", "/images/", "/img/", "/fonts/",
	}

	for _, path := range staticPaths {
		if strings.Contains(urlLower, path) {
			return true
		}
	}

	return false
}

// isValidHTTPMethod 验证HTTP方法是否有效
// 检查HTTP方法是否在支持的范围内
func (o *Orchestrator) isValidHTTPMethod(method string) bool {
	if method == "" {
		return false
	}

	validMethods := []string{
		http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodDelete,
		http.MethodPatch,
		http.MethodHead,
		http.MethodOptions,
	}

	methodUpper := strings.ToUpper(method)
	for _, validMethod := range validMethods {
		if methodUpper == validMethod {
			return true
		}
	}

	log.Debug().Str("method", method).Msg("不支持的HTTP方法")
	return false
}

// scanRequestWithRetry 带重试机制的请求扫描
// 对单个请求执行漏洞扫描，包含重试逻辑
func (o *Orchestrator) scanRequestWithRetry(ctx context.Context, req *models.Request, reporter *output.Reporter) int {
    if req == nil || req.URL == nil {
        log.Warn().Msg("无效的扫描请求")
        return 0
    }

    var totalVulnerabilities int
    startTime := time.Now()

    for attempt := 0; attempt <= o.retryConfig.MaxRetries; attempt++ {
        if attempt > 0 {
            log.Debug().
                Str("url", req.URL.String()).
                Int("attempt", attempt).
                Msg("重试请求扫描")

            select {
            case <-time.After(o.retryConfig.RetryDelay):
            case <-ctx.Done():
                log.Debug().Msg("扫描上下文已取消")
                return totalVulnerabilities
            }
        }

        vulnerabilities := o.scanRequest(ctx, req, reporter)
        if vulnerabilities >= 0 {
            // 扫描成功完成
            totalVulnerabilities = vulnerabilities
            break
        }

        // 扫描失败，准备重试
        log.Debug().
            Str("url", req.URL.String()).
            Int("attempt", attempt+1).
            Msg("扫描失败，准备重试")
    }

    log.Debug().
        Str("url", req.URL.String()).
        Int("vulnerabilities", totalVulnerabilities).
        Dur("elapsed", time.Since(startTime)). // 修复：Duration -> Dur
        Msg("请求扫描完成")

    return totalVulnerabilities
}

// scanRequest 对单个请求执行所有插件的扫描，返回发现的漏洞数量
// 这是漏洞扫描的核心逻辑
func (o *Orchestrator) scanRequest(ctx context.Context, req *models.Request, reporter *output.Reporter) int {
	if req == nil || req.URL == nil {
		return -1 // 返回-1表示扫描失败
	}

	vulnerabilityCount := 0
	pluginErrors := 0

	log.Debug().
		Str("url", req.URL.String()).
		Str("method", req.Method).
		Int("plugins", len(o.plugins)).
		Msg("开始漏洞扫描")

	for _, plugin := range o.plugins {
		select {
		case <-ctx.Done():
			log.Debug().
				Str("plugin", plugin.Info().Name).
				Msg("插件扫描被取消")
			return vulnerabilityCount
		default:
		}

		// 为每个插件创建带超时的上下文
		pluginCtx, cancel := context.WithTimeout(ctx, o.config.Scanner.Timeout)

		// 获取插件的payloads
		pluginName := plugin.Info().Name
		payloads, ok := o.payloads[pluginName]
		if !ok || len(payloads) == 0 {
			log.Debug().
				Str("plugin", pluginName).
				Msg("插件没有可用的payloads，跳过扫描")
			cancel()
			continue
		}

		// AI辅助payload生成（如果启用）
		enhancedPayloads := o.enhancePayloadsWithAI(pluginCtx, plugin, req, payloads)

		// 执行插件扫描
		vulnerabilities, err := plugin.Scan(pluginCtx, req, enhancedPayloads)
		if err != nil {
			pluginErrors++
			log.Error().
				Err(err).
				Str("plugin", pluginName).
				Str("url", req.URL.String()).
				Msg("插件扫描失败")
		} else {
			// 处理发现的漏洞
			for _, vuln := range vulnerabilities {
				reporter.LogVulnerability(vuln)
				vulnerabilityCount++
			}

			if len(vulnerabilities) > 0 {
				log.Info().
					Str("plugin", pluginName).
					Int("count", len(vulnerabilities)).
					Str("url", req.URL.String()).
					Msg("发现漏洞")
			}
		}

		cancel()
	}

	// 记录扫描统计
	log.Debug().
		Str("url", req.URL.String()).
		Int("vulnerabilities", vulnerabilityCount).
		Int("plugin_errors", pluginErrors).
		Int("plugins_total", len(o.plugins)).
		Msg("漏洞扫描完成")

	// 如果所有插件都失败了，返回-1表示扫描失败
	if pluginErrors == len(o.plugins) && len(o.plugins) > 0 {
		return -1
	}

	return vulnerabilityCount
}

// enhancePayloadsWithAI AI辅助payload增强
// 使用AI分析器生成额外的测试payload
func (o *Orchestrator) enhancePayloadsWithAI(ctx context.Context, plugin vulnscan.Plugin, req *models.Request, originalPayloads []string) []string {
	// 如果AI分析器未启用，直接返回原始payloads
	if o.aiAnalyzer == nil {
		return originalPayloads
	}

	// 提取参数名用于AI分析
	var paramNames []string
	for _, p := range req.Params {
		if p.Name != "" {
			paramNames = append(paramNames, p.Name)
		}
	}

	if len(paramNames) == 0 {
		return originalPayloads
	}

	// 生成AI payloads
	aiPayloads, err := o.aiAnalyzer.GeneratePayloads(
		ctx,
		plugin.Info().Name,
		req.URL.String(),
		req.Method,
		strings.Join(paramNames, ","),
	)

	if err != nil {
		log.Debug().
			Err(err).
			Str("plugin", plugin.Info().Name).
			Msg("AI payload生成失败")
		return originalPayloads
	}

	if len(aiPayloads) == 0 {
		return originalPayloads
	}

	// 合并原始payloads和AI生成的payloads
	enhancedPayloads := make([]string, 0, len(originalPayloads)+len(aiPayloads))
	enhancedPayloads = append(enhancedPayloads, originalPayloads...)
	enhancedPayloads = append(enhancedPayloads, aiPayloads...)

	log.Debug().
		Str("plugin", plugin.Info().Name).
		Int("original_count", len(originalPayloads)).
		Int("ai_count", len(aiPayloads)).
		Int("total_count", len(enhancedPayloads)).
		Msg("AI payload增强完成")

	return enhancedPayloads
}

// GetStatistics 获取当前统计信息
// 提供外部访问统计数据的接口
func (o *Orchestrator) GetStatistics() Statistics {
	return Statistics{
		URLsProcessed:        atomic.LoadInt64(&o.stats.URLsProcessed),
		RequestsScanned:      atomic.LoadInt64(&o.stats.RequestsScanned),
		VulnerabilitiesFound: atomic.LoadInt64(&o.stats.VulnerabilitiesFound),
		DuplicatesSkipped:    atomic.LoadInt64(&o.stats.DuplicatesSkipped),
		SimilarPagesSkipped:  atomic.LoadInt64(&o.stats.SimilarPagesSkipped),
	}
}

// GetDomainStatistics 获取域名统计信息
// 提供外部访问域名统计的接口
func (o *Orchestrator) GetDomainStatistics() map[string]*DomainStatistics {
	o.domainStatsMutex.RLock()
	defer o.domainStatsMutex.RUnlock()

	// 创建副本以避免并发访问问题
	result := make(map[string]*DomainStatistics)
	for domain, stats := range o.domainStats {
		result[domain] = &DomainStatistics{
			TotalPages:        stats.TotalPages,
			UniqueForms:       stats.UniqueForms,
			AverageSimilarity: stats.AverageSimilarity,
			LastAdjustment:    stats.LastAdjustment,
		}
	}

	return result
}

// UpdateSimilarityConfig 更新相似度配置
// 允许运行时调整相似度检测参数
func (o *Orchestrator) UpdateSimilarityConfig(config SimilarityConfig) {
	o.mu.Lock()
	defer o.mu.Unlock()

	oldConfig := o.similarityConfig
	o.similarityConfig = config

	log.Info().
		Float64("old_dom_threshold", oldConfig.DOMThreshold).
		Float64("new_dom_threshold", config.DOMThreshold).
		Float64("old_content_threshold", oldConfig.ContentThreshold).
		Float64("new_content_threshold", config.ContentThreshold).
		Float64("old_form_threshold", oldConfig.FormThreshold).
		Float64("new_form_threshold", config.FormThreshold).
		Bool("auto_adjust", config.AutoAdjust).
		Msg("相似度配置已更新")
}

// Stop 停止编排器
// 优雅地停止所有正在进行的操作
func (o *Orchestrator) Stop() {
	if o.cancel != nil {
		log.Info().Msg("正在停止编排器...")
		o.cancel()
	}
}

// IsRunning 检查编排器是否正在运行
func (o *Orchestrator) IsRunning() bool {
	select {
	case <-o.ctx.Done():
		return false
	default:
		return true
	}
}

// GetUptime 获取运行时间
func (o *Orchestrator) GetUptime() time.Duration {
	return time.Since(o.startTime)
}

		