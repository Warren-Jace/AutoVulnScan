// Package core 包含了 AutoVulnScan 应用程序的核心编排器。
package core

import (
	"bytes"
	"context"
	"crypto/md5"
	"errors"
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
	"autovulnscan/internal/browser"
	"autovulnscan/internal/config"
	"autovulnscan/internal/crawler"
	"autovulnscan/internal/dedup"
	"autovulnscan/internal/models"
	"autovulnscan/internal/output"
	"autovulnscan/internal/requester"
	"autovulnscan/internal/vulnscan"
	_ "autovulnscan/internal/vulnscan/plugins" // 匿名导入以执行插件的init()函数进行注册

	"github.com/rs/zerolog/log"
	"golang.org/x/net/html"
)

// PageStructure 页面结构信息
type PageStructure struct {
	DOMHash     string            // DOM结构哈希
	TextHash    string            // 文本内容哈希
	FormFields  map[string]string // 表单字段映射
	InputCount  int               // 输入字段数量
	LinkCount   int               // 链接数量
	ScriptCount int               // 脚本数量
	Title       string            // 页面标题
}

// TimestampedPageStructure 带时间戳的页面结构
type TimestampedPageStructure struct {
	*PageStructure
	Timestamp time.Time
}

// URLPattern URL模式
type URLPattern struct {
	BaseURL    string   // 基础URL
	ParamNames []string // 参数名列表
	Pattern    string   // URL模式
}

// SimilarityConfig 相似度配置
type SimilarityConfig struct {
	DOMThreshold     float64 // DOM结构相似度阈值
	ContentThreshold float64 // 内容相似度阈值
	FormThreshold    float64 // 表单相似度阈值
	URLThreshold     float64 // URL模式相似度阈值
	AutoAdjust       bool    // 是否自动调整阈值
}

// Orchestrator 负责协调爬虫、扫描和报告的主流程控制器。
type Orchestrator struct {
	config       *config.Settings
	targetURL    string
	crawler      *crawler.Crawler
	scanEngine   *vulnscan.Engine // 使用扫描引擎
	deduplicator *dedup.Deduplicator
	aiAnalyzer   *ai.AIAnalyzer
	httpClient   *requester.HTTPClient
	ctx          context.Context
	cancel       context.CancelFunc

	vulnerabilities []*vulnscan.Vulnerability // 存储所有发现的漏洞
	vulnMutex       sync.Mutex                // 保护vulnerabilities切片

	stats struct {
		urlsProcessed        int64
		requestsScanned      int64
		paramsFound          int64
		postParamsFound      int64
		vulnerabilitiesFound int64
		duplicatesSkipped    int64
		similarPagesSkipped  int64
		startTime            time.Time
		currentPhase         string
	}

	retryConfig struct {
		maxRetries int
		retryDelay time.Duration
	}

	similarityConfig SimilarityConfig
	pageStructures   sync.Map
	urlPatterns      sync.Map
	formStructures   sync.Map
	requestDedup     sync.Map
	domainStats      map[string]*DomainStatistics
	domainStatsMutex sync.RWMutex

	// 清理相关
	cleanupTicker *time.Ticker
	cleanupDone   chan struct{}
}

// DomainStatistics 域名统计信息，用于动态调整阈值
type DomainStatistics struct {
	TotalPages        int       // 总页面数
	UniqueForms       int       // 唯一表单数
	AverageSimilarity float64   // 平均相似度
	LastAdjustment    time.Time // 最后调整时间
}

// FormStructure 表单结构
type FormStructure struct {
	Fields []string // 字段名列表
	Types  []string // 字段类型列表
	Action string   // 表单action
	Method string   // 表单method
	Hash   string   // 结构哈希
}

// 对象池优化
var builderPool = sync.Pool{
	New: func() interface{} {
		return &strings.Builder{}
	},
}

// validateConfig 验证配置
func validateConfig(cfg *config.Settings) error {
	if cfg == nil {
		return errors.New("配置不能为空")
	}
	if cfg.Spider.Concurrency <= 0 {
		return errors.New("爬虫并发数必须大于0")
	}
	if cfg.Spider.MaxDepth < 0 {
		return errors.New("最大深度不能为负数")
	}
	if cfg.Scanner.Timeout <= 0 {
		return errors.New("扫描器超时时间必须大于0")
	}
	return nil
}

// validateTargetURL 验证目标URL
func validateTargetURL(targetURL string) error {
	if targetURL == "" {
		return errors.New("目标URL不能为空")
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("无效的URL格式: %w", err)
	}

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return errors.New("URL必须使用http或https协议")
	}

	if parsedURL.Host == "" {
		return errors.New("URL必须包含有效的主机名")
	}

	return nil
}

// NewOrchestrator 创建并初始化一个Orchestrator实例。
// 这个函数负责组装所有必要的组件，如HTTP客户端、爬虫、扫描引擎等。
func NewOrchestrator(cfg *config.Settings, targetURL string) (*Orchestrator, error) {
	// 验证输入参数
	if err := validateConfig(cfg); err != nil {
		return nil, fmt.Errorf("配置验证失败: %w", err)
	}

	if err := validateTargetURL(targetURL); err != nil {
		return nil, fmt.Errorf("目标URL验证失败: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// 为爬虫创建独立的HTTP客户端
	spiderHttpClient := requester.NewHTTPClient(cfg.Spider.Timeout, cfg.Proxy, cfg.Headers)

	cr, err := crawler.NewCrawler(targetURL, cfg, spiderHttpClient)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("初始化爬虫失败: %w", err)
	}

	// 为扫描器创建独立的HTTP客户端
	scannerHttpClient := requester.NewHTTPClient(int(cfg.Scanner.Timeout/time.Second), cfg.Proxy, cfg.Headers)

	// 初始化浏览器服务
	var browserService *browser.BrowserService
	if cfg.Spider.DynamicCrawler.Enabled {
		browserService, err = browser.NewBrowserService(browser.Config{
			Headless:  cfg.Spider.DynamicCrawler.Headless,
			Proxy:     cfg.Proxy,
			UserAgent: cfg.Headers["User-Agent"],
		})
		if err != nil {
			log.Warn().Err(err).Msg("初始化浏览器服务失败，部分功能（如XSS DOM验证）将受限")
			// 非致命错误，允许继续
		}
	}

	scanEngine, err := vulnscan.NewEngine(&cfg.Scanner, scannerHttpClient, browserService)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("初始化扫描引擎失败: %w", err)
	}

	var aiAnalyzer *ai.AIAnalyzer
	if cfg.AIModule.Enabled {
		aiAnalyzer, err = ai.NewAIAnalyzer(cfg.AIModule.APIKey, cfg.AIModule.Model, "")
		if err != nil {
			log.Warn().Err(err).Msg("初始化AI分析器失败，AI功能将被禁用")
		}
	}

	o := &Orchestrator{
		config:       cfg,
		targetURL:    targetURL,
		crawler:      cr,
		scanEngine:   scanEngine,
		deduplicator: dedup.NewDeduplicator(dedup.WithThreshold(0.95)),
		aiAnalyzer:   aiAnalyzer,
		httpClient:   spiderHttpClient, // Orchestrator自身保留一个用于通用目的的客户端
		ctx:          ctx,
		cancel:       cancel,
		domainStats:  make(map[string]*DomainStatistics),
		cleanupDone:  make(chan struct{}),
	}

	// 初始化统计数据
	o.stats.startTime = time.Now()
	o.stats.currentPhase = "初始化"

	// 初始化重试配置
	o.retryConfig.maxRetries = 3
	o.retryConfig.retryDelay = 2 * time.Second

	// 初始化相似度配置
	o.initSimilarityConfig()

	// 启动清理任务
	o.startCleanupTask()

	return o, nil
}

// startCleanupTask 启动清理任务
func (o *Orchestrator) startCleanupTask() {
	o.cleanupTicker = time.NewTicker(30 * time.Minute) // 每30分钟清理一次
	go func() {
		defer o.cleanupTicker.Stop()
		for {
			select {
			case <-o.cleanupTicker.C:
				o.cleanupOldStructures()
			case <-o.cleanupDone:
				return
			case <-o.ctx.Done():
				return
			}
		}
	}()
}

// stopCleanupTask 停止清理任务
func (o *Orchestrator) stopCleanupTask() {
	if o.cleanupTicker != nil {
		close(o.cleanupDone)
	}
}

// cleanupOldStructures 清理旧的页面结构
func (o *Orchestrator) cleanupOldStructures() {
	cutoff := time.Now().Add(-time.Hour)
	cleaned := 0

	o.pageStructures.Range(func(key, value interface{}) bool {
		if shouldCleanup(value, cutoff) {
			o.pageStructures.Delete(key)
			cleaned++
		}
		return true
	})

	if cleaned > 0 {
		log.Debug().Int("cleaned", cleaned).Msg("清理了过期的页面结构")
	}
}

// shouldCleanup 检查是否应该清理
func shouldCleanup(value interface{}, cutoff time.Time) bool {
	if timestamped, ok := value.(*TimestampedPageStructure); ok {
		return timestamped.Timestamp.Before(cutoff)
	}
	return false
}

// isInScope 检查给定的URL是否在扫描范围内。
// 它会根据配置的域名范围和黑名单进行判断。
func (o *Orchestrator) isInScope(link string) bool {
	parsedURL, err := url.Parse(link)
	if err != nil {
		log.Debug().Str("url", link).Err(err).Msg("无法解析URL，已跳过")
		return false
	}

	// 检查URL是否在黑名单中
	for _, blacklistedPattern := range o.config.Blacklist {
		if matched, _ := regexp.MatchString(blacklistedPattern, link); matched {
			return false
		}
	}

	// 检查URL域名是否在范围内
	for _, scopeDomain := range o.config.Scope {
		if strings.HasSuffix(parsedURL.Host, scopeDomain) {
			return true
		}
	}

	return false
}

// initSimilarityConfig 初始化相似度配置
func (o *Orchestrator) initSimilarityConfig() {
	o.similarityConfig = SimilarityConfig{
		DOMThreshold:     0.85, // DOM结构相似度阈值85%
		ContentThreshold: 0.80, // 内容相似度阈值80%
		FormThreshold:    0.90, // 表单相似度阈值90%
		URLThreshold:     0.75, // URL模式相似度阈值75%
		AutoAdjust:       false, // 启用自动调整
	}
}

// Start 启动编排器的总执行流程。
func (o *Orchestrator) Start(reporter *output.Reporter) {
	log.Info().Msg("🚀 扫描任务开始 (Scan task started)")
	o.stats.startTime = time.Now()

	// 确保在任务结束时关闭报告器和清理资源
	defer func() {
		reporter.Close()
		o.stopCleanupTask()
	}()

	// 启动一个goroutine来收集漏洞
	go o.collectVulnerabilities()

	// 启动统计和阈值调整的 Ticker
	statsTicker := time.NewTicker(30 * time.Second)
	defer statsTicker.Stop()

	if o.similarityConfig.AutoAdjust {
		adjustTicker := time.NewTicker(1 * time.Minute)
		defer adjustTicker.Stop()
		go o.autoAdjustThresholds(adjustTicker.C)
	}

	// --- 阶段一: 爬取 ---
	o.stats.currentPhase = "正在爬取"
	requestsToScan, err := o.crawl(reporter)
	if err != nil {
		log.Error().Err(err).Msg("爬取阶段失败")
		return
	}

	// --- 阶段二: 扫描 ---
	o.stats.currentPhase = "漏洞检测中"
	o.scan(requestsToScan)

	o.cancel()
	o.scanEngine.Close()

	log.Info().Msg("✅ 扫描任务完成 (Scan task finished)")
	o.printFinalStats()
}

func (o *Orchestrator) crawl(reporter *output.Reporter) ([]*models.Request, error) {
	log.Info().Msg("--- 爬取阶段开始 ---")
	var wg sync.WaitGroup
	crawlQueue := make(chan models.Task, o.config.Spider.Concurrency*2)
	seenURLs := &sync.Map{}
	var requestsToScan []*models.Request
	var reqMutex sync.Mutex

	// 启动爬虫工作协程
	for i := 1; i <= o.config.Spider.Concurrency; i++ {
		go func(workerID int) {
			for task := range crawlQueue {
				o.handleCrawlTask(task, &wg, reporter, seenURLs, crawlQueue, &requestsToScan, &reqMutex)
				wg.Done()
			}
		}(i)
	}

	// 添加入口URL
	wg.Add(1)
	crawlQueue <- models.Task{URL: o.targetURL, Depth: 0}

	wg.Wait()
	close(crawlQueue)
	log.Info().Msg("--- 爬取阶段完成 ---")
	return requestsToScan, nil
}

func (o *Orchestrator) scan(requests []*models.Request) {
	log.Info().Int("request_count", len(requests)).Msg("--- 扫描阶段开始 ---")
	o.scanEngine.Start()

	for _, req := range requests {
		o.scanEngine.QueueRequest(req)
		atomic.AddInt64(&o.stats.requestsScanned, 1)
	}

	o.scanEngine.Stop()
	log.Info().Msg("--- 扫描阶段完成 ---")
}

func (o *Orchestrator) collectVulnerabilities() {
	for vuln := range o.scanEngine.VulnerabilityChan() {
		atomic.AddInt64(&o.stats.vulnerabilitiesFound, 1)

		o.vulnMutex.Lock()
		o.vulnerabilities = append(o.vulnerabilities, vuln)
		o.vulnMutex.Unlock()

		mode := "normal"
		if o.config.Debug {
			mode = "debug"
		}

		log.Warn().
			Str("模式", mode).
			Str("URL", vuln.URL).
			Str("方法", vuln.Method).
			Str("参数", vuln.Param).
			Str("Payload", vuln.Payload).
			Msgf("🚨 发现漏洞 (Vulnerability found)")
	}
}

// printFinalStats 输出最终统计信息
func (o *Orchestrator) printFinalStats() {
	totalTime := time.Since(o.stats.startTime).Round(time.Second)
	mode := "normal"
	if o.config.Debug {
		mode = "debug"
	}
	log.Info().Msgf(`\n======== 📈 扫描统计汇总 📈 ========\n| 总用时:           %s\n| 已处理URL数:      %d\n| 已扫描请求数:     %d\n| 已发现参数数:     %d\n| 已发现POST参数数: %d\n| 已发现漏洞数:     %d\n| 跳过重复URL数:    %d\n| 跳过相似页面数:   %d\n| 当前模式:         %s\n| 日志文件:         %s\n| 报告文件路径:     %s\n====================================`,
		totalTime,
		atomic.LoadInt64(&o.stats.urlsProcessed),
		atomic.LoadInt64(&o.stats.requestsScanned),
		atomic.LoadInt64(&o.stats.paramsFound),
		atomic.LoadInt64(&o.stats.postParamsFound),
		atomic.LoadInt64(&o.stats.vulnerabilitiesFound),
		atomic.LoadInt64(&o.stats.duplicatesSkipped),
		atomic.LoadInt64(&o.stats.similarPagesSkipped),
		mode,
		o.config.Log.FilePath,
		o.config.Reporting.Path,
	)

	// 输出域名统计
	o.domainStatsMutex.RLock()
	for domain, stats := range o.domainStats {
		log.Info().
			Str("domain", domain).
			Int("total_pages", stats.TotalPages).
			Int("unique_forms", stats.UniqueForms).
			Float64("avg_similarity", stats.AverageSimilarity).
			Msg("📈 域名统计 (Domain statistics)")
	}
	o.domainStatsMutex.RUnlock()
}

// autoAdjustThresholds 自动调整相似度阈值
func (o *Orchestrator) autoAdjustThresholds(ticker <-chan time.Time) {
	for {
		select {
		case <-ticker:
			o.domainStatsMutex.RLock()
			for domain, stats := range o.domainStats {
				if time.Since(stats.LastAdjustment) < time.Minute*10 {
					continue
				}

				// 根据平均相似度调整阈值
				if stats.AverageSimilarity > 0.9 {
					// 页面相似度很高，降低阈值以减少重复爬取
					o.similarityConfig.DOMThreshold = 0.90
					o.similarityConfig.ContentThreshold = 0.85
				} else if stats.AverageSimilarity < 0.5 {
					// 页面差异较大，提高阈值以爬取更多页面
					o.similarityConfig.DOMThreshold = 0.75
					o.similarityConfig.ContentThreshold = 0.70
				}

				stats.LastAdjustment = time.Now()
				log.Debug().
					Str("domain", domain).
					Float64("dom_threshold", o.similarityConfig.DOMThreshold).
					Float64("content_threshold", o.similarityConfig.ContentThreshold).
					Msg("Adjusted similarity thresholds")
			}
			o.domainStatsMutex.RUnlock()
		case <-o.ctx.Done():
			return
		}
	}
}

// handleError 统一错误处理
func (o *Orchestrator) handleError(err error, url string, operation string) bool {
	if err == nil {
		return false
	}

	log.Error().
		Err(err).
		Str("url", url).
		Str("operation", operation).
		Msg("操作失败")

	// 根据错误类型决定是否继续
	return o.isCriticalError(err)
}

// isCriticalError 判断是否为关键错误
func (o *Orchestrator) isCriticalError(err error) bool {
	if err == nil {
		return false
	}

	errStr := strings.ToLower(err.Error())
	criticalErrors := []string{
		"context canceled",
		"context deadline exceeded",
		"connection refused",
		"no such host",
		"network unreachable",
	}

	for _, critical := range criticalErrors {
		if strings.Contains(errStr, critical) {
			return true
		}
	}

	return false
}

// handleCrawlTask 处理爬取任务，包括深度检查、相似度分析、链接和请求发现
func (o *Orchestrator) handleCrawlTask(task models.Task, wg *sync.WaitGroup, reporter *output.Reporter, seenURLs *sync.Map, crawlQueue chan models.Task, requestsToScan *[]*models.Request, reqMutex *sync.Mutex) {
	// 检查上下文取消
	select {
	case <-o.ctx.Done():
		return
	default:
	}

	atomic.AddInt64(&o.stats.urlsProcessed, 1)

	// 0. 范围检查
	if !o.isInScope(task.URL) {
		log.Debug().Str("url", task.URL).Str("reason", "out_of_scope").Msg("⏭️ 跳过爬取 (Skipping crawl)")
		reporter.LogUnscopedURL(task.URL)
		return
	}

	if task.Depth >= o.config.Spider.MaxDepth {
		log.Debug().Str("url", task.URL).Int("depth", task.Depth).Str("reason", "max_depth_reached").Msg("⏭️ 跳过爬取 (Skipping crawl)")
		return
	}

	// 1. URL模式检查
	if o.isURLPatternDuplicate(task.URL) {
		log.Debug().Str("url", task.URL).Str("reason", "duplicate_pattern").Msg("⏭️ 跳过爬取 (Skipping crawl)")
		atomic.AddInt64(&o.stats.similarPagesSkipped, 1)
		return
	}

	// 2. 获取页面内容
	log.Debug().Str("url", task.URL).Msg("⬇️ 正在获取页面 (Fetching page)")
	bodyBytes, err := o.fetchURLWithRetry(task.URL)
	if err != nil {
		if o.handleError(err, task.URL, "fetch") {
			return
		}
		log.Error().Err(err).Str("url", task.URL).Msg("❌ 获取URL失败 (Failed to fetch URL)")
		return
	}
	log.Debug().Str("url", task.URL).Int("size", len(bodyBytes)).Msg("✅ 页面获取成功 (Page fetched successfully)")

	// 3. 分析页面结构
	log.Debug().Str("url", task.URL).Msg("🔬 正在分析页面结构 (Analyzing page structure)")
	pageStructure, err := o.analyzePageStructure(task.URL, bodyBytes)
	if err != nil {
		log.Error().Err(err).Str("url", task.URL).Msg("❌ 页面结构分析失败 (Failed to analyze page structure)")
		return
	}

	// 4. 相似度检查
	if o.isSimilarPage(pageStructure) {
		log.Debug().Str("url", task.URL).Str("reason", "similar_page").Msg("⏭️ 跳过爬取 (Skipping crawl)")
		atomic.AddInt64(&o.stats.similarPagesSkipped, 1)
		return
	}

	// 5. 传统去重检查（作为备份）
	isUnique, err := o.deduplicator.IsUnique(task.URL, bytes.NewReader(bodyBytes))
	if err != nil {
		log.Error().Err(err).Str("url", task.URL).Msg("❌ 去重检查失败 (Deduplication check failed)")
		return
	}
	if !isUnique {
		log.Debug().Str("url", task.URL).Str("reason", "duplicate_content").Msg("⏭️ 跳过爬取 (Skipping crawl)")
		reporter.LogDeDuplicateURL(task.URL)
		atomic.AddInt64(&o.stats.duplicatesSkipped, 1)
		return
	}

	// 6. 存储页面结构
	o.storePageStructure(task.URL, pageStructure)
	o.updateDomainStatistics(task.URL, pageStructure)

	// 7. 爬取和解析页面内容
	log.Info().Str("url", task.URL).Msg("🏁 开始爬取 (Starting crawl)")
	allLinks, allRequests, err := o.crawler.Crawl(o.ctx, task.URL, bodyBytes)
	if err != nil {
		log.Error().Err(err).Str("url", task.URL).Msg("❌ 爬取失败 (Crawl failed)")
		return
	}
	log.Info().
		Str("url", task.URL).
		Int("found_links", len(allLinks)).
		Int("found_requests", len(allRequests)).
		Msg("✅ 爬取完成 (Crawl finished)")

	reporter.LogURL(task.URL)
	// 更新参数统计
	for _, req := range allRequests {
		if u, err := url.Parse(req.URL); err == nil {
			atomic.AddInt64(&o.stats.paramsFound, int64(len(u.Query())))
		}
		if req.Method == "POST" {
			// 这里假设 Body 是 urlencoded 的表单
			if params, err := url.ParseQuery(req.Body); err == nil {
				atomic.AddInt64(&o.stats.postParamsFound, int64(len(params)))
				atomic.AddInt64(&o.stats.paramsFound, int64(len(params)))
			}
		}
	}

	log.Debug().Str("url", task.URL).Int("found_links", len(allLinks)).Int("found_requests", len(allRequests)).Msg("🔗 发现新链接和请求 (Found new links and requests)")

	// 8. 过滤和验证新发现的链接和请求
	validLinks := o.filterValidLinks(allLinks)
	validRequests := o.filterValidRequests(allRequests)
	log.Debug().Str("url", task.URL).Int("valid_links", len(validLinks)).Int("valid_requests", len(validRequests)).Msg("🛡️ 过滤后有效的链接和请求 (Filtered valid links and requests)")

	// 9. 优先处理结构差异较大的表单
	validRequests = o.prioritizeUniqueFormRequests(validRequests)

	// 10. 将新任务加入队列
	for _, link := range validLinks {
		if _, loaded := seenURLs.LoadOrStore(link, true); !loaded {
			wg.Add(1)
			select {
			case crawlQueue <- models.Task{URL: link, Depth: task.Depth + 1}:
			case <-o.ctx.Done():
				wg.Done()
				return
			}
		}
	}

	reqMutex.Lock()
	*requestsToScan = append(*requestsToScan, validRequests...)
	reqMutex.Unlock()

	log.Debug().
		Int("found_links", len(allLinks)).
		Int("found_requests", len(allRequests)).
		Int("found_params", int(atomic.LoadInt64(&o.stats.paramsFound))).
		Str("url", task.URL).
		Msg("🕷️ 爬取完成 (Crawl finished)")
}

// storePageStructure 存储页面结构（带时间戳）
func (o *Orchestrator) storePageStructure(url string, structure *PageStructure) {
	timestamped := &TimestampedPageStructure{
		PageStructure: structure,
		Timestamp:     time.Now(),
	}
	o.pageStructures.Store(url, timestamped)
}

// analyzePageStructure 分析页面结构
func (o *Orchestrator) analyzePageStructure(pageURL string, bodyBytes []byte) (*PageStructure, error) {
	doc, err := html.Parse(bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("解析HTML失败: %w", err)
	}

	structure := &PageStructure{
		FormFields: make(map[string]string),
	}

	// 计算DOM结构哈希
	structure.DOMHash = o.calculateDOMHash(doc)

	// 计算文本内容哈希
	textContent := o.extractTextContent(doc)
	hash := md5.Sum([]byte(textContent))
	structure.TextHash = fmt.Sprintf("%x", hash)

	// 提取页面标题
	structure.Title = o.extractTitle(doc)

	// 分析页面元素
	o.analyzeNode(doc, structure)

	return structure, nil
}

// calculateDOMHash 计算DOM结构哈希（优化版）
func (o *Orchestrator) calculateDOMHash(node *html.Node) string {
	builder := builderPool.Get().(*strings.Builder)
	defer func() {
		builder.Reset()
		builderPool.Put(builder)
	}()

	o.traverseDOM(node, builder, 0)

	hash := md5.Sum([]byte(builder.String()))
	return fmt.Sprintf("%x", hash)
}

// traverseDOM 遍历DOM结构
func (o *Orchestrator) traverseDOM(node *html.Node, builder *strings.Builder, depth int) {
	if node == nil {
		return
	}

	// 只记录结构性元素，忽略文本内容和属性值
	if node.Type == html.ElementNode {
		// 添加缩进表示层级
		for i := 0; i < depth; i++ {
			builder.WriteString("  ")
		}
		builder.WriteString(node.Data)

		// 记录重要属性的存在性（不记录具体值）
		importantAttrs := []string{"id", "class", "name", "type", "method", "action"}
		for _, attr := range node.Attr {
			for _, important := range importantAttrs {
				if attr.Key == important {
					builder.WriteString(fmt.Sprintf("[%s]", attr.Key))
					break
				}
			}
		}
		builder.WriteString("\n")
	}

	// 递归处理子节点
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		o.traverseDOM(child, builder, depth+1)
	}
}

// extractTextContent 提取文本内容
func (o *Orchestrator) extractTextContent(node *html.Node) string {
	builder := builderPool.Get().(*strings.Builder)
	defer func() {
		builder.Reset()
		builderPool.Put(builder)
	}()

	o.extractTextFromNode(node, builder)
	return strings.TrimSpace(builder.String())
}

// extractTextFromNode 从节点提取文本
func (o *Orchestrator) extractTextFromNode(node *html.Node, builder *strings.Builder) {
	if node == nil {
		return
	}

	if node.Type == html.TextNode {
		text := strings.TrimSpace(node.Data)
		if text != "" {
			builder.WriteString(text)
			builder.WriteString(" ")
		}
	}

	for child := node.FirstChild; child != nil; child = child.NextSibling {
		o.extractTextFromNode(child, builder)
	}
}

// extractTitle 提取页面标题
func (o *Orchestrator) extractTitle(node *html.Node) string {
	if node == nil {
		return ""
	}

	if node.Type == html.ElementNode && node.Data == "title" {
		if node.FirstChild != nil && node.FirstChild.Type == html.TextNode {
			return strings.TrimSpace(node.FirstChild.Data)
		}
	}

	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if title := o.extractTitle(child); title != "" {
			return title
		}
	}

	return ""
}

// analyzeNode 分析节点，统计各种元素
func (o *Orchestrator) analyzeNode(node *html.Node, structure *PageStructure) {
	if node == nil {
		return
	}

	if node.Type == html.ElementNode {
		switch node.Data {
		case "input", "textarea", "select":
			structure.InputCount++
			// 提取表单字段信息
			name := o.getAttrValue(node, "name")
			fieldType := o.getAttrValue(node, "type")
			if name != "" {
				structure.FormFields[name] = fieldType
			}
		case "a":
			structure.LinkCount++
		case "script":
			structure.ScriptCount++
		}
	}

	// 递归处理子节点
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		o.analyzeNode(child, structure)
	}
}

// getAttrValue 获取属性值
func (o *Orchestrator) getAttrValue(node *html.Node, attrName string) string {
	for _, attr := range node.Attr {
		if attr.Key == attrName {
			return attr.Val
		}
	}
	return ""
}

// isSimilarPage 检查页面相似度
func (o *Orchestrator) isSimilarPage(newStructure *PageStructure) bool {
	var maxSimilarity float64

	o.pageStructures.Range(func(key, value interface{}) bool {
		var existingStructure *PageStructure

		// 处理新的时间戳结构
		if timestamped, ok := value.(*TimestampedPageStructure); ok {
			existingStructure = timestamped.PageStructure
		} else if structure, ok := value.(*PageStructure); ok {
			existingStructure = structure
		} else {
			return true // 继续遍历
		}

		// 计算DOM相似度
		domSimilarity := o.calculateDOMSimilarity(newStructure.DOMHash, existingStructure.DOMHash)

		// 计算内容相似度
		contentSimilarity := o.calculateContentSimilarity(newStructure.TextHash, existingStructure.TextHash)

		// 计算表单相似度
		formSimilarity := o.calculateFormSimilarity(newStructure.FormFields, existingStructure.FormFields)

		// 综合相似度
		overallSimilarity := (domSimilarity + contentSimilarity + formSimilarity) / 3.0

		if overallSimilarity > maxSimilarity {
			maxSimilarity = overallSimilarity
		}

		return true // 继续遍历
	})

	// 检查是否超过阈值
	return maxSimilarity > o.similarityConfig.DOMThreshold
}

// calculatePageSimilarity 计算页面相似度
func (o *Orchestrator) calculatePageSimilarity(structure *PageStructure) float64 {
	if structure == nil {
		return 0.0
	}

	var totalSimilarity float64
	var count int

	o.pageStructures.Range(func(key, value interface{}) bool {
		var existingStructure *PageStructure

		if timestamped, ok := value.(*TimestampedPageStructure); ok {
			existingStructure = timestamped.PageStructure
		} else if structure, ok := value.(*PageStructure); ok {
			existingStructure = structure
		} else {
			return true
		}

		// 计算DOM相似度
		domSimilarity := o.calculateDOMSimilarity(structure.DOMHash, existingStructure.DOMHash)

		// 计算内容相似度
		contentSimilarity := o.calculateContentSimilarity(structure.TextHash, existingStructure.TextHash)

		// 计算表单相似度
		formSimilarity := o.calculateFormSimilarity(structure.FormFields, existingStructure.FormFields)

		// 综合相似度
		overallSimilarity := (domSimilarity + contentSimilarity + formSimilarity) / 3.0

		totalSimilarity += overallSimilarity
		count++

		return true
	})

	if count == 0 {
		return 0.0
	}

	return totalSimilarity / float64(count)
}

// calculateDOMSimilarity 计算DOM相似度
func (o *Orchestrator) calculateDOMSimilarity(hash1, hash2 string) float64 {
	if hash1 == hash2 {
		return 1.0
	}
	return 0.0 // 简化版本，实际可以使用更复杂的算法
}

// calculateContentSimilarity 计算内容相似度
func (o *Orchestrator) calculateContentSimilarity(hash1, hash2 string) float64 {
	if hash1 == hash2 {
		return 1.0
	}
	return 0.0 // 简化版本
}

// calculateFormSimilarity 计算表单相似度
func (o *Orchestrator) calculateFormSimilarity(form1, form2 map[string]string) float64 {
	if len(form1) == 0 && len(form2) == 0 {
		return 1.0
	}

	if len(form1) == 0 || len(form2) == 0 {
		return 0.0
	}

	// 计算字段名的交集
	common := 0
	total := len(form1)
	if len(form2) > total {
		total = len(form2)
	}

	for field := range form1 {
		if _, exists := form2[field]; exists {
			common++
		}
	}

	return float64(common) / float64(total)
}

// isURLPatternDuplicate 检查URL模式是否重复
func (o *Orchestrator) isURLPatternDuplicate(targetURL string) bool {
	pattern := o.extractURLPattern(targetURL)
	if pattern == "" {
		return false
	}

	_, exists := o.urlPatterns.LoadOrStore(pattern, true)
	return exists
}

// extractURLPattern 提取URL模式
func (o *Orchestrator) extractURLPattern(targetURL string) string {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}

	// 移除查询参数的值，只保留参数名
	if parsedURL.RawQuery != "" {
		values, err := url.ParseQuery(parsedURL.RawQuery)
		if err != nil {
			return ""
		}

		var paramNames []string
		for name := range values {
			paramNames = append(paramNames, name)
		}
		sort.Strings(paramNames)

		// 构建模式：path + 排序后的参数名
		pattern := parsedURL.Path
		if len(paramNames) > 0 {
			pattern += "?" + strings.Join(paramNames, "&")
		}
		return pattern
	}

	return parsedURL.Path
}

// updateDomainStatistics 更新域名统计
func (o *Orchestrator) updateDomainStatistics(pageURL string, structure *PageStructure) {
	parsedURL, err := url.Parse(pageURL)
	if err != nil {
		return
	}

	domain := parsedURL.Host

	o.domainStatsMutex.Lock()
	defer o.domainStatsMutex.Unlock()

	stats, exists := o.domainStats[domain]
	if !exists {
		stats = &DomainStatistics{
			LastAdjustment: time.Now(),
		}
		o.domainStats[domain] = stats
	}

	stats.TotalPages++
	stats.UniqueForms += len(structure.FormFields)

	// 修正平均相似度计算
	if stats.TotalPages == 1 {
		stats.AverageSimilarity = 0.5 // 初始值
	} else {
		// 计算当前页面的相似度
		currentSimilarity := o.calculatePageSimilarity(structure)
		stats.AverageSimilarity = (stats.AverageSimilarity*float64(stats.TotalPages-1) + currentSimilarity) / float64(stats.TotalPages)
	}
}

// fetchURLWithRetry 带重试的URL获取
func (o *Orchestrator) fetchURLWithRetry(targetURL string) ([]byte, error) {
	var lastErr error

	for attempt := 0; attempt <= o.retryConfig.maxRetries; attempt++ {
		if attempt > 0 {
			log.Debug().Str("url", targetURL).Int("attempt", attempt).Msg("Retrying URL fetch")
			select {
			case <-time.After(o.retryConfig.retryDelay):
			case <-o.ctx.Done():
				return nil, o.ctx.Err()
			}
		}

		resp, err := o.httpClient.Get(o.ctx, targetURL, nil)
		if err != nil {
			lastErr = err
			if !o.isRetryableError(err) {
				break
			}
			continue
		}

		// 使用闭包确保资源正确释放
		bodyBytes, readErr := func() ([]byte, error) {
			defer resp.Body.Close()
			return io.ReadAll(resp.Body)
		}()

		if readErr != nil {
			lastErr = readErr
			continue
		}

		return bodyBytes, nil
	}

	return nil, fmt.Errorf("failed after %d attempts: %w", o.retryConfig.maxRetries+1, lastErr)
}

// isRetryableError 判断错误是否可重试
func (o *Orchestrator) isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := strings.ToLower(err.Error())
	retryableErrors := []string{
		"timeout",
		"connection reset",
		"temporary failure",
		"network is unreachable",
		"connection refused",
	}

	for _, retryable := range retryableErrors {
		if strings.Contains(errStr, retryable) {
			return true
		}
	}

	// 检查HTTP状态码
	if strings.Contains(errStr, "500") || strings.Contains(errStr, "502") ||
		strings.Contains(errStr, "503") || strings.Contains(errStr, "504") {
		return true
	}

	return false
}

// filterValidLinks 过滤有效链接
func (o *Orchestrator) filterValidLinks(links []string) []string {
	var validLinks []string
	seenLinks := make(map[string]bool)

	for _, link := range links {
		// 去重
		if seenLinks[link] {
			continue
		}
		seenLinks[link] = true

		// 范围检查
		if !o.isInScope(link) {
			continue
		}

		// URL格式检查
		if _, err := url.Parse(link); err != nil {
			continue
		}

		validLinks = append(validLinks, link)
	}

	return validLinks
}

// filterValidRequests 过滤有效请求
func (o *Orchestrator) filterValidRequests(requests []*models.Request) []*models.Request {
	var validRequests []*models.Request
	seenRequests := make(map[string]bool)

	for _, req := range requests {
		// 生成请求唯一标识
		requestKey := fmt.Sprintf("%s:%s:%s", req.Method, req.URL, req.Body)
		
		// 去重
		if seenRequests[requestKey] {
			continue
		}
		seenRequests[requestKey] = true

		// 范围检查
		if !o.isInScope(req.URL) {
			continue
		}

		// 请求去重检查
		if o.isRequestDuplicate(req) {
			continue
		}

		validRequests = append(validRequests, req)
	}

	return validRequests
}

// isRequestDuplicate 检查请求是否重复
func (o *Orchestrator) isRequestDuplicate(req *models.Request) bool {
	// 生成请求指纹
	fingerprint := o.generateRequestFingerprint(req)
	
	_, exists := o.requestDedup.LoadOrStore(fingerprint, true)
	return exists
}

// generateRequestFingerprint 生成请求指纹
func (o *Orchestrator) generateRequestFingerprint(req *models.Request) string {
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return req.URL
	}

	// 提取参数名（忽略参数值）
	var paramNames []string
	if parsedURL.RawQuery != "" {
		values, _ := url.ParseQuery(parsedURL.RawQuery)
		for name := range values {
			paramNames = append(paramNames, name)
		}
	}

	// 处理POST参数
	if req.Method == "POST" && req.Body != "" {
		if postValues, err := url.ParseQuery(req.Body); err == nil {
			for name := range postValues {
				paramNames = append(paramNames, "POST:"+name)
			}
		}
	}

	sort.Strings(paramNames)

	// 构建指纹：方法 + 路径 + 参数名
	fingerprint := fmt.Sprintf("%s:%s:%s", 
		req.Method, 
		parsedURL.Path, 
		strings.Join(paramNames, ","))

	return fingerprint
}

// prioritizeUniqueFormRequests 优先处理独特的表单请求
func (o *Orchestrator) prioritizeUniqueFormRequests(requests []*models.Request) []*models.Request {
	// 按表单结构分组
	formGroups := make(map[string][]*models.Request)
	
	for _, req := range requests {
		formHash := o.calculateFormHash(req)
		formGroups[formHash] = append(formGroups[formHash], req)
	}

	var prioritizedRequests []*models.Request

	// 每个表单结构只取一个代表性请求
	for _, group := range formGroups {
		if len(group) > 0 {
			// 选择参数最多的请求作为代表
			representative := group[0]
			maxParams := o.countRequestParams(representative)

			for _, req := range group[1:] {
				paramCount := o.countRequestParams(req)
				if paramCount > maxParams {
					representative = req
					maxParams = paramCount
				}
			}

			prioritizedRequests = append(prioritizedRequests, representative)
		}
	}

	return prioritizedRequests
}

// calculateFormHash 计算表单哈希
func (o *Orchestrator) calculateFormHash(req *models.Request) string {
	var paramNames []string

	// 处理URL参数
	if parsedURL, err := url.Parse(req.URL); err == nil && parsedURL.RawQuery != "" {
		if values, err := url.ParseQuery(parsedURL.RawQuery); err == nil {
			for name := range values {
				paramNames = append(paramNames, "GET:"+name)
			}
		}
	}

	// 处理POST参数
	if req.Method == "POST" && req.Body != "" {
		if values, err := url.ParseQuery(req.Body); err == nil {
			for name := range values {
				paramNames = append(paramNames, "POST:"+name)
			}
		}
	}

	sort.Strings(paramNames)
	combined := strings.Join(paramNames, ",")
	
	hash := md5.Sum([]byte(combined))
	return fmt.Sprintf("%x", hash)
}

// countRequestParams 计算请求参数数量
func (o *Orchestrator) countRequestParams(req *models.Request) int {
	count := 0

	// 计算URL参数
	if parsedURL, err := url.Parse(req.URL); err == nil && parsedURL.RawQuery != "" {
		if values, err := url.ParseQuery(parsedURL.RawQuery); err == nil {
			count += len(values)
		}
	}

	// 计算POST参数
	if req.Method == "POST" && req.Body != "" {
		if values, err := url.ParseQuery(req.Body); err == nil {
			count += len(values)
		}
	}

	return count
}

// Close 清理资源
func (o *Orchestrator) Close() error {
	// 取消上下文
	if o.cancel != nil {
		o.cancel()
	}

	// 停止清理任务
	o.stopCleanupTask()

	// 关闭扫描引擎
	if o.scanEngine != nil {
		o.scanEngine.Close()
	}

	return nil
}
