// Package core 包含了 AutoVulnScan 应用程序的核心编排器。
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

	stats struct {
		urlsProcessed        int64
		requestsScanned      int64
		vulnerabilitiesFound int64
		duplicatesSkipped    int64
		similarPagesSkipped  int64
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

// NewOrchestrator 创建并初始化一个Orchestrator实例。
// 这个函数负责组装所有必要的组件，如HTTP客户端、爬虫、扫描引擎等。
func NewOrchestrator(cfg *config.Settings, targetURL string) (*Orchestrator, error) {
	ctx, cancel := context.WithCancel(context.Background())

	httpClient := requester.NewHTTPClient(cfg.Spider.Timeout, cfg.Headers)

	cr, err := crawler.NewCrawler(targetURL, cfg, httpClient)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("初始化爬虫失败: %w", err)
	}

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

	scanEngine, err := vulnscan.NewEngine(httpClient, browserService)
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
		deduplicator: dedup.NewDeduplicator(0.95), // 使用默认阈值
		aiAnalyzer:   aiAnalyzer,
		httpClient:   httpClient,
		ctx:          ctx,
		cancel:       cancel,
		domainStats:  make(map[string]*DomainStatistics),
	}

	// 初始化重试配置
	o.retryConfig.maxRetries = 3
	o.retryConfig.retryDelay = 2 * time.Second

	// 初始化相似度配置
	o.initSimilarityConfig()

	return o, nil
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
		AutoAdjust:       true, // 启用自动调整
	}
}

// Start 启动编排器的总执行流程。
func (o *Orchestrator) Start(reporter *output.Reporter) {
	log.Info().Str("target", o.targetURL).Msg("✅ 编排器启动 (Orchestrator started)")
	defer func() {
		o.printFinalStats()
		log.Info().Str("target", o.targetURL).Msg("✅ 编排器执行完毕 (Orchestrator finished)")
		o.cancel()
	}()

	// 启动统计信息定期输出
	statsTicker := time.NewTicker(30 * time.Second)
	defer statsTicker.Stop()
	go o.printStats(statsTicker.C)

	// 启动阈值自动调整
	if o.similarityConfig.AutoAdjust {
		adjustTicker := time.NewTicker(5 * time.Minute)
		defer adjustTicker.Stop()
		go o.autoAdjustThresholds(adjustTicker.C)
	}

	var wg sync.WaitGroup
	taskQueue := make(chan models.Task, o.config.Spider.Concurrency*4)

	// 启动工作协程池
	for i := 0; i < o.config.Spider.Concurrency; i++ {
		go o.worker(i, taskQueue, &wg, reporter)
	}

	// 将初始目标URL作为第一个任务添加到队列中
	log.Info().Str("url", o.targetURL).Msg("将初始目标URL添加到任务队列")
	wg.Add(1)
	taskQueue <- models.Task{URL: o.targetURL, Depth: 0}

	// 等待所有任务完成
	wg.Wait()
	close(taskQueue)

	log.Info().Msg("✅ 所有任务处理完毕 (All tasks processed)")
}

// printStats 定期输出统计信息
func (o *Orchestrator) printStats(ticker <-chan time.Time) {
	for range ticker {
		urls := atomic.LoadInt64(&o.stats.urlsProcessed)
		requests := atomic.LoadInt64(&o.stats.requestsScanned)
		vulns := atomic.LoadInt64(&o.stats.vulnerabilitiesFound)
		dups := atomic.LoadInt64(&o.stats.duplicatesSkipped)
		similar := atomic.LoadInt64(&o.stats.similarPagesSkipped)

		log.Info().Msgf("======== 📈 PROGRESS UPDATE 📈 ========\n"+
			"| URLs Processed: %-5d |\n"+
			"| Requests Scanned: %-5d |\n"+
			"| Vulns Found: %-5d |\n"+
			"| Duplicates Skipped: %-5d |\n"+
			"| Similar Pages Skipped: %-5d |\n"+
			"======================================",
			urls, requests, vulns, dups, similar)
	}
}

// printFinalStats 输出最终统计信息
func (o *Orchestrator) printFinalStats() {
	urls := atomic.LoadInt64(&o.stats.urlsProcessed)
	requests := atomic.LoadInt64(&o.stats.requestsScanned)
	vulns := atomic.LoadInt64(&o.stats.vulnerabilitiesFound)
	dups := atomic.LoadInt64(&o.stats.duplicatesSkipped)
	similar := atomic.LoadInt64(&o.stats.similarPagesSkipped)

	log.Info().Msgf("============== 📊 FINAL STATISTICS 📊 ==============\n"+
		"| Total URLs Processed: %-5d |\n"+
		"| Total Requests Scanned: %-5d |\n"+
		"| Total Vulns Found: %-5d |\n"+
		"| Total Duplicates Skipped: %-5d |\n"+
		"| Total Similar Pages Skipped: %-5d |\n"+
		"===================================================",
		urls, requests, vulns, dups, similar)

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
	for range ticker {
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
	}
}

// worker 工作协程，不断从任务队列中取任务处理
func (o *Orchestrator) worker(id int, taskQueue chan models.Task, wg *sync.WaitGroup, reporter *output.Reporter) {
	log.Debug().Int("worker_id", id).Msg("👷 工作协程启动 (Worker started)")
	defer log.Debug().Int("worker_id", id).Msg("👷 工作协程完成 (Worker finished)")

	for task := range taskQueue {
		select {
		case <-o.ctx.Done():
			log.Debug().Int("worker_id", id).Msg(" কাজ Worker取消 (Worker cancelled)")
			wg.Done()
			return
		default:
		}

		if task.Request != nil {
			// --- 处理扫描任务 ---
			log.Debug().
				Int("worker_id", id).
				Str("method", task.Request.Method).
				Str("url", task.Request.URL.String()).
				Msg("⚡️ 执行扫描任务 (Executing scan task)")

			// 执行范围检查
			if !o.isInScope(task.Request.URL.String()) {
				log.Debug().
					Int("worker_id", id).
					Str("url", task.Request.URL.String()).
					Str("reason", "out_of_scope").
					Msg("⏭️ 跳过扫描任务 (Skipping scan task)")
				reporter.LogUnscopedURL(task.Request.URL.String())
				wg.Done()
				continue
			}

			requestKey := o.generateRequestKey(task.Request)
			if _, exists := o.requestDedup.LoadOrStore(requestKey, true); exists {
				log.Debug().
					Int("worker_id", id).
					Str("url", task.Request.URL.String()).
					Str("reason", "duplicate_request").
					Msg("⏭️ 跳过扫描任务 (Skipping scan task)")
				wg.Done()
				continue
			}

			reporter.LogParamURL(task.Request)
			o.scanRequestWithRetry(o.ctx, task.Request, reporter)
			atomic.AddInt64(&o.stats.requestsScanned, 1)

		} else {
			// --- 处理爬取任务 ---
			log.Debug().
				Int("worker_id", id).
				Str("url", task.URL).
				Int("depth", task.Depth).
				Msg("🕸️ 执行爬取任务 (Executing crawl task)")
			o.handleCrawlTask(task, taskQueue, wg, reporter)
		}

		wg.Done()
	}
}

// generateRequestKey 生成请求的唯一标识符用于去重
func (o *Orchestrator) generateRequestKey(req *models.Request) string {
	var keyBuilder strings.Builder
	keyBuilder.WriteString(req.Method)
	keyBuilder.WriteString(":")
	keyBuilder.WriteString(req.URL.String())

	if len(req.Params) > 0 {
		keyBuilder.WriteString("?")
		for i, param := range req.Params {
			if i > 0 {
				keyBuilder.WriteString("&")
			}
			keyBuilder.WriteString(param.Name)
		}
	}

	return keyBuilder.String()
}

// handleCrawlTask 处理爬取任务，包括深度检查、相似度分析、链接和请求发现
func (o *Orchestrator) handleCrawlTask(task models.Task, taskQueue chan models.Task, wg *sync.WaitGroup, reporter *output.Reporter) {
	// 注意：handleCrawlTask不再需要调用wg.Done()，因为它在worker中被调用

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
	o.pageStructures.Store(task.URL, pageStructure)
	o.updateDomainStatistics(task.URL, pageStructure)

	// 7. 爬取和解析页面内容
	log.Info().Str("url", task.URL).Msg("🏁 开始静态爬取 (Starting static crawl)")
	staticLinks, staticRequests, err := o.crawler.StaticCrawl(o.ctx, task.URL, bodyBytes)
	if err != nil {
		log.Error().Err(err).Str("url", task.URL).Msg("❌ 静态爬取失败 (Static crawl failed)")
		// 即使静态爬取失败，我们仍然可以尝试动态爬取
	} else {
		log.Info().
			Str("url", task.URL).
			Int("found_links", len(staticLinks)).
			Int("found_requests", len(staticRequests)).
			Msg("✅ 静态爬取完成 (Static crawl finished)")
	}

	var allLinks []string
	var allRequests []*models.Request
	allLinks = append(allLinks, staticLinks...)
	allRequests = append(allRequests, staticRequests...)

	// 如果启用了动态爬虫，则执行
	if o.config.Spider.DynamicCrawler.Enabled {
		log.Info().Str("url", task.URL).Msg("🏁 开始动态爬取 (Starting dynamic crawl)")
		dynamicLinks, dynamicRequests, err := o.crawler.DynamicCrawl(o.ctx, task.URL)
		if err != nil {
			log.Error().Err(err).Str("url", task.URL).Msg("❌ 动态爬取失败 (Dynamic crawl failed)")
		} else {
			log.Info().
				Str("url", task.URL).
				Int("found_links", len(dynamicLinks)).
				Int("found_requests", len(dynamicRequests)).
				Msg("✅ 动态爬取完成 (Dynamic crawl finished)")

			// 合并动态爬取的结果
			allLinks = append(allLinks, dynamicLinks...)
			allRequests = append(allRequests, dynamicRequests...)
		}
	}

	reporter.LogURL(task.URL)
	atomic.AddInt64(&o.stats.urlsProcessed, 1)
	log.Debug().Str("url", task.URL).Int("found_links", len(allLinks)).Int("found_requests", len(allRequests)).Msg("🔗 发现新链接和请求 (Found new links and requests)")

	// 8. 过滤和验证新发现的链接和请求
	validLinks := o.filterValidLinks(allLinks)
	validRequests := o.filterValidRequests(allRequests)
	log.Debug().Str("url", task.URL).Int("valid_links", len(validLinks)).Int("valid_requests", len(validRequests)).Msg("🛡️ 过滤后有效的链接和请求 (Filtered valid links and requests)")

	// 9. 优先处理结构差异较大的表单
	validRequests = o.prioritizeUniqueFormRequests(validRequests)

	// 10. 将新任务加入队列
	totalTasks := len(validLinks) + len(validRequests)
	if totalTasks > 0 {
		wg.Add(totalTasks)
		log.Debug().Str("url", task.URL).Int("new_tasks", totalTasks).Msg("➕ 添加新任务到队列 (Adding new tasks to queue)")

		for _, link := range validLinks {
			select {
			case taskQueue <- models.Task{URL: link, Depth: task.Depth + 1}:
			case <-o.ctx.Done():
				wg.Done()
				return
			}
		}

		for _, req := range validRequests {
			select {
			case taskQueue <- models.Task{Request: req}:
			case <-o.ctx.Done():
				wg.Done()
				return
			}
		}
	}
}

// analyzePageStructure 分析页面结构
func (o *Orchestrator) analyzePageStructure(pageURL string, bodyBytes []byte) (*PageStructure, error) {
	doc, err := html.Parse(bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML: %w", err)
	}

	structure := &PageStructure{
		FormFields: make(map[string]string),
	}

	// 分析DOM结构
	structure.DOMHash = o.calculateDOMHash(doc)

	// 分析文本内容
	structure.TextHash = o.calculateTextHash(bodyBytes)

	// 分析表单结构
	o.analyzeFormStructure(doc, structure)

	// 统计各种元素
	o.countElements(doc, structure)

	// 提取标题
	structure.Title = o.extractTitle(doc)

	return structure, nil
}

// calculateDOMHash 计算DOM结构哈希
func (o *Orchestrator) calculateDOMHash(node *html.Node) string {
	var domStructure strings.Builder
	o.traverseDOM(node, &domStructure, 0)

	hash := md5.Sum([]byte(domStructure.String()))
	return fmt.Sprintf("%x", hash)
}

// traverseDOM 遍历DOM结构
func (o *Orchestrator) traverseDOM(node *html.Node, builder *strings.Builder, depth int) {
	if node.Type == html.ElementNode {
		builder.WriteString(strings.Repeat("  ", depth))
		builder.WriteString(node.Data)

		// 包含重要属性
		for _, attr := range node.Attr {
			if attr.Key == "class" || attr.Key == "id" || attr.Key == "name" {
				builder.WriteString(fmt.Sprintf("[%s=%s]", attr.Key, attr.Val))
			}
		}
		builder.WriteString("\n")
	}

	for child := node.FirstChild; child != nil; child = child.NextSibling {
		o.traverseDOM(child, builder, depth+1)
	}
}

// calculateTextHash 计算文本内容哈希
func (o *Orchestrator) calculateTextHash(bodyBytes []byte) string {
	// 提取纯文本内容
	text := string(bodyBytes)
	// 移除HTML标签
	re := regexp.MustCompile(`<[^>]*>`)
	text = re.ReplaceAllString(text, "")
	// 移除多余空白
	text = regexp.MustCompile(`\s+`).ReplaceAllString(text, " ")
	text = strings.TrimSpace(text)

	hash := md5.Sum([]byte(text))
	return fmt.Sprintf("%x", hash)
}

// analyzeFormStructure 分析表单结构
func (o *Orchestrator) analyzeFormStructure(node *html.Node, structure *PageStructure) {
	if node.Type == html.ElementNode {
		switch node.Data {
		case "form":
			formStruct := o.extractFormStructure(node)
			if formStruct != nil {
				structure.FormFields[formStruct.Hash] = formStruct.Action
			}
		case "input", "textarea", "select":
			structure.InputCount++
		}
	}

	for child := node.FirstChild; child != nil; child = child.NextSibling {
		o.analyzeFormStructure(child, structure)
	}
}

// extractFormStructure 提取表单结构
func (o *Orchestrator) extractFormStructure(formNode *html.Node) *FormStructure {
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
			form.Method = attr.Val
		}
	}

	// 提取表单字段
	o.extractFormFields(formNode, form)

	// 计算表单哈希
	form.Hash = o.calculateFormHash(form)

	return form
}

// extractFormFields 提取表单字段
func (o *Orchestrator) extractFormFields(node *html.Node, form *FormStructure) {
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
			if name != "" {
				form.Fields = append(form.Fields, name)
				form.Types = append(form.Types, fieldType)
			}
		}
	}

	for child := node.FirstChild; child != nil; child = child.NextSibling {
		o.extractFormFields(child, form)
	}
}

// calculateFormHash 计算表单结构哈希
func (o *Orchestrator) calculateFormHash(form *FormStructure) string {
	var hashBuilder strings.Builder

	// 排序字段名以确保一致性
	sortedFields := make([]string, len(form.Fields))
	copy(sortedFields, form.Fields)
	sort.Strings(sortedFields)

	for _, field := range sortedFields {
		hashBuilder.WriteString(field)
		hashBuilder.WriteString(":")
	}

	hash := md5.Sum([]byte(hashBuilder.String()))
	return fmt.Sprintf("%x", hash)
}

// countElements 统计页面元素
func (o *Orchestrator) countElements(node *html.Node, structure *PageStructure) {
	if node.Type == html.ElementNode {
		switch node.Data {
		case "a":
			structure.LinkCount++
		case "script":
			structure.ScriptCount++
		}
	}

	for child := node.FirstChild; child != nil; child = child.NextSibling {
		o.countElements(child, structure)
	}
}

// extractTitle 提取页面标题
func (o *Orchestrator) extractTitle(node *html.Node) string {
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

// isURLPatternDuplicate 检查URL模式是否重复
func (o *Orchestrator) isURLPatternDuplicate(targetURL string) bool {
	pattern := o.extractURLPattern(targetURL)
	if pattern == "" {
		return false
	}

	_, exists := o.urlPatterns.LoadOrStore(pattern, URLPattern{
		BaseURL: targetURL,
		Pattern: pattern,
	})

	return exists
}

// extractURLPattern 提取URL模式
func (o *Orchestrator) extractURLPattern(targetURL string) string {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}

	// 将数字参数值替换为占位符
	query := parsedURL.Query()
	var paramNames []string

	for key, values := range query {
		paramNames = append(paramNames, key)
		// 检查值是否为数字
		for i, value := range values {
			if _, err := strconv.Atoi(value); err == nil {
				values[i] = "{num}"
			}
		}
		query[key] = values
	}

	sort.Strings(paramNames)
	parsedURL.RawQuery = query.Encode()

	return parsedURL.String()
}

// isSimilarPage 检查页面是否相似
func (o *Orchestrator) isSimilarPage(newStructure *PageStructure) bool {
	var maxSimilarity float64

	o.pageStructures.Range(func(key, value interface{}) bool {
		existingStructure := value.(*PageStructure)

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

// calculateDOMSimilarity 计算DOM结构相似度
func (o *Orchestrator) calculateDOMSimilarity(hash1, hash2 string) float64 {
	if hash1 == hash2 {
		return 1.0
	}

	// 使用Jaccard相似度计算
	// 这里简化处理，实际可以使用更复杂的算法
	return o.calculateHashSimilarity(hash1, hash2)
}

// calculateContentSimilarity 计算内容相似度
func (o *Orchestrator) calculateContentSimilarity(hash1, hash2 string) float64 {
	if hash1 == hash2 {
		return 1.0
	}

	return o.calculateHashSimilarity(hash1, hash2)
}

// calculateFormSimilarity 计算表单相似度
func (o *Orchestrator) calculateFormSimilarity(forms1, forms2 map[string]string) float64 {
	if len(forms1) == 0 && len(forms2) == 0 {
		return 1.0
	}

	if len(forms1) == 0 || len(forms2) == 0 {
		return 0.0
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

// calculateHashSimilarity 计算哈希相似度
func (o *Orchestrator) calculateHashSimilarity(hash1, hash2 string) float64 {
	if len(hash1) != len(hash2) {
		return 0.0
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

	// 计算平均相似度（简化处理）
	if stats.TotalPages > 1 {
		// 这里可以实现更复杂的平均相似度计算
		stats.AverageSimilarity = (stats.AverageSimilarity*float64(stats.TotalPages-1) + 0.5) / float64(stats.TotalPages)
	}
}

// prioritizeUniqueFormRequests 优先处理结构差异较大的表单请求
func (o *Orchestrator) prioritizeUniqueFormRequests(requests []*models.Request) []*models.Request {
	if len(requests) <= 1 {
		return requests
	}

	// 按表单唯一性排序
	sort.Slice(requests, func(i, j int) bool {
		scoreI := o.calculateFormUniquenessScore(requests[i])
		scoreJ := o.calculateFormUniquenessScore(requests[j])
		return scoreI > scoreJ // 分数高的排在前面
	})

	return requests
}

// calculateFormUniquenessScore 计算表单唯一性分数
func (o *Orchestrator) calculateFormUniquenessScore(req *models.Request) float64 {
	if len(req.Params) == 0 {
		return 0.0
	}

	// 创建表单结构哈希
	var formBuilder strings.Builder
	paramNames := make([]string, 0, len(req.Params))

	for _, param := range req.Params {
		paramNames = append(paramNames, param.Name)
	}

	sort.Strings(paramNames)
	for _, name := range paramNames {
		formBuilder.WriteString(name)
		formBuilder.WriteString(":")
	}

	formHash := fmt.Sprintf("%x", md5.Sum([]byte(formBuilder.String())))

	// 检查是否已存在相似表单
	similarityCount := 0
	o.formStructures.Range(func(key, value interface{}) bool {
		existingHash := key.(string)
		similarity := o.calculateHashSimilarity(formHash, existingHash)
		if similarity > o.similarityConfig.FormThreshold {
			similarityCount++
		}
		return true
	})

	// 存储表单结构
	o.formStructures.Store(formHash, true)

	// 返回唯一性分数（相似表单越少，分数越高）
	return 1.0 / (1.0 + float64(similarityCount))
}

// fetchURLWithRetry 带重试机制的URL获取
func (o *Orchestrator) fetchURLWithRetry(url string) ([]byte, error) {
	var lastErr error

	for attempt := 0; attempt <= o.retryConfig.maxRetries; attempt++ {
		if attempt > 0 {
			log.Debug().Str("url", url).Int("attempt", attempt).Msg("Retrying URL fetch")
			time.Sleep(o.retryConfig.retryDelay)
		}

		resp, err := o.httpClient.Get(o.ctx, url, nil)
		if err != nil {
			lastErr = err
			if !o.isRetryableError(err) {
				break
			}
			continue
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if err != nil {
			lastErr = err
			continue
		}

		return bodyBytes, nil
	}

	return nil, fmt.Errorf("failed after %d attempts: %w", o.retryConfig.maxRetries+1, lastErr)
}

// isRetryableError 判断错误是否可重试
func (o *Orchestrator) isRetryableError(err error) bool {
	errStr := err.Error()
	retryableErrors := []string{
		"timeout",
		"connection reset",
		"connection refused",
		"temporary failure",
		"server closed",
	}

	for _, retryable := range retryableErrors {
		if strings.Contains(strings.ToLower(errStr), retryable) {
			return true
		}
	}

	return false
}

// filterValidLinks 过滤有效的链接
func (o *Orchestrator) filterValidLinks(links []string) []string {
	var validLinks []string

	for _, link := range links {
		if link == "" || len(link) > 2048 {
			continue
		}

		if o.isStaticResource(link) {
			continue
		}

		validLinks = append(validLinks, link)
	}

	return validLinks
}

// filterValidRequests 过滤有效的请求
func (o *Orchestrator) filterValidRequests(requests []*models.Request) []*models.Request {
	var validRequests []*models.Request

	for _, req := range requests {
		if req == nil || req.URL == nil {
			continue
		}

		if o.isStaticResource(req.URL.String()) {
			continue
		}

		if !o.isValidHTTPMethod(req.Method) {
			continue
		}

		validRequests = append(validRequests, req)
	}

	return validRequests
}

// isStaticResource 判断是否为静态资源
func (o *Orchestrator) isStaticResource(url string) bool {
	staticExtensions := []string{
		".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
		".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".tar", ".gz",
		".mp4", ".mp3", ".avi", ".mov", ".wmv", ".flv",
	}

	urlLower := strings.ToLower(url)
	for _, ext := range staticExtensions {
		if strings.HasSuffix(urlLower, ext) {
			return true
		}
	}

	return false
}

// isValidHTTPMethod 验证HTTP方法是否有效
func (o *Orchestrator) isValidHTTPMethod(method string) bool {
	validMethods := []string{
		http.MethodGet, http.MethodPost, http.MethodPut,
		http.MethodDelete, http.MethodPatch, http.MethodHead,
		http.MethodOptions,
	}

	for _, validMethod := range validMethods {
		if strings.EqualFold(method, validMethod) {
			return true
		}
	}

	return false
}

// scanRequestWithRetry 对单个请求执行扫描（包含重试逻辑）。
func (o *Orchestrator) scanRequestWithRetry(ctx context.Context, req *models.Request, reporter *output.Reporter) {
	log.Info().Str("url", req.URL.String()).Msg("🏁 开始漏洞扫描 (Starting vulnerability scan)")
	for attempt := 0; attempt <= o.retryConfig.maxRetries; attempt++ {
		if attempt > 0 {
			log.Debug().Str("url", req.URL.String()).Int("attempt", attempt).Msg("🔁 重试请求扫描 (Retrying request scan)")
			time.Sleep(o.retryConfig.retryDelay)
		}

		vulnerabilities := o.scanRequest(ctx, req, reporter)
		if vulnerabilities > 0 {
			atomic.AddInt64(&o.stats.vulnerabilitiesFound, int64(vulnerabilities))
		}

		return // 无论成功与否，只执行一次完整的扫描流程
	}
	log.Error().Str("url", req.URL.String()).Msg("❌ 扫描请求失败 (Scan request failed after retries)")
}

// scanRequest 对单个请求执行所有插件的扫描，并报告发现的漏洞。
func (o *Orchestrator) scanRequest(ctx context.Context, req *models.Request, reporter *output.Reporter) int {
	// 使用扫描引擎执行扫描
	vulnerabilities := o.scanEngine.Execute(req)

	// 如果AI分析器启用，可以添加额外的分析逻辑
	if o.aiAnalyzer != nil && len(vulnerabilities) > 0 {
		// 例如：让AI对发现的漏洞进行二次验证或分析
		log.Debug().Int("count", len(vulnerabilities)).Msg("🤖 将发现的漏洞提交给AI进行分析... (Submitting vulnerabilities to AI for analysis...)")
	}

	for _, vuln := range vulnerabilities {
		reporter.LogVulnerability(vuln)
	}

	if len(vulnerabilities) > 0 {
		log.Info().Int("count", len(vulnerabilities)).Str("url", req.URL.String()).Msg("🚨 发现新漏洞！ (New vulnerabilities found!)")
	}

	return len(vulnerabilities)
}
