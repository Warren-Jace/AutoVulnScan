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

// Orchestrator 负责协调爬虫、扫描和报告的主流程控制器
type Orchestrator struct {
	config       *config.Settings      // 配置文件
	targetURL    string                // 目标URL
	crawler      *crawler.Crawler      // 爬虫实例
	plugins      []vulnscan.Plugin     // 插件列表
	deduplicator *dedup.Deduplicator   // 去重模块
	aiAnalyzer   *ai.AIAnalyzer        // AI 分析器
	httpClient   *requester.HTTPClient // HTTP客户端
	payloads     map[string][]string   // 预加载的payloads（按插件名分类）
	ctx          context.Context       // 主上下文
	cancel       context.CancelFunc    // 取消函数

	// 新增统计字段
	stats struct {
		urlsProcessed        int64 // 已处理的URL数量
		requestsScanned      int64 // 已扫描的请求数量
		vulnerabilitiesFound int64 // 发现的漏洞数量
		duplicatesSkipped    int64 // 跳过的重复内容数量
		similarPagesSkipped  int64 // 跳过的相似页面数量
	}

	// 新增错误重试机制
	retryConfig struct {
		maxRetries int           // 最大重试次数
		retryDelay time.Duration // 重试延迟
	}

	// 相似度爬虫相关
	similarityConfig SimilarityConfig             // 相似度配置
	pageStructures   sync.Map                     // 页面结构缓存 URL -> PageStructure
	urlPatterns      sync.Map                     // URL模式缓存 Pattern -> URLPattern
	formStructures   sync.Map                     // 表单结构缓存 FormHash -> FormStructure
	requestDedup     sync.Map                     // 用于请求去重
	domainStats      map[string]*DomainStatistics // 域名统计信息
	domainStatsMutex sync.RWMutex                 // 域名统计锁
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

// NewOrchestrator 创建并初始化 Orchestrator 实例
func NewOrchestrator(cfg *config.Settings, targetURL string) (*Orchestrator, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// 4. 初始化配置
	var configFile string
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	reporter, err := output.NewReporter(cfg.Reporting)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize reporter")
	}
	defer reporter.Close()

	// 5. 初始化HTTP客户端
	httpClient := requester.NewHTTPClient(cfg.Spider.Timeout, cfg.Spider.UserAgents)

	// 6. 初始化爬虫
	cr, err := crawler.NewCrawler(targetURL, cfg, httpClient)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize crawler")
	}

	// 7. 启动爬虫
	seen := make(map[string]bool)
	taskQueue := make(chan string, cfg.Spider.Concurrency)
	var wg sync.WaitGroup

	initialURLs, _, err := cr.Crawl(ctx, targetURL, nil)
	if err != nil {
		log.Error().Err(err).Msg("Failed to crawl initial URL")
		cancel()
		return nil, err
	}

	for _, u := range initialURLs {
		if _, ok := seen[u]; !ok {
			seen[u] = true
			parsedURL, err := url.Parse(u)
			if err != nil {
				log.Warn().Str("url", u).Msg("Failed to parse URL")
				continue
			}
			if cr.IsInScope(parsedURL) {
				taskQueue <- u
				wg.Add(1)
			} else if cfg.Debug {
				reporter.LogUnscopedURL(u)
				log.Debug().Str("url", u).Msg("URL is out of scope")
			}
		}
	}

	for i := 0; i < cfg.Spider.Concurrency; i++ {
		go func() {
			for u := range taskQueue {
				select {
				case <-ctx.Done():
					wg.Done()
					return
				default:
				}

				if u == "" { // Handle empty string from taskQueue
					wg.Done()
					continue
				}

				newURLs, _, err := cr.Crawl(ctx, u, nil)
				if err != nil {
					log.Error().Err(err).Str("url", u).Msg("Failed to crawl URL")
					wg.Done()
					continue
				}

				for _, newURL := range newURLs {
					if _, ok := seen[newURL]; !ok {
						seen[newURL] = true
						parsedURL, err := url.Parse(newURL)
						if err != nil {
							log.Warn().Str("url", newURL).Msg("Failed to parse URL")
							continue
						}
						if cr.IsInScope(parsedURL) {
							taskQueue <- newURL
							wg.Add(1)
						} else if cfg.Debug {
							reporter.LogUnscopedURL(newURL)
							log.Debug().Str("url", newURL).Msg("URL is out of scope")
						}
					}
				}
				wg.Done()
			}
		}()
	}

	wg.Wait()
	close(taskQueue)

	log.Info().Msg("Spider finished.")

	// 10. 运行扫描
	// The scanner implementation will be addressed in a future step.

	return nil, nil
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

// loadAllPayloads 预加载所有插件的payloads
func (o *Orchestrator) loadAllPayloads() error {
	var loadErrors []string

	for _, p := range o.plugins {
		pluginName := p.Info().Name
		payloads, err := vulnscan.LoadPayloads(pluginName)
		if err != nil {
			errMsg := fmt.Sprintf("plugin %s: %v", pluginName, err)
			loadErrors = append(loadErrors, errMsg)
			log.Warn().Err(err).Str("plugin", pluginName).Msg("Failed to load payloads for plugin")
			continue
		}

		if len(payloads) == 0 {
			log.Warn().Str("plugin", pluginName).Msg("No payloads loaded for plugin")
		}

		o.payloads[pluginName] = payloads
		log.Debug().Str("plugin", pluginName).Int("count", len(payloads)).Msg("Loaded payloads for plugin")
	}

	if len(loadErrors) > 0 && len(o.payloads) == 0 {
		return fmt.Errorf("failed to load payloads for all plugins: %s", strings.Join(loadErrors, "; "))
	}

	return nil
}

// Start 启动主流程，包含爬取、扫描和报告
func (o *Orchestrator) Start(reporter *output.Reporter) {
	log.Info().Msg("Orchestrator starting with advanced similarity crawler...")
	defer log.Info().Msg("Orchestrator finished.")
	defer o.cancel()

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

	for i := 0; i < o.config.Spider.Concurrency; i++ {
		go o.worker(i, taskQueue, &wg, reporter)
	}

	wg.Add(1)
	taskQueue <- models.Task{URL: o.targetURL, Depth: 0}

	wg.Wait()
	close(taskQueue)

	o.printFinalStats()
	log.Info().Msg("Orchestrator shutdown complete.")
}

// printStats 定期输出统计信息
func (o *Orchestrator) printStats(ticker <-chan time.Time) {
	for range ticker {
		urls := atomic.LoadInt64(&o.stats.urlsProcessed)
		requests := atomic.LoadInt64(&o.stats.requestsScanned)
		vulns := atomic.LoadInt64(&o.stats.vulnerabilitiesFound)
		dups := atomic.LoadInt64(&o.stats.duplicatesSkipped)
		similar := atomic.LoadInt64(&o.stats.similarPagesSkipped)

		log.Info().
			Int64("urls_processed", urls).
			Int64("requests_scanned", requests).
			Int64("vulnerabilities_found", vulns).
			Int64("duplicates_skipped", dups).
			Int64("similar_pages_skipped", similar).
			Msg("Progress update")
	}
}

// printFinalStats 输出最终统计信息
func (o *Orchestrator) printFinalStats() {
	urls := atomic.LoadInt64(&o.stats.urlsProcessed)
	requests := atomic.LoadInt64(&o.stats.requestsScanned)
	vulns := atomic.LoadInt64(&o.stats.vulnerabilitiesFound)
	dups := atomic.LoadInt64(&o.stats.duplicatesSkipped)
	similar := atomic.LoadInt64(&o.stats.similarPagesSkipped)

	log.Info().
		Int64("total_urls_processed", urls).
		Int64("total_requests_scanned", requests).
		Int64("total_vulnerabilities_found", vulns).
		Int64("total_duplicates_skipped", dups).
		Int64("total_similar_pages_skipped", similar).
		Msg("Final statistics")

	// 输出域名统计
	o.domainStatsMutex.RLock()
	for domain, stats := range o.domainStats {
		log.Info().
			Str("domain", domain).
			Int("total_pages", stats.TotalPages).
			Int("unique_forms", stats.UniqueForms).
			Float64("avg_similarity", stats.AverageSimilarity).
			Msg("Domain statistics")
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
	log.Debug().Int("worker_id", id).Msg("Worker started")
	defer log.Debug().Int("worker_id", id).Msg("Worker finished")

	for task := range taskQueue {
		select {
		case <-o.ctx.Done():
			log.Debug().Int("worker_id", id).Msg("Worker cancelled")
			wg.Done()
			return
		default:
		}

		if task.Request != nil {
			log.Debug().Str("url", task.Request.URL.String()).Msg("Executing scan task")

			requestKey := o.generateRequestKey(task.Request)
			if _, exists := o.requestDedup.LoadOrStore(requestKey, true); exists {
				log.Debug().Str("url", task.Request.URL.String()).Msg("Skipping duplicate request")
				wg.Done()
				continue
			}

			reporter.LogParamURL(task.Request)
			o.scanRequestWithRetry(o.ctx, task.Request, reporter)
			atomic.AddInt64(&o.stats.requestsScanned, 1)
			wg.Done()
			continue
		}

		o.handleCrawlTask(task, taskQueue, wg, reporter)
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
	defer wg.Done()

	if task.Depth >= o.config.Spider.MaxDepth {
		log.Debug().Str("url", task.URL).Int("depth", task.Depth).Msg("Max depth reached, not crawling")
		return
	}

	// 1. URL模式检查
	if o.isURLPatternDuplicate(task.URL) {
		log.Debug().Str("url", task.URL).Msg("Skipping URL with duplicate pattern")
		atomic.AddInt64(&o.stats.similarPagesSkipped, 1)
		return
	}

	// 2. 获取页面内容
	bodyBytes, err := o.fetchURLWithRetry(task.URL)
	if err != nil {
		log.Error().Err(err).Str("url", task.URL).Msg("Failed to fetch URL after retries")
		return
	}

	// 3. 分析页面结构
	pageStructure, err := o.analyzePageStructure(task.URL, bodyBytes)
	if err != nil {
		log.Error().Err(err).Str("url", task.URL).Msg("Failed to analyze page structure")
		return
	}

	// 4. 相似度检查
	if o.isSimilarPage(pageStructure) {
		log.Debug().Str("url", task.URL).Msg("Skipping similar page")
		atomic.AddInt64(&o.stats.similarPagesSkipped, 1)
		return
	}

	// 5. 传统去重检查（作为备份）
	isUnique, err := o.deduplicator.IsUnique(task.URL, bytes.NewReader(bodyBytes))
	if err != nil {
		log.Error().Err(err).Str("url", task.URL).Msg("Deduplication check failed")
		return
	}
	if !isUnique {
		log.Debug().Str("url", task.URL).Msg("Skipping duplicate content")
		reporter.LogDeDuplicateURL(task.URL)
		atomic.AddInt64(&o.stats.duplicatesSkipped, 1)
		return
	}

	// 6. 存储页面结构
	o.pageStructures.Store(task.URL, pageStructure)
	o.updateDomainStatistics(task.URL, pageStructure)

	// 7. 爬取和解析页面内容
	links, requests, err := o.crawler.Crawl(o.ctx, task.URL, bodyBytes)
	if err != nil {
		log.Error().Err(err).Str("url", task.URL).Msg("Failed to crawl URL")
		return
	}

	reporter.LogURL(task.URL)
	atomic.AddInt64(&o.stats.urlsProcessed, 1)

	// 8. 过滤和验证新发现的链接和请求
	validLinks := o.filterValidLinks(links)
	validRequests := o.filterValidRequests(requests)

	// 9. 优先处理结构差异较大的表单
	validRequests = o.prioritizeUniqueFormRequests(validRequests)

	// 10. 将新任务加入队列
	totalTasks := len(validLinks) + len(validRequests)
	if totalTasks > 0 {
		wg.Add(totalTasks)

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

// scanRequestWithRetry 带重试机制的请求扫描
func (o *Orchestrator) scanRequestWithRetry(ctx context.Context, req *models.Request, reporter *output.Reporter) {
	for attempt := 0; attempt <= o.retryConfig.maxRetries; attempt++ {
		if attempt > 0 {
			log.Debug().Str("url", req.URL.String()).Int("attempt", attempt).Msg("Retrying request scan")
			time.Sleep(o.retryConfig.retryDelay)
		}

		vulnerabilities := o.scanRequest(ctx, req, reporter)
		if vulnerabilities > 0 {
			atomic.AddInt64(&o.stats.vulnerabilitiesFound, int64(vulnerabilities))
		}

		return
	}
}

// scanRequest 对单个请求执行所有插件的扫描，返回发现的漏洞数量
func (o *Orchestrator) scanRequest(ctx context.Context, req *models.Request, reporter *output.Reporter) int {
	vulnerabilityCount := 0

	for _, plugin := range o.plugins {
		select {
		case <-ctx.Done():
			log.Debug().Str("plugin", plugin.Info().Name).Msg("Plugin scan cancelled")
			return vulnerabilityCount
		default:
		}

		pluginCtx, cancel := context.WithTimeout(ctx, o.config.Scanner.Timeout)

		payloads, ok := o.payloads[plugin.Info().Name]
		if !ok || len(payloads) == 0 {
			log.Debug().Str("plugin", plugin.Info().Name).Msg("No payloads loaded for plugin, skipping scan.")
			cancel()
			continue
		}

		// AI辅助payload生成
		if o.aiAnalyzer != nil {
			var paramNames []string
			for _, p := range req.Params {
				paramNames = append(paramNames, p.Name)
			}
			aiPayloads, err := o.aiAnalyzer.GeneratePayloads(pluginCtx, plugin.Info().Name, req.URL.String(), req.Method, strings.Join(paramNames, ","))
			if err != nil {
				log.Debug().Err(err).Str("plugin", plugin.Info().Name).Msg("Failed to generate AI payloads")
			} else {
				payloads = append(payloads, aiPayloads...)
				log.Debug().Str("plugin", plugin.Info().Name).Int("ai_payloads", len(aiPayloads)).Msg("Generated AI payloads")
			}
		}

		vulnerabilities, err := plugin.Scan(pluginCtx, req, payloads)
		if err != nil {
			log.Error().Err(err).Str("plugin", plugin.Info().Name).Str("url", req.URL.String()).Msg("Plugin scan failed")
		} else {
			for _, vuln := range vulnerabilities {
				reporter.LogVulnerability(vuln)
				vulnerabilityCount++
			}

			if len(vulnerabilities) > 0 {
				log.Info().Str("plugin", plugin.Info().Name).Int("count", len(vulnerabilities)).Str("url", req.URL.String()).Msg("Vulnerabilities found")
			}
		}

		cancel()
	}

	return vulnerabilityCount
}
