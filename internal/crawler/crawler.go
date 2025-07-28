// Package crawler 提供了网站爬取功能，包括静态和动态爬取。
// 它负责从网页中提取链接和表单，为后续的漏洞扫描提供目标。
package crawler

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"autovulnscan/internal/config"
	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"

	"github.com/PuerkitoBio/goquery"
	"github.com/rs/zerolog/log"
	"golang.org/x/time/rate"
)

// 预编译正则表达式以提高性能
var (
	// JavaScript链接提取正则表达式
	jsLinkRegex = regexp.MustCompile(`['\"]((https?://[^\s'"<>]+|/[^\s'"<>]*))['\"]`)
	routeRegex  = regexp.MustCompile(`(?:path|route|to):\s*['\"]([^'"<>]+)['\"]`)
	apiRegex    = regexp.MustCompile(`(?:api|endpoint|url):\s*['\"]([^'"<>]+)['\"]`)
	
	// API端点提取正则表达式
	apiPatterns = []*regexp.Regexp{
		regexp.MustCompile(`fetch\s*\(\s*['\"]([^'"]+)['\"]`),
		regexp.MustCompile(`\.open\s*\(\s*['\"]([^'"]+)['"]\s*,\s*['\"]([^'"]+)['\"]`),
		regexp.MustCompile(`\$\.(?:ajax|get|post|put|delete)\s*\(\s*['\"]([^'"]+)['\"]`),
		regexp.MustCompile(`axios\.(?:get|post|put|delete|patch)\s*\(\s*['\"]([^'"]+)['\"]`),
		regexp.MustCompile(`['"](/api/[^'"\s]+)['\"]`),
		regexp.MustCompile(`['"](/v\d+/[^'"\s]+)['\"]`),
		regexp.MustCompile(`['"](/graphql[^'"\s]*)['\"]`),
		regexp.MustCompile(`['"](wss?://[^'"\s]+)['\"]`),
	}
	
	// HTML编码清理模式
	htmlEncodePatterns = []string{
		"%22", "%3C", "%3E", "&quot;", "&lt;", "&gt;", "&amp;",
	}
	
	// URL提取正则表达式
	urlInCommentRegex = regexp.MustCompile(`(https?://[^\s<>"']+|/[^\s<>"']+)`)
	jsonRegex         = regexp.MustCompile(`\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}`)
	urlPattern        = regexp.MustCompile(`(https?://[^\s<>"']+|/[^\s<>"']+)`)
	
	// 单行和多行注释正则
	singleLineComments = regexp.MustCompile(`//.*$`)
	multiLineComments  = regexp.MustCompile(`/\*[\s\S]*?\*/`)
	
	// 新增的正则表达式
	emailRegex    = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	phoneRegex    = regexp.MustCompile(`\+?[\d\s\-\(\)]{10,}`)
	ipRegex       = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	domainRegex   = regexp.MustCompile(`[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,}|xn--[a-zA-Z0-9]+)`)
	
	// 敏感信息正则
	sensitivePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(password|pwd|pass|secret|key|token|auth|api_key|access_key)[\s]*[=:]\s*['\"]?([^'"\s\n]+)['\"]?`),
		regexp.MustCompile(`(?i)(username|user|login|email)[\s]*[=:]\s*['\"]?([^'"\s\n]+)['\"]?`),
		regexp.MustCompile(`(?i)(database|db|host|server)[\s]*[=:]\s*['\"]?([^'"\s\n]+)['\"]?`),
	}
)

// CrawlResult 爬取结果
type CrawlResult struct {
	Links        []string
	Requests     []*models.Request
	Assets       []Asset
	Metadata     *PageMetadata
	SensitiveInfo []SensitiveData
	Errors       []error
}

// Asset 资源信息
type Asset struct {
	URL         string    `json:"url"`
	Type        string    `json:"type"` // js, css, image, font, etc.
	Size        int64     `json:"size"`
	ContentType string    `json:"content_type"`
	LastModified time.Time `json:"last_modified"`
	Hash        string    `json:"hash"`
}

// PageMetadata 页面元数据
type PageMetadata struct {
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Keywords    string            `json:"keywords"`
	Author      string            `json:"author"`
	Language    string            `json:"language"`
	Charset     string            `json:"charset"`
	Viewport    string            `json:"viewport"`
	Canonical   string            `json:"canonical"`
	OpenGraph   map[string]string `json:"open_graph"`
	TwitterCard map[string]string `json:"twitter_card"`
	JsonLD      []string          `json:"json_ld"`
	Comments    []string          `json:"comments"`
}

// SensitiveData 敏感信息
type SensitiveData struct {
	Type     string `json:"type"`
	Value    string `json:"value"`
	Context  string `json:"context"`
	Location string `json:"location"`
	Risk     string `json:"risk"`
}

// Crawler 负责获取网页并从中提取链接和参数。
// 它集成了静态和动态（基于浏览器）两种爬取模式。
type Crawler struct {
	baseURL        *url.URL
	config         *config.SpiderConfig
	httpClient     *requester.HTTPClient
	limiter        *rate.Limiter
	dynamicCrawler *DynamicCrawler
	appConfig      *config.Settings
	
	// 缓存和优化
	blacklistRegexes []*regexp.Regexp
	blacklistOnce    sync.Once
	linkCache        sync.Map // URL -> bool (是否已访问)
	assetCache       sync.Map // URL -> Asset
	
	// 统计信息
	stats *CrawlerStats
	
	// 上下文和取消
	ctx    context.Context
	cancel context.CancelFunc
	
	// 工作池
	workerPool chan struct{}
	
	// 结果收集器
	resultCollector *ResultCollector
}

// CrawlerStats 爬虫统计信息
type CrawlerStats struct {
	mu              sync.RWMutex
	StartTime       time.Time
	TotalPages      int64
	SuccessfulPages int64
	FailedPages     int64
	TotalLinks      int64
	TotalForms      int64
	TotalAssets     int64
	BytesProcessed  int64
	Errors          []error
}

// ResultCollector 结果收集器
type ResultCollector struct {
	mu           sync.RWMutex
	results      map[string]*CrawlResult
	duplicates   map[string]int
	maxResults   int
	totalResults int
}

// NewCrawler 创建一个新的爬虫实例。
func NewCrawler(baseURL string, appCfg *config.Settings, client *requester.HTTPClient) (*Crawler, error) {
	parsedBaseURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("无效的基础URL: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	
	c := &Crawler{
		baseURL:    parsedBaseURL,
		config:     &appCfg.Spider,
		appConfig:  appCfg,
		httpClient: client,
		limiter:    rate.NewLimiter(rate.Limit(appCfg.Spider.Concurrency), appCfg.Spider.Concurrency),
		ctx:        ctx,
		cancel:     cancel,
		workerPool: make(chan struct{}, appCfg.Spider.Concurrency),
		stats: &CrawlerStats{
			StartTime: time.Now(),
		},
		resultCollector: &ResultCollector{
			results:    make(map[string]*CrawlResult),
			duplicates: make(map[string]int),
			maxResults: appCfg.Spider.Limit,
		},
	}

	// 初始化动态爬虫
	if c.config.DynamicCrawler.Enabled {
		dynamicConfig := DynamicCrawlerConfig{
			Headless:         c.config.DynamicCrawler.Headless,
			BrowserType:      c.config.DynamicCrawler.BrowserType,
			MaxInstances:     c.config.DynamicCrawler.MaxInstances,
			PageTimeout:      c.config.DynamicCrawler.PageTimeout,
			WaitTime:         c.config.DynamicCrawler.WaitTime,
			EnableJavaScript: c.config.DynamicCrawler.EnableJavaScript,
			EnableImages:     c.config.DynamicCrawler.EnableImages,
			EnableCSS:        c.config.DynamicCrawler.EnableCSS,
			ViewportWidth:    c.config.DynamicCrawler.ViewportWidth,
			ViewportHeight:   c.config.DynamicCrawler.ViewportHeight,
			UserAgent:        c.getUserAgent(),
			Proxy:            appCfg.Proxy,
		}
		
		c.dynamicCrawler = NewDynamicCrawler(dynamicConfig)
	}

	return c, nil
}

// getUserAgent 获取随机用户代理
func (c *Crawler) getUserAgent() string {
	if len(c.config.UserAgents) == 0 {
		return "AutoVulnScan/1.0"
	}
	
	if c.config.RandomizeUserAgent {
		// 简单的随机选择，实际应该使用更好的随机算法
		return c.config.UserAgents[time.Now().Unix()%int64(len(c.config.UserAgents))]
	}
	
	return c.config.UserAgents[0]
}

// IsInScope 检查给定的URL是否在爬取范围内。
func (c *Crawler) IsInScope(u *url.URL) bool {
	c.blacklistOnce.Do(func() {
		for _, pattern := range c.appConfig.Blacklist {
			if re, err := regexp.Compile(pattern); err == nil {
				c.blacklistRegexes = append(c.blacklistRegexes, re)
			} else {
				log.Warn().Str("pattern", pattern).Err(err).Msg("无效的黑名单正则表达式")
			}
		}
	})

	// 检查黑名单
	urlStr := u.String()
	for _, re := range c.blacklistRegexes {
		if re.MatchString(urlStr) {
			log.Debug().Str("url", urlStr).Msg("URL被黑名单过滤")
			return false
		}
	}

	// 检查文件扩展名
	if c.shouldSkipByExtension(u.Path) {
		log.Debug().Str("url", urlStr).Msg("URL因扩展名被跳过")
		return false
	}

	// 检查范围
	if len(c.appConfig.Scope) == 0 {
		return u.Hostname() == c.baseURL.Hostname()
	}

	for _, scopePattern := range c.appConfig.Scope {
		if c.matchesScope(u, scopePattern) {
			return true
		}
	}
	
	return false
}

// shouldSkipByExtension 检查是否应该根据文件扩展名跳过URL
func (c *Crawler) shouldSkipByExtension(path string) bool {
	if len(c.config.ExcludeExtensions) == 0 {
		return false
	}
	
	ext := strings.ToLower(strings.TrimPrefix(getFileExtension(path), "."))
	if ext == "" {
		return false
	}
	
	for _, excludeExt := range c.config.ExcludeExtensions {
		if ext == strings.ToLower(excludeExt) {
			return true
		}
	}
	
	return false
}

// matchesScope 检查URL是否匹配范围模式
func (c *Crawler) matchesScope(u *url.URL, scopePattern string) bool {
	// 支持多种范围模式
	if strings.HasPrefix(scopePattern, "*.") {
		// 通配符域名匹配
		domain := strings.TrimPrefix(scopePattern, "*.")
		return strings.HasSuffix(u.Hostname(), domain)
	} else if strings.Contains(scopePattern, "*") {
		// 通配符模式匹配
		pattern := strings.ReplaceAll(scopePattern, "*", ".*")
		if re, err := regexp.Compile(pattern); err == nil {
			return re.MatchString(u.String())
		}
	} else if strings.HasPrefix(scopePattern, "http") {
		// 完整URL匹配
		return strings.HasPrefix(u.String(), scopePattern)
	} else {
		// 域名匹配
		return strings.HasSuffix(u.Hostname(), scopePattern)
	}
	
	return false
}

// Crawl 根据配置（静态或动态）爬取URL，并返回发现的链接和请求。
func (c *Crawler) Crawl(ctx context.Context, crawlURL string, body []byte) (*CrawlResult, error) {
	// 检查是否已达到限制
	if c.resultCollector.totalResults >= c.resultCollector.maxResults {
		return nil, fmt.Errorf("已达到最大爬取限制: %d", c.resultCollector.maxResults)
	}
	
	// 检查URL是否已经爬取过
	if _, exists := c.linkCache.Load(crawlURL); exists {
		log.Debug().Str("url", crawlURL).Msg("URL已经爬取过，跳过")
		return nil, nil
	}
	
	// 标记URL为已访问
	c.linkCache.Store(crawlURL, true)
	
	log.Debug().Str("url", crawlURL).Msg("开始爬取页面")
	
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime)
		log.Debug().Str("url", crawlURL).Dur("duration", duration).Msg("爬取完成")
	}()

	var result *CrawlResult
	var err error

	// 应用速率限制
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("速率限制等待失败: %w", err)
	}

	if c.config.DynamicCrawler.Enabled {
		result, err = c.crawlDynamic(ctx, crawlURL)
	} else {
		result, err = c.crawlStatic(ctx, crawlURL, body)
	}

	if err != nil {
		c.updateStats(false, 0, err)
		return nil, err
	}

	// 过滤范围内的链接
	result.Links = c.filterInScopeLinks(result.Links)
	
	// 更新统计信息
	c.updateStats(true, int64(len(body)), nil)
	
	// 存储结果
	c.resultCollector.addResult(crawlURL, result)

	return result, nil
}

// updateStats 更新统计信息
func (c *Crawler) updateStats(success bool, bytesProcessed int64, err error) {
	c.stats.mu.Lock()
	defer c.stats.mu.Unlock()
	
	c.stats.TotalPages++
	if success {
		c.stats.SuccessfulPages++
	} else {
		c.stats.FailedPages++
	}
	
	c.stats.BytesProcessed += bytesProcessed
	
	if err != nil {
		c.stats.Errors = append(c.stats.Errors, err)
		// 限制错误数量
		if len(c.stats.Errors) > 100 {
			c.stats.Errors = c.stats.Errors[1:]
		}
	}
}

// filterInScopeLinks 过滤范围内的链接
func (c *Crawler) filterInScopeLinks(links []string) []string {
	var inScopeLinks []string
	seen := make(map[string]struct{})
	
	for _, link := range links {
		if _, ok := seen[link]; ok {
			continue
		}
		
		parsedURL, err := url.Parse(link)
		if err != nil {
			log.Warn().Str("url", link).Err(err).Msg("解析链接失败")
			continue
		}
		
		if c.IsInScope(parsedURL) {
			inScopeLinks = append(inScopeLinks, link)
			seen[link] = struct{}{}
		}
	}
	
	return inScopeLinks
}

// crawlStatic 对给定的HTML内容进行静态分析，提取链接和请求。
func (c *Crawler) crawlStatic(ctx context.Context, crawlURL string, body []byte) (*CrawlResult, error) {
	log.Debug().Str("url", crawlURL).Int("size", len(body)).Msg("静态解析页面")

	// 如果没有提供body，则获取页面内容
	if body == nil {
		resp, err := c.httpClient.Get(ctx, crawlURL, nil)
		if err != nil {
			return nil, fmt.Errorf("获取页面内容失败: %w", err)
		}
		defer resp.Body.Close()
		
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("读取页面内容失败: %w", err)
		}
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("解析HTML失败: %w", err)
	}

	parsedURL, err := url.Parse(crawlURL)
	if err != nil {
		return nil, fmt.Errorf("解析爬取URL失败: %w", err)
	}

	result := &CrawlResult{
		Links:         make([]string, 0),
		Requests:      make([]*models.Request, 0),
		Assets:        make([]Asset, 0),
		SensitiveInfo: make([]SensitiveData, 0),
		Errors:        make([]error, 0),
	}

	// 并发提取不同类型的内容
	var wg sync.WaitGroup
	var mu sync.Mutex

	// 提取链接
	wg.Add(1)
	go func() {
		defer wg.Done()
		links := c.extractLinksEnhanced(doc, parsedURL)
		mu.Lock()
		result.Links = append(result.Links, links...)
		mu.Unlock()
	}()

	// 提取表单
	wg.Add(1)
	go func() {
		defer wg.Done()
		forms := c.extractFormsEnhanced(doc, parsedURL)
		mu.Lock()
		result.Requests = append(result.Requests, forms...)
		mu.Unlock()
	}()

	// 提取JavaScript链接
	wg.Add(1)
	go func() {
		defer wg.Done()
		jsLinks := c.extractJSLinksEnhanced(string(body), parsedURL)
		mu.Lock()
		result.Links = append(result.Links, jsLinks...)
		mu.Unlock()
	}()

	// 提取资源
	wg.Add(1)
	go func() {
		defer wg.Done()
		assets := c.extractAssets(doc, parsedURL)
		mu.Lock()
		result.Assets = append(result.Assets, assets...)
		mu.Unlock()
	}()

	// 提取元数据
	wg.Add(1)
	go func() {
		defer wg.Done()
		metadata := c.extractMetadata(doc, string(body))
		mu.Lock()
		result.Metadata = metadata
		mu.Unlock()
	}()

	// 提取敏感信息
	wg.Add(1)
	go func() {
		defer wg.Done()
		sensitive := c.extractSensitiveInfo(string(body), crawlURL)
		mu.Lock()
		result.SensitiveInfo = append(result.SensitiveInfo, sensitive...)
		mu.Unlock()
	}()

	wg.Wait()

	// 去重和排序
	result.Links = c.deduplicateAndSort(result.Links)
	
	log.Debug().
		Str("url", crawlURL).
		Int("links", len(result.Links)).
		Int("forms", len(result.Requests)).
		Int("assets", len(result.Assets)).
		Int("sensitive", len(result.SensitiveInfo)).
		Msg("静态解析完成")

	return result, nil
}

// crawlDynamic 使用无头浏览器执行动态分析
func (c *Crawler) crawlDynamic(ctx context.Context, crawlURL string) (*CrawlResult, error) {
	if c.dynamicCrawler == nil {
		log.Warn().Msg("动态爬虫未初始化，回退到静态爬取")
		return c.crawlStatic(ctx, crawlURL, nil)
	}

	log.Debug().Str("url", crawlURL).Msg("开始动态渲染")

	// 创建带超时的上下文
	dynamicCtx, cancel := context.WithTimeout(ctx, c.config.DynamicCrawler.PageTimeout)
	defer cancel()

	result, err := c.dynamicCrawler.CrawlPage(dynamicCtx, crawlURL)
	if err != nil {
		log.Error().Str("url", crawlURL).Err(err).Msg("动态渲染失败，回退到静态爬取")
		return c.crawlStatic(ctx, crawlURL, nil)
	}

	log.Debug().
		Str("url", crawlURL).
		Int("html_size", len(result.RenderedHTML)).
		Int("network_requests", len(result.NetworkRequests)).
		Int("console_logs", len(result.ConsoleLogs)).
		Msg("动态渲染成功")

	// 解析渲染后的HTML
	staticResult, err := c.crawlStatic(ctx, crawlURL, []byte(result.RenderedHTML))
	if err != nil {
		return nil, fmt.Errorf("解析动态渲染HTML失败: %w", err)
	}

	// 合并动态和静态结果
	c.mergeDynamicResults(staticResult, result)

	return staticResult, nil
}

// mergeDynamicResults 合并动态和静态爬取结果
func (c *Crawler) mergeDynamicResults(staticResult *CrawlResult, dynamicResult *DynamicCrawlResult) {
	// 添加网络请求中发现的链接
	for _, req := range dynamicResult.NetworkRequests {
		if c.IsInScope(req.URL) {
			staticResult.Links = append(staticResult.Links, req.URL.String())
		}
	}

	// 添加控制台日志中的敏感信息
	for _, logEntry := range dynamicResult.ConsoleLogs {
		if sensitive := c.analyzeSensitiveText(logEntry.Text, "console_log"); len(sensitive) > 0 {
			staticResult.SensitiveInfo = append(staticResult.SensitiveInfo, sensitive...)
		}
	}

	// 添加JavaScript错误信息
	for _, err := range dynamicResult.JSErrors {
		staticResult.SensitiveInfo = append(staticResult.SensitiveInfo, SensitiveData{
			Type:     "js_error",
			Value:    err.Message,
			Context:  err.Source,
			Location: "javascript",
			Risk:     "low",
		})
	}

	// 去重链接
	staticResult.Links = c.deduplicateAndSort(staticResult.Links)
}

// extractLinksEnhanced 增强的链接提取
func (c *Crawler) extractLinksEnhanced(doc *goquery.Document, baseURL *url.URL) []string {
	found := make(map[string]struct{})

	// 提取标准链接
	selectors := []string{
		"a[href]",
		"link[href]",
		"area[href]",
		"base[href]",
		"form[action]",
		"frame[src]",
		"iframe[src]",
		"embed[src]",
		"object[data]",
		"source[src]",
		"track[src]",
	}

	for _, selector := range selectors {
		doc.Find(selector).Each(func(i int, s *goquery.Selection) {
			var href string
			var exists bool
			
			// 根据不同元素类型获取URL属性
			switch s.Get(0).Data {
			case "form":
				href, exists = s.Attr("action")
			case "object":
				href, exists = s.Attr("data")
			default:
				if href, exists = s.Attr("href"); !exists {
					href, exists = s.Attr("src")
				}
			}
			
			if exists && href != "" {
				if absURL := c.toAbsoluteURL(baseURL, href); absURL != "" {
					found[absURL] = struct{}{}
				}
			}
		})
	}

	// 提取JavaScript中的URL
	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		scriptContent := s.Text()
		if scriptContent != "" {
			jsLinks := c.extractJSLinksFromText(scriptContent, baseURL)
			for _, link := range jsLinks {
				found[link] = struct{}{}
			}
		}
	})

	// 提取CSS中的URL
	doc.Find("style").Each(func(i int, s *goquery.Selection) {
		cssContent := s.Text()
		if cssContent != "" {
			cssLinks := c.extractCSSLinks(cssContent, baseURL)
			for _, link := range cssLinks {
				found[link] = struct{}{}
			}
		}
	})

	// 提取HTML注释中的URL
	doc.Contents().Each(func(i int, s *goquery.Selection) {
		if s.Get(0).Type == 8 { // Comment node
			commentText := s.Get(0).Data
			matches := urlInCommentRegex.FindAllString(commentText, -1)
			for _, match := range matches {
				if absURL := c.toAbsoluteURL(baseURL, match); absURL != "" {
					found[absURL] = struct{}{}
				}
			}
		}
	})

	// 转换为切片
	var result []string
	for link := range found {
		result = append(result, link)
	}

	return result
}

// extractFormsEnhanced 增强的表单提取
func (c *Crawler) extractFormsEnhanced(doc *goquery.Document, baseURL *url.URL) []*models.Request {
	var requests []*models.Request

	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, _ := s.Attr("action")
		method, _ := s.Attr("method")
		enctype, _ := s.Attr("enctype")
		
		if method == "" {
			method = "GET"
		}
		method = strings.ToUpper(method)

		if enctype == "" {
			enctype = "application/x-www-form-urlencoded"
		}

		formURL := c.toAbsoluteURL(baseURL, action)
		if formURL == "" {
			return
		}

		// 提取表单字段
		params := make([]models.Parameter, 0)
		hiddenParams := make([]models.Parameter, 0)
		
		s.Find("input, textarea, select").Each(func(j int, el *goquery.Selection) {
			name, nameExists := el.Attr("name")
			if !nameExists || name == "" {
				return
			}

			inputType, _ := el.Attr("type")
			value, _ := el.Attr("value")
			placeholder, _ := el.Attr("placeholder")
			required := el.AttrOr("required", "") != ""
			
			param := models.Parameter{
				Name:        name,
				Value:       c.generateTestValue(inputType, value, placeholder),
				Type:        inputType,
				Required:    required,
				Placeholder: placeholder,
			}

			// 区分隐藏字段和普通字段
			if inputType == "hidden" {
				hiddenParams = append(hiddenParams, param)
			} else {
				params = append(params, param)
			}
		})

		// 处理select选项
		s.Find("select").Each(func(j int, sel *goquery.Selection) {
			name, nameExists := sel.Attr("name")
			if !nameExists || name == "" {
				return
			}

			// 获取第一个option的值作为默认值
			var defaultValue string
			sel.Find("option").First().Each(func(k int, opt *goquery.Selection) {
				if val, exists := opt.Attr("value"); exists {
					defaultValue = val
				} else {
					defaultValue = opt.Text()
				}
			})

			param := models.Parameter{
				Name:  name,
				Value: defaultValue,
				Type:  "select",
			}
			params = append(params, param)
		})

		// 创建请求对象
		req := &models.Request{
			URL:      formURL,
			Method:   method,
			Headers:  make(map[string]string),
			Params:   params,
			Body:     "",
			FormData: make(map[string]string),
		}

		// 设置Content-Type
		req.Headers["Content-Type"] = enctype

		// 处理不同的请求方法
		if method == "POST" || method == "PUT" || method == "PATCH" {
			if enctype == "multipart/form-data" {
				// 处理文件上传表单
				for _, param := range params {
					req.FormData[param.Name] = param.Value
				}
				for _, param := range hiddenParams {
					req.FormData[param.Name] = param.Value
				}
			} else {
				// 处理普通表单
				formValues := url.Values{}
				for _, param := range params {
					formValues.Set(param.Name, param.Value)
				}
				for _, param := range hiddenParams {
					formValues.Set(param.Name, param.Value)
				}
				req.Body = formValues.Encode()
			}
		} else {
			// GET请求，参数添加到URL
			if len(params) > 0 || len(hiddenParams) > 0 {
				u, err := url.Parse(formURL)
				if err == nil {
					query := u.Query()
					for _, param := range params {
						query.Set(param.Name, param.Value)
					}
					for _, param := range hiddenParams {
						query.Set(param.Name, param.Value)
					}
					u.RawQuery = query.Encode()
					req.URL = u.String()
				}
			}
		}

		requests = append(requests, req)
	})

	return requests
}

// generateTestValue 生成测试值
func (c *Crawler) generateTestValue(inputType, currentValue, placeholder string) string {
	if currentValue != "" {
		return currentValue
	}

	switch strings.ToLower(inputType) {
	case "email":
		return "test@example.com"
	case "password":
		return "password123"
	case "number":
		return "123"
	case "tel", "phone":
		return "1234567890"
	case "url":
		return "https://example.com"
	case "date":
		return time.Now().Format("2006-01-02")
	case "datetime-local":
		return time.Now().Format("2006-01-02T15:04")
	case "time":
		return time.Now().Format("15:04")
	case "month":
		return time.Now().Format("2006-01")
	case "week":
		return time.Now().Format("2006-W01")
	case "color":
		return "#000000"
	case "range":
		return "50"
	case "search":
		return "search"
	case "hidden":
		return currentValue // 保持隐藏字段的原值
	default:
		if placeholder != "" {
			return placeholder
		}
		return "test"
	}
}

// extractJSLinksEnhanced 增强的JavaScript链接提取
func (c *Crawler) extractJSLinksEnhanced(content string, baseURL *url.URL) []string {
	var links []string
	found := make(map[string]struct{})

	// 清理注释
	content = c.removeComments(content)

	// 使用所有API模式提取链接
	for _, pattern := range apiPatterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				link := match[1]
				if absURL := c.toAbsoluteURL(baseURL, link); absURL != "" {
					if _, exists := found[absURL]; !exists {
						found[absURL] = struct{}{}
						links = append(links, absURL)
					}
				}
			}
		}
	}

	// 提取字符串中的URL
	stringMatches := jsLinkRegex.FindAllStringSubmatch(content, -1)
	for _, match := range stringMatches {
		if len(match) > 1 {
			link := match[1]
			if c.isValidURL(link) {
				if absURL := c.toAbsoluteURL(baseURL, link); absURL != "" {
					if _, exists := found[absURL]; !exists {
						found[absURL] = struct{}{}
						links = append(links, absURL)
					}
				}
			}
		}
	}

	// 提取路由配置
	routeMatches := routeRegex.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			route := match[1]
			if absURL := c.toAbsoluteURL(baseURL, route); absURL != "" {
				if _, exists := found[absURL]; !exists {
					found[absURL] = struct{}{}
					links = append(links, absURL)
				}
			}
		}
	}

	// 提取JSON中的URL
	jsonMatches := jsonRegex.FindAllString(content, -1)
	for _, jsonStr := range jsonMatches {
		urlMatches := urlPattern.FindAllString(jsonStr, -1)
		for _, urlStr := range urlMatches {
			if c.isValidURL(urlStr) {
				if absURL := c.toAbsoluteURL(baseURL, urlStr); absURL != "" {
					if _, exists := found[absURL]; !exists {
						found[absURL] = struct{}{}
						links = append(links, absURL)
					}
				}
			}
		}
	}

	return links
}

// extractJSLinksFromText 从文本中提取JavaScript链接
func (c *Crawler) extractJSLinksFromText(text string, baseURL *url.URL) []string {
	return c.extractJSLinksEnhanced(text, baseURL)
}

// extractCSSLinks 提取CSS中的链接
func (c *Crawler) extractCSSLinks(cssContent string, baseURL *url.URL) []string {
	var links []string
	found := make(map[string]struct{})

	// CSS url() 函数正则
	cssUrlRegex := regexp.MustCompile(`url\s*\(\s*['"']?([^'"')]+)['"']?\s*\)`)
	matches := cssUrlRegex.FindAllStringSubmatch(cssContent, -1)

	for _, match := range matches {
		if len(match) > 1 {
			link := strings.TrimSpace(match[1])
			if link != "" && !strings.HasPrefix(link, "data:") {
				if absURL := c.toAbsoluteURL(baseURL, link); absURL != "" {
					if _, exists := found[absURL]; !exists {
						found[absURL] = struct{}{}
						links = append(links, absURL)
					}
				}
			}
		}
	}

	// @import 规则
	importRegex := regexp.MustCompile(`@import\s+['"']([^'"']+)['"']`)
	importMatches := importRegex.FindAllStringSubmatch(cssContent, -1)

	for _, match := range importMatches {
		if len(match) > 1 {
			link := strings.TrimSpace(match[1])
			if link != "" {
				if absURL := c.toAbsoluteURL(baseURL, link); absURL != "" {
					if _, exists := found[absURL]; !exists {
						found[absURL] = struct{}{}
						links = append(links, absURL)
					}
				}
			}
		}
	}

	return links
}

// extractAssets 提取页面资源
func (c *Crawler) extractAssets(doc *goquery.Document, baseURL *url.URL) []Asset {
	var assets []Asset
	found := make(map[string]Asset)

	// 定义资源选择器和类型映射
	assetSelectors := map[string]string{
		"script[src]":                    "js",
		"link[rel=stylesheet][href]":     "css",
		"img[src]":                       "image",
		"video[src]":                     "video",
		"audio[src]":                     "audio",
		"source[src]":                    "media",
		"track[src]":                     "track",
		"embed[src]":                     "embed",
		"object[data]":                   "object",
		"iframe[src]":                    "iframe",
		"link[rel=icon][href]":           "icon",
		"link[rel=shortcut\\ icon][href]": "icon",
		"link[rel=apple-touch-icon][href]": "icon",
	}

	for selector, assetType := range assetSelectors {
		doc.Find(selector).Each(func(i int, s *goquery.Selection) {
			var src string
			var exists bool

			// 根据元素类型获取URL
			if assetType == "object" {
				src, exists = s.Attr("data")
			} else {
				if src, exists = s.Attr("href"); !exists {
					src, exists = s.Attr("src")
				}
			}

			if exists && src != "" {
				absURL := c.toAbsoluteURL(baseURL, src)
				if absURL != "" {
					if _, ok := found[absURL]; !ok {
						asset := Asset{
							URL:  absURL,
							Type: assetType,
						}

						// 尝试获取额外信息
						if size, exists := s.Attr("size"); exists {
							// 解析size属性 (如果存在)
							_ = size
						}

						// 检查缓存
						if cachedAsset, cached := c.assetCache.Load(absURL); cached {
							asset = cachedAsset.(Asset)
						} else {
							// 异步获取资源信息
							go c.fetchAssetInfo(&asset)
							c.assetCache.Store(absURL, asset)
						}

						found[absURL] = asset
					}
				}
			}
		})
	}

	// 转换为切片
	for _, asset := range found {
		assets = append(assets, asset)
	}

	return assets
}

// fetchAssetInfo 异步获取资源信息
func (c *Crawler) fetchAssetInfo(asset *Asset) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.httpClient.Head(ctx, asset.URL, nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// 获取Content-Type
	asset.ContentType = resp.Header.Get("Content-Type")

	// 获取Content-Length
	if contentLength := resp.Header.Get("Content-Length"); contentLength != "" {
		if size, err := strconv.ParseInt(contentLength, 10, 64); err == nil {
			asset.Size = size
		}
	}

	// 获取Last-Modified
	if lastModified := resp.Header.Get("Last-Modified"); lastModified != "" {
		if t, err := time.Parse(time.RFC1123, lastModified); err == nil {
			asset.LastModified = t
		}
	}

	// 更新缓存
	c.assetCache.Store(asset.URL, *asset)
}

// extractMetadata 提取页面元数据
func (c *Crawler) extractMetadata(doc *goquery.Document, htmlContent string) *PageMetadata {
	metadata := &PageMetadata{
		OpenGraph:   make(map[string]string),
		TwitterCard: make(map[string]string),
		JsonLD:      make([]string, 0),
		Comments:    make([]string, 0),
	}

	// 基本元数据
	metadata.Title = doc.Find("title").Text()
	metadata.Description = doc.Find("meta[name=description]").AttrOr("content", "")
	metadata.Keywords = doc.Find("meta[name=keywords]").AttrOr("content", "")
	metadata.Author = doc.Find("meta[name=author]").AttrOr("content", "")
	metadata.Language = doc.Find("html").AttrOr("lang", "")
	metadata.Charset = doc.Find("meta[charset]").AttrOr("charset", "")
	metadata.Viewport = doc.Find("meta[name=viewport]").AttrOr("content", "")
	metadata.Canonical = doc.Find("link[rel=canonical]").AttrOr("href", "")

	// Open Graph 元数据
	doc.Find("meta[property^=og:]").Each(func(i int, s *goquery.Selection) {
		property, _ := s.Attr("property")
		content, _ := s.Attr("content")
		if property != "" && content != "" {
			metadata.OpenGraph[property] = content
		}
	})

	// Twitter Card 元数据
	doc.Find("meta[name^=twitter:]").Each(func(i int, s *goquery.Selection) {
		name, _ := s.Attr("name")
		content, _ := s.Attr("content")
		if name != "" && content != "" {
			metadata.TwitterCard[name] = content
		}
	})

	// JSON-LD 结构化数据
	doc.Find("script[type='application/ld+json']").Each(func(i int, s *goquery.Selection) {
		jsonLD := strings.TrimSpace(s.Text())
		if jsonLD != "" {
			metadata.JsonLD = append(metadata.JsonLD, jsonLD)
		}
	})

	// 提取HTML注释
	comments := c.extractHTMLComments(htmlContent)
	metadata.Comments = comments

	return metadata
}

// extractHTMLComments 提取HTML注释
func (c *Crawler) extractHTMLComments(htmlContent string) []string {
	var comments []string
	commentRegex := regexp.MustCompile(`<!--(.*?)-->`)
	matches := commentRegex.FindAllStringSubmatch(htmlContent, -1)

	for _, match := range matches {
		if len(match) > 1 {
			comment := strings.TrimSpace(match[1])
			if comment != "" && len(comment) < 500 { // 限制注释长度
				comments = append(comments, comment)
			}
		}
	}

	return comments
}

// extractSensitiveInfo 提取敏感信息
func (c *Crawler) extractSensitiveInfo(content, sourceURL string) []SensitiveData {
	var sensitiveData []SensitiveData

	// 使用预定义的敏感信息模式
	for _, pattern := range sensitivePatterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) >= 3 {
				key := match[1]
				value := match[2]
				
				// 过滤明显的假值
				if c.isLikelySensitive(key, value) {
					risk := c.assessRisk(key, value)
					sensitiveData = append(sensitiveData, SensitiveData{
						Type:     c.categorizeKey(key),
						Value:    c.maskSensitiveValue(value),
						Context:  key,
						Location: sourceURL,
						Risk:     risk,
					})
				}
			}
		}
	}

	// 提取邮箱地址
	emailMatches := emailRegex.FindAllString(content, -1)
	for _, email := range emailMatches {
		if !c.isCommonTestEmail(email) {
			sensitiveData = append(sensitiveData, SensitiveData{
				Type:     "email",
				Value:    email,
				Context:  "email_address",
				Location: sourceURL,
				Risk:     "low",
			})
		}
	}

	// 提取IP地址
	ipMatches := ipRegex.FindAllString(content, -1)
	for _, ip := range ipMatches {
		if !c.isPrivateIP(ip) && !c.isCommonPublicIP(ip) {
			sensitiveData = append(sensitiveData, SensitiveData{
				Type:     "ip_address",
				Value:    ip,
				Context:  "ip_address",
				Location: sourceURL,
				Risk:     "medium",
			})
		}
	}

	// 提取域名
	domainMatches := domainRegex.FindAllString(content, -1)
	for _, domain := range domainMatches {
		if !c.isCommonDomain(domain) {
			sensitiveData = append(sensitiveData, SensitiveData{
				Type:     "domain",
				Value:    domain,
				Context:  "domain_name",
				Location: sourceURL,
				Risk:     "low",
			})
		}
	}

	return c.analyzeSensitiveText(content, sourceURL)
}

// analyzeSensitiveText 分析文本中的敏感信息
func (c *Crawler) analyzeSensitiveText(text, sourceURL string) []SensitiveData {
	var sensitiveData []SensitiveData

	// 查找可能的API密钥模式
	apiKeyPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)api[_-]?key['":\s=]+([a-zA-Z0-9_-]{20,})`),
		regexp.MustCompile(`(?i)access[_-]?token['":\s=]+([a-zA-Z0-9_-]{20,})`),
		regexp.MustCompile(`(?i)secret[_-]?key['":\s=]+([a-zA-Z0-9_-]{20,})`),
		regexp.MustCompile(`(?i)private[_-]?key['":\s=]+([a-zA-Z0-9_-]{20,})`),
		regexp.MustCompile(`(?i)auth[_-]?token['":\s=]+([a-zA-Z0-9_-]{20,})`),
	}

	for _, pattern := range apiKeyPatterns {
		matches := pattern.FindAllStringSubmatch(text, -1)
		for _, match := range matches {
			if len(match) > 1 {
				key := match[1]
				if len(key) >= 20 && !c.isCommonTestKey(key) {
					sensitiveData = append(sensitiveData, SensitiveData{
						Type:     "api_key",
						Value:    c.maskSensitiveValue(key),
						Context:  "potential_api_key",
						Location: sourceURL,
						Risk:     "high",
					})
				}
			}
		}
	}

	// 查找数据库连接字符串
	dbPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(mysql|postgresql|mongodb|redis)://[^\s'"<>]+`),
		regexp.MustCompile(`(?i)server\s*=\s*[^;]+;.*database\s*=\s*[^;]+`),
		regexp.MustCompile(`(?i)data\s+source\s*=\s*[^;]+`),
	}

	for _, pattern := range dbPatterns {
		matches := pattern.FindAllString(text, -1)
		for _, match := range matches {
			sensitiveData = append(sensitiveData, SensitiveData{
				Type:     "database_connection",
				Value:    c.maskSensitiveValue(match),
				Context:  "connection_string",
				Location: sourceURL,
				Risk:     "critical",
			})
		}
	}

	return sensitiveData
}

// 辅助方法

// isLikelySensitive 判断是否可能是敏感信息
func (c *Crawler) isLikelySensitive(key, value string) bool {
	key = strings.ToLower(key)
	value = strings.TrimSpace(value)

	// 过滤空值和占位符
	if value == "" || len(value) < 3 {
		return false
	}

	// 过滤明显的占位符
	placeholders := []string{
		"your_", "example", "test", "demo", "placeholder", "xxx", "***",
		"null", "undefined", "none", "empty", "default",
	}

	lowerValue := strings.ToLower(value)
	for _, placeholder := range placeholders {
		if strings.Contains(lowerValue, placeholder) {
			return false
		}
	}

	// 检查是否是敏感键
	sensitiveKeys := []string{
		"password", "pwd", "pass", "secret", "key", "token", "auth",
		"api_key", "access_key", "private_key", "session", "cookie",
	}

	for _, sensitiveKey := range sensitiveKeys {
		if strings.Contains(key, sensitiveKey) {
			return true
		}
	}

	return false
}

// assessRisk 评估风险等级
func (c *Crawler) assessRisk(key, value string) string {
	key = strings.ToLower(key)
	
	criticalKeys := []string{"password", "secret", "private_key", "api_key"}
	highKeys := []string{"token", "auth", "session", "cookie"}
	mediumKeys := []string{"username", "email", "phone"}

	for _, criticalKey := range criticalKeys {
		if strings.Contains(key, criticalKey) {
			return "critical"
		}
	}

	for _, highKey := range highKeys {
		if strings.Contains(key, highKey) {
			return "high"
		}
	}

	for _, mediumKey := range mediumKeys {
		if strings.Contains(key, mediumKey) {
			return "medium"
		}
	}

	return "low"
}

// categorizeKey 分类键类型
func (c *Crawler) categorizeKey(key string) string {
	key = strings.ToLower(key)

	if strings.Contains(key, "password") || strings.Contains(key, "pwd") {
		return "password"
	}
	if strings.Contains(key, "token") {
		return "token"
	}
	if strings.Contains(key, "key") {
		return "api_key"
	}
	if strings.Contains(key, "secret") {
		return "secret"
	}
	if strings.Contains(key, "auth") {
		return "authentication"
	}
	if strings.Contains(key, "session") {
		return "session"
	}
	if strings.Contains(key, "cookie") {
		return "cookie"
	}
	if strings.Contains(key, "username") || strings.Contains(key, "user") {
		return "username"
	}
	if strings.Contains(key, "email") {
		return "email"
	}

	return "unknown"
}

// maskSensitiveValue 掩码敏感值
func (c *Crawler) maskSensitiveValue(value string) string {
	if len(value) <= 6 {
		return strings.Repeat("*", len(value))
	}

	// 显示前3个和后3个字符，中间用*代替
	return value[:3] + strings.Repeat("*", len(value)-6) + value[len(value)-3:]
}

// isCommonTestEmail 检查是否是常见的测试邮箱
func (c *Crawler) isCommonTestEmail(email string) bool {
	testEmails := []string{
		"test@example.com", "admin@example.com", "user@example.com",
		"noreply@example.com", "support@example.com", "info@example.com",
		"test@test.com", "admin@test.com", "user@test.com",
	}

	lowerEmail := strings.ToLower(email)
	for _, testEmail := range testEmails {
		if lowerEmail == testEmail {
			return true
		}
	}

	return false
}

// isPrivateIP 检查是否是私有IP地址
func (c *Crawler) isPrivateIP(ip string) bool {
	privateRanges := []string{
		"10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
		"172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
		"172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.",
		"127.", "169.254.",
	}

	for _, privateRange := range privateRanges {
		if strings.HasPrefix(ip, privateRange) {
			return true
		}
	}

	return false
}

// isCommonPublicIP 检查是否是常见的公共IP
func (c *Crawler) isCommonPublicIP(ip string) bool {
	commonIPs := []string{
		"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
		"208.67.222.222", "208.67.220.220",
	}

	for _, commonIP := range commonIPs {
		if ip == commonIP {
			return true
		}
	}

	return false
}

// isCommonDomain 检查是否是常见域名
func (c *Crawler) isCommonDomain(domain string) bool {
	commonDomains := []string{
		"example.com", "test.com", "localhost", "google.com",
		"facebook.com", "twitter.com", "github.com", "stackoverflow.com",
	}

	lowerDomain := strings.ToLower(domain)
	for _, commonDomain := range commonDomains {
		if lowerDomain == commonDomain {
			return true
		}
	}

	return false
}

// isCommonTestKey 检查是否是常见的测试密钥
func (c *Crawler) isCommonTestKey(key string) bool {
	testKeys := []string{
		"your_api_key_here", "replace_with_your_key", "test_key",
		"example_key", "demo_key", "placeholder_key",
	}

	lowerKey := strings.ToLower(key)
	for _, testKey := range testKeys {
		if strings.Contains(lowerKey, testKey) {
			return true
		}
	}

	// 检查是否全是相同字符
	if len(key) > 0 {
		firstChar := key[0]
		allSame := true
		for _, char := range key {
			if char != rune(firstChar) {
				allSame = false
				break
			}
		}
		if allSame {
			return true
		}
	}

	return false
}

// removeComments 移除JavaScript注释
func (c *Crawler) removeComments(content string) string {
	// 移除单行注释
	content = singleLineComments.ReplaceAllString(content, "")
	// 移除多行注释
	content = multiLineComments.ReplaceAllString(content, "")
	return content
}

// isValidURL 检查是否是有效的URL
func (c *Crawler) isValidURL(str string) bool {
	if str == "" {
		return false
	}

	// 检查是否以协议开头或以/开头
	if strings.HasPrefix(str, "http://") || strings.HasPrefix(str, "https://") || strings.HasPrefix(str, "/") {
		return true
	}

	// 检查是否包含域名模式
	if strings.Contains(str, ".") && !strings.Contains(str, " ") {
		return true
	}

	return false
}

// toAbsoluteURL 转换为绝对URL
func (c *Crawler) toAbsoluteURL(baseURL *url.URL, href string) string {
	if href == "" {
		return ""
	}

	// 清理URL
	href = strings.TrimSpace(href)
	
	// 跳过特殊协议
	if strings.HasPrefix(href, "javascript:") || 
	   strings.HasPrefix(href, "mailto:") || 
	   strings.HasPrefix(href, "tel:") || 
	   strings.HasPrefix(href, "data:") ||
	   strings.HasPrefix(href, "#") {
		return ""
	}

	parsedURL, err := url.Parse(href)
	if err != nil {
		return ""
	}

	// 如果已经是绝对URL，直接返回
	if parsedURL.IsAbs() {
		return parsedURL.String()
	}

	// 解析为绝对URL
	absoluteURL := baseURL.ResolveReference(parsedURL)
	return absoluteURL.String()
}

// deduplicateAndSort 去重并排序
func (c *Crawler) deduplicateAndSort(links []string) []string {
	seen := make(map[string]struct{})
	var result []string

	for _, link := range links {
		if _, exists := seen[link]; !exists {
			seen[link] = struct{}{}
			result = append(result, link)
		}
	}

	sort.Strings(result)
	return result
}

// getFileExtension 获取文件扩展名
func getFileExtension(path string) string {
	if idx := strings.LastIndex(path, "."); idx != -1 {
		return path[idx:]
	}
	return ""
}

// addResult 添加结果到收集器
func (rc *ResultCollector) addResult(url string, result *CrawlResult) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	// 检查是否已达到最大结果数
	if rc.totalResults >= rc.maxResults {
		return
	}

	// 生成结果指纹用于去重
	fingerprint := rc.generateFingerprint(result)
	
	if count, exists := rc.duplicates[fingerprint]; exists {
		rc.duplicates[fingerprint] = count + 1
		log.Debug().Str("url", url).Int("count", count+1).Msg("发现重复结果")
		return
	}

	rc.duplicates[fingerprint] = 1
	rc.results[url] = result
	rc.totalResults++

	log.Debug().
		Str("url", url).
		Int("total_results", rc.totalResults).
		Msg("添加爬取结果")
}

// generateFingerprint 生成结果指纹
func (rc *ResultCollector) generateFingerprint(result *CrawlResult) string {
	// 简单的指纹生成：基于链接数量和表单数量
	fingerprint := fmt.Sprintf("links:%d,forms:%d,assets:%d", 
		len(result.Links), len(result.Requests), len(result.Assets))
	
	// 添加内容哈希
	hasher := md5.New()
	hasher.Write([]byte(fingerprint))
	return hex.EncodeToString(hasher.Sum(nil))
}

// GetResults 获取所有结果
func (rc *ResultCollector) GetResults() map[string]*CrawlResult {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	
	// 返回副本以避免并发修改
	results := make(map[string]*CrawlResult)
	for k, v := range rc.results {
		results[k] = v
	}
	
	return results
}

// GetStats 获取统计信息
func (c *Crawler) GetStats() *CrawlerStats {
	c.stats.mu.RLock()
	defer c.stats.mu.RUnlock()
	
	// 返回副本
	statsCopy := &CrawlerStats{
		StartTime:       c.stats.StartTime,
		TotalPages:      c.stats.TotalPages,
		SuccessfulPages: c.stats.SuccessfulPages,
		FailedPages:     c.stats.FailedPages,
		TotalLinks:      c.stats.TotalLinks,
		TotalForms:      c.stats.TotalForms,
		TotalAssets:     c.stats.TotalAssets,
		BytesProcessed:  c.stats.BytesProcessed,
		Errors:          make([]error, len(c.stats.Errors)),
	}
	
	copy(statsCopy.Errors, c.stats.Errors)
	return statsCopy
}

// Close 关闭爬虫并清理资源
func (c *Crawler) Close() error {
	log.Info().Msg("正在关闭爬虫...")
	
	// 取消上下文
	if c.cancel != nil {
		c.cancel()
	}
	
	// 关闭动态爬虫
	if c.dynamicCrawler != nil {
		if err := c.dynamicCrawler.Close(); err != nil {
			log.Error().Err(err).Msg("关闭动态爬虫失败")
		}
	}
	
	// 清理缓存
	c.linkCache = sync.Map{}
	c.assetCache = sync.Map{}
	
	log.Info().Msg("爬虫已关闭")
	return nil
}

// CrawlBatch 批量爬取多个URL
func (c *Crawler) CrawlBatch(ctx context.Context, urls []string) (map[string]*CrawlResult, error) {
	if len(urls) == 0 {
		return nil, fmt.Errorf("URL列表为空")
	}

	results := make(map[string]*CrawlResult)
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	// 创建工作池
	semaphore := make(chan struct{}, c.config.Concurrency)
	
	for _, url := range urls {
		wg.Add(1)
		go func(crawlURL string) {
			defer wg.Done()
			
			// 获取工作许可
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			result, err := c.Crawl(ctx, crawlURL, nil)
			if err != nil {
				log.Error().Str("url", crawlURL).Err(err).Msg("批量爬取失败")
				return
			}
			
			if result != nil {
				mu.Lock()
				results[crawlURL] = result
				mu.Unlock()
			}
		}(url)
	}
	
	wg.Wait()
	
	log.Info().
		Int("total_urls", len(urls)).
		Int("successful", len(results)).
		Msg("批量爬取完成")
	
	return results, nil
}

// SetRateLimit 设置速率限制
func (c *Crawler) SetRateLimit(requestsPerSecond float64) {
	c.limiter = rate.NewLimiter(rate.Limit(requestsPerSecond), int(requestsPerSecond))
	log.Info().Float64("rps", requestsPerSecond).Msg("更新速率限制")
}

// DynamicCrawlerConfig 动态爬虫配置
type DynamicCrawlerConfig struct {
	Headless         bool          `json:"headless"`
	BrowserType      string        `json:"browser_type"`
	MaxInstances     int           `json:"max_instances"`
	PageTimeout      time.Duration `json:"page_timeout"`
	WaitTime         time.Duration `json:"wait_time"`
	EnableJavaScript bool          `json:"enable_javascript"`
	EnableImages     bool          `json:"enable_images"`
	EnableCSS        bool          `json:"enable_css"`
	ViewportWidth    int           `json:"viewport_width"`
	ViewportHeight   int           `json:"viewport_height"`
	UserAgent        string        `json:"user_agent"`
	Proxy            string        `json:"proxy"`
}

// DynamicCrawler 动态爬虫（使用浏览器）
type DynamicCrawler struct {
	config    DynamicCrawlerConfig
	instances chan *BrowserInstance
	ctx       context.Context
	cancel    context.CancelFunc
}

// BrowserInstance 浏览器实例
type BrowserInstance struct {
	ID       string
	Browser  interface{} // 实际的浏览器实例，根据使用的库而定
	InUse    bool
	LastUsed time.Time
}

// DynamicCrawlResult 动态爬取结果
type DynamicCrawlResult struct {
	RenderedHTML     string           `json:"rendered_html"`
	NetworkRequests  []NetworkRequest `json:"network_requests"`
	ConsoleLogs      []ConsoleLog     `json:"console_logs"`
	JSErrors         []JSError        `json:"js_errors"`
	Screenshots      []Screenshot     `json:"screenshots"`
	PerformanceMetrics *PerformanceMetrics `json:"performance_metrics"`
	Error            error            `json:"error,omitempty"`
}

// NetworkRequest 网络请求信息
type NetworkRequest struct {
	URL        *url.URL          `json:"url"`
	Method     string            `json:"method"`
	Headers    map[string]string `json:"headers"`
	PostData   string            `json:"post_data"`
	StatusCode int               `json:"status_code"`
	ResponseSize int64           `json:"response_size"`
	Duration   time.Duration     `json:"duration"`
	Timestamp  time.Time         `json:"timestamp"`
}

// ConsoleLog 控制台日志
type ConsoleLog struct {
	Level     string    `json:"level"`
	Text      string    `json:"text"`
	URL       string    `json:"url"`
	Line      int       `json:"line"`
	Column    int       `json:"column"`
	Timestamp time.Time `json:"timestamp"`
}

// JSError JavaScript错误
type JSError struct {
	Message   string    `json:"message"`
	Source    string    `json:"source"`
	Line      int       `json:"line"`
	Column    int       `json:"column"`
	Stack     string    `json:"stack"`
	Timestamp time.Time `json:"timestamp"`
}

// Screenshot 截图信息
type Screenshot struct {
	Data      []byte    `json:"data"`
	Format    string    `json:"format"`
	Width     int       `json:"width"`
	Height    int       `json:"height"`
	Timestamp time.Time `json:"timestamp"`
}

// PerformanceMetrics 性能指标
type PerformanceMetrics struct {
	LoadTime          time.Duration `json:"load_time"`
	DOMContentLoaded  time.Duration `json:"dom_content_loaded"`
	FirstPaint        time.Duration `json:"first_paint"`
	FirstContentfulPaint time.Duration `json:"first_contentful_paint"`
	LargestContentfulPaint time.Duration `json:"largest_contentful_paint"`
	CumulativeLayoutShift float64     `json:"cumulative_layout_shift"`
	FirstInputDelay   time.Duration `json:"first_input_delay"`
	TotalBlockingTime time.Duration `json:"total_blocking_time"`
	ResourceCount     int           `json:"resource_count"`
	JSHeapUsed        int64         `json:"js_heap_used"`
	JSHeapTotal       int64         `json:"js_heap_total"`
}

// NewDynamicCrawler 创建动态爬虫
func NewDynamicCrawler(config DynamicCrawlerConfig) *DynamicCrawler {
	ctx, cancel := context.WithCancel(context.Background())
	
	dc := &DynamicCrawler{
		config:    config,
		instances: make(chan *BrowserInstance, config.MaxInstances),
		ctx:       ctx,
		cancel:    cancel,
	}
	
	// 初始化浏览器实例池
	go dc.initializeBrowserPool()
	
	return dc
}

// initializeBrowserPool 初始化浏览器实例池
func (dc *DynamicCrawler) initializeBrowserPool() {
	for i := 0; i < dc.config.MaxInstances; i++ {
		instance := &BrowserInstance{
			ID:       fmt.Sprintf("browser-%d", i),
			InUse:    false,
			LastUsed: time.Now(),
		}
		
		// 这里应该初始化实际的浏览器实例
		// 根据配置选择不同的浏览器驱动（Chrome, Firefox等）
		if err := dc.initializeBrowserInstance(instance); err != nil {
			log.Error().Str("instance_id", instance.ID).Err(err).Msg("初始化浏览器实例失败")
			continue
		}
		
		dc.instances <- instance
	}
	
	log.Info().Int("instances", dc.config.MaxInstances).Msg("浏览器实例池初始化完成")
}

// initializeBrowserInstance 初始化浏览器实例
func (dc *DynamicCrawler) initializeBrowserInstance(instance *BrowserInstance) error {
	// 这里应该根据配置初始化实际的浏览器实例
	// 例如使用 chromedp, selenium 或其他浏览器自动化库
	
	log.Debug().Str("instance_id", instance.ID).Msg("初始化浏览器实例")
	
	// 示例代码框架（需要根据实际使用的库进行实现）
	/*
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", dc.config.Headless),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.WindowSize(dc.config.ViewportWidth, dc.config.ViewportHeight),
	)
	
	if dc.config.Proxy != "" {
		opts = append(opts, chromedp.ProxyServer(dc.config.Proxy))
	}
	
	allocCtx, cancel := chromedp.NewExecAllocator(dc.ctx, opts...)
	defer cancel()
	
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()
	
	instance.Browser = ctx
	*/
	
	return nil
}

// CrawlPage 爬取单个页面
func (dc *DynamicCrawler) CrawlPage(ctx context.Context, url string) (*DynamicCrawlResult, error) {
	// 获取浏览器实例
	select {
	case instance := <-dc.instances:
		defer func() {
			instance.InUse = false
			instance.LastUsed = time.Now()
			dc.instances <- instance
		}()
		
		instance.InUse = true
		return dc.crawlWithInstance(ctx, url, instance)
		
	case <-ctx.Done():
		return nil, ctx.Err()
		
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("获取浏览器实例超时")
	}
}

// crawlWithInstance 使用指定实例爬取
func (dc *DynamicCrawler) crawlWithInstance(ctx context.Context, url string, instance *BrowserInstance) (*DynamicCrawlResult, error) {
	log.Debug().
		Str("url", url).
		Str("instance_id", instance.ID).
		Msg("开始动态爬取")
	
	startTime := time.Now()
	result := &DynamicCrawlResult{
		NetworkRequests: make([]NetworkRequest, 0),
		ConsoleLogs:     make([]ConsoleLog, 0),
		JSErrors:        make([]JSError, 0),
		Screenshots:     make([]Screenshot, 0),
	}
	
	// 创建带超时的上下文
	timeoutCtx, cancel := context.WithTimeout(ctx, dc.config.PageTimeout)
	defer cancel()
	
	// 这里应该实现实际的浏览器操作
	// 以下是示例代码框架
	
	/*
	// 设置网络监听
	chromedp.ListenTarget(timeoutCtx, func(ev interface{}) {
		switch ev := ev.(type) {
		case *network.EventRequestWillBeSent:
			// 记录网络请求
		case *network.EventResponseReceived:
			// 记录网络响应
		case *runtime.EventConsoleAPICalled:
			// 记录控制台日志
		case *runtime.EventExceptionThrown:
			// 记录JavaScript错误
		}
	})
	
	// 启用网络和运行时域
	if err := chromedp.Run(timeoutCtx,
		network.Enable(),
		runtime.Enable(),
		page.Enable(),
	); err != nil {
		return nil, fmt.Errorf("启用浏览器域失败: %w", err)
	}
	
	// 导航到页面
	if err := chromedp.Run(timeoutCtx,
		chromedp.Navigate(url),
		chromedp.WaitVisible("body", chromedp.ByQuery),
	); err != nil {
		return nil, fmt.Errorf("导航到页面失败: %w", err)
	}
	
	// 等待页面加载完成
	time.Sleep(dc.config.WaitTime)
	
	// 获取渲染后的HTML
	if err := chromedp.Run(timeoutCtx,
		chromedp.OuterHTML("html", &result.RenderedHTML, chromedp.ByQuery),
	); err != nil {
		return nil, fmt.Errorf("获取HTML失败: %w", err)
	}
	
	// 获取性能指标
	var performanceMetrics map[string]interface{}
	if err := chromedp.Run(timeoutCtx,
		chromedp.Evaluate(`JSON.stringify(performance.getEntriesByType('navigation')[0])`, &performanceMetrics),
	); err == nil {
		result.PerformanceMetrics = dc.parsePerformanceMetrics(performanceMetrics)
	}
	
	// 截图（如果需要）
	if dc.config.EnableScreenshots {
		var screenshot []byte
		if err := chromedp.Run(timeoutCtx,
			chromedp.CaptureScreenshot(&screenshot),
		); err == nil {
			result.Screenshots = append(result.Screenshots, Screenshot{
				Data:      screenshot,
				Format:    "png",
				Timestamp: time.Now(),
			})
		}
	}
	*/
	
	// 临时返回基本结果
	result.RenderedHTML = fmt.Sprintf("<html><body>Dynamic crawl result for %s</body></html>", url)
	result.PerformanceMetrics = &PerformanceMetrics{
		LoadTime: time.Since(startTime),
	}
	
	log.Debug().
		Str("url", url).
		Str("instance_id", instance.ID).
		Dur("duration", time.Since(startTime)).
		Msg("动态爬取完成")
	
	return result, nil
}

// parsePerformanceMetrics 解析性能指标
func (dc *DynamicCrawler) parsePerformanceMetrics(data map[string]interface{}) *PerformanceMetrics {
	metrics := &PerformanceMetrics{}
	
	// 这里应该解析实际的性能数据
	// 示例代码框架
	if loadTime, ok := data["loadEventEnd"].(float64); ok {
		metrics.LoadTime = time.Duration(loadTime) * time.Millisecond
	}
	
	if domContentLoaded, ok := data["domContentLoadedEventEnd"].(float64); ok {
		metrics.DOMContentLoaded = time.Duration(domContentLoaded) * time.Millisecond
	}
	
	return metrics
}

// Close 关闭动态爬虫
func (dc *DynamicCrawler) Close() error {
	log.Info().Msg("正在关闭动态爬虫...")
	
	// 取消上下文
	dc.cancel()
	
	// 关闭所有浏览器实例
	close(dc.instances)
	for instance := range dc.instances {
		if err := dc.closeBrowserInstance(instance); err != nil {
			log.Error().Str("instance_id", instance.ID).Err(err).Msg("关闭浏览器实例失败")
		}
	}
	
	log.Info().Msg("动态爬虫已关闭")
	return nil
}

// closeBrowserInstance 关闭浏览器实例
func (dc *DynamicCrawler) closeBrowserInstance(instance *BrowserInstance) error {
	log.Debug().Str("instance_id", instance.ID).Msg("关闭浏览器实例")
	
	// 这里应该关闭实际的浏览器实例
	// 例如：
	/*
	if ctx, ok := instance.Browser.(context.Context); ok {
		return chromedp.Cancel(ctx)
	}
	*/
	
	return nil
}

// CrawlerManager 爬虫管理器
type CrawlerManager struct {
	crawlers map[string]*Crawler
	mu       sync.RWMutex
	config   *config.Settings
}

// NewCrawlerManager 创建爬虫管理器
func NewCrawlerManager(config *config.Settings) *CrawlerManager {
	return &CrawlerManager{
		crawlers: make(map[string]*Crawler),
		config:   config,
	}
}

// GetCrawler 获取或创建爬虫实例
func (cm *CrawlerManager) GetCrawler(baseURL string, client *requester.HTTPClient) (*Crawler, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	if crawler, exists := cm.crawlers[baseURL]; exists {
		return crawler, nil
	}
	
	crawler, err := NewCrawler(baseURL, cm.config, client)
	if err != nil {
		return nil, err
	}
	
	cm.crawlers[baseURL] = crawler
	return crawler, nil
}

// CloseAll 关闭所有爬虫
func (cm *CrawlerManager) CloseAll() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	var errors []error
	for baseURL, crawler := range cm.crawlers {
		if err := crawler.Close(); err != nil {
			errors = append(errors, fmt.Errorf("关闭爬虫 %s 失败: %w", baseURL, err))
		}
	}
	
	cm.crawlers = make(map[string]*Crawler)
	
	if len(errors) > 0 {
		return fmt.Errorf("关闭爬虫时发生错误: %v", errors)
	}
	
	return nil
}

// GetAllStats 获取所有爬虫的统计信息
func (cm *CrawlerManager) GetAllStats() map[string]*CrawlerStats {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	stats := make(map[string]*CrawlerStats)
	for baseURL, crawler := range cm.crawlers {
		stats[baseURL] = crawler.GetStats()
	}
	
	return stats
}

// 全局爬虫管理器实例
var (
	globalCrawlerManager *CrawlerManager
	crawlerManagerOnce   sync.Once
)

// GetGlobalCrawlerManager 获取全局爬虫管理器
func GetGlobalCrawlerManager(config *config.Settings) *CrawlerManager {
	crawlerManagerOnce.Do(func() {
		globalCrawlerManager = NewCrawlerManager(config)
	})
	return globalCrawlerManager
}

// CrawlerHealthCheck 爬虫健康检查
type CrawlerHealthCheck struct {
	crawler *Crawler
}

// NewCrawlerHealthCheck 创建健康检查
func NewCrawlerHealthCheck(crawler *Crawler) *CrawlerHealthCheck {
	return &CrawlerHealthCheck{crawler: crawler}
}

// Check 执行健康检查
func (hc *CrawlerHealthCheck) Check() map[string]interface{} {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now(),
	}
	
	stats := hc.crawler.GetStats()
	
	// 检查错误率
	if stats.TotalPages > 0 {
		errorRate := float64(stats.FailedPages) / float64(stats.TotalPages)
		health["error_rate"] = errorRate
		
		if errorRate > 0.5 {
			health["status"] = "unhealthy"
			health["reason"] = "错误率过高"
		} else if errorRate > 0.2 {
			health["status"] = "warning"
			health["reason"] = "错误率较高"
		}
	}
	
	// 检查内存使用
	if stats.BytesProcessed > 1024*1024*1024 { // 1GB
		health["status"] = "warning"
		health["reason"] = "内存使用量较高"
	}
	
	// 检查运行时间
	runTime := time.Since(stats.StartTime)
	health["uptime"] = runTime.String()
	
	if runTime > 24*time.Hour {
		health["status"] = "warning"
		health["reason"] = "运行时间过长，建议重启"
	}
	
	health["stats"] = stats
	
	return health
}
