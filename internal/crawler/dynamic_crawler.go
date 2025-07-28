// Package crawler 提供了网站爬取功能，包括静态和动态爬取。
package crawler

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/playwright-community/playwright-go"
	"github.com/rs/zerolog/log"
)

// DynamicCrawlerResult 封装了动态爬取的结果，包括渲染后的HTML和可能的错误。
type DynamicCrawlerResult struct {
	RenderedHTML     string                 `json:"rendered_html"`
	URL              string                 `json:"url"`
	Title            string                 `json:"title"`
	StatusCode       int                    `json:"status_code"`
	LoadTime         time.Duration          `json:"load_time"`
	NetworkRequests  []NetworkRequest       `json:"network_requests"`
	ConsoleLogs      []ConsoleLog           `json:"console_logs"`
	JSErrors         []JSError              `json:"js_errors"`
	Screenshots      []Screenshot           `json:"screenshots"`
	Cookies          []Cookie               `json:"cookies"`
	LocalStorage     map[string]string      `json:"local_storage"`
	SessionStorage   map[string]string      `json:"session_storage"`
	PerformanceMetrics *PerformanceMetrics  `json:"performance_metrics"`
	Error            error                  `json:"error,omitempty"`
	Timestamp        time.Time              `json:"timestamp"`
}

// NetworkRequest 网络请求信息
type NetworkRequest struct {
	URL        string            `json:"url"`
	Method     string            `json:"method"`
	Headers    map[string]string `json:"headers"`
	PostData   string            `json:"post_data"`
	StatusCode int               `json:"status_code"`
	ResponseSize int64           `json:"response_size"`
	Duration   time.Duration     `json:"duration"`
	Timestamp  time.Time         `json:"timestamp"`
	ResourceType string          `json:"resource_type"`
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

// Cookie Cookie信息
type Cookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	Expires  int64  `json:"expires"`
	HttpOnly bool   `json:"http_only"`
	Secure   bool   `json:"secure"`
	SameSite string `json:"same_site"`
}

// PerformanceMetrics 性能指标
type PerformanceMetrics struct {
	LoadTime             time.Duration `json:"load_time"`
	DOMContentLoaded     time.Duration `json:"dom_content_loaded"`
	FirstPaint           time.Duration `json:"first_paint"`
	FirstContentfulPaint time.Duration `json:"first_contentful_paint"`
	LargestContentfulPaint time.Duration `json:"largest_contentful_paint"`
	CumulativeLayoutShift float64      `json:"cumulative_layout_shift"`
	FirstInputDelay      time.Duration `json:"first_input_delay"`
	TotalBlockingTime    time.Duration `json:"total_blocking_time"`
	ResourceCount        int           `json:"resource_count"`
	JSHeapUsed          int64         `json:"js_heap_used"`
	JSHeapTotal         int64         `json:"js_heap_total"`
}

// DynamicCrawlerConfig 动态爬虫配置
type DynamicCrawlerConfig struct {
	Headless           bool          `json:"headless"`
	BrowserType        string        `json:"browser_type"`        // chromium, firefox, webkit
	MaxInstances       int           `json:"max_instances"`
	PageTimeout        time.Duration `json:"page_timeout"`
	NavigationTimeout  time.Duration `json:"navigation_timeout"`
	WaitTime           time.Duration `json:"wait_time"`
	EnableJavaScript   bool          `json:"enable_javascript"`
	EnableImages       bool          `json:"enable_images"`
	EnableCSS          bool          `json:"enable_css"`
	ViewportWidth      int           `json:"viewport_width"`
	ViewportHeight     int           `json:"viewport_height"`
	UserAgent          string        `json:"user_agent"`
	Proxy              string        `json:"proxy"`
	EnableScreenshots  bool          `json:"enable_screenshots"`
	EnableNetworkLogs  bool          `json:"enable_network_logs"`
	EnableConsoleLogs  bool          `json:"enable_console_logs"`
	EnablePerformance  bool          `json:"enable_performance"`
	BlockResources     []string      `json:"block_resources"`     // 阻止加载的资源类型
	ExtraHeaders       map[string]string `json:"extra_headers"`
	IgnoreHTTPSErrors  bool          `json:"ignore_https_errors"`
	SlowMo             time.Duration `json:"slow_mo"`             // 操作间延迟
}

// DefaultDynamicCrawlerConfig 默认配置
func DefaultDynamicCrawlerConfig() DynamicCrawlerConfig {
	return DynamicCrawlerConfig{
		Headless:           true,
		BrowserType:        "chromium",
		MaxInstances:       5,
		PageTimeout:        30 * time.Second,
		NavigationTimeout:  15 * time.Second,
		WaitTime:           2 * time.Second,
		EnableJavaScript:   true,
		EnableImages:       false,
		EnableCSS:          true,
		ViewportWidth:      1920,
		ViewportHeight:     1080,
		EnableScreenshots:  false,
		EnableNetworkLogs:  true,
		EnableConsoleLogs:  true,
		EnablePerformance:  true,
		BlockResources:     []string{"image", "font", "media"},
		IgnoreHTTPSErrors:  true,
		SlowMo:            0,
	}
}

// DynamicCrawler 负责使用无头浏览器动态爬取网页。
type DynamicCrawler struct {
	config    DynamicCrawlerConfig
	pw        *playwright.Playwright
	browser   playwright.Browser
	instances chan *BrowserInstance
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.RWMutex
	stats     *CrawlerStats
}

// BrowserInstance 浏览器实例
type BrowserInstance struct {
	ID       string
	Context  playwright.BrowserContext
	InUse    bool
	LastUsed time.Time
	mu       sync.Mutex
}

// CrawlerStats 爬虫统计信息
type CrawlerStats struct {
	mu              sync.RWMutex
	StartTime       time.Time
	TotalRequests   int64
	SuccessRequests int64
	FailedRequests  int64
	TotalLoadTime   time.Duration
	AverageLoadTime time.Duration
	Errors          []error
}

// NewDynamicCrawler 创建并初始化一个新的DynamicCrawler实例。
func NewDynamicCrawler(config DynamicCrawlerConfig) (*DynamicCrawler, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	dc := &DynamicCrawler{
		config:    config,
		instances: make(chan *BrowserInstance, config.MaxInstances),
		ctx:       ctx,
		cancel:    cancel,
		stats: &CrawlerStats{
			StartTime: time.Now(),
		},
	}

	if err := dc.initialize(); err != nil {
		cancel()
		return nil, fmt.Errorf("初始化动态爬虫失败: %w", err)
	}

	return dc, nil
}

// initialize 初始化Playwright和浏览器实例池
func (dc *DynamicCrawler) initialize() error {
	// 启动Playwright
	pw, err := playwright.Run()
	if err != nil {
		return fmt.Errorf("无法启动Playwright: %w", err)
	}
	dc.pw = pw

	// 选择浏览器类型
	var browserType playwright.BrowserType
	switch dc.config.BrowserType {
	case "firefox":
		browserType = pw.Firefox
	case "webkit":
		browserType = pw.WebKit
	default:
		browserType = pw.Chromium
	}

	// 配置浏览器启动选项
	launchOptions := playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(dc.config.Headless),
		SlowMo:   playwright.Float(float64(dc.config.SlowMo.Milliseconds())),
	}

	// 设置代理
	if dc.config.Proxy != "" {
		launchOptions.Proxy = &playwright.Proxy{Server: dc.config.Proxy}
	}

	// 启动浏览器
	browser, err := browserType.Launch(launchOptions)
	if err != nil {
		dc.pw.Stop()
		return fmt.Errorf("无法启动浏览器: %w", err)
	}
	dc.browser = browser

	// 初始化浏览器实例池
	go dc.initializeBrowserPool()

	log.Info().
		Str("browser_type", dc.config.BrowserType).
		Int("max_instances", dc.config.MaxInstances).
		Bool("headless", dc.config.Headless).
		Msg("动态爬虫初始化完成")

	return nil
}

// initializeBrowserPool 初始化浏览器实例池
func (dc *DynamicCrawler) initializeBrowserPool() {
	for i := 0; i < dc.config.MaxInstances; i++ {
		instance, err := dc.createBrowserInstance(fmt.Sprintf("instance-%d", i))
		if err != nil {
			log.Error().Err(err).Int("instance", i).Msg("创建浏览器实例失败")
			continue
		}
		
		dc.instances <- instance
	}
	
	log.Info().Int("instances", dc.config.MaxInstances).Msg("浏览器实例池初始化完成")
}

// createBrowserInstance 创建浏览器实例
func (dc *DynamicCrawler) createBrowserInstance(id string) (*BrowserInstance, error) {
	// 配置浏览器上下文选项
	contextOptions := playwright.BrowserNewContextOptions{
		Viewport: &playwright.Size{
			Width:  dc.config.ViewportWidth,
			Height: dc.config.ViewportHeight,
		},
		UserAgent:         playwright.String(dc.config.UserAgent),
		JavaScriptEnabled: playwright.Bool(dc.config.EnableJavaScript),
		IgnoreHTTPSErrors: playwright.Bool(dc.config.IgnoreHTTPSErrors),
	}

	// 设置额外的HTTP头
	if len(dc.config.ExtraHeaders) > 0 {
		contextOptions.ExtraHTTPHeaders = dc.config.ExtraHeaders
	}

	// 创建浏览器上下文
	context, err := dc.browser.NewContext(contextOptions)
	if err != nil {
		return nil, fmt.Errorf("创建浏览器上下文失败: %w", err)
	}

	// 配置资源阻止
	if len(dc.config.BlockResources) > 0 {
		context.Route("**/*", func(route playwright.Route) {
			request := route.Request()
			resourceType := request.ResourceType()
			
			for _, blockType := range dc.config.BlockResources {
				if resourceType == blockType {
					route.Abort()
					return
				}
			}
			
			route.Continue()
		})
	}

	instance := &BrowserInstance{
		ID:       id,
		Context:  context,
		InUse:    false,
		LastUsed: time.Now(),
	}

	return instance, nil
}

// CrawlPage 爬取单个页面
func (dc *DynamicCrawler) CrawlPage(ctx context.Context, targetURL string) (*DynamicCrawlerResult, error) {
	// 验证URL
	if _, err := url.Parse(targetURL); err != nil {
		return nil, fmt.Errorf("无效的URL: %w", err)
	}

	// 获取浏览器实例
	instance, err := dc.getBrowserInstance(ctx)
	if err != nil {
		return nil, fmt.Errorf("获取浏览器实例失败: %w", err)
	}
	defer dc.releaseBrowserInstance(instance)

	// 执行爬取
	result, err := dc.crawlWithInstance(ctx, targetURL, instance)
	if err != nil {
		dc.updateStats(false, 0)
		return result, err
	}

	dc.updateStats(true, result.LoadTime)
	return result, nil
}

// getBrowserInstance 获取可用的浏览器实例
func (dc *DynamicCrawler) getBrowserInstance(ctx context.Context) (*BrowserInstance, error) {
	select {
	case instance := <-dc.instances:
		instance.mu.Lock()
		instance.InUse = true
		instance.LastUsed = time.Now()
		instance.mu.Unlock()
		return instance, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("获取浏览器实例超时")
	}
}

// releaseBrowserInstance 释放浏览器实例
func (dc *DynamicCrawler) releaseBrowserInstance(instance *BrowserInstance) {
	instance.mu.Lock()
	instance.InUse = false
	instance.LastUsed = time.Now()
	instance.mu.Unlock()
	
	// 将实例放回池中
	select {
	case dc.instances <- instance:
	default:
		// 池已满，关闭实例
		log.Warn().Str("instance_id", instance.ID).Msg("实例池已满，关闭实例")
		instance.Context.Close()
	}
}

// crawlWithInstance 使用指定实例执行爬取
func (dc *DynamicCrawler) crawlWithInstance(ctx context.Context, targetURL string, instance *BrowserInstance) (*DynamicCrawlerResult, error) {
	startTime := time.Now()
	
	result := &DynamicCrawlerResult{
		URL:             targetURL,
		Timestamp:       startTime,
		NetworkRequests: make([]NetworkRequest, 0),
		ConsoleLogs:     make([]ConsoleLog, 0),
		JSErrors:        make([]JSError, 0),
		Screenshots:     make([]Screenshot, 0),
		Cookies:         make([]Cookie, 0),
		LocalStorage:    make(map[string]string),
		SessionStorage:  make(map[string]string),
	}

	// 创建页面
	page, err := instance.Context.NewPage()
	if err != nil {
		result.Error = fmt.Errorf("创建页面失败: %w", err)
		return result, err
	}
	defer page.Close()

	// 设置页面超时
	page.SetDefaultTimeout(float64(dc.config.PageTimeout.Milliseconds()))
	page.SetDefaultNavigationTimeout(float64(dc.config.NavigationTimeout.Milliseconds()))

	// 设置事件监听器
	dc.setupEventListeners(page, result)

	// 导航到目标URL
	response, err := page.Goto(targetURL, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateNetworkidle,
		Timeout:   playwright.Float(float64(dc.config.NavigationTimeout.Milliseconds())),
	})

	if err != nil {
		result.Error = fmt.Errorf("导航到URL失败: %w", err)
		return result, err
	}

	if response != nil {
		result.StatusCode = response.Status()
	}

	// 等待页面完全加载
	if dc.config.WaitTime > 0 {
		page.WaitForTimeout(float64(dc.config.WaitTime.Milliseconds()))
	}

	// 获取页面标题
	if title, err := page.Title(); err == nil {
		result.Title = title
	}

	// 获取渲染后的HTML
	if html, err := page.Content(); err == nil {
		result.RenderedHTML = html
	} else {
		result.Error = fmt.Errorf("获取页面内容失败: %w", err)
		return result, err
	}

	// 获取性能指标
	if dc.config.EnablePerformance {
		dc.collectPerformanceMetrics(page, result)
	}

	// 获取存储数据
	dc.collectStorageData(page, result)

	// 获取Cookies
	dc.collectCookies(page, result)

	// 截图
	if dc.config.EnableScreenshots {
		dc.takeScreenshot(page, result)
	}

	result.LoadTime = time.Since(startTime)

	log.Debug().
		Str("url", targetURL).
		Str("instance_id", instance.ID).
		Dur("load_time", result.LoadTime).
		Int("status_code", result.StatusCode).
		Int("network_requests", len(result.NetworkRequests)).
		Int("console_logs", len(result.ConsoleLogs)).
		Int("js_errors", len(result.JSErrors)).
		Msg("页面爬取完成")

	return result, nil
}

// setupEventListeners 设置事件监听器
func (dc *DynamicCrawler) setupEventListeners(page playwright.Page, result *DynamicCrawlerResult) {
	// 网络请求监听
	if dc.config.EnableNetworkLogs {
		page.OnRequest(func(request playwright.Request) {
			result.NetworkRequests = append(result.NetworkRequests, NetworkRequest{
				URL:          request.URL(),
				Method:       request.Method(),
				Headers:      request.Headers(),
				PostData:     request.PostData(),
				Timestamp:    time.Now(),
				ResourceType: request.ResourceType(),
			})
		})

		page.OnResponse(func(response playwright.Response) {
			// 更新对应的请求信息
			for i := range result.NetworkRequests {
				if result.NetworkRequests[i].URL == response.URL() {
					result.NetworkRequests[i].StatusCode = response.Status()
					if headers := response.Headers(); len(headers) > 0 {
						if contentLength, ok := headers["content-length"]; ok {
							// 解析content-length
							_ = contentLength
						}
					}
					break
				}
			}
		})
	}

	// 控制台日志监听
	if dc.config.EnableConsoleLogs {
		page.OnConsole(func(msg playwright.ConsoleMessage) {
			result.ConsoleLogs = append(result.ConsoleLogs, ConsoleLog{
				Level:     msg.Type(),
				Text:      msg.Text(),
				Timestamp: time.Now(),
			})
		})
	}

	// JavaScript错误监听
	page.OnPageError(func(err error) {
		result.JSErrors = append(result.JSErrors, JSError{
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
	})
}

// collectPerformanceMetrics 收集性能指标
func (dc *DynamicCrawler) collectPerformanceMetrics(page playwright.Page, result *DynamicCrawlerResult) {
	// 执行JavaScript获取性能数据
	performanceData, err := page.Evaluate(`() => {
		const navigation = performance.getEntriesByType('navigation')[0];
		const paint = performance.getEntriesByType('paint');
		const memory = performance.memory || {};
		
		return {
			loadTime: navigation ? navigation.loadEventEnd - navigation.fetchStart : 0,
			domContentLoaded: navigation ? navigation.domContentLoadedEventEnd - navigation.fetchStart : 0,
			firstPaint: paint.find(p => p.name === 'first-paint')?.startTime || 0,
			firstContentfulPaint: paint.find(p => p.name === 'first-contentful-paint')?.startTime || 0,
			jsHeapUsed: memory.usedJSHeapSize || 0,
			jsHeapTotal: memory.totalJSHeapSize || 0,
			resourceCount: performance.getEntriesByType('resource').length
		};
	}`)

	if err == nil {
		if data, ok := performanceData.(map[string]interface{}); ok {
			metrics := &PerformanceMetrics{}
			
			if loadTime, ok := data["loadTime"].(float64); ok {
				metrics.LoadTime = time.Duration(loadTime) * time.Millisecond
			}
			if domContentLoaded, ok := data["domContentLoaded"].(float64); ok {
				metrics.DOMContentLoaded = time.Duration(domContentLoaded) * time.Millisecond
			}
			if firstPaint, ok := data["firstPaint"].(float64); ok {
				metrics.FirstPaint = time.Duration(firstPaint) * time.Millisecond
			}
			if firstContentfulPaint, ok := data["firstContentfulPaint"].(float64); ok {
				metrics.FirstContentfulPaint = time.Duration(firstContentfulPaint) * time.Millisecond
			}
			if jsHeapUsed, ok := data["jsHeapUsed"].(float64); ok {
				metrics.JSHeapUsed = int64(jsHeapUsed)
			}
			if jsHeapTotal, ok := data["jsHeapTotal"].(float64); ok {
				metrics.JSHeapTotal = int64(jsHeapTotal)
			}
			if resourceCount, ok := data["resourceCount"].(float64); ok {
				metrics.ResourceCount = int(resourceCount)
			}
			
			result.PerformanceMetrics = metrics
		}
	}
}

// collectStorageData 收集存储数据
func (dc *DynamicCrawler) collectStorageData(page playwright.Page, result *DynamicCrawlerResult) {
	// 获取localStorage
	localStorage, err := page.Evaluate(`() => {
		const data = {};
		for (let i = 0; i < localStorage.length; i++) {
			const key = localStorage.key(i);
			data[key] = localStorage.getItem(key);
		}
		return data;
	}`)
	
	if err == nil {
		if data, ok := localStorage.(map[string]interface{}); ok {
			for key, value := range data {
				if strValue, ok := value.(string); ok {
					result.LocalStorage[key] = strValue
				}
			}
		}
	}

	// 获取sessionStorage
	sessionStorage, err := page.Evaluate(`() => {
		const data = {};
		for (let i = 0; i < sessionStorage.length; i++) {
			const key = sessionStorage.key(i);
			data[key] = sessionStorage.getItem(key);
		}
		return data;
	}`)
	
	if err == nil {
		if data, ok := sessionStorage.(map[string]interface{}); ok {
			for key, value := range data {
				if strValue, ok := value.(string); ok {
					result.SessionStorage[key] = strValue
				}
			}
		}
	}
}

// collectCookies 收集Cookies
func (dc *DynamicCrawler) collectCookies(page playwright.Page, result *DynamicCrawlerResult) {
	cookies, err := page.Context().Cookies()
	if err == nil {
		for _, cookie := range cookies {
			result.Cookies = append(result.Cookies, Cookie{
				Name:     cookie.Name,
				Value:    cookie.Value,
				Domain:   cookie.Domain,
				Path:     cookie.Path,
				Expires:  int64(cookie.Expires),
				HttpOnly: cookie.HttpOnly,
				Secure:   cookie.Secure,
				SameSite: cookie.SameSite,
			})
		}
	}
}

// takeScreenshot 截图
func (dc *DynamicCrawler) takeScreenshot(page playwright.Page, result *DynamicCrawlerResult) {
	screenshot, err := page.Screenshot(playwright.PageScreenshotOptions{
		FullPage: playwright.Bool(true),
		Type:     playwright.ScreenshotTypePng,
	})
	
	if err == nil {
		result.Screenshots = append(result.Screenshots, Screenshot{
			Data:      screenshot,
			Format:    "png",
			Width:     dc.config.ViewportWidth,
			Height:    dc.config.ViewportHeight,
			Timestamp: time.Now(),
		})
	}
}

// updateStats 更新统计信息
func (dc *DynamicCrawler) updateStats(success bool, loadTime time.Duration) {
	dc.stats.mu.Lock()
	defer dc.stats.mu.Unlock()
	
	dc.stats.TotalRequests++
	if success {
		dc.stats.SuccessRequests++
		dc.stats.TotalLoadTime += loadTime
		dc.stats.AverageLoadTime = dc.stats.TotalLoadTime / time.Duration(dc.stats.SuccessRequests)
	} else {
		dc.stats.FailedRequests++
	}
}

// GetStats 获取统计信息
func (dc *DynamicCrawler) GetStats() *CrawlerStats {
	dc.stats.mu.RLock()
	defer dc.stats.mu.RUnlock()
	
	// 返回副本
	statsCopy := &CrawlerStats{
		StartTime:       dc.stats.StartTime,
		TotalRequests:   dc.stats.TotalRequests,
		SuccessRequests: dc.stats.SuccessRequests,
		FailedRequests:  dc.stats.FailedRequests,
		TotalLoadTime:   dc.stats.TotalLoadTime,
		AverageLoadTime: dc.stats.AverageLoadTime,
		Errors:          make([]error, len(dc.stats.Errors)),
	}
	
	copy(statsCopy.Errors, dc.stats.Errors)
	return statsCopy
}

// CrawlBatch 批量爬取多个URL
func (dc *DynamicCrawler) CrawlBatch(ctx context.Context, urls []string) (map[string]*DynamicCrawlerResult, error) {
	if len(urls) == 0 {
		return nil, fmt.Errorf("URL列表为空")
	}

	results := make(map[string]*DynamicCrawlerResult)
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	// 限制并发数
	semaphore := make(chan struct{}, dc.config.MaxInstances)
	
	for _, url := range urls {
		wg.Add(1)
		go func(crawlURL string) {
			defer wg.Done()
			
			// 获取信号量
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			result, err := dc.CrawlPage(ctx, crawlURL)
			if err != nil {
				log.Error().Str("url", crawlURL).Err(err).Msg("批量爬取失败")
				result = &DynamicCrawlerResult{
					URL:       crawlURL,
					Error:     err,
					Timestamp: time.Now(),
				}
			}
			
			mu.Lock()
			results[crawlURL] = result
			mu.Unlock()
		}(url)
	}
	
	wg.Wait()
	
	log.Info().
		Int("total_urls", len(urls)).
		Int("results", len(results)).
		Msg("批量爬取完成")
	
	return results, nil
}

// Close 关闭浏览器和Playwright实例，释放资源。
func (dc *DynamicCrawler) Close() error {
	log.Info().Msg("正在关闭动态爬虫...")
	
	// 取消上下文
	if dc.cancel != nil {
		dc.cancel()
	}
	
	// 关闭所有浏览器实例
	if dc.instances != nil {
		close(dc.instances)
		for instance := range dc.instances {
			if instance.Context != nil {
				instance.Context.Close()
			}
		}
	}
	
	// 关闭浏览器
	if dc.browser != nil {
		if err := dc.browser.Close(); err != nil {
			log.Error().Err(err).Msg("关闭浏览器失败")
		}
	}
	
	// 停止Playwright
	if dc.pw != nil {
		if err := dc.pw.Stop(); err != nil {
			log.Error().Err(err).Msg("停止Playwright失败")
		}
	}
	
	log.Info().Msg("动态爬虫已关闭")
	return nil
}

// HealthCheck 健康检查
func (dc *DynamicCrawler) HealthCheck() map[string]interface{} {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	
	stats := dc.GetStats()
	
	health := map[string]interface{}{
		"status":           "healthy",
		"timestamp":        time.Now(),
		"uptime":          time.Since(stats.StartTime).String(),
		"total_requests":  stats.TotalRequests,
		"success_rate":    float64(stats.SuccessRequests) / float64(stats.TotalRequests) * 100,
		"average_load_time": stats.AverageLoadTime.String(),
		"available_instances": len(dc.instances),
	}
	
	// 检查成功率
	if stats.TotalRequests > 0 {
		successRate := float64(stats.SuccessRequests) / float64(stats.TotalRequests)
		if successRate < 0.5 {
			health["status"] = "unhealthy"
			health["reason"] = "成功率过低"
		} else if successRate < 0.8 {
			health["status"] = "warning"
			health["reason"] = "成功率较低"
		}
	}
	
	// 检查实例可用性
	if len(dc.instances) == 0 {
		health["status"] = "unhealthy"
		health["reason"] = "没有可用的浏览器实例"
	}
	
	return health
}

// WaitForElement 等待元素出现
func (dc *DynamicCrawler) WaitForElement(page playwright.Page, selector string, timeout time.Duration) error {
	return page.WaitForSelector(selector, playwright.PageWaitForSelectorOptions{
		Timeout: playwright.Float(float64(timeout.Milliseconds())),
	})
}

// ExecuteScript 执行JavaScript脚本
func (dc *DynamicCrawler) ExecuteScript(page playwright.Page, script string) (interface{}, error) {
	return page.Evaluate(script)
}

// FillForm 填写表单
func (dc *DynamicCrawler) FillForm(page playwright.Page, formData map[string]string) error {
	for selector, value := range formData {
		if err := page.Fill(selector, value); err != nil {
			return fmt.Errorf("填写表单字段 %s 失败: %w", selector, err)
		}
	}
	return nil
}

// ClickElement 点击元素
func (dc *DynamicCrawler) ClickElement(page playwright.Page, selector string) error {
	return page.Click(selector)
}

// ScrollToBottom 滚动到页面底部
func (dc *DynamicCrawler) ScrollToBottom(page playwright.Page) error {
	_, err := page.Evaluate(`() => {
		window.scrollTo(0, document.body.scrollHeight);
	}`)
	return err
}

// GetElementText 获取元素文本
func (dc *DynamicCrawler) GetElementText(page playwright.Page, selector string) (string, error) {
	element, err := page.QuerySelector(selector)
	if err != nil {
		return "", err
	}
	if element == nil {
		return "", fmt.Errorf("元素未找到: %s", selector)
	}
	return element.TextContent()
}

// GetElementAttribute 获取元素属性
func (dc *DynamicCrawler) GetElementAttribute(page playwright.Page, selector, attribute string) (string, error) {
	element, err := page.QuerySelector(selector)
	if err != nil {
		return "", err
	}
	if element == nil {
		return "", fmt.Errorf("元素未找到: %s", selector)
	}
	return element.GetAttribute(attribute)
}

// CrawlWithActions 执行自定义动作的爬取
func (dc *DynamicCrawler) CrawlWithActions(ctx context.Context, targetURL string, actions []PageAction) (*DynamicCrawlerResult, error) {
	// 获取浏览器实例
	instance, err := dc.getBrowserInstance(ctx)
	if err != nil {
		return nil, fmt.Errorf("获取浏览器实例失败: %w", err)
	}
	defer dc.releaseBrowserInstance(instance)

	// 创建页面
	page, err := instance.Context.NewPage()
	if err != nil {
		return nil, fmt.Errorf("创建页面失败: %w", err)
	}
	defer page.Close()

	// 设置页面超时
	page.SetDefaultTimeout(float64(dc.config.PageTimeout.Milliseconds()))
	page.SetDefaultNavigationTimeout(float64(dc.config.NavigationTimeout.Milliseconds()))

	startTime := time.Now()
	result := &DynamicCrawlerResult{
		URL:             targetURL,
		Timestamp:       startTime,
		NetworkRequests: make([]NetworkRequest, 0),
		ConsoleLogs:     make([]ConsoleLog, 0),
		JSErrors:        make([]JSError, 0),
		Screenshots:     make([]Screenshot, 0),
		Cookies:         make([]Cookie, 0),
		LocalStorage:    make(map[string]string),
		SessionStorage:  make(map[string]string),
	}

	// 设置事件监听器
	dc.setupEventListeners(page, result)

	// 导航到目标URL
	response, err := page.Goto(targetURL, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateNetworkidle,
		Timeout:   playwright.Float(float64(dc.config.NavigationTimeout.Milliseconds())),
	})

	if err != nil {
		result.Error = fmt.Errorf("导航到URL失败: %w", err)
		return result, err
	}

	if response != nil {
		result.StatusCode = response.Status()
	}

	// 执行自定义动作
	for i, action := range actions {
		log.Debug().
			Str("url", targetURL).
			Int("action_index", i).
			Str("action_type", string(action.Type)).
			Msg("执行页面动作")

		if err := dc.executePageAction(page, action); err != nil {
			log.Error().
				Str("url", targetURL).
				Int("action_index", i).
				Str("action_type", string(action.Type)).
				Err(err).
				Msg("执行页面动作失败")
			
			// 根据配置决定是否继续执行后续动作
			if action.StopOnError {
				result.Error = fmt.Errorf("执行动作 %d 失败: %w", i, err)
				return result, err
			}
		}

		// 动作间延迟
		if action.Delay > 0 {
			time.Sleep(action.Delay)
		}
	}

	// 获取最终的页面内容
	if html, err := page.Content(); err == nil {
		result.RenderedHTML = html
	} else {
		result.Error = fmt.Errorf("获取页面内容失败: %w", err)
		return result, err
	}

	// 获取页面标题
	if title, err := page.Title(); err == nil {
		result.Title = title
	}

	// 收集其他数据
	if dc.config.EnablePerformance {
		dc.collectPerformanceMetrics(page, result)
	}
	dc.collectStorageData(page, result)
	dc.collectCookies(page, result)
	if dc.config.EnableScreenshots {
		dc.takeScreenshot(page, result)
	}

	result.LoadTime = time.Since(startTime)
	dc.updateStats(true, result.LoadTime)

	return result, nil
}

// PageActionType 页面动作类型
type PageActionType string

const (
	ActionClick       PageActionType = "click"
	ActionFill        PageActionType = "fill"
	ActionWait        PageActionType = "wait"
	ActionScroll      PageActionType = "scroll"
	ActionScreenshot  PageActionType = "screenshot"
	ActionExecuteJS   PageActionType = "execute_js"
	ActionWaitForElement PageActionType = "wait_for_element"
	ActionHover       PageActionType = "hover"
	ActionSelect      PageActionType = "select"
	ActionUpload      PageActionType = "upload"
)

// PageAction 页面动作
type PageAction struct {
	Type        PageActionType    `json:"type"`
	Selector    string           `json:"selector,omitempty"`
	Value       string           `json:"value,omitempty"`
	Script      string           `json:"script,omitempty"`
	Timeout     time.Duration    `json:"timeout,omitempty"`
	Delay       time.Duration    `json:"delay,omitempty"`
	StopOnError bool             `json:"stop_on_error"`
	Options     map[string]interface{} `json:"options,omitempty"`
}

// executePageAction 执行页面动作
func (dc *DynamicCrawler) executePageAction(page playwright.Page, action PageAction) error {
	switch action.Type {
	case ActionClick:
		return page.Click(action.Selector)
		
	case ActionFill:
		return page.Fill(action.Selector, action.Value)
		
	case ActionWait:
		if action.Timeout > 0 {
			page.WaitForTimeout(float64(action.Timeout.Milliseconds()))
		} else {
			page.WaitForTimeout(1000) // 默认等待1秒
		}
		return nil
		
	case ActionScroll:
		if action.Selector != "" {
			return page.ScrollIntoViewIfNeeded(action.Selector)
		} else {
			// 滚动到底部
			_, err := page.Evaluate(`() => window.scrollTo(0, document.body.scrollHeight)`)
			return err
		}
		
	case ActionScreenshot:
		screenshot, err := page.Screenshot(playwright.PageScreenshotOptions{
			FullPage: playwright.Bool(true),
			Type:     playwright.ScreenshotTypePng,
		})
		if err == nil {
			// 这里可以保存截图或添加到结果中
			log.Debug().Int("screenshot_size", len(screenshot)).Msg("截图完成")
		}
		return err
		
	case ActionExecuteJS:
		_, err := page.Evaluate(action.Script)
		return err
		
	case ActionWaitForElement:
		timeout := action.Timeout
		if timeout == 0 {
			timeout = 10 * time.Second
		}
		return page.WaitForSelector(action.Selector, playwright.PageWaitForSelectorOptions{
			Timeout: playwright.Float(float64(timeout.Milliseconds())),
		})
		
	case ActionHover:
		return page.Hover(action.Selector)
		
	case ActionSelect:
		_, err := page.SelectOption(action.Selector, playwright.SelectOptionValues{
			Values: &[]string{action.Value},
		})
		return err
		
	case ActionUpload:
		return page.SetInputFiles(action.Selector, action.Value)
		
	default:
		return fmt.Errorf("未知的动作类型: %s", action.Type)
	}
}

// CrawlerPool 爬虫池管理
type CrawlerPool struct {
	crawlers []*DynamicCrawler
	current  int
	mu       sync.Mutex
	config   DynamicCrawlerConfig
}

// NewCrawlerPool 创建爬虫池
func NewCrawlerPool(size int, config DynamicCrawlerConfig) (*CrawlerPool, error) {
	pool := &CrawlerPool{
		crawlers: make([]*DynamicCrawler, 0, size),
		config:   config,
	}

	// 创建爬虫实例
	for i := 0; i < size; i++ {
		crawler, err := NewDynamicCrawler(config)
		if err != nil {
			// 清理已创建的爬虫
			for _, c := range pool.crawlers {
				c.Close()
			}
			return nil, fmt.Errorf("创建爬虫实例 %d 失败: %w", i, err)
		}
		pool.crawlers = append(pool.crawlers, crawler)
	}

	log.Info().Int("pool_size", size).Msg("爬虫池创建完成")
	return pool, nil
}

// GetCrawler 获取爬虫实例（轮询）
func (cp *CrawlerPool) GetCrawler() *DynamicCrawler {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	
	crawler := cp.crawlers[cp.current]
	cp.current = (cp.current + 1) % len(cp.crawlers)
	return crawler
}

// GetAllCrawlers 获取所有爬虫实例
func (cp *CrawlerPool) GetAllCrawlers() []*DynamicCrawler {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	
	// 返回副本
	crawlers := make([]*DynamicCrawler, len(cp.crawlers))
	copy(crawlers, cp.crawlers)
	return crawlers
}

// Close 关闭爬虫池
func (cp *CrawlerPool) Close() error {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	
	var errors []error
	for i, crawler := range cp.crawlers {
		if err := crawler.Close(); err != nil {
			errors = append(errors, fmt.Errorf("关闭爬虫 %d 失败: %w", i, err))
		}
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("关闭爬虫池时发生错误: %v", errors)
	}
	
	log.Info().Msg("爬虫池已关闭")
	return nil
}

// GetPoolStats 获取池统计信息
func (cp *CrawlerPool) GetPoolStats() map[string]interface{} {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	
	stats := map[string]interface{}{
		"pool_size":     len(cp.crawlers),
		"current_index": cp.current,
		"crawlers":      make([]map[string]interface{}, 0, len(cp.crawlers)),
	}
	
	var totalRequests, totalSuccess, totalFailed int64
	var totalLoadTime time.Duration
	
	for i, crawler := range cp.crawlers {
		crawlerStats := crawler.GetStats()
		crawlerInfo := map[string]interface{}{
			"index":           i,
			"total_requests":  crawlerStats.TotalRequests,
			"success_requests": crawlerStats.SuccessRequests,
			"failed_requests":  crawlerStats.FailedRequests,
			"average_load_time": crawlerStats.AverageLoadTime.String(),
			"uptime":          time.Since(crawlerStats.StartTime).String(),
		}
		
		stats["crawlers"] = append(stats["crawlers"].([]map[string]interface{}), crawlerInfo)
		
		totalRequests += crawlerStats.TotalRequests
		totalSuccess += crawlerStats.SuccessRequests
		totalFailed += crawlerStats.FailedRequests
		totalLoadTime += crawlerStats.TotalLoadTime
	}
	
	stats["total_requests"] = totalRequests
	stats["total_success"] = totalSuccess
	stats["total_failed"] = totalFailed
	
	if totalSuccess > 0 {
		stats["average_load_time"] = (totalLoadTime / time.Duration(totalSuccess)).String()
		stats["success_rate"] = float64(totalSuccess) / float64(totalRequests) * 100
	}
	
	return stats
}

// CrawlWithPool 使用池进行爬取
func (cp *CrawlerPool) CrawlWithPool(ctx context.Context, urls []string) (map[string]*DynamicCrawlerResult, error) {
	if len(urls) == 0 {
		return nil, fmt.Errorf("URL列表为空")
	}

	results := make(map[string]*DynamicCrawlerResult)
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	// 使用通道控制并发
	urlChan := make(chan string, len(urls))
	for _, url := range urls {
		urlChan <- url
	}
	close(urlChan)
	
	// 启动工作协程
	numWorkers := len(cp.crawlers)
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			
			crawler := cp.crawlers[workerID]
			
			for url := range urlChan {
				select {
				case <-ctx.Done():
					return
				default:
					result, err := crawler.CrawlPage(ctx, url)
					if err != nil {
						log.Error().
							Str("url", url).
							Int("worker_id", workerID).
							Err(err).
							Msg("池爬取失败")
						
						result = &DynamicCrawlerResult{
							URL:       url,
							Error:     err,
							Timestamp: time.Now(),
						}
					}
					
					mu.Lock()
					results[url] = result
					mu.Unlock()
				}
			}
		}(i)
	}
	
	wg.Wait()
	
	log.Info().
		Int("total_urls", len(urls)).
		Int("results", len(results)).
		Int("workers", numWorkers).
		Msg("池批量爬取完成")
	
	return results, nil
}

// SaveResultToFile 保存结果到文件
func SaveResultToFile(result *DynamicCrawlerResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建文件失败: %w", err)
	}
	defer file.Close()
	
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	
	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("编码JSON失败: %w", err)
	}
	
	return nil
}

// LoadResultFromFile 从文件加载结果
func LoadResultFromFile(filename string) (*DynamicCrawlerResult, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %w", err)
	}
	defer file.Close()
	
	var result DynamicCrawlerResult
	decoder := json.NewDecoder(file)
	
	if err := decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("解码JSON失败: %w", err)
	}
	
	return &result, nil
}
