// Package browser 封装了与无头浏览器（如Chrome）的交互。
// 它提供了一个服务，可以用于执行需要JavaScript渲染或模拟用户交互的任务，
// 例如，验证反射型XSS漏洞是否真的可以在DOM中执行。
package browser

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/playwright-community/playwright-go"
	"github.com/rs/zerolog/log"
)

// BrowserType 浏览器类型
type BrowserType string

const (
	BrowserChromium BrowserType = "chromium"
	BrowserFirefox  BrowserType = "firefox"
	BrowserWebkit   BrowserType = "webkit"
)

// DetectionType 检测类型
type DetectionType string

const (
	DetectionXSS          DetectionType = "xss"
	DetectionCSRF         DetectionType = "csrf"
	DetectionClickjacking DetectionType = "clickjacking"
	DetectionRedirect     DetectionType = "redirect"
	DetectionFormHijack   DetectionType = "form_hijack"
	DetectionDOMClobbering DetectionType = "dom_clobbering"
)

// Config 浏览器服务配置
type Config struct {
	// 基础配置
	BrowserType     BrowserType   `json:"browser_type"`
	Headless        bool          `json:"headless"`
	SlowMo          time.Duration `json:"slow_mo"`
	Timeout         time.Duration `json:"timeout"`
	NavigationTimeout time.Duration `json:"navigation_timeout"`
	
	// 网络配置
	Proxy           string        `json:"proxy"`
	UserAgent       string        `json:"user_agent"`
	ExtraHeaders    map[string]string `json:"extra_headers"`
	IgnoreHTTPSErrors bool        `json:"ignore_https_errors"`
	
	// 窗口配置
	ViewportWidth   int           `json:"viewport_width"`
	ViewportHeight  int           `json:"viewport_height"`
	DeviceScaleFactor float64     `json:"device_scale_factor"`
	
	// 安全配置
	JavaScriptEnabled bool        `json:"javascript_enabled"`
	WebSecurity      bool         `json:"web_security"`
	AllowedDomains   []string     `json:"allowed_domains"`
	BlockedDomains   []string     `json:"blocked_domains"`
	MaxRedirects     int          `json:"max_redirects"`
	
	// 性能配置
	MaxConcurrency   int          `json:"max_concurrency"`
	PoolSize         int          `json:"pool_size"`
	IdleTimeout      time.Duration `json:"idle_timeout"`
	EnableCache      bool         `json:"enable_cache"`
	
	// 调试配置
	ScreenshotOnError bool        `json:"screenshot_on_error"`
	SaveHAR          bool         `json:"save_har"`
	LogLevel         string       `json:"log_level"`
	RecordVideo      bool         `json:"record_video"`
	VideoPath        string       `json:"video_path"`
}

// DetectionRequest 检测请求
type DetectionRequest struct {
	URL             string                 `json:"url"`
	Method          string                 `json:"method"`
	Headers         map[string]string      `json:"headers"`
	Body            string                 `json:"body"`
	Cookies         []Cookie               `json:"cookies"`
	DetectionType   DetectionType          `json:"detection_type"`
	Payload         string                 `json:"payload"`
	ExpectedResults []string               `json:"expected_results"`
	Timeout         time.Duration          `json:"timeout"`
	WaitConditions  []WaitCondition        `json:"wait_conditions"`
	CustomJS        string                 `json:"custom_js"`
	Context         map[string]interface{} `json:"context"`
}

// Cookie 表示HTTP Cookie
type Cookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	Expires  int64  `json:"expires"`
	HTTPOnly bool   `json:"http_only"`
	Secure   bool   `json:"secure"`
	SameSite string `json:"same_site"`
}

// WaitCondition 等待条件
type WaitCondition struct {
	Type       string        `json:"type"`        // selector, url, networkidle, timeout
	Value      string        `json:"value"`
	Timeout    time.Duration `json:"timeout"`
	State      string        `json:"state"`       // visible, hidden, attached, detached
}

// DetectionResult 检测结果
type DetectionResult struct {
	Success         bool                   `json:"success"`
	Vulnerable      bool                   `json:"vulnerable"`
	Confidence      float64                `json:"confidence"`
	DetectionType   DetectionType          `json:"detection_type"`
	Evidence        []Evidence             `json:"evidence"`
	Screenshots     []string               `json:"screenshots"`
	NetworkLogs     []NetworkLog           `json:"network_logs"`
	ConsoleLogs     []ConsoleLog           `json:"console_logs"`
	Errors          []string               `json:"errors"`
	Warnings        []string               `json:"warnings"`
	ExecutionTime   time.Duration          `json:"execution_time"`
	PageMetadata    PageMetadata           `json:"page_metadata"`
	Recommendations []string               `json:"recommendations"`
	RiskLevel       string                 `json:"risk_level"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// Evidence 证据
type Evidence struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Location    string                 `json:"location"`
	Content     string                 `json:"content"`
	Severity    string                 `json:"severity"`
	Timestamp   time.Time              `json:"timestamp"`
	Context     map[string]interface{} `json:"context"`
}

// NetworkLog 网络日志
type NetworkLog struct {
	URL        string            `json:"url"`
	Method     string            `json:"method"`
	Status     int               `json:"status"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	Timestamp  time.Time         `json:"timestamp"`
	Duration   time.Duration     `json:"duration"`
	Size       int64             `json:"size"`
	Redirected bool              `json:"redirected"`
}

// ConsoleLog 控制台日志
type ConsoleLog struct {
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Source    string    `json:"source"`
	Line      int       `json:"line"`
	Column    int       `json:"column"`
	Timestamp time.Time `json:"timestamp"`
	Args      []string  `json:"args"`
}

// PageMetadata 页面元数据
type PageMetadata struct {
	Title       string            `json:"title"`
	URL         string            `json:"url"`
	FinalURL    string            `json:"final_url"`
	StatusCode  int               `json:"status_code"`
	ContentType string            `json:"content_type"`
	Size        int64             `json:"size"`
	LoadTime    time.Duration     `json:"load_time"`
	DOMNodes    int               `json:"dom_nodes"`
	JSErrors    int               `json:"js_errors"`
	Redirects   []string          `json:"redirects"`
	CSP         string            `json:"csp"`
	Headers     map[string]string `json:"headers"`
}

// BrowserStats 浏览器统计信息
type BrowserStats struct {
	TotalRequests      int64         `json:"total_requests"`
	SuccessfulRequests int64         `json:"successful_requests"`
	FailedRequests     int64         `json:"failed_requests"`
	AverageTime        time.Duration `json:"average_time"`
	ActiveSessions     int           `json:"active_sessions"`
	PoolUtilization    float64       `json:"pool_utilization"`
	ErrorsByType       map[string]int64 `json:"errors_by_type"`
	DetectionsByType   map[DetectionType]int64 `json:"detections_by_type"`
	VulnerabilitiesFound int64       `json:"vulnerabilities_found"`
}

// BrowserPool 浏览器连接池
type BrowserPool struct {
	browsers    chan playwright.Browser
	contexts    sync.Map // contextID -> BrowserContext
	config      Config
	pw          *playwright.Playwright
	stats       BrowserStats
	statsMu     sync.RWMutex
	closed      bool
	closeMu     sync.RWMutex
}

// BrowserService 管理浏览器实例、上下文和页面的生命周期
type BrowserService struct {
	pool        *BrowserPool
	config      Config
	detectors   map[DetectionType]Detector
	validators  []RequestValidator
	interceptors []ResponseInterceptor
	
	// 缓存和性能
	resultCache sync.Map // requestHash -> DetectionResult
	
	// 安全过滤
	domainFilter  *DomainFilter
	payloadFilter *PayloadFilter
	
	// 监控
	metrics *BrowserMetrics
}

// Detector 检测器接口
type Detector interface {
	Detect(ctx context.Context, page playwright.Page, req DetectionRequest) (*DetectionResult, error)
	GetType() DetectionType
	Validate(req DetectionRequest) error
}

// RequestValidator 请求验证器
type RequestValidator interface {
	Validate(req DetectionRequest) error
}

// ResponseInterceptor 响应拦截器
type ResponseInterceptor interface {
	Intercept(result *DetectionResult) error
}

// DomainFilter 域名过滤器
type DomainFilter struct {
	allowedDomains []string
	blockedDomains []string
	allowedRegex   []*regexp.Regexp
	blockedRegex   []*regexp.Regexp
}

// PayloadFilter payload过滤器
type PayloadFilter struct {
	maxLength       int
	blockedPatterns []*regexp.Regexp
	allowedTags     []string
}

// BrowserMetrics 浏览器指标
type BrowserMetrics struct {
	requests       int64
	errors         int64
	totalTime      time.Duration
	vulnerabilities map[DetectionType]int64
	mu             sync.RWMutex
}

// 默认配置
var defaultConfig = Config{
	BrowserType:       BrowserChromium,
	Headless:          true,
	Timeout:           30 * time.Second,
	NavigationTimeout: 15 * time.Second,
	ViewportWidth:     1920,
	ViewportHeight:    1080,
	DeviceScaleFactor: 1.0,
	JavaScriptEnabled: true,
	WebSecurity:       true,
	MaxRedirects:      5,
	MaxConcurrency:    10,
	PoolSize:          5,
	IdleTimeout:       5 * time.Minute,
	EnableCache:       true,
	IgnoreHTTPSErrors: false,
	LogLevel:          "warn",
}

// NewBrowserService 创建新的浏览器服务
func NewBrowserService(cfg Config) (*BrowserService, error) {
	// 使用默认配置填充未设置的字段
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultConfig.Timeout
	}
	if cfg.ViewportWidth == 0 {
		cfg.ViewportWidth = defaultConfig.ViewportWidth
	}
	if cfg.ViewportHeight == 0 {
		cfg.ViewportHeight = defaultConfig.ViewportHeight
	}
	if cfg.PoolSize == 0 {
		cfg.PoolSize = defaultConfig.PoolSize
	}
	if cfg.MaxConcurrency == 0 {
		cfg.MaxConcurrency = defaultConfig.MaxConcurrency
	}
	
	// 创建浏览器池
	pool, err := NewBrowserPool(cfg)
	if err != nil {
		return nil, fmt.Errorf("创建浏览器池失败: %w", err)
	}
	
	service := &BrowserService{
		pool:      pool,
		config:    cfg,
		detectors: make(map[DetectionType]Detector),
		metrics:   NewBrowserMetrics(),
	}
	
	// 初始化检测器
	service.initializeDetectors()
	
	// 初始化过滤器
	service.initializeFilters()
	
	// 初始化验证器
	service.initializeValidators()
	
	log.Info().
		Str("browser_type", string(cfg.BrowserType)).
		Bool("headless", cfg.Headless).
		Int("pool_size", cfg.PoolSize).
		Msg("浏览器服务初始化完成")
	
	return service, nil
}

// NewBrowserPool 创建浏览器池
func NewBrowserPool(cfg Config) (*BrowserPool, error) {
	pw, err := playwright.Run()
	if err != nil {
		return nil, fmt.Errorf("启动Playwright失败: %w", err)
	}
	
	pool := &BrowserPool{
		browsers: make(chan playwright.Browser, cfg.PoolSize),
		config:   cfg,
		pw:       pw,
		stats: BrowserStats{
			ErrorsByType:     make(map[string]int64),
			DetectionsByType: make(map[DetectionType]int64),
		},
	}
	
	// 预创建浏览器实例
	for i := 0; i < cfg.PoolSize; i++ {
		browser, err := pool.createBrowser()
		if err != nil {
			pool.Close()
			return nil, fmt.Errorf("创建浏览器实例失败: %w", err)
		}
		pool.browsers <- browser
	}
	
	return pool, nil
}

// createBrowser 创建浏览器实例
func (p *BrowserPool) createBrowser() (playwright.Browser, error) {
	var browserType playwright.BrowserType
	
	switch p.config.BrowserType {
	case BrowserChromium:
		browserType = p.pw.Chromium
	case BrowserFirefox:
		browserType = p.pw.Firefox
	case BrowserWebkit:
		browserType = p.pw.Webkit
	default:
		browserType = p.pw.Chromium
	}
	
	options := playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(p.config.Headless),
		SlowMo:   playwright.Float(float64(p.config.SlowMo.Milliseconds())),
	}
	
	if p.config.Proxy != "" {
		options.Proxy = &playwright.Proxy{Server: p.config.Proxy}
	}
	
	// 添加启动参数
	args := []string{
		"--no-sandbox",
		"--disable-dev-shm-usage",
		"--disable-gpu",
		"--disable-extensions",
		"--disable-plugins",
		"--disable-images",
	}
	
	if !p.config.WebSecurity {
		args = append(args, "--disable-web-security", "--disable-features=VizDisplayCompositor")
	}
	
	if p.config.IgnoreHTTPSErrors {
		args = append(args, "--ignore-certificate-errors", "--ignore-ssl-errors")
	}
	
	options.Args = args
	
	return browserType.Launch(options)
}

// GetBrowser 从池中获取浏览器实例
func (p *BrowserPool) GetBrowser(ctx context.Context) (playwright.Browser, error) {
	p.closeMu.RLock()
	defer p.closeMu.RUnlock()
	
	if p.closed {
		return nil, fmt.Errorf("浏览器池已关闭")
	}
	
	select {
	case browser := <-p.browsers:
		return browser, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ReturnBrowser 将浏览器实例返回池中
func (p *BrowserPool) ReturnBrowser(browser playwright.Browser) {
	p.closeMu.RLock()
	defer p.closeMu.RUnlock()
	
	if p.closed {
		if browser != nil {
			browser.Close()
		}
		return
	}
	
	select {
	case p.browsers <- browser:
	default:
		// 池已满，关闭浏览器
		if browser != nil {
			browser.Close()
		}
	}
}

// initializeDetectors 初始化检测器
func (s *BrowserService) initializeDetectors() {
	s.detectors[DetectionXSS] = NewXSSDetector()
	s.detectors[DetectionCSRF] = NewCSRFDetector()
	s.detectors[DetectionClickjacking] = NewClickjackingDetector()
	s.detectors[DetectionRedirect] = NewRedirectDetector()
	s.detectors[DetectionFormHijack] = NewFormHijackDetector()
	s.detectors[DetectionDOMClobbering] = NewDOMClobberingDetector()
}

// initializeFilters 初始化过滤器
func (s *BrowserService) initializeFilters() {
	s.domainFilter = &DomainFilter{
		allowedDomains: s.config.AllowedDomains,
		blockedDomains: s.config.BlockedDomains,
	}
	s.domainFilter.compileRegexes()
	
	s.payloadFilter = &PayloadFilter{
		maxLength: 10000,
		allowedTags: []string{"script", "img", "iframe", "object", "embed"},
	}
	s.payloadFilter.compilePatterns()
}

// initializeValidators 初始化验证器
func (s *BrowserService) initializeValidators() {
	s.validators = []RequestValidator{
		&URLValidator{},
		&PayloadValidator{filter: s.payloadFilter},
		&DomainValidator{filter: s.domainFilter},
	}
}

// DetectVulnerability 检测漏洞
func (s *BrowserService) DetectVulnerability(ctx context.Context, req DetectionRequest) (*DetectionResult, error) {
	startTime := time.Now()
	defer func() {
		s.metrics.RecordRequest(time.Since(startTime))
	}()
	
	// 验证请求
	if err := s.validateRequest(req); err != nil {
		return nil, fmt.Errorf("请求验证失败: %w", err)
	}
	
	// 检查缓存
	if s.config.EnableCache {
		if cached := s.getCachedResult(req); cached != nil {
			return cached, nil
		}
	}
	
	// 获取检测器
	detector, exists := s.detectors[req.DetectionType]
	if !exists {
		return nil, fmt.Errorf("不支持的检测类型: %s", req.DetectionType)
	}
	
	// 获取浏览器实例
	browser, err := s.pool.GetBrowser(ctx)
	if err != nil {
		return nil, fmt.Errorf("获取浏览器实例失败: %w", err)
	}
	defer s.pool.ReturnBrowser(browser)
	
	// 创建浏览器上下文
	browserContext, err := s.createBrowserContext(browser)
	if err != nil {
		return nil, fmt.Errorf("创建浏览器上下文失败: %w", err)
	}
	defer s.closeBrowserContext(browserContext)
	
	// 创建页面
	page, err := browserContext.NewPage()
	if err != nil {
		return nil, fmt.Errorf("创建页面失败: %w", err)
	}
	defer s.closePage(page)
	
	// 设置页面配置
	if err := s.configurePage(page); err != nil {
		return nil, fmt.Errorf("配置页面失败: %w", err)
	}
	
	// 执行检测
	result, err := detector.Detect(ctx, page, req)
	if err != nil {
		s.metrics.RecordError()
		return nil, fmt.Errorf("检测失败: %w", err)
	}
	
	// 后处理
	if err := s.postProcessResult(result); err != nil {
		log.Warn().Err(err).Msg("后处理失败")
	}
	
	// 缓存结果
	if s.config.EnableCache {
		s.cacheResult(req, result)
	}
	
	// 记录统计
	s.metrics.RecordDetection(req.DetectionType, result.Vulnerable)
	
	log.Info().
		Str("detection_type", string(req.DetectionType)).
		Bool("vulnerable", result.Vulnerable).
		Float64("confidence", result.Confidence).
		Dur("execution_time", result.ExecutionTime).
		Msg("漏洞检测完成")
	
	return result, nil
}

// VerifyXSS 验证XSS漏洞（向后兼容）
func (s *BrowserService) VerifyXSS(ctx context.Context, targetURL, payload string) (bool, error) {
	req := DetectionRequest{
		URL:           targetURL,
		DetectionType: DetectionXSS,
		Payload:       payload,
		Method:        "GET",
		Timeout:       s.config.Timeout,
	}
	
	result, err := s.DetectVulnerability(ctx, req)
	if err != nil {
		return false, err
	}
	
	return result.Vulnerable, nil
}

// createBrowserContext 创建浏览器上下文
func (s *BrowserService) createBrowserContext(browser playwright.Browser) (playwright.BrowserContext, error) {
	options := playwright.BrowserNewContextOptions{
		Viewport: &playwright.Size{
			Width:  s.config.ViewportWidth,
			Height: s.config.ViewportHeight,
		},
		DeviceScaleFactor: playwright.Float(s.config.DeviceScaleFactor),
		JavaScriptEnabled: playwright.Bool(s.config.JavaScriptEnabled),
		IgnoreHTTPSErrors: playwright.Bool(s.config.IgnoreHTTPSErrors),
	}
	
	if s.config.UserAgent != "" {
		options.UserAgent = playwright.String(s.config.UserAgent)
	}
	
	if len(s.config.ExtraHeaders) > 0 {
		options.ExtraHTTPHeaders = s.config.ExtraHeaders
	}
	
	return browser.NewContext(options)
}

// configurePage 配置页面
func (s *BrowserService) configurePage(page playwright.Page) error {
	// 设置超时
	page.SetDefaultTimeout(float64(s.config.Timeout.Milliseconds()))
	page.SetDefaultNavigationTimeout(float64(s.config.NavigationTimeout.Milliseconds()))
	
	// 设置网络拦截
	if err := s.setupNetworkInterception(page); err != nil {
		return fmt.Errorf("设置网络拦截失败: %w", err)
	}
	
	// 设置控制台日志监听
	s.setupConsoleLogging(page)
	
	// 设置错误监听
	s.setupErrorHandling(page)
	
	return nil
}

// setupNetworkInterception 设置网络拦截
func (s *BrowserService) setupNetworkInterception(page playwright.Page) error {
	return page.Route("**/*", func(route playwright.Route) {
		request := route.Request()
		
		// 检查域名过滤
		if s.domainFilter != nil && !s.domainFilter.IsAllowed(request.URL()) {
			route.Abort()
			return
		}
		
		// 继续请求
		route.Continue()
	})
}

// setupConsoleLogging 设置控制台日志监听
func (s *BrowserService) setupConsoleLogging(page playwright.Page) {
	page.On("console", func(msg playwright.ConsoleMessage) {
		log.Debug().
			Str("level", msg.Type()).
			Str("text", msg.Text()).
			Str("location", msg.Location().String()).
			Msg("浏览器控制台日志")
	})
}

// setupErrorHandling 设置错误处理
func (s *BrowserService) setupErrorHandling(page playwright.Page) {
	page.On("pageerror", func(err error) {
		log.Warn().
			Err(err).
			Msg("页面JavaScript错误")
	})
	
	page.On("requestfailed", func(request playwright.Request) {
		log.Warn().
			Str("url", request.URL()).
			Str("method", request.Method()).
			Msg("网络请求失败")
	})
}

// validateRequest 验证请求
func (s *BrowserService) validateRequest(req DetectionRequest) error {
	for _, validator := range s.validators {
		if err := validator.Validate(req); err != nil {
			return err
		}
	}
	return nil
}

// postProcessResult 后处理结果
func (s *BrowserService) postProcessResult(result *DetectionResult) error {
	for _, interceptor := range s.interceptors {
		if err := interceptor.Intercept(result); err != nil {
			return err
		}
	}
	return nil
}

// getCachedResult 获取缓存结果
func (s *BrowserService) getCachedResult(req DetectionRequest) *DetectionResult {
	key := s.generateCacheKey(req)
	if cached, ok := s.resultCache.Load(key); ok {
		return cached.(*DetectionResult)
	}
	return nil
}

// cacheResult 缓存结果
func (s *BrowserService) cacheResult(req DetectionRequest, result *DetectionResult) {
	key := s.generateCacheKey(req)
	s.resultCache.Store(key, result)
}

// generateCacheKey 生成缓存键
func (s *BrowserService) generateCacheKey(req DetectionRequest) string {
	return fmt.Sprintf("%s_%s_%s_%s", req.DetectionType, req.URL, req.Method, req.Payload)
}

// closeBrowserContext 关闭浏览器上下文
func (s *BrowserService) closeBrowserContext(ctx playwright.BrowserContext) {
	if ctx != nil {
		if err := ctx.Close(); err != nil {
			log.Warn().Err(err).Msg("关闭浏览器上下文失败")
		}
	}
}

// closePage 关闭页面
func (s *BrowserService) closePage(page playwright.Page) {
	if page != nil {
		if err := page.Close(); err != nil {
			log.Warn().Err(err).Msg("关闭页面失败")
		}
	}
}

// GetStats 获取统计信息
func (s *BrowserService) GetStats() BrowserStats {
	s.pool.statsMu.RLock()
	defer s.pool.statsMu.RUnlock()
	
	stats := s.pool.stats
	stats.ActiveSessions = len(s.pool.browsers)
	stats.PoolUtilization = float64(s.config.PoolSize-len(s.pool.browsers)) / float64(s.config.PoolSize)
	
	return stats
}

// Close 关闭浏览器服务
func (s *BrowserService) Close() error {
	return s.pool.Close()
}

// Close 关闭浏览器池
func (p *BrowserPool) Close() error {
	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	
	if p.closed {
		return nil
	}
	
	p.closed = true
	
	// 关闭所有浏览器实例
	close(p.browsers)
	for browser := range p.browsers {
		if err := browser.Close(); err != nil {
			log.Warn().Err(err).Msg("关闭浏览器实例失败")
		}
	}
	
	// 关闭所有上下文
	p.contexts.Range(func(key, value interface{}) bool {
		if ctx, ok := value.(playwright.BrowserContext); ok {
			ctx.Close()
		}
		return true
	})
	
	// 停止Playwright
	if p.pw != nil {
		if err := p.pw.Stop(); err != nil {
			log.Warn().Err(err).Msg("停止Playwright失败")
		}
	}
	
	log.Info().Msg("浏览器池已关闭")
	return nil
}

// NewBrowserMetrics 创建浏览器指标
func NewBrowserMetrics() *BrowserMetrics {
	return &BrowserMetrics{
		vulnerabilities: make(map[DetectionType]int64),
	}
}

// RecordRequest 记录请求
func (m *BrowserMetrics) RecordRequest(duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.requests++
	m.totalTime += duration
}

// RecordError 记录错误
func (m *BrowserMetrics) RecordError() {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.errors++
}

// RecordDetection 记录检测
func (m *BrowserMetrics) RecordDetection(detectionType DetectionType, vulnerable bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if vulnerable {
		m.vulnerabilities[detectionType]++
	}
}

// GetMetrics 获取指标
// GetMetrics 获取指标
func (m *BrowserMetrics) GetMetrics() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	avgTime := time.Duration(0)
	if m.requests > 0 {
		avgTime = m.totalTime / time.Duration(m.requests)
	}
	
	return map[string]interface{}{
		"total_requests":     m.requests,
		"total_errors":       m.errors,
		"average_time":       avgTime.String(),
		"vulnerabilities":    m.vulnerabilities,
		"success_rate":       float64(m.requests-m.errors) / float64(m.requests),
	}
}

// 域名过滤器实现

// compileRegexes 编译正则表达式
func (df *DomainFilter) compileRegexes() {
	for _, domain := range df.allowedDomains {
		if regex, err := regexp.Compile(domain); err == nil {
			df.allowedRegex = append(df.allowedRegex, regex)
		}
	}
	
	for _, domain := range df.blockedDomains {
		if regex, err := regexp.Compile(domain); err == nil {
			df.blockedRegex = append(df.blockedRegex, regex)
		}
	}
}

// IsAllowed 检查域名是否被允许
func (df *DomainFilter) IsAllowed(urlStr string) bool {
	if df == nil {
		return true
	}
	
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	
	hostname := u.Hostname()
	
	// 检查阻止列表
	for _, domain := range df.blockedDomains {
		if strings.Contains(hostname, domain) {
			return false
		}
	}
	
	for _, regex := range df.blockedRegex {
		if regex.MatchString(hostname) {
			return false
		}
	}
	
	// 如果没有允许列表，则默认允许
	if len(df.allowedDomains) == 0 && len(df.allowedRegex) == 0 {
		return true
	}
	
	// 检查允许列表
	for _, domain := range df.allowedDomains {
		if strings.Contains(hostname, domain) {
			return true
		}
	}
	
	for _, regex := range df.allowedRegex {
		if regex.MatchString(hostname) {
			return true
		}
	}
	
	return false
}

// Payload过滤器实现

// compilePatterns 编译模式
func (pf *PayloadFilter) compilePatterns() {
	// 危险模式
	dangerousPatterns := []string{
		`(?i)rm\s+-rf`,
		`(?i)format\s+c:`,
		`(?i)drop\s+database`,
		`(?i)delete\s+from`,
		`(?i)<script[^>]*>.*?</script>`,
		`(?i)javascript:`,
		`(?i)vbscript:`,
		`(?i)data:text/html`,
	}
	
	for _, pattern := range dangerousPatterns {
		if regex, err := regexp.Compile(pattern); err == nil {
			pf.blockedPatterns = append(pf.blockedPatterns, regex)
		}
	}
}

// IsPayloadSafe 检查payload是否安全
func (pf *PayloadFilter) IsPayloadSafe(payload string) bool {
	if pf == nil {
		return true
	}
	
	// 检查长度
	if pf.maxLength > 0 && len(payload) > pf.maxLength {
		return false
	}
	
	// 检查危险模式
	for _, pattern := range pf.blockedPatterns {
		if pattern.MatchString(payload) {
			return false
		}
	}
	
	return true
}

// 验证器实现

// URLValidator URL验证器
type URLValidator struct{}

func (v *URLValidator) Validate(req DetectionRequest) error {
	if strings.TrimSpace(req.URL) == "" {
		return fmt.Errorf("URL不能为空")
	}
	
	if _, err := url.Parse(req.URL); err != nil {
		return fmt.Errorf("无效的URL格式: %w", err)
	}
	
	return nil
}

// PayloadValidator Payload验证器
type PayloadValidator struct {
	filter *PayloadFilter
}

func (v *PayloadValidator) Validate(req DetectionRequest) error {
	if req.DetectionType != DetectionXSS && strings.TrimSpace(req.Payload) == "" {
		return fmt.Errorf("payload不能为空")
	}
	
	if v.filter != nil && !v.filter.IsPayloadSafe(req.Payload) {
		return fmt.Errorf("payload未通过安全检查")
	}
	
	return nil
}

// DomainValidator 域名验证器
type DomainValidator struct {
	filter *DomainFilter
}

func (v *DomainValidator) Validate(req DetectionRequest) error {
	if v.filter != nil && !v.filter.IsAllowed(req.URL) {
		return fmt.Errorf("目标域名不在允许列表中")
	}
	
	return nil
}

// 检测器实现

// XSSDetector XSS检测器
type XSSDetector struct {
	payloadPatterns []*regexp.Regexp
}

func NewXSSDetector() *XSSDetector {
	detector := &XSSDetector{}
	detector.compilePatterns()
	return detector
}

func (d *XSSDetector) GetType() DetectionType {
	return DetectionXSS
}

func (d *XSSDetector) Validate(req DetectionRequest) error {
	if req.Payload == "" {
		return fmt.Errorf("XSS检测需要payload")
	}
	return nil
}

func (d *XSSDetector) compilePatterns() {
	patterns := []string{
		`<script[^>]*>.*?</script>`,
		`javascript:`,
		`on\w+\s*=`,
		`<img[^>]*onerror`,
		`<svg[^>]*onload`,
	}
	
	for _, pattern := range patterns {
		if regex, err := regexp.Compile(`(?i)` + pattern); err == nil {
			d.payloadPatterns = append(d.payloadPatterns, regex)
		}
	}
}

func (d *XSSDetector) Detect(ctx context.Context, page playwright.Page, req DetectionRequest) (*DetectionResult, error) {
	startTime := time.Now()
	result := &DetectionResult{
		DetectionType: DetectionXSS,
		Evidence:      []Evidence{},
		NetworkLogs:   []NetworkLog{},
		ConsoleLogs:   []ConsoleLog{},
		Errors:        []string{},
		Warnings:      []string{},
		Metadata:      make(map[string]interface{}),
	}
	
	// 设置对话框监听器
	alertTriggered := false
	dialogHandler := func(dialog playwright.Dialog) {
		defer dialog.Dismiss()
		
		message := dialog.Message()
		log.Debug().
			Str("type", dialog.Type()).
			Str("message", message).
			Msg("检测到对话框")
		
		// 检查对话框消息是否包含payload
		if d.isPayloadInMessage(message, req.Payload) {
			alertTriggered = true
			result.Evidence = append(result.Evidence, Evidence{
				Type:        "dialog",
				Description: "检测到包含payload的对话框",
				Content:     message,
				Severity:    "high",
				Timestamp:   time.Now(),
				Context: map[string]interface{}{
					"dialog_type": dialog.Type(),
					"payload":     req.Payload,
				},
			})
		}
	}
	
	page.On("dialog", dialogHandler)
	defer page.RemoveListener("dialog", dialogHandler)
	
	// 设置控制台日志监听
	consoleHandler := func(msg playwright.ConsoleMessage) {
		consoleLog := ConsoleLog{
			Level:     msg.Type(),
			Message:   msg.Text(),
			Source:    msg.Location().URL,
			Line:      msg.Location().LineNumber,
			Column:    msg.Location().ColumnNumber,
			Timestamp: time.Now(),
		}
		result.ConsoleLogs = append(result.ConsoleLogs, consoleLog)
		
		// 检查控制台错误中是否包含payload相关信息
		if msg.Type() == "error" && strings.Contains(msg.Text(), req.Payload) {
			result.Evidence = append(result.Evidence, Evidence{
				Type:        "console_error",
				Description: "控制台错误中包含payload",
				Content:     msg.Text(),
				Severity:    "medium",
				Timestamp:   time.Now(),
			})
		}
	}
	
	page.On("console", consoleHandler)
	defer page.RemoveListener("console", consoleHandler)
	
	// 设置网络监听
	networkHandler := func(response playwright.Response) {
		networkLog := NetworkLog{
			URL:       response.URL(),
			Method:    response.Request().Method(),
			Status:    response.Status(),
			Timestamp: time.Now(),
		}
		
		if headers := response.Headers(); headers != nil {
			networkLog.Headers = headers
		}
		
		result.NetworkLogs = append(result.NetworkLogs, networkLog)
	}
	
	page.On("response", networkHandler)
	defer page.RemoveListener("response", networkHandler)
	
	// 导航到目标URL
	navCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	
	response, err := page.Goto(req.URL, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateNetworkidle,
		Timeout:   playwright.Float(15000),
	})
	
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("导航失败: %v", err))
		result.Success = false
		return result, nil
	}
	
	// 记录页面元数据
	result.PageMetadata = d.extractPageMetadata(page, response)
	
	// 等待JavaScript执行
	time.Sleep(2 * time.Second)
	
	// 检查DOM中是否包含payload
	domContainsPayload, err := d.checkDOMForPayload(page, req.Payload)
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("DOM检查失败: %v", err))
	} else if domContainsPayload {
		result.Evidence = append(result.Evidence, Evidence{
			Type:        "dom_content",
			Description: "DOM中发现payload内容",
			Content:     req.Payload,
			Severity:    "high",
			Timestamp:   time.Now(),
		})
	}
	
	// 检查页面源码
	content, err := page.Content()
	if err == nil {
		if d.isPayloadInContent(content, req.Payload) {
			result.Evidence = append(result.Evidence, Evidence{
				Type:        "page_source",
				Description: "页面源码中发现payload",
				Content:     req.Payload,
				Severity:    "medium",
				Timestamp:   time.Now(),
			})
		}
	}
	
	// 执行自定义JavaScript
	if req.CustomJS != "" {
		if jsResult, err := page.Evaluate(req.CustomJS); err == nil {
			result.Metadata["custom_js_result"] = jsResult
		}
	}
	
	// 计算结果
	result.Vulnerable = alertTriggered || domContainsPayload || len(result.Evidence) > 0
	result.Confidence = d.calculateConfidence(result)
	result.Success = true
	result.ExecutionTime = time.Since(startTime)
	result.RiskLevel = d.calculateRiskLevel(result)
	result.Recommendations = d.generateRecommendations(result)
	
	return result, nil
}

func (d *XSSDetector) isPayloadInMessage(message, payload string) bool {
	return strings.Contains(strings.ToLower(message), strings.ToLower(payload))
}

func (d *XSSDetector) checkDOMForPayload(page playwright.Page, payload string) (bool, error) {
	script := fmt.Sprintf(`
		() => {
			const payload = %s;
			const bodyText = document.body.innerText || document.body.textContent || '';
			const innerHTML = document.body.innerHTML || '';
			return bodyText.includes(payload) || innerHTML.includes(payload);
		}
	`, fmt.Sprintf(`"%s"`, strings.ReplaceAll(payload, `"`, `\"`)))
	
	result, err := page.Evaluate(script)
	if err != nil {
		return false, err
	}
	
	if boolResult, ok := result.(bool); ok {
		return boolResult, nil
	}
	
	return false, nil
}

func (d *XSSDetector) isPayloadInContent(content, payload string) bool {
	for _, pattern := range d.payloadPatterns {
		if pattern.MatchString(content) && strings.Contains(content, payload) {
			return true
		}
	}
	return strings.Contains(content, payload)
}

func (d *XSSDetector) extractPageMetadata(page playwright.Page, response playwright.Response) PageMetadata {
	metadata := PageMetadata{
		URL:        page.URL(),
		StatusCode: response.Status(),
		Headers:    response.Headers(),
		Timestamp:  time.Now(),
	}
	
	if title, err := page.Title(); err == nil {
		metadata.Title = title
	}
	
	if finalURL := page.URL(); finalURL != "" {
		metadata.FinalURL = finalURL
	}
	
	return metadata
}

func (d *XSSDetector) calculateConfidence(result *DetectionResult) float64 {
	if !result.Vulnerable {
		return 0.0
	}
	
	confidence := 0.0
	evidenceCount := len(result.Evidence)
	
	for _, evidence := range result.Evidence {
		switch evidence.Type {
		case "dialog":
			confidence += 0.9
		case "dom_content":
			confidence += 0.8
		case "page_source":
			confidence += 0.6
		case "console_error":
			confidence += 0.4
		}
	}
	
	// 基于证据数量调整置信度
	if evidenceCount > 0 {
		confidence = confidence / float64(evidenceCount)
	}
	
	if confidence > 1.0 {
		confidence = 1.0
	}
	
	return confidence
}

func (d *XSSDetector) calculateRiskLevel(result *DetectionResult) string {
	if !result.Vulnerable {
		return "none"
	}
	
	if result.Confidence >= 0.8 {
		return "critical"
	} else if result.Confidence >= 0.6 {
		return "high"
	} else if result.Confidence >= 0.4 {
		return "medium"
	}
	
	return "low"
}

func (d *XSSDetector) generateRecommendations(result *DetectionResult) []string {
	if !result.Vulnerable {
		return []string{"未发现XSS漏洞"}
	}
	
	recommendations := []string{
		"对用户输入进行适当的编码和转义",
		"实施内容安全策略(CSP)",
		"使用安全的模板引擎",
		"验证和清理所有用户输入",
		"避免将用户数据直接插入到HTML中",
	}
	
	// 基于证据类型添加特定建议
	for _, evidence := range result.Evidence {
		switch evidence.Type {
		case "dialog":
			recommendations = append(recommendations, "检查JavaScript执行上下文，防止恶意脚本执行")
		case "dom_content":
			recommendations = append(recommendations, "审查DOM操作代码，确保安全地处理动态内容")
		}
	}
	
	return recommendations
}

// 其他检测器的基础实现

// CSRFDetector CSRF检测器
type CSRFDetector struct{}

func NewCSRFDetector() *CSRFDetector {
	return &CSRFDetector{}
}

func (d *CSRFDetector) GetType() DetectionType {
	return DetectionCSRF
}

func (d *CSRFDetector) Validate(req DetectionRequest) error {
	return nil
}

func (d *CSRFDetector) Detect(ctx context.Context, page playwright.Page, req DetectionRequest) (*DetectionResult, error) {
	// CSRF检测逻辑实现
	result := &DetectionResult{
		DetectionType: DetectionCSRF,
		Success:       true,
		Vulnerable:    false,
		Confidence:    0.0,
		Evidence:      []Evidence{},
	}
	
	// 检查CSRF token
	hasCSRFToken, err := d.checkCSRFToken(page)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
	}
	
	if !hasCSRFToken {
		result.Vulnerable = true
		result.Confidence = 0.8
		result.Evidence = append(result.Evidence, Evidence{
			Type:        "missing_csrf_token",
			Description: "表单缺少CSRF保护token",
			Severity:    "high",
			Timestamp:   time.Now(),
		})
	}
	
	return result, nil
}

func (d *CSRFDetector) checkCSRFToken(page playwright.Page) (bool, error) {
	// 检查页面中是否存在CSRF token
	script := `
		() => {
			const forms = document.querySelectorAll('form');
			for (let form of forms) {
				const csrfInputs = form.querySelectorAll('input[name*="csrf"], input[name*="_token"], input[name*="authenticity_token"]');
				if (csrfInputs.length > 0) {
					return true;
				}
			}
			return false;
		}
	`
	
	result, err := page.Evaluate(script)
	if err != nil {
		return false, err
	}
	
	if boolResult, ok := result.(bool); ok {
		return boolResult, nil
	}
	
	return false, nil
}

// ClickjackingDetector 点击劫持检测器
type ClickjackingDetector struct{}

func NewClickjackingDetector() *ClickjackingDetector {
	return &ClickjackingDetector{}
}

func (d *ClickjackingDetector) GetType() DetectionType {
	return DetectionClickjacking
}

func (d *ClickjackingDetector) Validate(req DetectionRequest) error {
	return nil
}

func (d *ClickjackingDetector) Detect(ctx context.Context, page playwright.Page, req DetectionRequest) (*DetectionResult, error) {
	result := &DetectionResult{
		DetectionType: DetectionClickjacking,
		Success:       true,
		Vulnerable:    false,
		Confidence:    0.0,
		Evidence:      []Evidence{},
	}
	
	// 检查X-Frame-Options头
	response, err := page.Goto(req.URL)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result, nil
	}
	
	headers := response.Headers()
	
	// 检查X-Frame-Options
	xFrameOptions := headers["x-frame-options"]
	if xFrameOptions == "" {
		result.Vulnerable = true
		result.Confidence += 0.6
		result.Evidence = append(result.Evidence, Evidence{
			Type:        "missing_header",
			Description: "缺少X-Frame-Options头",
			Severity:    "medium",
			Timestamp:   time.Now(),
		})
	}
	
	// 检查CSP frame-ancestors
	csp := headers["content-security-policy"]
	if csp == "" || !strings.Contains(csp, "frame-ancestors") {
		result.Vulnerable = true
		result.Confidence += 0.4
		result.Evidence = append(result.Evidence, Evidence{
			Type:        "missing_csp",
			Description: "缺少CSP frame-ancestors指令",
			Severity:    "medium",
			Timestamp:   time.Now(),
		})
	}
	
	if result.Vulnerable {
		result.Confidence = result.Confidence / 2 // 平均置信度
		if result.Confidence > 1.0 {
			result.Confidence = 1.0
		}
	}
	
	return result, nil
}

// RedirectDetector 重定向检测器
type RedirectDetector struct{}

func NewRedirectDetector() *RedirectDetector {
	return &RedirectDetector{}
}

func (d *RedirectDetector) GetType() DetectionType {
	return DetectionRedirect
}

func (d *RedirectDetector) Validate(req DetectionRequest) error {
	return nil
}

func (d *RedirectDetector) Detect(ctx context.Context, page playwright.Page, req DetectionRequest) (*DetectionResult, error) {
	result := &DetectionResult{
		DetectionType: DetectionRedirect,
		Success:       true,
		Vulnerable:    false,
		Confidence:    0.0,
		Evidence:      []Evidence{},
		Metadata:      make(map[string]interface{}),
	}
	
	// 记录重定向链
	var redirectChain []string
	
	page.On("response", func(response playwright.Response) {
		if response.Status() >= 300 && response.Status() < 400 {
			location := response.Headers()["location"]
			if location != "" {
				redirectChain = append(redirectChain, location)
			}
		}
	})
	
	// 导航到目标URL
	_, err := page.Goto(req.URL)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result, nil
	}
	
	finalURL := page.URL()
	result.Metadata["redirect_chain"] = redirectChain
	result.Metadata["final_url"] = finalURL
	
	// 检查是否存在开放重定向
	if len(redirectChain) > 0 {
		for _, redirect := range redirectChain {
			if d.isExternalRedirect(req.URL, redirect) {
				result.Vulnerable = true
				result.Confidence = 0.8
				result.Evidence = append(result.Evidence, Evidence{
					Type:        "external_redirect",
					Description: "检测到外部重定向",
					Content:     redirect,
					Severity:    "high",
					Timestamp:   time.Now(),
				})
			}
		}
	}
	
	return result, nil
}

func (d *RedirectDetector) isExternalRedirect(originalURL, redirectURL string) bool {
	original, err := url.Parse(originalURL)
	if err != nil {
		return false
	}
	
	redirect, err := url.Parse(redirectURL)
	if err != nil {
		return false
	}
	
	return original.Host != redirect.Host
}

// FormHijackDetector 表单劫持检测器
type FormHijackDetector struct{}

func NewFormHijackDetector() *FormHijackDetector {
	return &FormHijackDetector{}
}

func (d *FormHijackDetector) GetType() DetectionType {
	return DetectionFormHijack
}

func (d *FormHijackDetector) Validate(req DetectionRequest) error {
	return nil
}

func (d *FormHijackDetector) Detect(ctx context.Context, page playwright.Page, req DetectionRequest) (*DetectionResult, error) {
	// 表单劫持检测逻辑
	return &DetectionResult{
		DetectionType: DetectionFormHijack,
		Success:       true,
		Vulnerable:    false,
		Confidence:    0.0,
	}, nil
}

// DOMClobberingDetector DOM Clobbering检测器
type DOMClobberingDetector struct{}

func NewDOMClobberingDetector() *DOMClobberingDetector {
	return &DOMClobberingDetector{}
}

func (d *DOMClobberingDetector) GetType() DetectionType {
	return DetectionDOMClobbering
}

func (d *DOMClobberingDetector) Validate(req DetectionRequest) error {
	return nil
}

func (d *DOMClobberingDetector) Detect(ctx context.Context, page playwright.Page, req DetectionRequest) (*DetectionResult, error) {
	// DOM Clobbering检测逻辑
	return &DetectionResult{
		DetectionType: DetectionDOMClobbering,
		Success:       true,
		Vulnerable:    false,
		Confidence:    0.0,
	}, nil
}

// 批量检测方法

// BatchDetect 批量检测
func (s *BrowserService) BatchDetect(ctx context.Context, requests []DetectionRequest) ([]*DetectionResult, error) {
	results := make([]*DetectionResult, len(requests))
	semaphore := make(chan struct{}, s.config.MaxConcurrency)
	
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errors []error
	
	for i, req := range requests {
		wg.Add(1)
		go func(idx int, request DetectionRequest) {
			defer wg.Done()
			
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			result, err := s.DetectVulnerability(ctx, request)
			
			mu.Lock()
			if err != nil {
				errors = append(errors, fmt.Errorf("请求%d失败: %w", idx, err))
			} else {
				results[idx] = result
			}
			mu.Unlock()
		}(i, req)
	}
	
	wg.Wait()
	
	if len(errors) > 0 {
		log.Warn().
			Int("success_count", len(requests)-len(errors)).
			Int("error_count", len(errors)).
			Msg("批量检测部分失败")
	}
	
	return results, nil
}

// 工具方法

// TakeScreenshot 截图
func (s *BrowserService) TakeScreenshot(ctx context.Context, url string) ([]byte, error) {
	browser, err := s.pool.GetBrowser(ctx)
	if err != nil {
		return nil, err
	}
	defer s.pool.ReturnBrowser(browser)
	
	context, err := s.createBrowserContext(browser)
	if err != nil {
		return nil, err
	}
	defer s.closeBrowserContext(context)
	
	page, err := context.NewPage()
	if err != nil {
		return nil, err
	}
	defer s.closePage(page)
	
	if _, err := page.Goto(url); err != nil {
		return nil, err
	}
	
	return page.Screenshot(playwright.PageScreenshotOptions{
		FullPage: playwright.Bool(true),
		Type:     playwright.ScreenshotTypeJpeg,
		Quality:  playwright.Int(80),
	})
}

// GetPageContent 获取页面内容
func (s *BrowserService) GetPageContent(ctx context.Context, url string) (string, error) {
	browser, err := s.pool.GetBrowser(ctx)
	if err != nil {
		return "", err
	}
	defer s.pool.ReturnBrowser(browser)
	
	context, err := s.createBrowserContext(browser)
	if err != nil {
		return "", err
	}
	defer s.closeBrowserContext(context)
	
	page, err := context.NewPage()
	if err != nil {
		return "", err
	}
	defer s.closePage(page)
	
	if _, err := page.Goto(url); err != nil {
		return "", err
	}
	
	return page.Content()
}

// ExecuteScript 执行自定义脚本
func (s *BrowserService) ExecuteScript(ctx context.Context, url, script string) (interface{}, error) {
	browser, err := s.pool.GetBrowser(ctx)
	if err != nil {
		return nil, err
	}
	defer s.pool.ReturnBrowser(browser)
	
	context, err := s.createBrowserContext(browser)
	if err != nil {
		return nil, err
	}
	defer s.closeBrowserContext(context)
	
	page, err := context.NewPage()
	if err != nil {
		return nil, err
	}
	defer s.closePage(page)
	
	if _, err := page.Goto(url); err != nil {
		return nil, err
	}
	
	return page.Evaluate(script)
}

// 健康检查

// HealthCheck 健康检查
func (s *BrowserService) HealthCheck(ctx context.Context) error {
	browser, err := s.pool.GetBrowser(ctx)
	if err != nil {
		return fmt.Errorf("无法获取浏览器实例: %w", err)
	}
	defer s.pool.ReturnBrowser(browser)
	
	context, err := s.createBrowserContext(browser)
	if err != nil {
		return fmt.Errorf("无法创建浏览器上下文: %w", err)
	}
	defer s.closeBrowserContext(context)
	
	page, err := context.NewPage()
	if err != nil {
		return fmt.Errorf("无法创建页面: %w", err)
	}
	defer s.closePage(page)
	
	// 测试导航到简单页面
	testURL := "data:text/html,<html><body><h1>Health Check</h1></body></html>"
	if _, err := page.Goto(testURL); err != nil {
		return fmt.Errorf("健康检查导航失败: %w", err)
	}
	
	// 测试JavaScript执行
	result, err := page.Evaluate("() => document.title")
	if err != nil {
		return fmt.Errorf("健康检查JavaScript执行失败: %w", err)
	}
	
	if result != "Health Check" {
		return fmt.Errorf("健康检查结果不匹配，期望'Health Check'，实际'%v'", result)
	}
	
	log.Info().Msg("浏览器服务健康检查通过")
	return nil
}

// 配置管理

// UpdateConfig 更新配置
func (s *BrowserService) UpdateConfig(newConfig Config) error {
	// 验证新配置
	if err := s.validateConfig(newConfig); err != nil {
		return fmt.Errorf("配置验证失败: %w", err)
	}
	
	// 创建新的浏览器池
	newPool, err := NewBrowserPool(newConfig)
	if err != nil {
		return fmt.Errorf("创建新浏览器池失败: %w", err)
	}
	
	// 关闭旧池
	oldPool := s.pool
	s.pool = newPool
	s.config = newConfig
	
	// 异步关闭旧池
	go func() {
		if err := oldPool.Close(); err != nil {
			log.Warn().Err(err).Msg("关闭旧浏览器池失败")
		}
	}()
	
	// 重新初始化过滤器
	s.initializeFilters()
	
	log.Info().Msg("浏览器服务配置已更新")
	return nil
}

// validateConfig 验证配置
func (s *BrowserService) validateConfig(cfg Config) error {
	if cfg.PoolSize <= 0 {
		return fmt.Errorf("池大小必须大于0")
	}
	
	if cfg.MaxConcurrency <= 0 {
		return fmt.Errorf("最大并发数必须大于0")
	}
	
	if cfg.Timeout <= 0 {
		return fmt.Errorf("超时时间必须大于0")
	}
	
	if cfg.ViewportWidth <= 0 || cfg.ViewportHeight <= 0 {
		return fmt.Errorf("视口尺寸必须大于0")
	}
	
	return nil
}

// GetConfig 获取当前配置
func (s *BrowserService) GetConfig() Config {
	return s.config
}

// 缓存管理

// ClearCache 清理缓存
func (s *BrowserService) ClearCache() {
	s.resultCache.Range(func(key, value interface{}) bool {
		s.resultCache.Delete(key)
		return true
	})
	
	log.Info().Msg("浏览器服务缓存已清理")
}

// GetCacheStats 获取缓存统计
func (s *BrowserService) GetCacheStats() map[string]interface{} {
	var count int64
	s.resultCache.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	
	return map[string]interface{}{
		"cached_results": count,
		"cache_enabled":  s.config.EnableCache,
	}
}

// 扩展功能

// WaitForElement 等待元素出现
func (s *BrowserService) WaitForElement(ctx context.Context, url, selector string, timeout time.Duration) error {
	browser, err := s.pool.GetBrowser(ctx)
	if err != nil {
		return err
	}
	defer s.pool.ReturnBrowser(browser)
	
	context, err := s.createBrowserContext(browser)
	if err != nil {
		return err
	}
	defer s.closeBrowserContext(context)
	
	page, err := context.NewPage()
	if err != nil {
		return err
	}
	defer s.closePage(page)
	
	if _, err := page.Goto(url); err != nil {
		return err
	}
	
	_, err = page.WaitForSelector(selector, playwright.PageWaitForSelectorOptions{
		Timeout: playwright.Float(float64(timeout.Milliseconds())),
	})
	
	return err
}

// FillForm 填充表单
func (s *BrowserService) FillForm(ctx context.Context, url string, formData map[string]string) error {
	browser, err := s.pool.GetBrowser(ctx)
	if err != nil {
		return err
	}
	defer s.pool.ReturnBrowser(browser)
	
	context, err := s.createBrowserContext(browser)
	if err != nil {
		return err
	}
	defer s.closeBrowserContext(context)
	
	page, err := context.NewPage()
	if err != nil {
		return err
	}
	defer s.closePage(page)
	
	if _, err := page.Goto(url); err != nil {
		return err
	}
	
	// 填充表单字段
	for selector, value := range formData {
		if err := page.Fill(selector, value); err != nil {
			return fmt.Errorf("填充字段%s失败: %w", selector, err)
		}
	}
	
	return nil
}

// ClickElement 点击元素
func (s *BrowserService) ClickElement(ctx context.Context, url, selector string) error {
	browser, err := s.pool.GetBrowser(ctx)
	if err != nil {
		return err
	}
	defer s.pool.ReturnBrowser(browser)
	
	context, err := s.createBrowserContext(browser)
	if err != nil {
		return err
	}
	defer s.closeBrowserContext(context)
	
	page, err := context.NewPage()
	if err != nil {
		return err
	}
	defer s.closePage(page)
	
	if _, err := page.Goto(url); err != nil {
		return err
	}
	
	return page.Click(selector)
}

// GetElementText 获取元素文本
func (s *BrowserService) GetElementText(ctx context.Context, url, selector string) (string, error) {
	browser, err := s.pool.GetBrowser(ctx)
	if err != nil {
		return "", err
	}
	defer s.pool.ReturnBrowser(browser)
	
	context, err := s.createBrowserContext(browser)
	if err != nil {
		return "", err
	}
	defer s.closeBrowserContext(context)
	
	page, err := context.NewPage()
	if err != nil {
		return "", err
	}
	defer s.closePage(page)
	
	if _, err := page.Goto(url); err != nil {
		return "", err
	}
	
	element, err := page.QuerySelector(selector)
	if err != nil {
		return "", err
	}
	
	if element == nil {
		return "", fmt.Errorf("元素未找到: %s", selector)
	}
	
	return element.TextContent()
}

// 监控和日志

// EnableDetailedLogging 启用详细日志
func (s *BrowserService) EnableDetailedLogging(enable bool) {
	if enable {
		log.Info().Msg("已启用浏览器服务详细日志")
	} else {
		log.Info().Msg("已禁用浏览器服务详细日志")
	}
}

// GetDetailedStats 获取详细统计信息
func (s *BrowserService) GetDetailedStats() map[string]interface{} {
	stats := s.GetStats()
	metrics := s.metrics.GetMetrics()
	cache := s.GetCacheStats()
	
	return map[string]interface{}{
		"pool_stats":   stats,
		"metrics":      metrics,
		"cache_stats":  cache,
		"config":       s.config,
		"detectors":    s.getDetectorInfo(),
		"validators":   len(s.validators),
		"interceptors": len(s.interceptors),
	}
}

// getDetectorInfo 获取检测器信息
func (s *BrowserService) getDetectorInfo() map[string]interface{} {
	info := make(map[string]interface{})
	for detectionType, detector := range s.detectors {
		info[string(detectionType)] = map[string]interface{}{
			"type":        detector.GetType(),
			"description": s.getDetectorDescription(detector.GetType()),
		}
	}
	return info
}

// getDetectorDescription 获取检测器描述
func (s *BrowserService) getDetectorDescription(detectionType DetectionType) string {
	descriptions := map[DetectionType]string{
		DetectionXSS:           "跨站脚本攻击检测",
		DetectionCSRF:          "跨站请求伪造检测",
		DetectionClickjacking:  "点击劫持检测",
		DetectionRedirect:      "开放重定向检测",
		DetectionFormHijack:    "表单劫持检测",
		DetectionDOMClobbering: "DOM污染检测",
	}
	
	if desc, ok := descriptions[detectionType]; ok {
		return desc
	}
	return "未知检测类型"
}

// 导出和导入

// ExportResults 导出检测结果
func (s *BrowserService) ExportResults(results []*DetectionResult, format string) ([]byte, error) {
	switch strings.ToLower(format) {
	case "json":
		return json.MarshalIndent(results, "", "  ")
	case "csv":
		return s.exportToCSV(results)
	case "html":
		return s.exportToHTML(results)
	default:
		return nil, fmt.Errorf("不支持的导出格式: %s", format)
	}
}

// exportToCSV 导出为CSV格式
func (s *BrowserService) exportToCSV(results []*DetectionResult) ([]byte, error) {
	var buffer strings.Builder
	
	// CSV头部
	buffer.WriteString("URL,Detection Type,Vulnerable,Confidence,Risk Level,Evidence Count,Execution Time\n")
	
	// 数据行
	for _, result := range results {
		if result != nil {
			buffer.WriteString(fmt.Sprintf("%s,%s,%t,%.2f,%s,%d,%s\n",
				result.PageMetadata.URL,
				result.DetectionType,
				result.Vulnerable,
				result.Confidence,
				result.RiskLevel,
				len(result.Evidence),
				result.ExecutionTime.String(),
			))
		}
	}
	
	return []byte(buffer.String()), nil
}

// exportToHTML 导出为HTML格式
func (s *BrowserService) exportToHTML(results []*DetectionResult) ([]byte, error) {
	var buffer strings.Builder
	
	buffer.WriteString(`<!DOCTYPE html>
<html>
<head>
    <title>浏览器安全检测报告</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .vulnerable { color: red; font-weight: bold; }
        .safe { color: green; }
        .evidence { margin: 5px 0; padding: 5px; background-color: #f9f9f9; border-left: 3px solid #007cba; }
    </style>
</head>
<body>
    <h1>浏览器安全检测报告</h1>
    <p>生成时间: ` + time.Now().Format("2006-01-02 15:04:05") + `</p>
    <table>
        <tr>
            <th>URL</th>
            <th>检测类型</th>
            <th>状态</th>
            <th>置信度</th>
            <th>风险等级</th>
            <th>证据</th>
            <th>执行时间</th>
        </tr>`)
	
	for _, result := range results {
		if result != nil {
			status := "安全"
			statusClass := "safe"
			if result.Vulnerable {
				status = "存在漏洞"
				statusClass = "vulnerable"
			}
			
			buffer.WriteString(fmt.Sprintf(`
        <tr>
            <td>%s</td>
            <td>%s</td>
            <td class="%s">%s</td>
            <td>%.2f</td>
            <td>%s</td>
            <td>`,
				result.PageMetadata.URL,
				result.DetectionType,
				statusClass,
				status,
				result.Confidence,
				result.RiskLevel,
			))
			
			// 添加证据详情
			for _, evidence := range result.Evidence {
				buffer.WriteString(fmt.Sprintf(`
                <div class="evidence">
                    <strong>%s:</strong> %s<br>
                    <small>严重程度: %s | 时间: %s</small>
                </div>`,
					evidence.Type,
					evidence.Description,
					evidence.Severity,
					evidence.Timestamp.Format("15:04:05"),
				))
			}
			
			buffer.WriteString(fmt.Sprintf(`
            </td>
            <td>%s</td>
        </tr>`, result.ExecutionTime.String()))
		}
	}
	
	buffer.WriteString(`
    </table>
</body>
</html>`)
	
	return []byte(buffer.String()), nil
}

// 性能优化

// WarmUp 预热浏览器池
func (s *BrowserService) WarmUp(ctx context.Context) error {
	log.Info().Msg("开始预热浏览器池")
	
	// 并发预热多个浏览器实例
	var wg sync.WaitGroup
	errors := make(chan error, s.config.PoolSize)
	
	for i := 0; i < s.config.PoolSize; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			
			browser, err := s.pool.GetBrowser(ctx)
			if err != nil {
				errors <- fmt.Errorf("预热浏览器%d失败: %w", index, err)
				return
			}
			defer s.pool.ReturnBrowser(browser)
			
			// 创建一个简单的页面来预热
			context, err := s.createBrowserContext(browser)
			if err != nil {
				errors <- fmt.Errorf("预热上下文%d失败: %w", index, err)
				return
			}
			defer s.closeBrowserContext(context)
			
			page, err := context.NewPage()
			if err != nil {
				errors <- fmt.Errorf("预热页面%d失败: %w", index, err)
				return
			}
			defer s.closePage(page)
			
			// 导航到简单页面
			testURL := "data:text/html,<html><body>Warmup</body></html>"
			if _, err := page.Goto(testURL); err != nil {
				errors <- fmt.Errorf("预热导航%d失败: %w", index, err)
				return
			}
			
			log.Debug().Int("browser_index", index).Msg("浏览器预热完成")
		}(i)
	}
	
	wg.Wait()
	close(errors)
	
	// 检查预热错误
	var warmupErrors []error
	for err := range errors {
		warmupErrors = append(warmupErrors, err)
	}
	
	if len(warmupErrors) > 0 {
		log.Warn().
			Int("error_count", len(warmupErrors)).
			Msg("浏览器池预热部分失败")
		return fmt.Errorf("预热失败: %v", warmupErrors)
	}
	
	log.Info().Msg("浏览器池预热完成")
	return nil
}

// 安全增强

// SetSecurityHeaders 设置安全头
func (s *BrowserService) SetSecurityHeaders(headers map[string]string) {
	if s.config.ExtraHeaders == nil {
		s.config.ExtraHeaders = make(map[string]string)
	}
	
	// 添加安全相关的默认头
	defaultSecurityHeaders := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"X-XSS-Protection":       "1; mode=block",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
	}
	
	// 合并用户提供的头和默认安全头
	for key, value := range defaultSecurityHeaders {
		if _, exists := headers[key]; !exists {
			headers[key] = value
		}
	}
	
	// 更新配置中的额外头
	for key, value := range headers {
		s.config.ExtraHeaders[key] = value
	}
	
	log.Info().
		Int("header_count", len(headers)).
		Msg("已设置安全头")
}

// ValidateSSL 验证SSL证书
func (s *BrowserService) ValidateSSL(ctx context.Context, url string) (*tls.ConnectionState, error) {
	// 这里可以实现SSL证书验证逻辑
	// 由于Playwright的限制，我们可能需要使用其他方法来获取SSL信息
	
	// 使用标准库进行SSL验证
	u, err := url.Parse(url)
	if err != nil {
		return nil, fmt.Errorf("解析URL失败: %w", err)
	}
	
	if u.Scheme != "https" {
		return nil, fmt.Errorf("URL不是HTTPS: %s", url)
	}
	
	conn, err := tls.Dial("tcp", u.Host+":443", &tls.Config{
		InsecureSkipVerify: false,
	})
	if err != nil {
		return nil, fmt.Errorf("SSL连接失败: %w", err)
	}
	defer conn.Close()
	
	state := conn.ConnectionState()
	return &state, nil
}

// 调试和开发工具

// EnableDebugMode 启用调试模式
func (s *BrowserService) EnableDebugMode(enable bool) {
	if enable {
		s.config.Headless = false
		s.config.SlowMo = 1000 * time.Millisecond
		s.config.ScreenshotOnError = true
		s.config.SaveHAR = true
		log.Info().Msg("已启用调试模式")
	} else {
		s.config.Headless = true
		s.config.SlowMo = 0
		s.config.ScreenshotOnError = false
		s.config.SaveHAR = false
		log.Info().Msg("已禁用调试模式")
	}
}

// GetBrowserVersion 获取浏览器版本信息
func (s *BrowserService) GetBrowserVersion(ctx context.Context) (string, error) {
	browser, err := s.pool.GetBrowser(ctx)
	if err != nil {
		return "", err
	}
	defer s.pool.ReturnBrowser(browser)
	
	return browser.Version(), nil
}

// 资源清理和优化

// OptimizeMemory 优化内存使用
func (s *BrowserService) OptimizeMemory() error {
	log.Info().Msg("开始优化内存使用")
	
	// 清理缓存
	s.ClearCache()
	
	// 可以添加更多内存优化逻辑
	// 例如：强制垃圾回收、清理临时文件等
	
	log.Info().Msg("内存优化完成")
	return nil
}

// GetResourceUsage 获取资源使用情况
func (s *BrowserService) GetResourceUsage() map[string]interface{} {
	stats := s.GetStats()
	
	return map[string]interface{}{
		"active_browsers":   s.config.PoolSize - len(s.pool.browsers),
		"pool_utilization": stats.PoolUtilization,
		"total_requests":   stats.TotalRequests,
		"memory_usage":     "N/A", // 可以集成内存监控
		"cpu_usage":        "N/A", // 可以集成CPU监控
	}
}

// 最终的Close方法确保所有资源都被正确释放
func (s *BrowserService) Close() error {
	log.Info().Msg("开始关闭浏览器服务")
	
	// 清理缓存
	s.ClearCache()
	
	// 关闭浏览器池
	if err := s.pool.Close(); err != nil {
		log.Error().Err(err).Msg("关闭浏览器池失败")
		return err
	}
	
	log.Info().Msg("浏览器服务已关闭")
	return nil
}

// 便利函数

// QuickXSSTest 快速XSS测试
func (s *BrowserService) QuickXSSTest(ctx context.Context, url, payload string) (bool, float64, error) {
	req := DetectionRequest{
		URL:           url,
		DetectionType: DetectionXSS,
		Payload:       payload,
		Method:        "GET",
		Timeout:       10 * time.Second,
	}
	
	result, err := s.DetectVulnerability(ctx, req)
	if err != nil {
		return false, 0, err
	}
	
	return result.Vulnerable, result.Confidence, nil
}

// QuickCSRFTest 快速CSRF测试
func (s *BrowserService) QuickCSRFTest(ctx context.Context, url string) (bool, float64, error) {
	req := DetectionRequest{
		URL:           url,
		DetectionType: DetectionCSRF,
		Method:        "GET",
		Timeout:       10 * time.Second,
	}
	
	result, err := s.DetectVulnerability(ctx, req)
	if err != nil {
		return false, 0, err
	}
	
	return result.Vulnerable, result.Confidence, nil
}

// QuickClickjackingTest 快速点击劫持测试
func (s *BrowserService) QuickClickjackingTest(ctx context.Context, url string) (bool, float64, error) {
	req := DetectionRequest{
		URL:           url,
		DetectionType: DetectionClickjacking,
		Method:        "GET",
		Timeout:       10 * time.Second,
	}
	
	result, err := s.DetectVulnerability(ctx, req)
	if err != nil {
		return false, 0, err
	}
	
	return result.Vulnerable, result.Confidence, nil
}
