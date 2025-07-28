// Package util 提供了各种在项目中共享的辅助函数
// 这些函数通常是无状态的、纯粹的工具函数，用于处理常见的任务
// 如URL解析、字符串操作、参数提取、HTML解析等
package util

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"autovulnscan/internal/models"

	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/chromedp"
	"github.com/rs/zerolog/log"
)

// 常量定义
const (
	// 默认超时时间
	DefaultTimeout = 30 * time.Second
	
	// 默认User-Agent
	DefaultUserAgent = "AutoVulnScan/1.0 (Security Scanner)"
	
	// 最大URL长度
	MaxURLLength = 8192
	
	// 最大参数数量
	MaxParameterCount = 1000
	
	// 常见的静态文件扩展名
	StaticFileExtensions = ".css,.js,.jpg,.jpeg,.png,.gif,.svg,.ico,.woff,.woff2,.ttf,.eot,.pdf,.zip,.rar,.tar,.gz"
)

// 预编译的正则表达式（性能优化）
var (
	// HTML参数提取正则
	htmlParamRegex = regexp.MustCompile(`(?i)(name|id|for)=["\']([^"\']+)["\']`)
	
	// JavaScript参数提取正则
	jsParamRegex = regexp.MustCompile(`(?i)(var|let|const)\s+(\w+)\s*=|\.(\w+)\s*=|["\'](\w+)["\']:\s*`)
	
	// URL参数提取正则
	urlParamRegex = regexp.MustCompile(`[?&]([^=&]+)=([^&]*)`)
	
	// 敏感信息正则
	sensitiveRegex = regexp.MustCompile(`(?i)(password|pass|pwd|token|key|secret|auth|session|csrf)`)
	
	// 邮箱正则
	emailRegex = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	
	// IP地址正则
	ipRegex = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	
	// 域名正则
	domainRegex = regexp.MustCompile(`[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*`)
	
	// 静态文件扩展名集合
	staticExtensions = make(map[string]bool)
	
	// 初始化一次
	initOnce sync.Once
)

// init 初始化函数
func init() {
	initOnce.Do(func() {
		// 初始化静态文件扩展名集合
		exts := strings.Split(StaticFileExtensions, ",")
		for _, ext := range exts {
			staticExtensions[strings.TrimSpace(ext)] = true
		}
	})
}

// ChromeConfig Chrome浏览器配置
type ChromeConfig struct {
	Headless           bool          `json:"headless"`
	Proxy              string        `json:"proxy,omitempty"`
	UserAgent          string        `json:"user_agent"`
	Timeout            time.Duration `json:"timeout"`
	DisableGPU         bool          `json:"disable_gpu"`
	NoSandbox          bool          `json:"no_sandbox"`
	DisableDevShmUsage bool          `json:"disable_dev_shm_usage"`
	WindowSize         string        `json:"window_size"`
	DisableImages      bool          `json:"disable_images"`
	DisableJavaScript  bool          `json:"disable_javascript"`
	IgnoreHTTPSErrors  bool          `json:"ignore_https_errors"`
	ExtraFlags         []string      `json:"extra_flags,omitempty"`
}

// DefaultChromeConfig 返回默认Chrome配置
func DefaultChromeConfig() *ChromeConfig {
	return &ChromeConfig{
		Headless:           true,
		UserAgent:          DefaultUserAgent,
		Timeout:            DefaultTimeout,
		DisableGPU:         true,
		NoSandbox:          true,
		DisableDevShmUsage: true,
		WindowSize:         "1920,1080",
		DisableImages:      false,
		DisableJavaScript:  false,
		IgnoreHTTPSErrors:  true,
		ExtraFlags:         []string{},
	}
}

// GetAllocContext 创建一个新的 chromedp 执行分配器上下文
func GetAllocContext(config *ChromeConfig) (context.Context, context.CancelFunc, error) {
	if config == nil {
		config = DefaultChromeConfig()
	}

	// 验证配置
	if err := validateChromeConfig(config); err != nil {
		return nil, nil, fmt.Errorf("Chrome配置无效: %w", err)
	}

	// 基础选项
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", config.Headless),
		chromedp.Flag("disable-gpu", config.DisableGPU),
		chromedp.Flag("no-sandbox", config.NoSandbox),
		chromedp.Flag("disable-dev-shm-usage", config.DisableDevShmUsage),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-plugins", true),
		chromedp.Flag("disable-background-timer-throttling", true),
		chromedp.Flag("disable-backgrounding-occluded-windows", true),
		chromedp.Flag("disable-renderer-backgrounding", true),
		chromedp.UserAgent(config.UserAgent),
	)

	// 窗口大小
	if config.WindowSize != "" {
		opts = append(opts, chromedp.WindowSize(parseWindowSize(config.WindowSize)))
	}

	// 代理配置
	if config.Proxy != "" {
		if err := validateProxy(config.Proxy); err != nil {
			return nil, nil, fmt.Errorf("代理配置无效: %w", err)
		}
		opts = append(opts, chromedp.ProxyServer(config.Proxy))
	}

	// 禁用图片加载
	if config.DisableImages {
		opts = append(opts, chromedp.Flag("blink-settings", "imagesEnabled=false"))
	}

	// 禁用JavaScript
	if config.DisableJavaScript {
		opts = append(opts, chromedp.Flag("disable-javascript", true))
	}

	// 忽略HTTPS错误
	if config.IgnoreHTTPSErrors {
		opts = append(opts, chromedp.Flag("ignore-certificate-errors", true))
		opts = append(opts, chromedp.Flag("ignore-ssl-errors", true))
		opts = append(opts, chromedp.Flag("ignore-certificate-errors-spki-list", true))
	}

	// 额外标志
	for _, flag := range config.ExtraFlags {
		if flag != "" {
			opts = append(opts, chromedp.Flag(flag, true))
		}
	}

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)

	// 设置超时
	if config.Timeout > 0 {
		timeoutCtx, timeoutCancel := context.WithTimeout(allocCtx, config.Timeout)
		return timeoutCtx, func() {
			timeoutCancel()
			cancel()
		}, nil
	}

	log.Debug().
		Bool("headless", config.Headless).
		Str("proxy", config.Proxy).
		Str("user_agent", config.UserAgent).
		Msg("Chrome上下文创建完成")

	return allocCtx, cancel, nil
}

// validateChromeConfig 验证Chrome配置
func validateChromeConfig(config *ChromeConfig) error {
	if config.UserAgent == "" {
		return fmt.Errorf("UserAgent不能为空")
	}
	
	if config.Timeout < 0 {
		return fmt.Errorf("超时时间不能为负数")
	}
	
	if config.WindowSize != "" {
		if !regexp.MustCompile(`^\d+,\d+$`).MatchString(config.WindowSize) {
			return fmt.Errorf("窗口大小格式无效，应为 'width,height'")
		}
	}
	
	return nil
}

// validateProxy 验证代理配置
func validateProxy(proxy string) error {
	if proxy == "" {
		return nil
	}
	
	u, err := url.Parse(proxy)
	if err != nil {
		return fmt.Errorf("代理URL解析失败: %w", err)
	}
	
	if u.Scheme == "" {
		return fmt.Errorf("代理URL缺少协议")
	}
	
	if u.Host == "" {
		return fmt.Errorf("代理URL缺少主机")
	}
	
	return nil
}

// parseWindowSize 解析窗口大小字符串
func parseWindowSize(size string) (int, int) {
	parts := strings.Split(size, ",")
	if len(parts) != 2 {
		return 1920, 1080 // 默认值
	}
	
	width, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	height, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	
	if err1 != nil || err2 != nil {
		return 1920, 1080 // 默认值
	}
	
	return width, height
}

// ScopeConfig 作用域配置
type ScopeConfig struct {
	Domains           []string `json:"domains"`
	BlacklistPatterns []string `json:"blacklist_patterns"`
	WhitelistPatterns []string `json:"whitelist_patterns"`
	IncludeSubdomains bool     `json:"include_subdomains"`
	MaxDepth          int      `json:"max_depth"`
	IgnoreStaticFiles bool     `json:"ignore_static_files"`
}

// IsInScope 检查给定的URL是否在配置定义的作用域内
func IsInScope(u *url.URL, config *ScopeConfig) bool {
	if u == nil || config == nil {
		return false
	}

	hostname := u.Hostname()
	fullURL := u.String()

	// 验证URL长度
	if len(fullURL) > MaxURLLength {
		log.Debug().Str("url", fullURL).Msg("URL长度超过限制")
		return false
	}

	// 检查是否为静态文件
	if config.IgnoreStaticFiles && IsStaticFile(u.Path) {
		return false
	}

	// 检查黑名单
	for _, pattern := range config.BlacklistPatterns {
		if pattern == "" {
			continue
		}
		if matched, err := regexp.MatchString(pattern, fullURL); err == nil && matched {
			log.Debug().Str("url", fullURL).Str("pattern", pattern).Msg("URL匹配黑名单")
			return false
		}
	}

	// 检查白名单（如果存在）
	if len(config.WhitelistPatterns) > 0 {
		whitelisted := false
		for _, pattern := range config.WhitelistPatterns {
			if pattern == "" {
				continue
			}
			if matched, err := regexp.MatchString(pattern, fullURL); err == nil && matched {
				whitelisted = true
				break
			}
		}
		if !whitelisted {
			return false
		}
	}

	// 检查域名作用域
	return isHostnameInScope(hostname, config.Domains, config.IncludeSubdomains)
}

// isHostnameInScope 检查主机名是否在作用域内
func isHostnameInScope(hostname string, domains []string, includeSubdomains bool) bool {
	if hostname == "" {
		return false
	}

	hostname = strings.ToLower(hostname)

	for _, domain := range domains {
		if domain == "" {
			continue
		}
		
		domain = strings.ToLower(domain)
		
		// 精确匹配
		if hostname == domain {
			return true
		}
		
		// 子域名匹配
		if includeSubdomains {
			if strings.HasSuffix(hostname, "."+domain) {
				return true
			}
		}
	}

	return false
}

// IsStaticFile 检查是否为静态文件
func IsStaticFile(path string) bool {
	if path == "" {
		return false
	}
	
	// 获取文件扩展名
	lastDot := strings.LastIndex(path, ".")
	if lastDot == -1 {
		return false
	}
	
	ext := strings.ToLower(path[lastDot:])
	return staticExtensions[ext]
}

// ParameterExtractor 参数提取器
type ParameterExtractor struct {
	MaxParams     int                    `json:"max_params"`
	IgnoreEmpty   bool                   `json:"ignore_empty"`
	CustomRegexes []*regexp.Regexp       `json:"-"`
	Filters       []ParameterFilter      `json:"-"`
	seen          map[string]struct{}    `json:"-"`
	mu            sync.RWMutex           `json:"-"`
}

// ParameterFilter 参数过滤器
type ParameterFilter func(param models.Parameter) bool

// NewParameterExtractor 创建参数提取器
func NewParameterExtractor() *ParameterExtractor {
	return &ParameterExtractor{
		MaxParams:   MaxParameterCount,
		IgnoreEmpty: true,
		seen:        make(map[string]struct{}),
		Filters:     []ParameterFilter{},
	}
}

// AddCustomRegex 添加自定义正则表达式
func (pe *ParameterExtractor) AddCustomRegex(pattern string) error {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("编译正则表达式失败: %w", err)
	}
	pe.CustomRegexes = append(pe.CustomRegexes, regex)
	return nil
}

// AddFilter 添加参数过滤器
func (pe *ParameterExtractor) AddFilter(filter ParameterFilter) {
	pe.Filters = append(pe.Filters, filter)
}

// ExtractParameters 从给定的字符串内容中提取所有潜在的参数
func (pe *ParameterExtractor) ExtractParameters(content string) []models.Parameter {
	if content == "" {
		return nil
	}

	pe.mu.Lock()
	defer pe.mu.Unlock()

	var params []models.Parameter
	
	// 重置seen map
	pe.seen = make(map[string]struct{})

	// 从HTML属性中提取
	params = append(params, pe.extractFromHTML(content)...)
	
	// 从JavaScript中提取
	params = append(params, pe.extractFromJavaScript(content)...)
	
	// 从URL中提取
	params = append(params, pe.extractFromURLs(content)...)
	
	// 使用自定义正则提取
	for _, regex := range pe.CustomRegexes {
		params = append(params, pe.extractWithRegex(content, regex)...)
	}

	// 应用过滤器
	filteredParams := make([]models.Parameter, 0, len(params))
	for _, param := range params {
		if pe.shouldIncludeParameter(param) {
			filteredParams = append(filteredParams, param)
		}
	}

	// 限制参数数量
	if len(filteredParams) > pe.MaxParams {
		filteredParams = filteredParams[:pe.MaxParams]
	}

	log.Debug().
		Int("total_found", len(params)).
		Int("after_filter", len(filteredParams)).
		Msg("参数提取完成")

	return filteredParams
}

// extractFromHTML 从HTML中提取参数
func (pe *ParameterExtractor) extractFromHTML(content string) []models.Parameter {
	matches := htmlParamRegex.FindAllStringSubmatch(content, -1)
	var params []models.Parameter

	for _, match := range matches {
		if len(match) > 2 {
			paramName := strings.TrimSpace(match[2])
			if pe.addIfNotSeen(paramName) {
				params = append(params, models.Parameter{
					Name:   paramName,
					Type:   "html",
					Source: "attribute",
				})
			}
		}
	}

	return params
}

// extractFromJavaScript 从JavaScript中提取参数
func (pe *ParameterExtractor) extractFromJavaScript(content string) []models.Parameter {
	matches := jsParamRegex.FindAllStringSubmatch(content, -1)
	var params []models.Parameter

	for _, match := range matches {
		for i := 2; i < len(match); i++ {
			if match[i] != "" {
				paramName := strings.TrimSpace(match[i])
				if pe.addIfNotSeen(paramName) && isValidParameterName(paramName) {
					params = append(params, models.Parameter{
						Name:   paramName,
						Type:   "javascript",
						Source: "variable",
					})
				}
			}
		}
	}

	return params
}

// extractFromURLs 从URL中提取参数
func (pe *ParameterExtractor) extractFromURLs(content string) []models.Parameter {
	matches := urlParamRegex.FindAllStringSubmatch(content, -1)
	var params []models.Parameter

	for _, match := range matches {
		if len(match) > 1 {
			paramName := strings.TrimSpace(match[1])
			paramValue := ""
			if len(match) > 2 {
				paramValue = strings.TrimSpace(match[2])
			}
			
			if pe.addIfNotSeen(paramName) {
				params = append(params, models.Parameter{
					Name:   paramName,
					Value:  paramValue,
					Type:   "url",
					Source: "query",
				})
			}
		}
	}

	return params
}

// extractWithRegex 使用自定义正则提取参数
func (pe *ParameterExtractor) extractWithRegex(content string, regex *regexp.Regexp) []models.Parameter {
	matches := regex.FindAllStringSubmatch(content, -1)
	var params []models.Parameter

	for _, match := range matches {
		if len(match) > 1 {
			paramName := strings.TrimSpace(match[1])
			if pe.addIfNotSeen(paramName) && isValidParameterName(paramName) {
				params = append(params, models.Parameter{
					Name:   paramName,
					Type:   "custom",
					Source: "regex",
				})
			}
		}
	}

	return params
}

// addIfNotSeen 如果参数名未见过则添加
func (pe *ParameterExtractor) addIfNotSeen(paramName string) bool {
	if paramName == "" || (pe.IgnoreEmpty && strings.TrimSpace(paramName) == "") {
		return false
	}
	
	key := strings.ToLower(paramName)
	if _, exists := pe.seen[key]; exists {
		return false
	}
	
	pe.seen[key] = struct{}{}
	return true
}

// shouldIncludeParameter 判断是否应该包含该参数
func (pe *ParameterExtractor) shouldIncludeParameter(param models.Parameter) bool {
	for _, filter := range pe.Filters {
		if !filter(param) {
			return false
		}
	}
	return true
}

// isValidParameterName 验证参数名是否有效
func isValidParameterName(name string) bool {
	if name == "" || len(name) > 100 {
		return false
	}
	
	// 检查是否包含有效字符
	for _, r := range name {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '-' {
			return false
		}
	}
	
	return true
}

// 便利函数：创建常用的参数过滤器

// FilterSensitiveParams 过滤敏感参数
func FilterSensitiveParams() ParameterFilter {
	return func(param models.Parameter) bool {
		return !sensitiveRegex.MatchString(strings.ToLower(param.Name))
	}
}

// FilterShortParams 过滤过短的参数名
func FilterShortParams(minLength int) ParameterFilter {
	return func(param models.Parameter) bool {
		return len(param.Name) >= minLength
	}
}

// FilterCommonParams 过滤常见的无用参数
func FilterCommonParams() ParameterFilter {
	commonParams := map[string]bool{
		"utm_source": true, "utm_medium": true, "utm_campaign": true,
		"fbclid": true, "gclid": true, "_ga": true, "_gid": true,
		"timestamp": true, "cache": true, "v": true, "ver": true,
	}
	
	return func(param models.Parameter) bool {
		return !commonParams[strings.ToLower(param.Name)]
	}
}

// ExtractParameters 全局参数提取函数（向后兼容）
func ExtractParameters(content string) []models.Parameter {
	extractor := NewParameterExtractor()
	extractor.AddFilter(FilterShortParams(2))
	extractor.AddFilter(FilterCommonParams())
	return extractor.ExtractParameters(content)
}

// CloneRequest 创建请求的深拷贝
func CloneRequest(r *models.Request) *models.Request {
	if r == nil {
		return nil
	}

	clone := &models.Request{
		URL:    r.URL,
		Method: r.Method,
		Body:   r.Body,
	}

	// 深拷贝Headers
	if r.Headers != nil {
		clone.Headers = r.Headers.Clone()
	}

	// 深拷贝Params
	if r.Params != nil {
		clone.Params = make([]models.Parameter, len(r.Params))
		copy(clone.Params, r.Params)
	}

	return clone
}

// URLHelper URL处理助手
type URLHelper struct {
	baseURL *url.URL
	cache   map[string]string
	mu      sync.RWMutex
}

// NewURLHelper 创建URL助手
func NewURLHelper(baseURL string) (*URLHelper, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("解析基础URL失败: %w", err)
	}

	return &URLHelper{
		baseURL: u,
		cache:   make(map[string]string),
	}, nil
}

// ToAbsoluteURL 将相对URL转换为绝对URL
func (uh *URLHelper) ToAbsoluteURL(href string) string {
	if href == "" {
		return ""
	}

	// 检查缓存
	uh.mu.RLock()
	if cached, exists := uh.cache[href]; exists {
		uh.mu.RUnlock()
		return cached
	}
	uh.mu.RUnlock()

	result := uh.toAbsoluteURLInternal(href)

	// 缓存结果
	uh.mu.Lock()
	uh.cache[href] = result
	uh.mu.Unlock()

	return result
}

// toAbsoluteURLInternal 内部URL转换逻辑
func (uh *URLHelper) toAbsoluteURLInternal(href string) string {
	// 已经是绝对URL
	if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
		return href
	}

	// 跳过特殊协议
	if strings.HasPrefix(href, "javascript:") || 
	   strings.HasPrefix(href, "mailto:") || 
	   strings.HasPrefix(href, "tel:") || 
	   strings.HasPrefix(href, "data:") {
		return ""
	}

	// 解析相对URL
	absURL, err := uh.baseURL.Parse(href)
	if err != nil {
		log.Debug().Err(err).Str("href", href).Msg("URL解析失败")
		return ""
	}

	return absURL.String()
}

// ToAbsoluteURL 全局函数（向后兼容）
func ToAbsoluteURL(baseURL *url.URL, href string) string {
	if baseURL == nil {
		return ""
	}
	
	helper, err := NewURLHelper(baseURL.String())
	if err != nil {
		return ""
	}
	
	return helper.ToAbsoluteURL(href)
}

// HTMLExtractor HTML内容提取器
type HTMLExtractor struct {
	MaxLinks int `json:"max_links"`
	MaxForms int `json:"max_forms"`
}

// NewHTMLExtractor 创建HTML提取器
func NewHTMLExtractor() *HTMLExtractor {
	return &HTMLExtractor{
		MaxLinks: 10000,
		MaxForms: 1000,
	}
}

// ExtractLinksFromDoc 从HTML文档中提取链接
func (he *HTMLExtractor) ExtractLinksFromDoc(doc *goquery.Document) []string {
	if doc == nil {
		return nil
	}

	var links []string
	seen := make(map[string]bool)

	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		if len(links) >= he.MaxLinks {
			return
		}

		link, exists := s.Attr("href")
		if !exists || link == "" {
			return
		}

		// 去重
		if seen[link] {
			return
		}
		seen[link] = true

		links = append(links, link)
	})

	log.Debug().Int("count", len(links)).Msg("提取链接完成")
	return links
}

// ExtractFormsFromDoc 从HTML文档中提取表单
func (he *HTMLExtractor) ExtractFormsFromDoc(doc *goquery.Document, baseURL *url.URL) []*models.Request {
	if doc == nil || baseURL == nil {
		return nil
	}

	var requests []*models.Request

	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		if len(requests) >= he.MaxForms {
			return
		}

		request := he.extractSingleForm(s, baseURL)
		if request != nil {
			requests = append(requests, request)
		}
	})

	log.Debug().Int("count", len(requests)).Msg("提取表单完成")
	return requests
}

// extractSingleForm 提取单个表单
func (he *HTMLExtractor) extractSingleForm(form *goquery.Selection, baseURL *url.URL) *models.Request {
	action, _ := form.Attr("action")
	method, _ := form.Attr("method")
	
	if method == "" {
		method = "GET"
	}
	method = strings.ToUpper(method)

	// 解析表单action URL
	formURL, err := baseURL.Parse(action)
	if err != nil {
		log.Debug().Err(err).Str("action", action).Msg("表单action解析失败")
		return nil
	}

	// 提取表单参数
	var params []models.Parameter
	
	// 提取input字段
	form.Find("input").Each(func(j int, input *goquery.Selection) {
		param := he.extractInputParameter(input)
		if param != nil {
			params = append(params, *param)
		}
	})

	// 提取select字段
	form.Find("select").Each(func(j int, sel *goquery.Selection) {
		param := he.extractSelectParameter(sel)
		if param != nil {
			params = append(params, *param)
		}
	})

	// 提取textarea字段
	form.Find("textarea").Each(func(j int, textarea *goquery.Selection) {
		param := he.extractTextareaParameter(textarea)
		if param != nil {
			params = append(params, *param)
		}
	})

	return &models.Request{
		URL:    formURL.String(),
		Method: method,
		Params: params,
	}
}

// extractInputParameter 提取input参数
func (he *HTMLExtractor) extractInputParameter(input *goquery.Selection) *models.Parameter {
	name, nameExists := input.Attr("name")
	if !nameExists || name == "" {
		return nil
	}

	inputType, _ := input.Attr("type")
	value, _ := input.Attr("value")
	placeholder, _ := input.Attr("placeholder")

	param := &models.Parameter{
		Name:        name,
		Value:       value,
		Type:        "form",
		Source:      "input",
		Placeholder: placeholder,
	}

		// 根据input类型设置默认值
		switch strings.ToLower(inputType) {
		case "hidden":
			param.Source = "hidden"
		case "password":
			param.Sensitive = true
			if param.Value == "" {
				param.Value = "test123"
			}
		case "email":
			if param.Value == "" {
				param.Value = "test@example.com"
			}
		case "number":
			if param.Value == "" {
				param.Value = "123"
			}
		case "tel":
			if param.Value == "" {
				param.Value = "1234567890"
			}
		case "url":
			if param.Value == "" {
				param.Value = "http://example.com"
			}
		case "date":
			if param.Value == "" {
				param.Value = time.Now().Format("2006-01-02")
			}
		case "checkbox", "radio":
			if param.Value == "" {
				param.Value = "1"
			}
		default:
			if param.Value == "" && placeholder != "" {
				param.Value = "test_" + strings.ReplaceAll(placeholder, " ", "_")
			} else if param.Value == "" {
				param.Value = "test_value"
			}
		}
	
		return param
	}
	
	// extractSelectParameter 提取select参数
	func (he *HTMLExtractor) extractSelectParameter(sel *goquery.Selection) *models.Parameter {
		name, nameExists := sel.Attr("name")
		if !nameExists || name == "" {
			return nil
		}
	
		var value string
		var options []string
	
		// 收集所有选项
		sel.Find("option").Each(func(k int, option *goquery.Selection) {
			optValue, _ := option.Attr("value")
			if optValue == "" {
				optValue = option.Text()
			}
			options = append(options, optValue)
	
			// 使用第一个选项或选中的选项作为默认值
			if value == "" || option.Is(":selected") {
				value = optValue
			}
		})
	
		if value == "" && len(options) > 0 {
			value = options[0]
		}
	
		return &models.Parameter{
			Name:    name,
			Value:   value,
			Type:    "form",
			Source:  "select",
			Options: options,
		}
	}
	
	// extractTextareaParameter 提取textarea参数
	func (he *HTMLExtractor) extractTextareaParameter(textarea *goquery.Selection) *models.Parameter {
		name, nameExists := textarea.Attr("name")
		if !nameExists || name == "" {
			return nil
		}
	
		value := textarea.Text()
		placeholder, _ := textarea.Attr("placeholder")
	
		if value == "" {
			if placeholder != "" {
				value = "test_" + strings.ReplaceAll(placeholder, " ", "_")
			} else {
				value = "test_textarea_content"
			}
		}
	
		return &models.Parameter{
			Name:        name,
			Value:       value,
			Type:        "form",
			Source:      "textarea",
			Placeholder: placeholder,
		}
	}
	
	// ExtractLinksFromDoc 全局函数（向后兼容）
	func ExtractLinksFromDoc(doc *goquery.Document) []string {
		extractor := NewHTMLExtractor()
		return extractor.ExtractLinksFromDoc(doc)
	}
	
	// ExtractFormsFromDoc 全局函数（向后兼容）
	func ExtractFormsFromDoc(doc *goquery.Document, baseURL *url.URL) []*models.Request {
		extractor := NewHTMLExtractor()
		return extractor.ExtractFormsFromDoc(doc, baseURL)
	}
	
	// GetParamsFromURL 从URL字符串中解析查询参数
	func GetParamsFromURL(urlStr string) ([]models.Parameter, error) {
		if urlStr == "" {
			return nil, fmt.Errorf("URL不能为空")
		}
	
		u, err := url.Parse(urlStr)
		if err != nil {
			return nil, fmt.Errorf("URL解析失败: %w", err)
		}
	
		query := u.Query()
		params := make([]models.Parameter, 0, len(query))
	
		for key, values := range query {
			for _, value := range values {
				params = append(params, models.Parameter{
					Name:   key,
					Value:  value,
					Type:   "url",
					Source: "query",
				})
			}
		}
	
		// 按参数名排序以确保一致性
		sort.Slice(params, func(i, j int) bool {
			return params[i].Name < params[j].Name
		})
	
		return params, nil
	}
	
	// URLValidator URL验证器
	type URLValidator struct {
		AllowedSchemes []string `json:"allowed_schemes"`
		BlockedHosts   []string `json:"blocked_hosts"`
		MaxLength      int      `json:"max_length"`
	}
	
	// NewURLValidator 创建URL验证器
	func NewURLValidator() *URLValidator {
		return &URLValidator{
			AllowedSchemes: []string{"http", "https"},
			BlockedHosts:   []string{"localhost", "127.0.0.1", "0.0.0.0"},
			MaxLength:      MaxURLLength,
		}
	}
	
	// ValidateURL 验证URL
	func (uv *URLValidator) ValidateURL(urlStr string) error {
		if urlStr == "" {
			return fmt.Errorf("URL不能为空")
		}
	
		if len(urlStr) > uv.MaxLength {
			return fmt.Errorf("URL长度超过限制: %d", uv.MaxLength)
		}
	
		u, err := url.Parse(urlStr)
		if err != nil {
			return fmt.Errorf("URL格式无效: %w", err)
		}
	
		// 验证协议
		if !uv.isSchemeAllowed(u.Scheme) {
			return fmt.Errorf("不支持的协议: %s", u.Scheme)
		}
	
		// 验证主机
		if u.Host == "" {
			return fmt.Errorf("URL缺少主机")
		}
	
		// 检查被阻止的主机
		hostname := u.Hostname()
		if uv.isHostBlocked(hostname) {
			return fmt.Errorf("被阻止的主机: %s", hostname)
		}
	
		return nil
	}
	
	// isSchemeAllowed 检查协议是否被允许
	func (uv *URLValidator) isSchemeAllowed(scheme string) bool {
		for _, allowed := range uv.AllowedSchemes {
			if strings.EqualFold(scheme, allowed) {
				return true
			}
		}
		return false
	}
	
	// isHostBlocked 检查主机是否被阻止
	func (uv *URLValidator) isHostBlocked(hostname string) bool {
		hostname = strings.ToLower(hostname)
		
		for _, blocked := range uv.BlockedHosts {
			if hostname == strings.ToLower(blocked) {
				return true
			}
		}
	
		// 检查是否为内网IP
		if ip := net.ParseIP(hostname); ip != nil {
			if ip.IsLoopback() || ip.IsPrivate() {
				return true
			}
		}
	
		return false
	}
	
	// ContentAnalyzer 内容分析器
	type ContentAnalyzer struct {
		MaxContentSize int64 `json:"max_content_size"`
	}
	
	// NewContentAnalyzer 创建内容分析器
	func NewContentAnalyzer() *ContentAnalyzer {
		return &ContentAnalyzer{
			MaxContentSize: 10 * 1024 * 1024, // 10MB
		}
	}
	
	// AnalyzeContent 分析内容
	func (ca *ContentAnalyzer) AnalyzeContent(content string) *ContentInfo {
		if len(content) > int(ca.MaxContentSize) {
			content = content[:ca.MaxContentSize]
		}
	
		info := &ContentInfo{
			Size:        int64(len(content)),
			ContentType: ca.detectContentType(content),
			Encoding:    ca.detectEncoding(content),
			Language:    ca.detectLanguage(content),
			Emails:      ca.extractEmails(content),
			IPs:         ca.extractIPs(content),
			Domains:     ca.extractDomains(content),
			Hash:        ca.calculateHash(content),
		}
	
		return info
	}
	
	// ContentInfo 内容信息
	type ContentInfo struct {
		Size        int64    `json:"size"`
		ContentType string   `json:"content_type"`
		Encoding    string   `json:"encoding"`
		Language    string   `json:"language"`
		Emails      []string `json:"emails"`
		IPs         []string `json:"ips"`
		Domains     []string `json:"domains"`
		Hash        string   `json:"hash"`
	}
	
	// detectContentType 检测内容类型
	func (ca *ContentAnalyzer) detectContentType(content string) string {
		content = strings.TrimSpace(content)
		
		if strings.HasPrefix(content, "<!DOCTYPE html") || 
		   strings.HasPrefix(content, "<html") ||
		   strings.Contains(content, "<body") {
			return "text/html"
		}
		
		if strings.HasPrefix(content, "{") && strings.HasSuffix(content, "}") {
			return "application/json"
		}
		
		if strings.HasPrefix(content, "<?xml") {
			return "text/xml"
		}
		
		return "text/plain"
	}
	
	// detectEncoding 检测编码
	func (ca *ContentAnalyzer) detectEncoding(content string) string {
		// 简单的编码检测
		if strings.Contains(strings.ToLower(content), "charset=utf-8") {
			return "utf-8"
		}
		
		if strings.Contains(strings.ToLower(content), "charset=gbk") {
			return "gbk"
		}
		
		if strings.Contains(strings.ToLower(content), "charset=gb2312") {
			return "gb2312"
		}
		
		return "utf-8" // 默认
	}
	
	// detectLanguage 检测语言
	func (ca *ContentAnalyzer) detectLanguage(content string) string {
		// 简单的语言检测
		chineseCount := 0
		englishCount := 0
		
		for _, r := range content {
			if r >= 0x4e00 && r <= 0x9fff {
				chineseCount++
			} else if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				englishCount++
			}
		}
		
		if chineseCount > englishCount {
			return "zh"
		}
		
		return "en"
	}
	
	// extractEmails 提取邮箱地址
	func (ca *ContentAnalyzer) extractEmails(content string) []string {
		matches := emailRegex.FindAllString(content, -1)
		return removeDuplicates(matches)
	}
	
	// extractIPs 提取IP地址
	func (ca *ContentAnalyzer) extractIPs(content string) []string {
		matches := ipRegex.FindAllString(content, -1)
		var validIPs []string
		
		for _, match := range matches {
			if ip := net.ParseIP(match); ip != nil {
				validIPs = append(validIPs, match)
			}
		}
		
		return removeDuplicates(validIPs)
	}
	
	// extractDomains 提取域名
	func (ca *ContentAnalyzer) extractDomains(content string) []string {
		matches := domainRegex.FindAllString(content, -1)
		var validDomains []string
		
		for _, match := range matches {
			// 简单验证域名格式
			if strings.Contains(match, ".") && len(match) > 3 {
				validDomains = append(validDomains, strings.ToLower(match))
			}
		}
		
		return removeDuplicates(validDomains)
	}
	
	// calculateHash 计算内容哈希
	func (ca *ContentAnalyzer) calculateHash(content string) string {
		hash := sha256.Sum256([]byte(content))
		return hex.EncodeToString(hash[:])
	}
	
	// SecurityUtils 安全工具
	type SecurityUtils struct{}
	
	// NewSecurityUtils 创建安全工具
	func NewSecurityUtils() *SecurityUtils {
		return &SecurityUtils{}
	}
	
	// SanitizeInput 清理输入
	func (su *SecurityUtils) SanitizeInput(input string) string {
		// 移除控制字符
		result := strings.Map(func(r rune) rune {
			if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
				return -1
			}
			return r
		}, input)
		
		// 限制长度
		if len(result) > 10000 {
			result = result[:10000]
		}
		
		return strings.TrimSpace(result)
	}
	
	// IsSensitiveParameter 检查是否为敏感参数
	func (su *SecurityUtils) IsSensitiveParameter(name string) bool {
		return sensitiveRegex.MatchString(strings.ToLower(name))
	}
	
	// GenerateRandomString 生成随机字符串
	func (su *SecurityUtils) GenerateRandomString(length int) string {
		if length <= 0 {
			length = 8
		}
		
		const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		result := make([]byte, length)
		
		for i := range result {
			result[i] = charset[time.Now().UnixNano()%int64(len(charset))]
		}
		
		return string(result)
	}
	
	// HashString 计算字符串哈希
	func (su *SecurityUtils) HashString(input string) string {
		hash := md5.Sum([]byte(input))
		return hex.EncodeToString(hash[:])
	}
	
	// MaskSensitiveData 掩码敏感数据
	func (su *SecurityUtils) MaskSensitiveData(data string) string {
		if len(data) <= 4 {
			return "****"
		}
		
		return data[:2] + strings.Repeat("*", len(data)-4) + data[len(data)-2:]
	}
	
	// PerformanceMonitor 性能监控器
	type PerformanceMonitor struct {
		startTime time.Time
		metrics   map[string]time.Duration
		mu        sync.RWMutex
	}
	
	// NewPerformanceMonitor 创建性能监控器
	func NewPerformanceMonitor() *PerformanceMonitor {
		return &PerformanceMonitor{
			startTime: time.Now(),
			metrics:   make(map[string]time.Duration),
		}
	}
	
	// StartTimer 开始计时
	func (pm *PerformanceMonitor) StartTimer(name string) func() {
		start := time.Now()
		return func() {
			duration := time.Since(start)
			pm.mu.Lock()
			pm.metrics[name] = duration
			pm.mu.Unlock()
			
			log.Debug().
				Str("operation", name).
				Dur("duration", duration).
				Msg("操作完成")
		}
	}
	
	// GetMetrics 获取性能指标
	func (pm *PerformanceMonitor) GetMetrics() map[string]time.Duration {
		pm.mu.RLock()
		defer pm.mu.RUnlock()
		
		result := make(map[string]time.Duration)
		for k, v := range pm.metrics {
			result[k] = v
		}
		
		return result
	}
	
	// GetTotalTime 获取总时间
	func (pm *PerformanceMonitor) GetTotalTime() time.Duration {
		return time.Since(pm.startTime)
	}
	
	// 工具函数
	
	// removeDuplicates 去除字符串切片中的重复项
	func removeDuplicates(slice []string) []string {
		if len(slice) == 0 {
			return slice
		}
		
		seen := make(map[string]bool)
		result := make([]string, 0, len(slice))
		
		for _, item := range slice {
			if item != "" && !seen[item] {
				seen[item] = true
				result = append(result, item)
			}
		}
		
		return result
	}
	
	// NormalizeURL 规范化URL
	func NormalizeURL(urlStr string) (string, error) {
		if urlStr == "" {
			return "", fmt.Errorf("URL不能为空")
		}
		
		u, err := url.Parse(urlStr)
		if err != nil {
			return "", fmt.Errorf("URL解析失败: %w", err)
		}
		
		// 规范化协议
		u.Scheme = strings.ToLower(u.Scheme)
		
		// 规范化主机名
		u.Host = strings.ToLower(u.Host)
		
		// 移除默认端口
		if (u.Scheme == "http" && strings.HasSuffix(u.Host, ":80")) ||
		   (u.Scheme == "https" && strings.HasSuffix(u.Host, ":443")) {
			u.Host = u.Host[:strings.LastIndex(u.Host, ":")]
		}
		
		// 规范化路径
		if u.Path == "" {
			u.Path = "/"
		}
		
		return u.String(), nil
	}
	
	// IsValidDomain 验证域名格式
	func IsValidDomain(domain string) bool {
		if domain == "" || len(domain) > 253 {
			return false
		}
		
		// 域名不能以点开始或结束
		if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
			return false
		}
		
		// 检查域名格式
		parts := strings.Split(domain, ".")
		if len(parts) < 2 {
			return false
		}
		
		for _, part := range parts {
			if len(part) == 0 || len(part) > 63 {
				return false
			}
			
			// 检查字符
			for _, r := range part {
				if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' {
					return false
				}
			}
			
			// 不能以连字符开始或结束
			if strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
				return false
			}
		}
		
		return true
	}
	
	// IsValidIP 验证IP地址
	func IsValidIP(ip string) bool {
		return net.ParseIP(ip) != nil
	}
	
	// GetDomainFromURL 从URL中提取域名
	func GetDomainFromURL(urlStr string) (string, error) {
		u, err := url.Parse(urlStr)
		if err != nil {
			return "", fmt.Errorf("URL解析失败: %w", err)
		}
		
		return u.Hostname(), nil
	}
	
	// BuildURL 构建URL
	func BuildURL(base string, params map[string]string) (string, error) {
		u, err := url.Parse(base)
		if err != nil {
			return "", fmt.Errorf("基础URL解析失败: %w", err)
		}
		
		if len(params) == 0 {
			return u.String(), nil
		}
		
		q := u.Query()
		for key, value := range params {
			q.Set(key, value)
		}
		u.RawQuery = q.Encode()
		
		return u.String(), nil
	}
	
	// ParseUserAgent 解析User-Agent
	func ParseUserAgent(ua string) map[string]string {
		result := make(map[string]string)
		result["raw"] = ua
		
		// 简单的User-Agent解析
		ua = strings.ToLower(ua)
		
		if strings.Contains(ua, "chrome") {
			result["browser"] = "chrome"
		} else if strings.Contains(ua, "firefox") {
			result["browser"] = "firefox"
		} else if strings.Contains(ua, "safari") {
			result["browser"] = "safari"
		} else if strings.Contains(ua, "edge") {
			result["browser"] = "edge"
		} else {
			result["browser"] = "unknown"
		}
		
		if strings.Contains(ua, "windows") {
			result["os"] = "windows"
		} else if strings.Contains(ua, "mac") {
			result["os"] = "macos"
		} else if strings.Contains(ua, "linux") {
			result["os"] = "linux"
		} else if strings.Contains(ua, "android") {
			result["os"] = "android"
		} else if strings.Contains(ua, "ios") {
			result["os"] = "ios"
		} else {
			result["os"] = "unknown"
		}
		
		return result
	}
	
	// FormatBytes 格式化字节数
	func FormatBytes(bytes int64) string {
		const unit = 1024
		if bytes < unit {
			return fmt.Sprintf("%d B", bytes)
		}
		
		div, exp := int64(unit), 0
		for n := bytes / unit; n >= unit; n /= unit {
			div *= unit
			exp++
		}
		
		return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
	}
	
	// FormatDuration 格式化时间间隔
	func FormatDuration(d time.Duration) string {
		if d < time.Microsecond {
			return fmt.Sprintf("%.0fns", float64(d.Nanoseconds()))
		} else if d < time.Millisecond {
			return fmt.Sprintf("%.2fµs", float64(d.Nanoseconds())/1000)
		} else if d < time.Second {
			return fmt.Sprintf("%.2fms", float64(d.Nanoseconds())/1000000)
		} else if d < time.Minute {
			return fmt.Sprintf("%.2fs", d.Seconds())
		} else if d < time.Hour {
			return fmt.Sprintf("%.1fm", d.Minutes())
		} else {
			return fmt.Sprintf("%.1fh", d.Hours())
		}
	}
	
	// TruncateString 截断字符串
	func TruncateString(s string, maxLen int) string {
		if len(s) <= maxLen {
			return s
		}
		
		if maxLen <= 3 {
			return s[:maxLen]
		}
		
		return s[:maxLen-3] + "..."
	}
	
	// ContainsAny 检查字符串是否包含任意一个子字符串
	func ContainsAny(s string, substrings []string) bool {
		for _, substr := range substrings {
			if strings.Contains(s, substr) {
				return true
			}
		}
		return false
	}
	
	// ContainsAll 检查字符串是否包含所有子字符串
	func ContainsAll(s string, substrings []string) bool {
		for _, substr := range substrings {
			if !strings.Contains(s, substr) {
				return false
			}
		}
		return true
	}
	
	// RandomChoice 从切片中随机选择一个元素
	func RandomChoice(choices []string) string {
		if len(choices) == 0 {
			return ""
		}
		
		index := time.Now().UnixNano() % int64(len(choices))
		return choices[index]
	}
	
	// MergeStringSlices 合并字符串切片并去重
	func MergeStringSlices(slices ...[]string) []string {
		seen := make(map[string]bool)
		var result []string
		
		for _, slice := range slices {
			for _, item := range slice {
				if item != "" && !seen[item] {
					seen[item] = true
					result = append(result, item)
				}
			}
		}
		
		return result
	}
	
	// FilterStringSlice 过滤字符串切片
	func FilterStringSlice(slice []string, predicate func(string) bool) []string {
		var result []string
		for _, item := range slice {
			if predicate(item) {
				result = append(result, item)
			}
		}
		return result
	}
	
	// MapStringSlice 映射字符串切片
	func MapStringSlice(slice []string, mapper func(string) string) []string {
		result := make([]string, len(slice))
		for i, item := range slice {
			result[i] = mapper(item)
		}
		return result
	}
	