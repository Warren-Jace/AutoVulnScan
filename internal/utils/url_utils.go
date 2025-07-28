// Package utils 提供了通用的工具函数，包括URL处理、字符串操作、验证等功能
package utils

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"unicode"

	"github.com/rs/zerolog/log"
)

// 常量定义
const (
	// URL相关常量
	MaxURLLength     = 8192
	MaxHostnameLength = 253
	MaxPathLength    = 2048
	
	// 默认协议
	DefaultScheme = "https"
	
	// 支持的协议
	HTTPScheme  = "http"
	HTTPSScheme = "https"
)

// 预编译的正则表达式（性能优化）
var (
	// 匹配有效的URL字符
	validURLRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:`)
	
	// 匹配IPv4地址
	ipv4Regex = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	
	// 匹配IPv6地址（简化版）
	ipv6Regex = regexp.MustCompile(`^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$`)
	
	// 需要忽略的协议前缀
	ignoredPrefixes = []string{
		"javascript:",
		"mailto:",
		"tel:",
		"ftp:",
		"file:",
		"data:",
		"blob:",
		"about:",
		"chrome:",
		"chrome-extension:",
		"moz-extension:",
		"safari-extension:",
	}
	
	// 需要忽略的片段标识符
	ignoredFragments = []string{
		"#",
		"#top",
		"#bottom",
		"#main",
		"#content",
	}
	
	// 初始化锁
	initOnce sync.Once
	
	// URL缓存（可选的性能优化）
	urlCache = make(map[string]string)
	cacheMu  sync.RWMutex
)

// URLProcessor URL处理器
type URLProcessor struct {
	// 配置选项
	MaxURLLength      int      `json:"max_url_length"`
	AllowedSchemes    []string `json:"allowed_schemes"`
	IgnoredPrefixes   []string `json:"ignored_prefixes"`
	IgnoredFragments  []string `json:"ignored_fragments"`
	EnableCache       bool     `json:"enable_cache"`
	NormalizeURL      bool     `json:"normalize_url"`
	RemoveFragment    bool     `json:"remove_fragment"`
	RemoveQuery       bool     `json:"remove_query"`
	
	// 内部缓存
	cache map[string]string
	mu    sync.RWMutex
}

// NewURLProcessor 创建URL处理器
func NewURLProcessor() *URLProcessor {
	return &URLProcessor{
		MaxURLLength:     MaxURLLength,
		AllowedSchemes:   []string{HTTPScheme, HTTPSScheme},
		IgnoredPrefixes:  ignoredPrefixes,
		IgnoredFragments: ignoredFragments,
		EnableCache:      true,
		NormalizeURL:     true,
		RemoveFragment:   false,
		RemoveQuery:      false,
		cache:           make(map[string]string),
	}
}

// ToAbsoluteURL 将相对URL转换为绝对URL（增强版）
func (up *URLProcessor) ToAbsoluteURL(baseURL *url.URL, href string) string {
	if baseURL == nil {
		log.Debug().Msg("baseURL为空")
		return ""
	}

	// 检查缓存
	if up.EnableCache {
		cacheKey := baseURL.String() + "|" + href
		up.mu.RLock()
		if cached, exists := up.cache[cacheKey]; exists {
			up.mu.RUnlock()
			return cached
		}
		up.mu.RUnlock()
	}

	result := up.processURL(baseURL, href)

	// 缓存结果
	if up.EnableCache && result != "" {
		cacheKey := baseURL.String() + "|" + href
		up.mu.Lock()
		up.cache[cacheKey] = result
		up.mu.Unlock()
	}

	return result
}

// processURL 内部URL处理逻辑
func (up *URLProcessor) processURL(baseURL *url.URL, href string) string {
	// 1. 基础验证和清理
	cleanHref := up.cleanHref(href)
	if cleanHref == "" {
		return ""
	}

	// 2. 检查是否应该忽略
	if up.shouldIgnore(cleanHref) {
		log.Debug().Str("href", cleanHref).Msg("URL被忽略")
		return ""
	}

	// 3. 解析URL
	parsedURL, err := url.Parse(cleanHref)
	if err != nil {
		log.Debug().Err(err).Str("href", cleanHref).Msg("URL解析失败")
		return ""
	}

	// 4. 处理绝对URL
	if parsedURL.IsAbs() {
		return up.processAbsoluteURL(parsedURL)
	}

	// 5. 处理相对URL
	return up.processRelativeURL(baseURL, parsedURL)
}

// cleanHref 清理href字符串
func (up *URLProcessor) cleanHref(href string) string {
	// 去除前后空格
	cleaned := strings.TrimSpace(href)
	if cleaned == "" {
		return ""
	}

	// 检查长度限制
	if len(cleaned) > up.MaxURLLength {
		log.Debug().
			Str("href", cleaned[:100]+"...").
			Int("length", len(cleaned)).
			Msg("URL长度超过限制")
		return ""
	}

	// 解码HTML实体（简单处理）
	cleaned = strings.ReplaceAll(cleaned, "&amp;", "&")
	cleaned = strings.ReplaceAll(cleaned, "&lt;", "<")
	cleaned = strings.ReplaceAll(cleaned, "&gt;", ">")
	cleaned = strings.ReplaceAll(cleaned, "&quot;", "\"")
	cleaned = strings.ReplaceAll(cleaned, "&#39;", "'")

	// 移除不可见字符
	cleaned = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\t' {
			return -1
		}
		return r
	}, cleaned)

	return cleaned
}

// shouldIgnore 检查是否应该忽略URL
func (up *URLProcessor) shouldIgnore(href string) bool {
	lowerHref := strings.ToLower(href)

	// 检查忽略的前缀
	for _, prefix := range up.IgnoredPrefixes {
		if strings.HasPrefix(lowerHref, prefix) {
			return true
		}
	}

	// 检查忽略的片段
	for _, fragment := range up.IgnoredFragments {
		if href == fragment {
			return true
		}
	}

	// 检查是否只是查询参数或片段
	if strings.HasPrefix(href, "?") || strings.HasPrefix(href, "#") {
		return true
	}

	return false
}

// processAbsoluteURL 处理绝对URL
func (up *URLProcessor) processAbsoluteURL(parsedURL *url.URL) string {
	// 验证协议
	if !up.isSchemeAllowed(parsedURL.Scheme) {
		log.Debug().Str("scheme", parsedURL.Scheme).Msg("不支持的协议")
		return ""
	}

	// 验证主机
	if !up.isValidHost(parsedURL.Host) {
		log.Debug().Str("host", parsedURL.Host).Msg("无效的主机")
		return ""
	}

	// 应用配置选项
	if up.RemoveFragment {
		parsedURL.Fragment = ""
	}

	if up.RemoveQuery {
		parsedURL.RawQuery = ""
	}

	if up.NormalizeURL {
		up.normalizeURL(parsedURL)
	}

	return parsedURL.String()
}

// processRelativeURL 处理相对URL
func (up *URLProcessor) processRelativeURL(baseURL *url.URL, parsedURL *url.URL) string {
	// 使用ResolveReference解析相对URL
	absoluteURL := baseURL.ResolveReference(parsedURL)

	// 验证结果
	if !up.isSchemeAllowed(absoluteURL.Scheme) {
		return ""
	}

	if !up.isValidHost(absoluteURL.Host) {
		return ""
	}

	// 应用配置选项
	if up.RemoveFragment {
		absoluteURL.Fragment = ""
	}

	if up.RemoveQuery {
		absoluteURL.RawQuery = ""
	}

	if up.NormalizeURL {
		up.normalizeURL(absoluteURL)
	}

	return absoluteURL.String()
}

// isSchemeAllowed 检查协议是否被允许
func (up *URLProcessor) isSchemeAllowed(scheme string) bool {
	if scheme == "" {
		return false
	}

	lowerScheme := strings.ToLower(scheme)
	for _, allowed := range up.AllowedSchemes {
		if lowerScheme == strings.ToLower(allowed) {
			return true
		}
	}

	return false
}

// isValidHost 验证主机名
func (up *URLProcessor) isValidHost(host string) bool {
	if host == "" {
		return false
	}

	// 检查长度
	if len(host) > MaxHostnameLength {
		return false
	}

	// 分离主机名和端口
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		// 如果没有端口，host就是hostname
		hostname = host
	}

	// 检查是否为IP地址
	if net.ParseIP(hostname) != nil {
		return true
	}

	// 检查域名格式
	return up.isValidDomain(hostname)
}

// isValidDomain 验证域名格式
func (up *URLProcessor) isValidDomain(domain string) bool {
	if domain == "" || len(domain) > MaxHostnameLength {
		return false
	}

	// 域名不能以点开始或结束
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}

	// 检查域名各部分
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}

	for _, part := range parts {
		if !up.isValidDomainPart(part) {
			return false
		}
	}

	return true
}

// isValidDomainPart 验证域名部分
func (up *URLProcessor) isValidDomainPart(part string) bool {
	if len(part) == 0 || len(part) > 63 {
		return false
	}

	// 不能以连字符开始或结束
	if strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
		return false
	}

	// 检查字符
	for _, r := range part {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' {
			return false
		}
	}

	return true
}

// normalizeURL 规范化URL
func (up *URLProcessor) normalizeURL(u *url.URL) {
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

	// 清理路径中的多余斜杠
	u.Path = regexp.MustCompile(`/+`).ReplaceAllString(u.Path, "/")
}

// URLValidator URL验证器
type URLValidator struct {
	MaxLength      int      `json:"max_length"`
	AllowedSchemes []string `json:"allowed_schemes"`
	BlockedHosts   []string `json:"blocked_hosts"`
	AllowLocalhost bool     `json:"allow_localhost"`
	AllowPrivateIP bool     `json:"allow_private_ip"`
}

// NewURLValidator 创建URL验证器
func NewURLValidator() *URLValidator {
	return &URLValidator{
		MaxLength:      MaxURLLength,
		AllowedSchemes: []string{HTTPScheme, HTTPSScheme},
		BlockedHosts:   []string{},
		AllowLocalhost: false,
		AllowPrivateIP: false,
	}
}

// ValidateURL 验证URL
func (uv *URLValidator) ValidateURL(urlStr string) error {
	if urlStr == "" {
		return fmt.Errorf("URL不能为空")
	}

	if len(urlStr) > uv.MaxLength {
		return fmt.Errorf("URL长度超过限制: %d > %d", len(urlStr), uv.MaxLength)
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

	// 检查localhost
	if !uv.AllowLocalhost && uv.isLocalhost(hostname) {
		return fmt.Errorf("不允许访问localhost: %s", hostname)
	}

	// 检查私有IP
	if !uv.AllowPrivateIP && uv.isPrivateIP(hostname) {
		return fmt.Errorf("不允许访问私有IP: %s", hostname)
	}

	return nil
}

// isSchemeAllowed 检查协议是否被允许
func (uv *URLValidator) isSchemeAllowed(scheme string) bool {
	lowerScheme := strings.ToLower(scheme)
	for _, allowed := range uv.AllowedSchemes {
		if lowerScheme == strings.ToLower(allowed) {
			return true
		}
	}
	return false
}

// isHostBlocked 检查主机是否被阻止
func (uv *URLValidator) isHostBlocked(hostname string) bool {
	lowerHostname := strings.ToLower(hostname)
	for _, blocked := range uv.BlockedHosts {
		if lowerHostname == strings.ToLower(blocked) {
			return true
		}
	}
	return false
}

// isLocalhost 检查是否为localhost
func (uv *URLValidator) isLocalhost(hostname string) bool {
	lowerHostname := strings.ToLower(hostname)
	return lowerHostname == "localhost" || lowerHostname == "127.0.0.1" || lowerHostname == "::1"
}

// isPrivateIP 检查是否为私有IP
func (uv *URLValidator) isPrivateIP(hostname string) bool {
	ip := net.ParseIP(hostname)
	if ip == nil {
		return false
	}
	return ip.IsPrivate()
}

// URLBuilder URL构建器
type URLBuilder struct {
	scheme   string
	host     string
	path     string
	query    url.Values
	fragment string
}

// NewURLBuilder 创建URL构建器
func NewURLBuilder(baseURL string) (*URLBuilder, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("解析基础URL失败: %w", err)
	}

	return &URLBuilder{
		scheme: u.Scheme,
		host:   u.Host,
		path:   u.Path,
		query:  u.Query(),
		fragment: u.Fragment,
	}, nil
}

// SetScheme 设置协议
func (ub *URLBuilder) SetScheme(scheme string) *URLBuilder {
	ub.scheme = scheme
	return ub
}

// SetHost 设置主机
func (ub *URLBuilder) SetHost(host string) *URLBuilder {
	ub.host = host
	return ub
}

// SetPath 设置路径
func (ub *URLBuilder) SetPath(path string) *URLBuilder {
	ub.path = path
	return ub
}

// AddQuery 添加查询参数
func (ub *URLBuilder) AddQuery(key, value string) *URLBuilder {
	ub.query.Add(key, value)
	return ub
}

// SetQuery 设置查询参数
func (ub *URLBuilder) SetQuery(key, value string) *URLBuilder {
	ub.query.Set(key, value)
	return ub
}

// SetFragment 设置片段
func (ub *URLBuilder) SetFragment(fragment string) *URLBuilder {
	ub.fragment = fragment
	return ub
}

// Build 构建URL
func (ub *URLBuilder) Build() string {
	u := &url.URL{
		Scheme:   ub.scheme,
		Host:     ub.host,
		Path:     ub.path,
		RawQuery: ub.query.Encode(),
		Fragment: ub.fragment,
	}
	return u.String()
}

// 全局便利函数（向后兼容）

// ToAbsoluteURL 将相对URL转换为绝对URL（全局函数）
func ToAbsoluteURL(baseURL *url.URL, href string) string {
	processor := NewURLProcessor()
	return processor.ToAbsoluteURL(baseURL, href)
}

// NormalizeURL 规范化URL
func NormalizeURL(urlStr string) (string, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return "", fmt.Errorf("URL解析失败: %w", err)
	}

	processor := NewURLProcessor()
	processor.normalizeURL(u)

	return u.String(), nil
}

// IsValidURL 检查URL是否有效
func IsValidURL(urlStr string) bool {
	validator := NewURLValidator()
	return validator.ValidateURL(urlStr) == nil
}

// GetDomainFromURL 从URL中提取域名
func GetDomainFromURL(urlStr string) (string, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return "", fmt.Errorf("URL解析失败: %w", err)
	}
	return u.Hostname(), nil
}

// JoinURL 连接URL路径
func JoinURL(base, path string) (string, error) {
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("基础URL解析失败: %w", err)
	}

	pathURL, err := url.Parse(path)
	if err != nil {
		return "", fmt.Errorf("路径URL解析失败: %w", err)
	}

	return baseURL.ResolveReference(pathURL).String(), nil
}

// ParseQueryString 解析查询字符串
func ParseQueryString(query string) (map[string][]string, error) {
	values, err := url.ParseQuery(query)
	if err != nil {
		return nil, fmt.Errorf("查询字符串解析失败: %w", err)
	}

	result := make(map[string][]string)
	for key, vals := range values {
		result[key] = vals
	}

	return result, nil
}

// BuildQueryString 构建查询字符串
func BuildQueryString(params map[string][]string) string {
	values := make(url.Values)
	for key, vals := range params {
		for _, val := range vals {
			values.Add(key, val)
		}
	}
	return values.Encode()
}

// ExtractURLs 从文本中提取URL
func ExtractURLs(text string) []string {
	// 简单的URL提取正则
	urlRegex := regexp.MustCompile(`https?://[^\s<>"{}|\\^` + "`" + `\[\]]+`)
	matches := urlRegex.FindAllString(text, -1)

	var validURLs []string
	validator := NewURLValidator()

	for _, match := range matches {
		if validator.ValidateURL(match) == nil {
			validURLs = append(validURLs, match)
		}
	}

	return validURLs
}

// SanitizeURL 清理URL中的危险字符
func SanitizeURL(urlStr string) string {
	// 移除控制字符和不可见字符
	cleaned := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, urlStr)

	// 去除前后空格
	cleaned = strings.TrimSpace(cleaned)

	return cleaned
}

// CompareURLs 比较两个URL是否相同（规范化后）
func CompareURLs(url1, url2 string) bool {
	norm1, err1 := NormalizeURL(url1)
	norm2, err2 := NormalizeURL(url2)

	if err1 != nil || err2 != nil {
		return false
	}

	return norm1 == norm2
}

// GetURLDepth 获取URL的路径深度
func GetURLDepth(urlStr string) int {
	u, err := url.Parse(urlStr)
	if err != nil {
		return 0
	}

	if u.Path == "" || u.Path == "/" {
		return 0
	}

	// 计算路径段数
	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	depth := 0
	for _, segment := range segments {
		if segment != "" {
			depth++
		}
	}

	return depth
}

// IsSubdomain 检查是否为子域名
func IsSubdomain(subdomain, domain string) bool {
	if subdomain == domain {
		return false
	}

	return strings.HasSuffix(strings.ToLower(subdomain), "."+strings.ToLower(domain))
}

// GetURLWithoutQuery 获取不包含查询参数的URL
func GetURLWithoutQuery(urlStr string) (string, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return "", fmt.Errorf("URL解析失败: %w", err)
	}

	u.RawQuery = ""
	u.Fragment = ""

	return u.String(), nil
}
