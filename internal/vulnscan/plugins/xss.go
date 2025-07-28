// Package plugins 包含了所有具体的漏洞扫描插件实现。
package plugins

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"autovulnscan/internal/browser"
	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"
	"autovulnscan/internal/vulnscan"

	"github.com/rs/zerolog/log"
)

// XSSPlugin 实现了用于检测跨站脚本（XSS）漏洞的插件。
// 支持反射型、存储型和DOM型XSS检测。
type XSSPlugin struct {
	vulnscan.BasePlugin
	
	// 核心组件
	browserService *browser.BrowserService
	httpClient     *requester.HTTPClient
	
	// 检测配置
	config XSSConfig
	
	// 缓存和状态
	responseCache  sync.Map // URL -> *models.ResponseInfo
	payloadCache   sync.Map // 缓存生成的payloads
	
	// 统计信息
	stats XSSStats
	
	// 正则表达式（预编译）
	reflectionRegex    *regexp.Regexp
	scriptTagRegex     *regexp.Regexp
	eventHandlerRegex  *regexp.Regexp
	javascriptRegex    *regexp.Regexp
	
	// 互斥锁
	mu sync.RWMutex
}

// XSSConfig XSS插件配置
type XSSConfig struct {
	// 基础配置
	MaxPayloads         int           `json:"max_payloads"`          // 最大payload数量
	Timeout             time.Duration `json:"timeout"`               // 请求超时
	DOMVerificationTimeout time.Duration `json:"dom_verification_timeout"` // DOM验证超时
	
	// 检测配置
	EnableReflectedXSS  bool `json:"enable_reflected_xss"`   // 启用反射型XSS检测
	EnableStoredXSS     bool `json:"enable_stored_xss"`      // 启用存储型XSS检测
	EnableDOMXSS        bool `json:"enable_dom_xss"`         // 启用DOM型XSS检测
	EnableDOMVerification bool `json:"enable_dom_verification"` // 启用DOM验证
	
	// 响应分析配置
	MinResponseDiff     int     `json:"min_response_diff"`      // 最小响应差异（字节）
	MaxResponseDiffRatio float64 `json:"max_response_diff_ratio"` // 最大响应差异比例
	EnableContentAnalysis bool   `json:"enable_content_analysis"` // 启用内容分析
	
	// WAF检测配置
	EnableWAFDetection  bool `json:"enable_waf_detection"`   // 启用WAF检测
	WAFThreshold        int  `json:"waf_threshold"`          // WAF检测阈值
	
	// 编码检测
	DetectEncodedPayloads bool `json:"detect_encoded_payloads"` // 检测编码后的payload
	
	// 误报减少
	EnableFalsePositiveReduction bool `json:"enable_false_positive_reduction"`
	ConfidenceThreshold         float64 `json:"confidence_threshold"`
}

// XSSStats XSS插件统计信息
type XSSStats struct {
	TotalRequests      int64 `json:"total_requests"`
	SuccessfulTests    int64 `json:"successful_tests"`
	ReflectedXSSFound  int64 `json:"reflected_xss_found"`
	StoredXSSFound     int64 `json:"stored_xss_found"`
	DOMXSSFound        int64 `json:"dom_xss_found"`
	FalsePositives     int64 `json:"false_positives"`
	WAFDetections      int64 `json:"waf_detections"`
	DOMVerifications   int64 `json:"dom_verifications"`
	AverageResponseTime time.Duration `json:"average_response_time"`
}

// XSSType XSS类型枚举
type XSSType int

const (
	XSSTypeReflected XSSType = iota
	XSSTypeStored
	XSSTypeDOM
)

// String 返回XSS类型字符串
func (t XSSType) String() string {
	switch t {
	case XSSTypeReflected:
		return "Reflected"
	case XSSTypeStored:
		return "Stored"
	case XSSTypeDOM:
		return "DOM"
	default:
		return "Unknown"
	}
}

// XSSContext XSS检测上下文
type XSSContext struct {
	OriginalRequest *models.Request
	Parameter       models.Parameter
	Payload         string
	XSSType         XSSType
	Context         context.Context
}

// XSSResult XSS检测结果
type XSSResult struct {
	Vulnerable    bool
	Confidence    float64
	Evidence      []vulnscan.Evidence
	XSSType       XSSType
	Payload       string
	Response      *models.ResponseInfo
	DOMVerified   bool
	WAFDetected   bool
}

// 默认配置
var defaultXSSConfig = XSSConfig{
	MaxPayloads:                     50,
	Timeout:                        30 * time.Second,
	DOMVerificationTimeout:         15 * time.Second,
	EnableReflectedXSS:             true,
	EnableStoredXSS:                false, // 需要特殊处理
	EnableDOMXSS:                   true,
	EnableDOMVerification:          true,
	MinResponseDiff:                10,
	MaxResponseDiffRatio:           0.1,
	EnableContentAnalysis:          true,
	EnableWAFDetection:             true,
	WAFThreshold:                   5,
	DetectEncodedPayloads:          true,
	EnableFalsePositiveReduction:   true,
	ConfidenceThreshold:            0.7,
}

// init 函数会在包初始化时被调用，用于自动注册插件。
func init() {
	plugin := NewXSSPlugin()
	vulnscan.RegisterPlugin(plugin)
}

// NewXSSPlugin 创建新的XSS插件实例
func NewXSSPlugin() *XSSPlugin {
	info := vulnscan.PluginInfo{
		Name:        "xss",
		Description: "检测反射型、存储型和DOM型跨站脚本（XSS）漏洞",
		Author:      "AutoVulnScan Team",
		Version:     "2.0",
		Category:    "injection",
		Severity:    vulnscan.SeverityHigh,
		Tags:        []string{"xss", "injection", "web", "client-side"},
		References: []string{
			"https://owasp.org/www-community/attacks/xss/",
			"https://portswigger.net/web-security/cross-site-scripting",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	
	plugin := &XSSPlugin{
		BasePlugin: *vulnscan.NewBasePlugin(info),
		config:     defaultXSSConfig,
	}
	
	// 预编译正则表达式
	plugin.compileRegexes()
	
	return plugin
}

// compileRegexes 预编译正则表达式
func (p *XSSPlugin) compileRegexes() {
	var err error
	
	// 反射检测正则
	p.reflectionRegex, err = regexp.Compile(`(?i)<script[^>]*>.*?</script>|javascript:|on\w+\s*=`)
	if err != nil {
		log.Warn().Err(err).Msg("编译反射检测正则失败")
	}
	
	// Script标签检测
	p.scriptTagRegex, err = regexp.Compile(`(?i)<script[^>]*>.*?</script>`)
	if err != nil {
		log.Warn().Err(err).Msg("编译script标签正则失败")
	}
	
	// 事件处理器检测
	p.eventHandlerRegex, err = regexp.Compile(`(?i)on\w+\s*=\s*["']?[^"']*["']?`)
	if err != nil {
		log.Warn().Err(err).Msg("编译事件处理器正则失败")
	}
	
	// JavaScript协议检测
	p.javascriptRegex, err = regexp.Compile(`(?i)javascript:\s*`)
	if err != nil {
		log.Warn().Err(err).Msg("编译JavaScript协议正则失败")
	}
}

// Initialize 实现Plugin接口
func (p *XSSPlugin) Initialize() error {
	if err := p.BasePlugin.Initialize(); err != nil {
		return err
	}
	
	// 初始化默认payloads
	if len(p.GetDefaultPayloads()) == 0 {
		p.SetPayloads(p.generateDefaultPayloads())
	}
	
	log.Info().
		Str("plugin", p.Info().Name).
		Int("payloads", len(p.GetDefaultPayloads())).
		Msg("XSS插件初始化完成")
	
	return nil
}

// Configure 实现ConfigurablePlugin接口
func (p *XSSPlugin) Configure(config vulnscan.PluginConfig) error {
	if err := p.BasePlugin.Configure(config); err != nil {
		return err
	}
	
	// 解析XSS特定配置
	if xssConfig, ok := config.CustomConfig["xss_config"]; ok {
		if cfg, ok := xssConfig.(XSSConfig); ok {
			p.config = cfg
		}
	}
	
	return nil
}

// SetBrowserService 设置浏览器服务
func (p *XSSPlugin) SetBrowserService(service *browser.BrowserService) {
	p.browserService = service
	log.Debug().Str("plugin", "xss").Msg("浏览器服务已设置")
}

// Scan 实现Plugin接口 - 主要扫描入口
func (p *XSSPlugin) Scan(client *requester.HTTPClient, req *models.Request) ([]*vulnscan.Vulnerability, error) {
	ctx := context.Background()
	return p.ScanWithContext(ctx, client, req)
}

// ScanWithContext 实现AdvancedPlugin接口
func (p *XSSPlugin) ScanWithContext(ctx context.Context, client *requester.HTTPClient, req *models.Request) ([]*vulnscan.Vulnerability, error) {
	startTime := time.Now()
	defer func() {
		p.UpdateStats(true, time.Since(startTime), 0)
	}()
	
	p.httpClient = client
	var vulnerabilities []*vulnscan.Vulnerability
	
	// 检查浏览器服务
	if p.browserService == nil && p.config.EnableDOMVerification {
		log.Warn().Msg("XSS插件未配置浏览器服务，DOM验证将被跳过")
		p.config.EnableDOMVerification = false
	}
	
	// 并发扫描参数
	paramChan := make(chan models.Parameter, len(req.Params))
	resultChan := make(chan []*vulnscan.Vulnerability, len(req.Params))
	
	// 启动工作协程
	const maxWorkers = 5
	workers := len(req.Params)
	if workers > maxWorkers {
		workers = maxWorkers
	}
	
	for i := 0; i < workers; i++ {
		go p.parameterWorker(ctx, req, paramChan, resultChan)
	}
	
	// 发送参数到通道
	for _, param := range req.Params {
		paramChan <- param
	}
	close(paramChan)
	
	// 收集结果
	for i := 0; i < len(req.Params); i++ {
		select {
		case vulns := <-resultChan:
			vulnerabilities = append(vulnerabilities, vulns...)
		case <-ctx.Done():
			return vulnerabilities, ctx.Err()
		}
	}
	
	// 去重和排序
	vulnerabilities = p.deduplicateVulnerabilities(vulnerabilities)
	
	log.Info().
		Str("plugin", "xss").
		Str("url", req.URL).
		Int("vulnerabilities", len(vulnerabilities)).
		Dur("duration", time.Since(startTime)).
		Msg("XSS扫描完成")
	
	return vulnerabilities, nil
}

// parameterWorker 参数扫描工作协程
func (p *XSSPlugin) parameterWorker(ctx context.Context, req *models.Request, paramChan <-chan models.Parameter, resultChan chan<- []*vulnscan.Vulnerability) {
	for param := range paramChan {
		vulns, err := p.scanParameter(ctx, req, param)
		if err != nil {
			log.Warn().
				Err(err).
				Str("url", req.URL).
				Str("param", param.Name).
				Msg("参数扫描失败")
			resultChan <- []*vulnscan.Vulnerability{}
			continue
		}
		resultChan <- vulns
	}
}

// scanParameter 扫描单个参数
func (p *XSSPlugin) scanParameter(ctx context.Context, req *models.Request, param models.Parameter) ([]*vulnscan.Vulnerability, error) {
	var vulnerabilities []*vulnscan.Vulnerability
	var payloadResponses []string
	
	payloads := p.selectPayloadsForParameter(req, param)
	
	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			return vulnerabilities, ctx.Err()
		default:
		}
		
		xssCtx := &XSSContext{
			OriginalRequest: req,
			Parameter:       param,
			Payload:         payload.Value,
			Context:         ctx,
		}
		
		result, err := p.testXSSPayload(xssCtx)
		if err != nil {
			log.Debug().
				Err(err).
				Str("param", param.Name).
				Str("payload", payload.Value).
				Msg("XSS payload测试失败")
			continue
		}
		
		if result.Response != nil {
			payloadResponses = append(payloadResponses, result.Response.Hash)
		}
		
		if result.Vulnerable && result.Confidence >= p.config.ConfidenceThreshold {
			vuln := p.createVulnerabilityFromResult(xssCtx, result)
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}
	
	// WAF检测
	if p.config.EnableWAFDetection {
		p.detectWAF(req.URL, param.Name, payloadResponses)
	}
	
	return vulnerabilities, nil
}

// testXSSPayload 测试XSS payload
func (p *XSSPlugin) testXSSPayload(xssCtx *XSSContext) (*XSSResult, error) {
	result := &XSSResult{
		Payload: xssCtx.Payload,
		XSSType: XSSTypeReflected, // 默认为反射型
	}
	
	// 1. 获取基线响应
	baselineResp, err := p.getBaselineResponse(xssCtx)
	if err != nil {
		return result, fmt.Errorf("获取基线响应失败: %w", err)
	}
	
	// 2. 发送payload请求
	testResp, err := p.sendPayloadRequest(xssCtx)
	if err != nil {
		return result, fmt.Errorf("发送payload请求失败: %w", err)
	}
	
	result.Response = testResp
	
	// 3. 分析响应
	if err := p.analyzeResponse(xssCtx, baselineResp, testResp, result); err != nil {
		return result, fmt.Errorf("分析响应失败: %w", err)
	}
	
	// 4. DOM验证（如果需要）
	if result.Vulnerable && p.config.EnableDOMVerification {
		if err := p.performDOMVerification(xssCtx, result); err != nil {
			log.Warn().Err(err).Msg("DOM验证失败")
		}
	}
	
	return result, nil
}

// getBaselineResponse 获取基线响应
func (p *XSSPlugin) getBaselineResponse(xssCtx *XSSContext) (*models.ResponseInfo, error) {
	cacheKey := p.generateCacheKey(xssCtx.OriginalRequest, xssCtx.Parameter.Name, xssCtx.Parameter.Value)
	
	// 检查缓存
	if cached, ok := p.responseCache.Load(cacheKey); ok {
		return cached.(*models.ResponseInfo), nil
	}
	
	// 构建基线请求
	req, err := p.buildHTTPRequest(xssCtx.OriginalRequest, xssCtx.Parameter.Name, xssCtx.Parameter.Value)
	if err != nil {
		return nil, err
	}
	
	// 发送请求
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	
	respInfo, err := p.getResponseInfo(resp)
	if err != nil {
		return nil, err
	}
	
	// 缓存响应
	p.responseCache.Store(cacheKey, respInfo)
	
	return respInfo, nil
}

// sendPayloadRequest 发送payload请求
func (p *XSSPlugin) sendPayloadRequest(xssCtx *XSSContext) (*models.ResponseInfo, error) {
	req, err := p.buildHTTPRequest(xssCtx.OriginalRequest, xssCtx.Parameter.Name, xssCtx.Payload)
	if err != nil {
		return nil, err
	}
	
	p.logRequestDebug(req, xssCtx.Payload)
	
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	
	respInfo, err := p.getResponseInfo(resp)
	if err != nil {
		return nil, err
	}
	
	p.logResponseDebug(respInfo)
	
	return respInfo, nil
}

// analyzeResponse 分析响应
func (p *XSSPlugin) analyzeResponse(xssCtx *XSSContext, baseline, test *models.ResponseInfo, result *XSSResult) error {
	confidence := 0.0
	var evidence []vulnscan.Evidence
	
	// 1. 检测payload反射
	if p.detectReflection(test.Body, xssCtx.Payload) {
		confidence += 0.6
		evidence = append(evidence, vulnscan.Evidence{
			Type:        "reflection",
			Location:    "response_body",
			Value:       xssCtx.Payload,
			Description: "Payload在响应体中被反射",
		})
		
		// 检测反射上下文
		context := p.analyzeReflectionContext(test.Body, xssCtx.Payload)
		if context != "" {
			confidence += 0.2
			evidence = append(evidence, vulnscan.Evidence{
				Type:        "context",
				Location:    "response_body",
				Value:       context,
				Description: "Payload反射上下文",
			})
		}
	}
	
	// 2. 检测响应差异
	if p.hasSignificantDifference(baseline, test) {
		confidence += 0.3
		evidence = append(evidence, vulnscan.Evidence{
			Type:        "response_diff",
			Location:    "response",
			Value:       fmt.Sprintf("基线长度: %d, 测试长度: %d", len(baseline.Body), len(test.Body)),
			Description: "响应存在显著差异",
		})
	}
	
	// 3. 检测XSS特征
	xssFeatures := p.detectXSSFeatures(test.Body, xssCtx.Payload)
	if len(xssFeatures) > 0 {
		confidence += 0.4
		for _, feature := range xssFeatures {
			evidence = append(evidence, vulnscan.Evidence{
				Type:        "xss_feature",
				Location:    "response_body",
				Value:       feature,
				Description: "检测到XSS特征",
			})
		}
	}
	
	// 4. 误报检测
	if p.config.EnableFalsePositiveReduction {
		if p.isFalsePositive(baseline, test, xssCtx.Payload) {
			confidence *= 0.5 // 降低置信度
			evidence = append(evidence, vulnscan.Evidence{
				Type:        "false_positive_indicator",
				Location:    "analysis",
				Value:       "检测到可能的误报指标",
				Description: "响应可能包含误报指标",
			})
		}
	}
	
	result.Vulnerable = confidence >= p.config.ConfidenceThreshold
	result.Confidence = confidence
	result.Evidence = evidence
	
	return nil
}

// analyzeReflectionContext 分析反射上下文
func (p *XSSPlugin) analyzeReflectionContext(body []byte, payload string) string {
	bodyStr := string(body)
	
	// 查找payload在响应中的位置
	index := strings.Index(bodyStr, payload)
	if index == -1 {
		return ""
	}
	
	// 提取上下文（前后各50个字符）
	start := index - 50
	if start < 0 {
		start = 0
	}
	
	end := index + len(payload) + 50
	if end > len(bodyStr) {
		end = len(bodyStr)
	}
	
	return bodyStr[start:end]
}

// detectXSSFeatures 检测XSS特征
func (p *XSSPlugin) detectXSSFeatures(body []byte, payload string) []string {
	var features []string
	bodyStr := string(body)
	
	// 检测script标签
	if p.scriptTagRegex != nil && p.scriptTagRegex.MatchString(bodyStr) {
		if strings.Contains(bodyStr, payload) {
			features = append(features, "script_tag_injection")
		}
	}
	
	// 检测事件处理器
	if p.eventHandlerRegex != nil && p.eventHandlerRegex.MatchString(bodyStr) {
		if strings.Contains(bodyStr, payload) {
			features = append(features, "event_handler_injection")
		}
	}
	
	// 检测JavaScript协议
	if p.javascriptRegex != nil && p.javascriptRegex.MatchString(bodyStr) {
		if strings.Contains(bodyStr, payload) {
			features = append(features, "javascript_protocol_injection")
		}
	}
	
	return features
}

// isFalsePositive 检测误报
func (p *XSSPlugin) isFalsePositive(baseline, test *models.ResponseInfo, payload string) bool {
	// 检查是否为错误页面
	if p.isErrorPage(test) {
		return true
	}
	
	// 检查是否为重定向
	if test.StatusCode >= 300 && test.StatusCode < 400 {
		return true
	}
	
	// 检查payload是否被完全编码
	if p.isPayloadCompletelyEncoded(test.Body, payload) {
		return true
	}
	
	return false
}

// isErrorPage 检查是否为错误页面
func (p *XSSPlugin) isErrorPage(resp *models.ResponseInfo) bool {
	if resp.StatusCode >= 400 {
		return true
	}
	
	bodyStr := strings.ToLower(string(resp.Body))
	errorIndicators := []string{
		"error", "exception", "not found", "forbidden",
		"access denied", "unauthorized", "bad request",
	}
	
	for _, indicator := range errorIndicators {
		if strings.Contains(bodyStr, indicator) {
			return true
		}
	}
	
	return false
}

// isPayloadCompletelyEncoded 检查payload是否被完全编码
func (p *XSSPlugin) isPayloadCompletelyEncoded(body []byte, payload string) bool {
	bodyStr := string(body)
	
	// 检查HTML编码
	htmlEncoded := html.EscapeString(payload)
	if strings.Contains(bodyStr, htmlEncoded) && !strings.Contains(bodyStr, payload) {
		return true
	}
	
	// 检查URL编码
	urlEncoded := url.QueryEscape(payload)
	if strings.Contains(bodyStr, urlEncoded) && !strings.Contains(bodyStr, payload) {
		return true
	}
	
	return false
}

// performDOMVerification 执行DOM验证
func (p *XSSPlugin) performDOMVerification(xssCtx *XSSContext, result *XSSResult) error {
	if p.browserService == nil {
		return fmt.Errorf("浏览器服务未配置")
	}
	
	testURL, err := p.buildTestURL(xssCtx.OriginalRequest, xssCtx.Parameter.Name, xssCtx.Payload)
	if err != nil {
		return fmt.Errorf("构建测试URL失败: %w", err)
	}
	
	ctx, cancel := context.WithTimeout(xssCtx.Context, p.config.DOMVerificationTimeout)
	defer cancel()
	
	verified, err := p.browserService.VerifyXSS(ctx, testURL, xssCtx.Payload)
	if err != nil {
		return fmt.Errorf("DOM验证失败: %w", err)
	}
	
	result.DOMVerified = verified
	
	if verified {
		result.Confidence = 1.0 // DOM验证成功，置信度设为最高
		result.Evidence = append(result.Evidence, vulnscan.Evidence{
			Type:        "dom_verification",
			Location:    "browser",
			Value:       "DOM验证成功",
			Description: "浏览器中成功执行XSS payload",
		})
		
		p.mu.Lock()
		p.stats.DOMVerifications++
		p.mu.Unlock()
	} else {
		result.Confidence *= 0.7 // DOM验证失败，降低置信度
	}
	
	return nil
}

// detectWAF 检测WAF
func (p *XSSPlugin) detectWAF(url, paramName string, responses []string) {
	if len(responses) < p.config.WAFThreshold {
		return
	}
	
	// 检查所有响应是否相同
	uniqueResponses := make(map[string]bool)
	for _, resp := range responses {
		uniqueResponses[resp] = true
	}
	
	if len(uniqueResponses) == 1 {
		log.Warn().
			Str("url", url).
			Str("param", paramName).
			Int("total_payloads", len(responses)).
			Msg("检测到可能的WAF/过滤器，所有payload响应一致")
		
		p.mu.Lock()
		p.stats.WAFDetections++
		p.mu.Unlock()
	}
}

// selectPayloadsForParameter 为参数选择合适的payloads
func (p *XSSPlugin) selectPayloadsForParameter(req *models.Request, param models.Parameter) []models.Payload {
	allPayloads := p.GetDefaultPayloads()
	
	// 根据参数类型和上下文选择payloads
	var selectedPayloads []models.Payload
	
	for _, payload := range allPayloads {
		if len(selectedPayloads) >= p.config.MaxPayloads {
			break
		}
		
		// 根据参数名称选择相关payload
		if p.isPayloadRelevantForParameter(param, payload) {
			selectedPayloads = append(selectedPayloads, payload)
		}
	}
	
	if len(selectedPayloads) == 0 {
		// 如果没有相关payload，使用基础payload
		selectedPayloads = allPayloads[:min(len(allPayloads), 10)]
	}
	
	return selectedPayloads
}

// isPayloadRelevantForParameter 检查payload是否与参数相关
func (p *XSSPlugin) isPayloadRelevantForParameter(param models.Parameter, payload models.Payload) bool {
	paramName := strings.ToLower(param.Name)
	
	// 根据参数名称判断
	if strings.Contains(paramName, "search") || strings.Contains(paramName, "query") {
		return strings.Contains(payload.Value, "<script>") || strings.Contains(payload.Value, "alert")
	}
	
	if strings.Contains(paramName, "url") || strings.Contains(paramName, "link") {
		return strings.Contains(payload.Value, "javascript:")
	}
	
	if strings.Contains(paramName, "name") || strings.Contains(paramName, "title") {
		return strings.Contains(payload.Value, "onload") || strings.Contains(payload.Value, "onerror")
	}
	
	return true // 默认相关
}

// generateDefaultPayloads 生成默认payloads
func (p *XSSPlugin) generateDefaultPayloads() []models.Payload {
	payloadStrings := []string{
		// 基础script标签
		`<script>alert('XSS')</script>`,
		`<script>alert(1)</script>`,
		`<script>confirm('XSS')</script>`,
		`<script>prompt('XSS')</script>`,
		
		// 事件处理器
		`<img src=x onerror=alert('XSS')>`,
		`<svg onload=alert('XSS')>`,
		`<body onload=alert('XSS')>`,
		`<input onfocus=alert('XSS') autofocus>`,
		`<select onfocus=alert('XSS') autofocus><option>test</option></select>`,
		`<textarea onfocus=alert('XSS') autofocus>test</textarea>`,
		`<keygen onfocus=alert('XSS') autofocus>`,
		`<video><source onerror=alert('XSS')>`,
		`<audio src=x onerror=alert('XSS')>`,
		`<details open ontoggle=alert('XSS')>`,
		
		// JavaScript协议
		`javascript:alert('XSS')`,
		`javascript:alert(1)`,
		`javascript:confirm('XSS')`,
		
		// 绕过过滤器的payload
		`<ScRiPt>alert('XSS')</ScRiPt>`,
		`<script>alert(String.fromCharCode(88,83,83))</script>`,
		`<script>alert(/XSS/.source)</script>`,
		`<script>alert`+"`XSS`"+`</script>`,
		`<script>eval('alert("XSS")')</script>`,
		
		// HTML5新标签
		`<marquee onstart=alert('XSS')>`,
		`<meter onmouseover=alert('XSS')>`,
		`<progress onmouseover=alert('XSS')>`,
		
		// 属性注入
		`" onmouseover="alert('XSS')`,
		`' onmouseover='alert('XSS')`,
		`> <script>alert('XSS')</script>`,
		`</script><script>alert('XSS')</script>`,
		
		// 编码绕过
		`&lt;script&gt;alert('XSS')&lt;/script&gt;`,
		`%3Cscript%3Ealert('XSS')%3C/script%3E`,
		`&#60;script&#62;alert('XSS')&#60;/script&#62;`,
		
		// CSS注入
		`<style>@import'javascript:alert("XSS")';</style>`,
		`<link rel=stylesheet href=javascript:alert('XSS')>`,
		
		// 数据协议
		`<iframe src="data:text/html,<script>alert('XSS')</script>">`,
		`<object data="data:text/html,<script>alert('XSS')</script>">`,
		
		// 特殊字符组合
		`<svg><script>alert&#40;1&#41;</script>`,
		`<math><script>alert('XSS')</script></math>`,
		
		// 短payload
		`<script>alert(1)`,
		`<svg onload=alert(1)>`,
		`<img src=1 onerror=alert(1)>`,
		
		// 复杂payload
		`<script>setTimeout('alert("XSS")',1)</script>`,
		`<script>setInterval('alert("XSS")',1000)</script>`,
		`<script>Function('alert("XSS")')();</script>`,
	}
	
	var payloads []models.Payload
	for i, payloadStr := range payloadStrings {
		payloads = append(payloads, models.Payload{
			ID:          fmt.Sprintf("xss_%d", i+1),
			Value:       payloadStr,
			Type:        "xss",
			Description: fmt.Sprintf("XSS payload #%d", i+1),
			Severity:    models.SeverityHigh,
		})
	}
	
	return payloads
}

// createVulnerabilityFromResult 从检测结果创建漏洞对象
func (p *XSSPlugin) createVulnerabilityFromResult(xssCtx *XSSContext, result *XSSResult) *vulnscan.Vulnerability {
	severity := vulnscan.SeverityMedium
	if result.DOMVerified {
		severity = vulnscan.SeverityHigh
	} else if result.Confidence >= 0.9 {
		severity = vulnscan.SeverityHigh
	}
	
	description := fmt.Sprintf("检测到%s XSS漏洞，置信度: %.2f", result.XSSType.String(), result.Confidence)
	if result.DOMVerified {
		description += "，已通过DOM验证"
	}
	
	testURL := p.buildVulnerableURL(xssCtx.OriginalRequest, xssCtx.Parameter.Name, xssCtx.Payload)
	
	vuln := &vulnscan.Vulnerability{
		Type:          p.Info().Name,
		URL:           xssCtx.OriginalRequest.URL,
		Payload:       xssCtx.Payload,
		Param:         xssCtx.Parameter.Name,
		Method:        xssCtx.OriginalRequest.Method,
		VulnerableURL: testURL,
		Timestamp:     time.Now(),
		Severity:      severity,
		Confidence:    result.Confidence,
		Description:   description,
		Evidence:      result.Evidence,
		Metadata: map[string]interface{}{
			"xss_type":      result.XSSType.String(),
			"dom_verified":  result.DOMVerified,
			"waf_detected":  result.WAFDetected,
			"response_size": len(result.Response.Body),
			"status_code":   result.Response.StatusCode,
		},
	}
	
	// 添加修复建议
	vuln.Remediation = p.generateRemediation(result.XSSType)
	
	return vuln
}

// generateRemediation 生成修复建议
func (p *XSSPlugin) generateRemediation(xssType XSSType) string {
	switch xssType {
	case XSSTypeReflected:
		return `修复建议：
1. 对所有用户输入进行适当的编码/转义
2. 使用内容安全策略(CSP)
3. 验证和过滤输入数据
4. 使用安全的模板引擎
5. 避免直接将用户输入插入HTML`
		
	case XSSTypeStored:
		return `修复建议：
1. 在存储前对用户输入进行严格验证和过滤
2. 在输出时进行适当的编码
3. 使用参数化查询防止存储型XSS
4. 实施严格的内容安全策略
5. 定期审计存储的用户数据`
		
	case XSSTypeDOM:
		return `修复建议：
1. 避免使用危险的DOM方法(如innerHTML)
2. 使用安全的DOM操作方法
3. 验证和过滤客户端JavaScript中的数据
4. 使用DOMPurify等安全库
5. 实施严格的CSP策略`
		
	default:
		return `修复建议：
1. 对所有用户输入进行编码/转义
2. 实施内容安全策略(CSP)
3. 使用安全的编程实践
4. 定期进行安全测试`
	}
}

// buildVulnerableURL 构建包含漏洞的URL
func (p *XSSPlugin) buildVulnerableURL(req *models.Request, paramName, payload string) string {
	if req.Method == "POST" {
		return req.URL // POST请求返回原始URL
	}
	
	// GET请求构建包含payload的URL
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return req.URL
	}
	
	query := parsedURL.Query()
	for _, param := range req.Params {
		if param.Name == paramName {
			query.Set(param.Name, payload)
		} else {
			query.Set(param.Name, param.Value)
		}
	}
	
	parsedURL.RawQuery = query.Encode()
	return parsedURL.String()
}

// deduplicateVulnerabilities 去重漏洞
func (p *XSSPlugin) deduplicateVulnerabilities(vulns []*vulnscan.Vulnerability) []*vulnscan.Vulnerability {
	seen := make(map[string]bool)
	var result []*vulnscan.Vulnerability
	
	for _, vuln := range vulns {
		key := fmt.Sprintf("%s_%s_%s", vuln.URL, vuln.Param, vuln.Method)
		if !seen[key] {
			seen[key] = true
			result = append(result, vuln)
		}
	}
	
	return result
}

// getResponseInfo 获取响应信息并计算hash
func (p *XSSPlugin) getResponseInfo(resp *http.Response) (*models.ResponseInfo, error) {
	if resp == nil {
		return nil, fmt.Errorf("http响应为空")
	}
	
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %w", err)
	}
	
	hash := sha256.Sum256(body)
	shortHash := hex.EncodeToString(hash[:4])
	
	return &models.ResponseInfo{
		Body:       body,
		StatusCode: resp.StatusCode,
		Hash:       shortHash,
		Headers:    resp.Header,
		Size:       len(body),
	}, nil
}

// buildHTTPRequest 构建HTTP请求
func (p *XSSPlugin) buildHTTPRequest(originalReq *models.Request, paramName, paramValue string) (*http.Request, error) {
	var req *http.Request
	var err error
	
	if originalReq.Method == "POST" {
		req, err = p.buildPOSTRequest(originalReq, paramName, paramValue)
	} else {
		req, err = p.buildGETRequest(originalReq, paramName, paramValue)
	}
	
	if err != nil {
		return nil, fmt.Errorf("创建HTTP请求失败: %w", err)
	}
	
	// 复制原始请求头
	if originalReq.Headers != nil {
		req.Header = originalReq.Headers.Clone()
	}
	
	// 设置超时
	ctx, cancel := context.WithTimeout(context.Background(), p.config.Timeout)
	req = req.WithContext(ctx)
	
	// 注意：这里不能直接调用cancel()，因为请求可能还在使用
	// 实际项目中应该有更好的上下文管理机制
	_ = cancel
	
	return req, nil
}

// buildPOSTRequest 构建POST请求
func (p *XSSPlugin) buildPOSTRequest(originalReq *models.Request, paramName, paramValue string) (*http.Request, error) {
	form := make(url.Values)
	for _, param := range originalReq.Params {
		if param.Name == paramName {
			form.Set(param.Name, paramValue)
		} else {
			form.Set(param.Name, param.Value)
		}
	}
	
	req, err := http.NewRequest("POST", originalReq.URL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

// buildGETRequest 构建GET请求
func (p *XSSPlugin) buildGETRequest(originalReq *models.Request, paramName, paramValue string) (*http.Request, error) {
	parsedURL, err := url.Parse(originalReq.URL)
	if err != nil {
		return nil, err
	}
	
	query := parsedURL.Query()
	for _, param := range originalReq.Params {
		if param.Name == paramName {
			query.Set(param.Name, paramValue)
		} else {
			query.Set(param.Name, param.Value)
		}
	}
	
	parsedURL.RawQuery = query.Encode()
	return http.NewRequest("GET", parsedURL.String(), nil)
}

// buildTestURL 构建包含payload的测试URL
func (p *XSSPlugin) buildTestURL(originalReq *models.Request, paramName, payload string) (string, error) {
	if originalReq.Method == "POST" {
		return originalReq.URL, nil
	}
	
	parsedURL, err := url.Parse(originalReq.URL)
	if err != nil {
		return "", fmt.Errorf("解析URL失败: %w", err)
	}
	
	query := parsedURL.Query()
	for _, param := range originalReq.Params {
		if param.Name == paramName {
			query.Set(param.Name, payload)
		} else {
			query.Set(param.Name, param.Value)
		}
	}
	
	parsedURL.RawQuery = query.Encode()
	return parsedURL.String(), nil
}

// detectReflection 检测payload是否在响应体中被反射
func (p *XSSPlugin) detectReflection(body []byte, payload string) bool {
	bodyStr := string(body)
	
	// 检查函数列表，按优先级排序
	checks := []func(string, string) bool{
		p.checkDirectReflection,
		p.checkHTMLEncodedReflection,
		p.checkURLEncodedReflection,
		p.checkJSEncodedReflection,
		p.checkPartialReflection,
	}
	
	for _, check := range checks {
		if check(bodyStr, payload) {
			return true
		}
	}
	
	return false
}

// checkDirectReflection 检查直接字符串匹配
func (p *XSSPlugin) checkDirectReflection(bodyStr, payload string) bool {
	return strings.Contains(bodyStr, payload)
}

// checkHTMLEncodedReflection 检查HTML实体编码后的反射
func (p *XSSPlugin) checkHTMLEncodedReflection(bodyStr, payload string) bool {
	encodedPayload := html.EscapeString(payload)
	return strings.Contains(bodyStr, encodedPayload)
}

// checkURLEncodedReflection 检查URL编码后的反射
func (p *XSSPlugin) checkURLEncodedReflection(bodyStr, payload string) bool {
	return strings.Contains(bodyStr, url.QueryEscape(payload))
}

// checkJSEncodedReflection 检查JavaScript编码后的反射
func (p *XSSPlugin) checkJSEncodedReflection(bodyStr, payload string) bool {
	// 简单的JavaScript编码检查
	jsEncoded := strings.ReplaceAll(payload, "'", "\\'")
	jsEncoded = strings.ReplaceAll(jsEncoded, "\"", "\\\"")
	return strings.Contains(bodyStr, jsEncoded)
}

// checkPartialReflection 检查部分反射
func (p *XSSPlugin) checkPartialReflection(bodyStr, payload string) bool {
	// 检查payload的关键部分是否被反射
	if len(payload) < 10 {
		return false
	}
	
	// 检查payload的前半部分和后半部分
	mid := len(payload) / 2
	firstHalf := payload[:mid]
	secondHalf := payload[mid:]
	
	return strings.Contains(bodyStr, firstHalf) && strings.Contains(bodyStr, secondHalf)
}

// hasSignificantDifference 检查两个响应是否有显著差异
func (p *XSSPlugin) hasSignificantDifference(base, test *models.ResponseInfo) bool {
	if base == nil || test == nil {
		return false
	}
	
	// 状态码不同
	if base.StatusCode != test.StatusCode {
		return true
	}
	
	// 内容hash不同
	if base.Hash != test.Hash {
		return true
	}
	
	// 响应长度差异检查
	lenDiff := len(test.Body) - len(base.Body)
	if lenDiff < 0 {
		lenDiff = -lenDiff
	}
	
	// 检查绝对差异和相对差异
	if lenDiff > p.config.MinResponseDiff {
		relativeRatio := float64(lenDiff) / float64(len(base.Body))
		return relativeRatio > p.config.MaxResponseDiffRatio
	}
	
	return false
}

// generateCacheKey 生成缓存键
func (p *XSSPlugin) generateCacheKey(req *models.Request, paramName, paramValue string) string {
	return fmt.Sprintf("%s_%s_%s_%s", req.Method, req.URL, paramName, paramValue)
}

// logRequestDebug 记录请求调试信息
func (p *XSSPlugin) logRequestDebug(req *http.Request, payload string) {
	if log.Debug().Enabled() {
		if dump, err := httputil.DumpRequestOut(req, true); err == nil {
			log.Debug().Str("plugin", "xss").Msgf("Raw XSS Request:\n%s", string(dump))
		}
		
		log.Debug().
			Str("plugin", "xss").
			Str("method", req.Method).
			Str("url", req.URL.String()).
			Str("payload", payload).
			Msg("Sending XSS test request")
	}
}

// logResponseDebug 记录响应调试信息
func (p *XSSPlugin) logResponseDebug(info *models.ResponseInfo) {
	if !log.Debug().Enabled() || info == nil {
		return
	}
	
	const previewLen = 200
	preview := string(info.Body)
	if len(preview) > previewLen {
		preview = preview[:previewLen] + "..."
	}
	
	log.Debug().
		Str("plugin", "xss").
		Int("status", info.StatusCode).
		Int("bodyLen", len(info.Body)).
		Str("bodyPreview", preview).
		Str("respHash", info.Hash).
		Msg("HTTP response received")
}

// UpdateStats 更新统计信息
func (p *XSSPlugin) UpdateStats(success bool, responseTime time.Duration, vulnCount int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	p.stats.TotalRequests++
	if success {
		p.stats.SuccessfulTests++
	}
	
	// 更新平均响应时间
	if p.stats.TotalRequests == 1 {
		p.stats.AverageResponseTime = responseTime
	} else {
		p.stats.AverageResponseTime = (p.stats.AverageResponseTime*time.Duration(p.stats.TotalRequests-1) + responseTime) / time.Duration(p.stats.TotalRequests)
	}
}

// GetStats 获取统计信息
func (p *XSSPlugin) GetStats() XSSStats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.stats
}

// ResetStats 重置统计信息
func (p *XSSPlugin) ResetStats() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stats = XSSStats{}
}

// Cleanup 清理资源
func (p *XSSPlugin) Cleanup() error {
	// 清理缓存
	p.responseCache.Range(func(key, value interface{}) bool {
		p.responseCache.Delete(key)
		return true
	})
	
	p.payloadCache.Range(func(key, value interface{}) bool {
		p.payloadCache.Delete(key)
		return true
	})
	
	log.Info().Str("plugin", "xss").Msg("XSS插件清理完成")
	return nil
}

// min 辅助函数
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Validate 实现Plugin接口的验证方法
func (p *XSSPlugin) Validate() error {
	if len(p.GetDefaultPayloads()) == 0 {
		return fmt.Errorf("XSS插件没有配置payloads")
	}
	
	if p.config.MaxPayloads <= 0 {
		return fmt.Errorf("MaxPayloads必须大于0")
	}
	
	if p.config.Timeout <= 0 {
		return fmt.Errorf("Timeout必须大于0")
	}
	
	return nil
}
