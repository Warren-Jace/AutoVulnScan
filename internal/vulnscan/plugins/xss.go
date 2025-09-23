// Package plugins 包含了所有具体的漏洞扫描插件实现。
package plugins

import (
	"context"
	"fmt"
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
	*vulnscan.BaseScanPlugin // 使用共享的基础插件类

	// 插件特定配置
	config XSSConfig

	// 检测模式和规则
	errorPatterns   []ErrorPattern
	reflectionTests []ReflectionTest
	domTests        []DOMTest

	// 状态管理
	stats XSSStats

	// 正则表达式（预编译）
	errorRegexes      []*regexp.Regexp
	reflectionRegex   *regexp.Regexp
	domRegex          *regexp.Regexp
	scriptTagRegex    *regexp.Regexp
	eventHandlerRegex *regexp.Regexp
	javascriptRegex   *regexp.Regexp

	// 浏览器服务
	browserService browser.BrowserService

	// 互斥锁
	mu sync.RWMutex
}

// XSSConfig XSS插件配置
type XSSConfig struct {
	// 基础配置
	MaxPayloads            int           `json:"max_payloads"`             // 最大payload数量
	Timeout                time.Duration `json:"timeout"`                  // 请求超时
	DOMVerificationTimeout time.Duration `json:"dom_verification_timeout"` // DOM验证超时

	// 检测配置
	EnableReflectedXSS    bool `json:"enable_reflected_xss"`    // 启用反射型XSS检测
	EnableStoredXSS       bool `json:"enable_stored_xss"`       // 启用存储型XSS检测
	EnableDOMXSS          bool `json:"enable_dom_xss"`          // 启用DOM型XSS检测
	EnableDOMVerification bool `json:"enable_dom_verification"` // 启用DOM验证

	// 响应分析配置
	MinResponseDiff       int     `json:"min_response_diff"`       // 最小响应差异（字节）
	MaxResponseDiffRatio  float64 `json:"max_response_diff_ratio"` // 最大响应差异比例
	EnableContentAnalysis bool    `json:"enable_content_analysis"` // 启用内容分析

	// WAF检测配置
	EnableWAFDetection bool `json:"enable_waf_detection"` // 启用WAF检测
	WAFThreshold       int  `json:"waf_threshold"`        // WAF检测阈值

	// 编码检测
	DetectEncodedPayloads bool `json:"detect_encoded_payloads"` // 检测编码后的payload

	// 误报减少
	EnableFalsePositiveReduction bool    `json:"enable_false_positive_reduction"`
	ConfidenceThreshold          float64 `json:"confidence_threshold"`
}

// XSSStats XSS插件统计信息
type XSSStats struct {
	TotalRequests       int64         `json:"total_requests"`
	SuccessfulTests     int64         `json:"successful_tests"`
	ReflectedXSSFound   int64         `json:"reflected_xss_found"`
	StoredXSSFound      int64         `json:"stored_xss_found"`
	DOMXSSFound         int64         `json:"dom_xss_found"`
	FalsePositives      int64         `json:"false_positives"`
	WAFDetections       int64         `json:"waf_detections"`
	DOMVerifications    int64         `json:"dom_verifications"`
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
	Vulnerable  bool
	Confidence  float64
	Evidence    []vulnscan.Evidence
	XSSType     XSSType
	Payload     string
	Response    *models.ResponseInfo
	DOMVerified bool
	WAFDetected bool
}

// ReflectionTest 反射型XSS测试定义
type ReflectionTest struct {
	Name        string  `json:"name"`        // 测试名称
	Payload     string  `json:"payload"`     // 测试payload
	Confidence  float64 `json:"confidence"`  // 置信度
	Description string  `json:"description"` // 测试描述
}

// DOMTest DOM型XSS测试定义
type DOMTest struct {
	Name        string  `json:"name"`        // 测试名称
	Payload     string  `json:"payload"`     // 测试payload
	Confidence  float64 `json:"confidence"`  // 置信度
	Description string  `json:"description"` // 测试描述
	DOMPattern  string  `json:"dom_pattern"` // DOM模式
}

// 默认配置
var defaultXSSConfig = XSSConfig{
	MaxPayloads:                  10,  // 增加payload数量
	Timeout:                      10 * time.Second,   // 增加超时时间
	DOMVerificationTimeout:       10 * time.Second,   // 增加DOM验证超时时间
	EnableReflectedXSS:           true,
	EnableStoredXSS:              true,  // 启用存储型XSS检测
	EnableDOMXSS:                 true,  // 启用DOM型XSS检测
	EnableDOMVerification:        true,  // 启用DOM验证
	MinResponseDiff:              10,
	MaxResponseDiffRatio:         0.1,
	EnableContentAnalysis:        true,  // 启用内容分析
	EnableWAFDetection:           true,  // 启用WAF检测
	WAFThreshold:                 3,
	DetectEncodedPayloads:        true,  // 启用编码检测
	EnableFalsePositiveReduction:  true,  // 启用误报减少功能
	ConfidenceThreshold:          0.7,  // 提高置信度阈值，减少误报
}

// init 函数会在包初始化时被调用，用于自动注册插件。
func init() {
	plugin := NewXSSPlugin()
	vulnscan.RegisterPlugin("xss", plugin)
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
	}

	plugin := &XSSPlugin{
		BaseScanPlugin: vulnscan.NewBaseScanPlugin(info),
		config:         defaultXSSConfig,
		stats:          XSSStats{},
	}

	// 初始化正则表达式
	plugin.initializeRegexes()

	return plugin
}

// initializeRegexes 初始化正则表达式
func (p *XSSPlugin) initializeRegexes() {
	// 错误模式正则表达式
	p.errorRegexes = []*regexp.Regexp{
		regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`),
		regexp.MustCompile(`(?i)on\w+\s*=\s*["']?[^\s"'>]*`),
		regexp.MustCompile(`(?i)javascript:\s*[^\s"'>]*`),
		regexp.MustCompile(`(?i)<iframe[^>]*>.*?</iframe>`),
		regexp.MustCompile(`(?i)<object[^>]*>.*?</object>`),
		regexp.MustCompile(`(?i)<embed[^>]*>.*?</embed>`),
		regexp.MustCompile(`(?i)<applet[^>]*>.*?</applet>`),
		regexp.MustCompile(`(?i)<meta[^>]*http-equiv[^>]*content[^>]*script`),
		regexp.MustCompile(`(?i)<link[^>]*href[^>]*javascript`),
		regexp.MustCompile(`(?i)<style[^>]*>.*?</style>`),
		regexp.MustCompile(`(?i)@import\s+['"]?[^'"]*['"]?`),
		regexp.MustCompile(`(?i)expression\s*\([^)]*\)`),
		regexp.MustCompile(`(?i)vbscript:`),
		regexp.MustCompile(`(?i)data:text/html`),
	}

	// 反射检测正则表达式
	p.reflectionRegex = regexp.MustCompile(`(?i)<script[^>]*>.*?alert\s*\([^)]*\).*?</script>`)

	// DOM检测正则表达式
	p.domRegex = regexp.MustCompile(`(?i)document\.(location|cookie|write|writeln)\s*=\s*[^;]*`)

	// script标签检测
	p.scriptTagRegex = regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`)

	// 事件处理器检测
	p.eventHandlerRegex = regexp.MustCompile(`(?i)on\w+\s*=\s*["']?[^\s"'>]*`)

	// JavaScript协议检测
	p.javascriptRegex = regexp.MustCompile(`(?i)javascript:\s*[^\s"'>]*`)
}

// Name 实现Plugin接口
func (p *XSSPlugin) Name() string {
	return "xss"
}

// Description 实现Plugin接口
func (p *XSSPlugin) Description() string {
	return "检测反射型、存储型和DOM型跨站脚本（XSS）漏洞"
}

// Scan 实现Plugin接口
func (p *XSSPlugin) Scan(client *requester.HTTPClient, req *models.Request) ([]*vulnscan.Vulnerability, error) {
	startTime := time.Now()
	
	log.Debug().
		Str("plugin", "xss").
		Str("url", req.URL).
		Msg("开始XSS扫描")

	// 设置HTTP客户端
	p.SetHTTPClient(client)

	// 检查是否启用XSS检测
	if !p.config.EnableReflectedXSS && !p.config.EnableStoredXSS && !p.config.EnableDOMXSS {
		log.Debug().
			Str("plugin", "xss").
			Str("url", req.URL).
			Msg("XSS检测已禁用，跳过扫描")
		return nil, nil
	}

	var vulnerabilities []*vulnscan.Vulnerability

	// 检查每个参数
	var params []models.Parameter
	for name, value := range req.Params {
		paramType := "query" // 默认为查询参数
		if req.Method == "POST" {
			paramType = "post" // POST请求的参数
		}
		params = append(params, models.Parameter{
			Name:  name,
			Value: value,
			Type:  paramType,
		})
	}

	log.Debug().
		Str("plugin", "xss").
		Str("url", req.URL).
		Int("param_count", len(params)).
		Msg("提取到参数数量")

	// 检查每个参数
	for _, param := range params {
		// 为参数选择合适的payloads
		selectedPayloads := p.selectPayloadsForParameter(req, param)
		
		log.Debug().
			Str("plugin", "xss").
			Str("url", req.URL).
			Str("param", param.Name).
			Int("payload_count", len(selectedPayloads)).
			Msg("为参数选择payloads")

		// 对每个payload进行测试
		for _, payload := range selectedPayloads {
			// 检查是否应该跳过这个payload
			if p.shouldSkipPayload(payload) {
				log.Debug().
					Str("plugin", "xss").
					Str("url", req.URL).
					Str("param", param.Name).
					Str("payload", payload.Value).
					Msg("跳过payload")
				continue
			}

			// 创建XSS上下文
			xssCtx := &XSSContext{
				OriginalRequest: req,
				Parameter:       param,
				Payload:         payload.Value,
				XSSType:         XSSTypeReflected,
				Context:         context.Background(),
			}

			// 执行测试
			result, err := p.executeTest(xssCtx)
			if err != nil {
				log.Error().
					Str("plugin", "xss").
					Str("url", req.URL).
					Str("param", param.Name).
					Str("payload", payload.Value).
					Err(err).
					Msg("执行XSS测试时出错")
				continue
			}

			// 检查结果
			if result.Vulnerable {
				log.Debug().
					Str("plugin", "xss").
					Str("url", req.URL).
					Str("param", param.Name).
					Str("payload", payload.Value).
					Float64("confidence", result.Confidence).
					Msg("发现潜在XSS漏洞")
				
				// 减少误报
				if p.config.EnableFalsePositiveReduction && result.Confidence < p.config.ConfidenceThreshold {
					log.Debug().
						Str("plugin", "xss").
						Str("url", req.URL).
						Str("param", param.Name).
						Float64("confidence", result.Confidence).
						Float64("threshold", p.config.ConfidenceThreshold).
						Msg("XSS检测置信度低于阈值，可能是误报")
					p.mu.Lock()
					p.stats.FalsePositives++
					p.mu.Unlock()
					continue
				}

				// 创建漏洞对象
				vuln := p.createVulnerabilityFromResult(xssCtx, result)
				vulnerabilities = append(vulnerabilities, vuln)

				// 更新统计信息
				p.mu.Lock()
				p.stats.ReflectedXSSFound++
				p.mu.Unlock()

				// 如果只寻找一个漏洞，就退出
				if !p.config.EnableStoredXSS && !p.config.EnableDOMXSS {
					break
				}
			}
		}
	}

	log.Debug().
		Str("plugin", "xss").
		Str("url", req.URL).
		Int("vulns", len(vulnerabilities)).
		Dur("duration", time.Since(startTime)).
		Msg("XSS扫描完成")

	return vulnerabilities, nil
}

// selectPayloadsForParameter 为参数选择合适的payloads
func (p *XSSPlugin) selectPayloadsForParameter(req *models.Request, param models.Parameter) []models.Payload {
	allPayloads := p.GetDefaultPayloads()

	// 根据参数类型和上下文选择payloads
	var selectedPayloads []models.Payload
	paramName := strings.ToLower(param.Name)

	// 根据参数名称选择更合适的payloads
	if strings.Contains(paramName, "search") || strings.Contains(paramName, "query") {
		// 搜索参数通常使用基础script标签
		for _, payload := range allPayloads {
			if strings.Contains(payload.Value, "<script>") || strings.Contains(payload.Value, "alert") {
				selectedPayloads = append(selectedPayloads, payload)
				if len(selectedPayloads) >= 5 { // 限制数量
					break
				}
			}
		}
	} else if strings.Contains(paramName, "url") || strings.Contains(paramName, "link") {
		// URL参数通常使用javascript:协议
		for _, payload := range allPayloads {
			if strings.Contains(payload.Value, "javascript:") {
				selectedPayloads = append(selectedPayloads, payload)
				if len(selectedPayloads) >= 5 { // 限制数量
					break
				}
			}
		}
	} else if strings.Contains(paramName, "name") || strings.Contains(paramName, "title") {
		// 名称和标题参数通常使用事件处理器
		for _, payload := range allPayloads {
			if strings.Contains(payload.Value, "onerror") || strings.Contains(payload.Value, "onload") || 
			   strings.Contains(payload.Value, "onfocus") || strings.Contains(payload.Value, "onclick") {
				selectedPayloads = append(selectedPayloads, payload)
				if len(selectedPayloads) >= 5 { // 限制数量
					break
				}
			}
		}
	} else {
		// 其他参数使用多样化的payloads
		// 选择不同类型的payloads，确保多样性
		scriptPayloads := 0
		eventPayloads := 0
		jsProtocolPayloads := 0
		encodedPayloads := 0
		otherPayloads := 0

		for _, payload := range allPayloads {
			if strings.Contains(payload.Value, "<script>") && scriptPayloads < 2 {
				selectedPayloads = append(selectedPayloads, payload)
				scriptPayloads++
			} else if (strings.Contains(payload.Value, "onerror") || strings.Contains(payload.Value, "onload") || 
			          strings.Contains(payload.Value, "onfocus") || strings.Contains(payload.Value, "onclick")) && eventPayloads < 2 {
				selectedPayloads = append(selectedPayloads, payload)
				eventPayloads++
			} else if strings.Contains(payload.Value, "javascript:") && jsProtocolPayloads < 1 {
				selectedPayloads = append(selectedPayloads, payload)
				jsProtocolPayloads++
			} else if (strings.Contains(payload.Value, "%3C") || strings.Contains(payload.Value, "&#")) && encodedPayloads < 1 {
				selectedPayloads = append(selectedPayloads, payload)
				encodedPayloads++
			} else if otherPayloads < 2 {
				selectedPayloads = append(selectedPayloads, payload)
				otherPayloads++
			}

			if len(selectedPayloads) >= 8 { // 限制数量
				break
			}
		}
	}

	// 如果没有选择到足够的payloads，使用默认选择
	if len(selectedPayloads) == 0 {
		for i := 0; i < 5 && i < len(allPayloads); i++ {
			selectedPayloads = append(selectedPayloads, allPayloads[i])
		}
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
		`<img src=x onerror=alert('XSS')>`,
		`<svg onload=alert('XSS')>`,
		`'"><script>alert(1)</script>`,
		// 更多高级payloads
		`<img src="x" onerror="alert(1)">`,
		`<body onload=alert(1)>`,
		`<input onfocus=alert(1) autofocus>`,
		`<select onfocus=alert(1) autofocus>`,
		`<textarea onfocus=alert(1) autofocus>`,
		`<keygen onfocus=alert(1) autofocus>`,
		`<video><source onerror=alert(1)>`,
		`<audio src=x onerror=alert(1)>`,
		`<details open ontoggle=alert(1)>`,
		`<marquee onstart=alert(1)>`,
		// 编码payloads
		`%3Cscript%3Ealert(1)%3C/script%3E`,
		`%22%3E%3Cscript%3Ealert(1)%3C/script%3E`,
		`&#60;script&#62;alert(1)&#60;/script&#62;`,
		// JavaScript协议
		`javascript:alert(1)`,
		`<a href="javascript:alert(1)">click</a>`,
		// 事件处理器
		`<div onclick="alert(1)">click</div>`,
		`<img src="x" onerror="javascript:alert(1)">`,
		// SVG相关
		`<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">`,
		`<svg><script>alert(1)</script></svg>`,
		// iframe相关
		`<iframe src="javascript:alert(1)">`,
		`<iframe srcdoc="<script>alert(1)</script>">`,
		// CSS表达式
		`<style>body{background:expression(alert(1))}</style>`,
		// 数据URI
		`<object data="data:text/html,<script>alert(1)</script>">`,
		// 表单相关
		`<form><button formaction="javascript:alert(1)">click</button></form>`,
		// 其他变体
		`"><script>alert(String.fromCharCode(88,83,83))</script>`,
		`' onmouseover='alert(1)'`,
		`" onfocusin=alert(1) autofocus x="`,
	}

	var payloads []models.Payload
	for i, payloadStr := range payloadStrings {
		payloads = append(payloads, models.Payload{
			ID:          fmt.Sprintf("xss_%d", i+1),
			Value:       payloadStr,
			Type:        models.VulnTypeXSS,
			Description: fmt.Sprintf("XSS payload #%d", i+1),
			Category:    "XSS",
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
		Severity:      severity,
		Description:   description,
	}

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
	for key, value := range req.Params {
		if key == paramName {
			query.Set(key, payload)
		} else {
			query.Set(key, value)
		}
	}

	parsedURL.RawQuery = query.Encode()
	return parsedURL.String()
}

// deduplicateVulnerabilities 去重漏洞
func (p *XSSPlugin) deduplicateVulnerabilities(vulns []*vulnscan.Vulnerability) []*vulnscan.Vulnerability {
	seen := make(map[string]bool)
	result := make([]*vulnscan.Vulnerability, 0, len(vulns))

	for _, vuln := range vulns {
		key := fmt.Sprintf("%s_%s_%s_%s", vuln.Type, vuln.URL, vuln.Param, vuln.Payload)
		if !seen[key] {
			seen[key] = true
			result = append(result, vuln)
		}
	}

	return result
}

// shouldSkipPayload 检查是否应该跳过payload
func (p *XSSPlugin) shouldSkipPayload(payload models.Payload) bool {
	// 检查payload是否为空
	if payload.Value == "" {
		return true
	}

	// 检查是否启用了编码检测
	if p.config.DetectEncodedPayloads {
		// 检查是否为编码的payload
		if strings.Contains(payload.Value, "&lt;") || strings.Contains(payload.Value, "&#") || strings.Contains(payload.Value, "%3C") {
			return false // 不跳过编码的payload
		}
	}

	return false
}

// executeTest 执行单个XSS测试
func (p *XSSPlugin) executeTest(ctx *XSSContext) (*XSSResult, error) {
	log.Debug().
		Str("url", ctx.OriginalRequest.URL).
		Str("param", ctx.Parameter.Name).
		Str("payload", ctx.Payload).
		Str("xss_type", ctx.XSSType.String()).
		Msg("开始执行XSS测试")

	// 使用BaseScanPlugin的公共方法发送payload请求
	respInfo, err := p.SendPayloadRequest(ctx.OriginalRequest, ctx.Parameter.Name, ctx.Payload)
	if err != nil {
		log.Error().
			Err(err).
			Str("url", ctx.OriginalRequest.URL).
			Str("param", ctx.Parameter.Name).
			Str("payload", ctx.Payload).
			Msg("发送payload请求失败")
		return nil, fmt.Errorf("发送payload请求失败: %w", err)
	}
	defer func() {
		// 注意：SendPayloadRequest返回的respInfo中的Body可能已经关闭
		// 如果需要访问Body内容，应该在调用SendPayloadRequest后立即处理
	}()

	log.Debug().
		Str("url", ctx.OriginalRequest.URL).
		Str("param", ctx.Parameter.Name).
		Str("payload", ctx.Payload).
		Int("status_code", respInfo.StatusCode).
		Int("body_length", len(respInfo.Body)).
		Msg("收到响应")

	// 检查响应中是否包含payload
	result := &XSSResult{
		Vulnerable: false,
		Confidence: 0.0,
		Evidence:   make([]vulnscan.Evidence, 0),
		XSSType:    ctx.XSSType,
		Payload:    ctx.Payload,
		Response:   respInfo,
	}

	// 检查响应体中是否包含payload
	bodyStr := string(respInfo.Body)
	if strings.Contains(bodyStr, ctx.Payload) {
		log.Debug().
			Str("url", ctx.OriginalRequest.URL).
			Str("param", ctx.Parameter.Name).
			Str("payload", ctx.Payload).
			Msg("在响应体中发现payload")
		
		result.Vulnerable = true
		result.Confidence = 0.8
		result.Evidence = append(result.Evidence, vulnscan.Evidence{
			Type:        "response_body",
			Location:    "body",
			Value:       ctx.Payload,
			Description: "在响应体中发现payload",
		})
	}

	// 检查响应头中是否包含payload
	// 注意：这里需要从respInfo.Headers中检查，而不是resp.Header
	for key, values := range respInfo.Headers {
		for _, value := range values {
			// 将value转换为string类型
			valueStr := fmt.Sprintf("%v", value)
			if strings.Contains(valueStr, ctx.Payload) {
				log.Debug().
					Str("url", ctx.OriginalRequest.URL).
					Str("param", ctx.Parameter.Name).
					Str("payload", ctx.Payload).
					Str("header", key).
					Msg("在响应头中发现payload")
				
				result.Vulnerable = true
				result.Confidence = max(result.Confidence, 0.6)
				result.Evidence = append(result.Evidence, vulnscan.Evidence{
					Type:        "response_header",
					Location:    key,
					Value:       ctx.Payload,
					Description: fmt.Sprintf("在响应头%s中发现payload", key),
				})
			}
		}
	}

	// 使用正则表达式进行更深入的检测
	// 检查script标签
	if p.scriptTagRegex.MatchString(bodyStr) {
		log.Debug().
			Str("url", ctx.OriginalRequest.URL).
			Str("param", ctx.Parameter.Name).
			Str("payload", ctx.Payload).
			Msg("在响应体中发现script标签")
		
		result.Vulnerable = true
		result.Confidence = max(result.Confidence, 0.7)
		result.Evidence = append(result.Evidence, vulnscan.Evidence{
			Type:        "regex_match",
			Location:    "body",
			Value:       "script_tag",
			Description: "在响应体中发现script标签",
		})
	}

	// 检查事件处理器
	if p.eventHandlerRegex.MatchString(bodyStr) {
		result.Vulnerable = true
		result.Confidence = max(result.Confidence, 0.7)
		result.Evidence = append(result.Evidence, vulnscan.Evidence{
			Type:        "regex_match",
			Location:    "body",
			Value:       "event_handler",
			Description: "在响应体中发现事件处理器",
		})
	}

	// 检查JavaScript协议
	if p.javascriptRegex.MatchString(bodyStr) {
		result.Vulnerable = true
		result.Confidence = max(result.Confidence, 0.7)
		result.Evidence = append(result.Evidence, vulnscan.Evidence{
			Type:        "regex_match",
			Location:    "body",
			Value:       "javascript_protocol",
			Description: "在响应体中发现JavaScript协议",
		})
	}

	// 检查反射型XSS特征
	if p.reflectionRegex.MatchString(bodyStr) {
		result.Vulnerable = true
		result.Confidence = max(result.Confidence, 0.9)
		result.Evidence = append(result.Evidence, vulnscan.Evidence{
			Type:        "regex_match",
			Location:    "body",
			Value:       "reflection_pattern",
			Description: "在响应体中发现反射型XSS特征",
		})
	}

	// 检查DOM型XSS特征
	if p.domRegex.MatchString(bodyStr) {
		result.Vulnerable = true
		result.Confidence = max(result.Confidence, 0.8)
		result.Evidence = append(result.Evidence, vulnscan.Evidence{
			Type:        "regex_match",
			Location:    "body",
			Value:       "dom_pattern",
			Description: "在响应体中发现DOM型XSS特征",
		})
	}

	// 检查错误模式
	for _, regex := range p.errorRegexes {
		if regex.MatchString(bodyStr) {
			result.Vulnerable = true
			result.Confidence = max(result.Confidence, 0.6)
			result.Evidence = append(result.Evidence, vulnscan.Evidence{
				Type:        "regex_match",
				Location:    "body",
				Value:       "error_pattern",
				Description: "在响应体中发现错误模式",
			})
			break // 只需要匹配一个错误模式
		}
	}

	// 如果启用了DOM验证且是GET请求，进行DOM验证
	if p.config.EnableDOMVerification && ctx.OriginalRequest.Method == "GET" {
		verified, err := p.verifyDOM(ctx.OriginalRequest.URL, ctx.Payload)
		if err == nil && verified {
			result.DOMVerified = true
			result.Confidence = min(1.0, result.Confidence+0.2)
		}
	}

	// 更新统计信息
	p.mu.Lock()
	p.stats.TotalRequests++
	if result.Vulnerable {
		p.stats.SuccessfulTests++
	}
	p.mu.Unlock()

	return result, nil
}

// verifyDOM 验证DOM型XSS
func (p *XSSPlugin) verifyDOM(url, payload string) (bool, error) {
	// 如果没有浏览器服务，跳过验证
	if p.browserService == nil {
		return false, nil
	}

	// 创建浏览器实例
	browser, err := p.browserService.NewBrowser()
	if err != nil {
		return false, err
	}
	defer browser.Close()

	// 访问URL
	err = browser.Navigate(url)
	if err != nil {
		return false, err
	}

	// 等待页面加载完成
	time.Sleep(1 * time.Second)

	// 获取页面HTML内容
	html, err := browser.GetHTML()
	if err != nil {
		return false, err
	}

	// 检查HTML中是否包含payload
	if strings.Contains(html, payload) {
		return true, nil
	}

	// 检查可能的编码形式
	encodedPayloads := []string{
		strings.ReplaceAll(payload, "<", "&lt;"),
		strings.ReplaceAll(payload, ">", "&gt;"),
		strings.ReplaceAll(payload, "\"", "&quot;"),
		strings.ReplaceAll(payload, "'", "&#39;"),
		strings.ReplaceAll(payload, "/", "&#x2F;"),
	}

	for _, encoded := range encodedPayloads {
		if strings.Contains(html, encoded) {
			return true, nil
		}
	}

	return false, nil
}

// GetDefaultPayloads 获取默认payloads
func (p *XSSPlugin) GetDefaultPayloads() []models.Payload {
	if len(p.BasePlugin.GetDefaultPayloads()) == 0 {
		generatedPayloads := p.generateDefaultPayloads()
		if len(generatedPayloads) > 0 {
			p.SetPayloads(generatedPayloads)
			return generatedPayloads
		}
	}
	return p.BasePlugin.GetDefaultPayloads()
}

// Info 返回插件信息
func (p *XSSPlugin) Info() vulnscan.PluginInfo {
	return p.BaseScanPlugin.Info()
}

// Validate 验证插件配置
func (p *XSSPlugin) Validate() error {
	// 验证XSS特定配置
	if p.config.MaxPayloads <= 0 {
		return fmt.Errorf("max_payloads必须大于0")
	}

	if p.config.Timeout <= 0 {
		return fmt.Errorf("timeout必须大于0")
	}

	if p.config.DOMVerificationTimeout <= 0 {
		return fmt.Errorf("dom_verification_timeout必须大于0")
	}

	if p.config.ConfidenceThreshold < 0 || p.config.ConfidenceThreshold > 1 {
		return fmt.Errorf("confidence_threshold必须在0到1之间")
	}

	return nil
}

// SetConfig 设置插件配置
func (p *XSSPlugin) SetConfig(config map[string]interface{}) error {
	// 设置XSS特定配置
	if maxPayloads, ok := config["max_payloads"]; ok {
		if val, ok := maxPayloads.(int); ok && val > 0 {
			p.config.MaxPayloads = val
		}
	}

	if timeout, ok := config["timeout"]; ok {
		if val, ok := timeout.(time.Duration); ok && val > 0 {
			p.config.Timeout = val
		}
	}

	if domTimeout, ok := config["dom_verification_timeout"]; ok {
		if val, ok := domTimeout.(time.Duration); ok && val > 0 {
			p.config.DOMVerificationTimeout = val
		}
	}

	if enableReflected, ok := config["enable_reflected_xss"]; ok {
		if val, ok := enableReflected.(bool); ok {
			p.config.EnableReflectedXSS = val
		}
	}

	if enableStored, ok := config["enable_stored_xss"]; ok {
		if val, ok := enableStored.(bool); ok {
			p.config.EnableStoredXSS = val
		}
	}

	if enableDOM, ok := config["enable_dom_xss"]; ok {
		if val, ok := enableDOM.(bool); ok {
			p.config.EnableDOMXSS = val
		}
	}

	if enableDOMVerification, ok := config["enable_dom_verification"]; ok {
		if val, ok := enableDOMVerification.(bool); ok {
			p.config.EnableDOMVerification = val
		}
	}

	if confidenceThreshold, ok := config["confidence_threshold"]; ok {
		if val, ok := confidenceThreshold.(float64); ok && val >= 0 && val <= 1 {
			p.config.ConfidenceThreshold = val
		}
	}

	if enableFalsePositiveReduction, ok := config["enable_false_positive_reduction"]; ok {
		if val, ok := enableFalsePositiveReduction.(bool); ok {
			p.config.EnableFalsePositiveReduction = val
		}
	}

	return nil
}

// UpdateStats 更新统计信息
func (p *XSSPlugin) UpdateStats(stats interface{}) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 类型断言
	xssStats, ok := stats.(XSSStats)
	if !ok {
		log.Warn().Msg("无法将stats转换为XSSStats类型")
		return
	}

	// 更新统计信息
	p.stats.TotalRequests += xssStats.TotalRequests
	p.stats.SuccessfulTests += xssStats.SuccessfulTests
	p.stats.ReflectedXSSFound += xssStats.ReflectedXSSFound
	p.stats.StoredXSSFound += xssStats.StoredXSSFound
	p.stats.DOMXSSFound += xssStats.DOMXSSFound
	p.stats.FalsePositives += xssStats.FalsePositives
	p.stats.WAFDetections += xssStats.WAFDetections
	p.stats.DOMVerifications += xssStats.DOMVerifications

	// 更新平均响应时间
	if xssStats.SuccessfulTests > 0 {
		totalTime := p.stats.AverageResponseTime*time.Duration(p.stats.SuccessfulTests) +
			xssStats.AverageResponseTime*time.Duration(xssStats.SuccessfulTests)
		p.stats.AverageResponseTime = totalTime / time.Duration(p.stats.SuccessfulTests+xssStats.SuccessfulTests)
	}
}

// GetStats 获取统计信息
func (p *XSSPlugin) GetStats() interface{} {
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
	// 调用基类清理方法
	if err := p.BasePlugin.Cleanup(); err != nil {
		log.Warn().Err(err).Msg("基类清理出错")
	}

	// 重置插件特定状态
	p.mu.Lock()
	p.stats = XSSStats{}
	p.mu.Unlock()

	// 清理浏览器服务
	if p.browserService != nil {
		// 注意：BrowserService接口没有Close方法，这里应该调用浏览器实例的Close方法
		// 具体的清理应该在浏览器实例创建和使用的地方进行
		p.browserService = nil
	}

	return nil
}

// SetBrowserService 设置浏览器服务
func (p *XSSPlugin) SetBrowserService(browserService browser.BrowserService) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.browserService = browserService
}

// max 辅助函数，返回两个数中的较大值
func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// min 辅助函数，返回两个数中的较小值
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
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

// ScanWithContext 实现contextAware接口，支持上下文超时控制
func (p *XSSPlugin) ScanWithContext(ctx context.Context, client *requester.HTTPClient, req *models.Request) ([]*vulnscan.Vulnerability, error) {
	// 设置HTTP客户端
	p.SetHTTPClient(client)

	// 检查是否启用XSS检测
	if !p.config.EnableReflectedXSS && !p.config.EnableStoredXSS && !p.config.EnableDOMXSS {
		return nil, nil
	}

	log.Debug().Str("plugin", "xss").Str("url", req.URL).Msg("开始XSS扫描（带上下文）")

	var vulnerabilities []*vulnscan.Vulnerability

	// 检查每个参数
	var params []models.Parameter
	for name, value := range req.Params {
		paramType := "query" // 默认为查询参数
		if req.Method == "POST" {
			paramType = "post" // POST请求的参数
		}
		params = append(params, models.Parameter{
			Name:  name,
			Value: value,
			Type:  paramType,
		})
	}

	// 创建一个带超时的上下文，用于整个扫描过程
	scanCtx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()

	// 检查每个参数
	for _, param := range params {
		// 检查上下文是否已取消
		select {
		case <-scanCtx.Done():
			log.Debug().Str("plugin", "xss").Err(scanCtx.Err()).Msg("XSS扫描被取消")
			return vulnerabilities, nil
		default:
		}

		// 为参数选择合适的payloads
		selectedPayloads := p.selectPayloadsForParameter(req, param)

		// 对每个payload进行测试
		for _, payload := range selectedPayloads {
			// 检查上下文是否已取消
			select {
			case <-scanCtx.Done():
				log.Debug().Str("plugin", "xss").Err(scanCtx.Err()).Msg("XSS扫描被取消")
				return vulnerabilities, nil
			default:
			}

			// 检查是否应该跳过这个payload
			if p.shouldSkipPayload(payload) {
				continue
			}

			// 创建XSS上下文
			xssCtx := &XSSContext{
				OriginalRequest: req,
				Parameter:       param,
				Payload:         payload.Value,
				XSSType:         XSSTypeReflected,
				Context:         scanCtx, // 使用带超时的上下文
			}

			// 执行测试
			result, err := p.executeTestWithContext(xssCtx)
			if err != nil {
				log.Debug().Str("plugin", "xss").Err(err).Msg("执行XSS测试时出错")
				continue
			}

			// 检查结果
			if result.Vulnerable {
				// 减少误报
				if p.config.EnableFalsePositiveReduction && result.Confidence < p.config.ConfidenceThreshold {
					log.Debug().Str("plugin", "xss").Float64("confidence", result.Confidence).Msg("XSS检测置信度低于阈值，可能是误报")
					p.mu.Lock()
					p.stats.FalsePositives++
					p.mu.Unlock()
					continue
				}

				// 创建漏洞对象
				vuln := p.createVulnerabilityFromResult(xssCtx, result)
				vulnerabilities = append(vulnerabilities, vuln)

				// 更新统计信息
				p.mu.Lock()
				p.stats.ReflectedXSSFound++
				p.mu.Unlock()

				// 如果只寻找一个漏洞，就退出
				if !p.config.EnableStoredXSS && !p.config.EnableDOMXSS {
					break
				}
			}
		}
	}

	log.Debug().Str("plugin", "xss").Int("vulns", len(vulnerabilities)).Msg("XSS扫描完成（带上下文）")

	return vulnerabilities, nil
}

// executeTestWithContext 执行单个XSS测试（带上下文）
func (p *XSSPlugin) executeTestWithContext(ctx *XSSContext) (*XSSResult, error) {
	// 创建一个带超时的上下文，用于单个测试
	testCtx, cancel := context.WithTimeout(ctx.Context, p.config.Timeout)
	defer cancel()

	// 使用BaseScanPlugin的公共方法发送payload请求
	respInfo, err := p.SendPayloadRequest(ctx.OriginalRequest, ctx.Parameter.Name, ctx.Payload)
	if err != nil {
		return nil, fmt.Errorf("发送payload请求失败: %w", err)
	}
	defer func() {
		// 注意：SendPayloadRequest返回的respInfo中的Body可能已经关闭
		// 如果需要访问Body内容，应该在调用SendPayloadRequest后立即处理
	}()

	// 检查响应中是否包含payload
	result := &XSSResult{
		Vulnerable: false,
		Confidence: 0.0,
		Evidence:   make([]vulnscan.Evidence, 0),
		XSSType:    ctx.XSSType,
		Payload:    ctx.Payload,
		Response:   respInfo,
	}

	// 获取响应体内容
	responseBody := string(respInfo.Body)
	
	// 1. 直接payload匹配检测
	if strings.Contains(responseBody, ctx.Payload) {
		result.Vulnerable = true
		result.Confidence = 0.9 // 提高置信度
		result.Evidence = append(result.Evidence, vulnscan.Evidence{
			Type:        "response_body",
			Location:    "body",
			Value:       ctx.Payload,
			Description: "在响应体中发现完整payload",
		})
	}

	// 2. 编码payload检测
	if p.config.DetectEncodedPayloads {
		// 检查HTML编码
		htmlEncoded := strings.ReplaceAll(ctx.Payload, "<", "&lt;")
		htmlEncoded = strings.ReplaceAll(htmlEncoded, ">", "&gt;")
		if strings.Contains(responseBody, htmlEncoded) {
			result.Vulnerable = true
			result.Confidence = max(result.Confidence, 0.8) // 提高置信度
			result.Evidence = append(result.Evidence, vulnscan.Evidence{
				Type:        "response_body",
				Location:    "body",
				Value:       htmlEncoded,
				Description: "在响应体中发现HTML编码的payload",
			})
		}

		// 检查URL编码
		urlEncoded := strings.ReplaceAll(ctx.Payload, "<", "%3C")
		urlEncoded = strings.ReplaceAll(urlEncoded, ">", "%3E")
		if strings.Contains(responseBody, urlEncoded) {
			result.Vulnerable = true
			result.Confidence = max(result.Confidence, 0.8) // 提高置信度
			result.Evidence = append(result.Evidence, vulnscan.Evidence{
				Type:        "response_body",
				Location:    "body",
				Value:       urlEncoded,
				Description: "在响应体中发现URL编码的payload",
			})
		}

		// 检查十进制编码
		decimalEncoded := strings.ReplaceAll(ctx.Payload, "<", "&#60;")
		decimalEncoded = strings.ReplaceAll(decimalEncoded, ">", "&#62;")
		if strings.Contains(responseBody, decimalEncoded) {
			result.Vulnerable = true
			result.Confidence = max(result.Confidence, 0.8) // 提高置信度
			result.Evidence = append(result.Evidence, vulnscan.Evidence{
				Type:        "response_body",
				Location:    "body",
				Value:       decimalEncoded,
				Description: "在响应体中发现十进制编码的payload",
			})
		}
	}

	// 3. 使用正则表达式进行模式匹配检测
	for _, regex := range p.errorRegexes {
		if regex.MatchString(responseBody) {
			result.Vulnerable = true
			result.Confidence = max(result.Confidence, 0.7) // 提高置信度
			result.Evidence = append(result.Evidence, vulnscan.Evidence{
				Type:        "response_body",
				Location:    "body",
				Value:       regex.String(),
				Description: "在响应体中发现XSS相关模式",
			})
		}
	}

	// 4. 检查JavaScript执行证据
	if strings.Contains(responseBody, "alert(") || 
	   strings.Contains(responseBody, "confirm(") || 
	   strings.Contains(responseBody, "prompt(") {
		result.Vulnerable = true
		result.Confidence = max(result.Confidence, 0.85) // 提高置信度
		result.Evidence = append(result.Evidence, vulnscan.Evidence{
			Type:        "response_body",
			Location:    "body",
			Value:       "JavaScript execution evidence",
			Description: "在响应体中发现JavaScript执行证据",
		})
	}

	// 5. 检查事件处理器
	if p.eventHandlerRegex.MatchString(responseBody) {
		result.Vulnerable = true
		result.Confidence = max(result.Confidence, 0.75) // 提高置信度
		result.Evidence = append(result.Evidence, vulnscan.Evidence{
			Type:        "response_body",
			Location:    "body",
			Value:       "event handler",
			Description: "在响应体中发现事件处理器",
		})
	}

	// 6. 检查JavaScript协议
	if p.javascriptRegex.MatchString(responseBody) {
		result.Vulnerable = true
		result.Confidence = max(result.Confidence, 0.75) // 提高置信度
		result.Evidence = append(result.Evidence, vulnscan.Evidence{
			Type:        "response_body",
			Location:    "body",
			Value:       "javascript protocol",
			Description: "在响应体中发现JavaScript协议",
		})
	}

	// 7. 检查响应头中是否包含payload
	for key, values := range respInfo.Headers {
		for _, value := range values {
			// 将value转换为string类型
			valueStr := fmt.Sprintf("%v", value)
			if strings.Contains(valueStr, ctx.Payload) {
				result.Vulnerable = true
				result.Confidence = max(result.Confidence, 0.7) // 提高置信度
				result.Evidence = append(result.Evidence, vulnscan.Evidence{
					Type:        "response_header",
					Location:    key,
					Value:       ctx.Payload,
					Description: fmt.Sprintf("在响应头%s中发现payload", key),
				})
			}
		}
	}

	// 8. 检查简短的payload片段（针对其他工具检测到的漏洞类型）
	// 提取payload中的关键部分
	payloadKeyParts := []string{}
	if strings.Contains(ctx.Payload, "<") {
		// 提取标签名
		tagRegex := regexp.MustCompile(`<([a-zA-Z0-9]+)`)
		if matches := tagRegex.FindStringSubmatch(ctx.Payload); len(matches) > 1 {
			payloadKeyParts = append(payloadKeyParts, matches[1])
		}
	}
	
	// 检查事件处理器
	if strings.Contains(ctx.Payload, "on") {
		eventRegex := regexp.MustCompile(`on([a-zA-Z]+)`)
		if matches := eventRegex.FindStringSubmatch(ctx.Payload); len(matches) > 1 {
			payloadKeyParts = append(payloadKeyParts, "on"+matches[1])
		}
	}
	
	// 检查alert等JavaScript函数
	if strings.Contains(ctx.Payload, "alert") {
		payloadKeyParts = append(payloadKeyParts, "alert")
	}
	
	// 在响应体中查找这些关键部分
	for _, part := range payloadKeyParts {
		if strings.Contains(responseBody, part) {
			result.Vulnerable = true
			result.Confidence = max(result.Confidence, 0.6) // 提高置信度
			result.Evidence = append(result.Evidence, vulnscan.Evidence{
				Type:        "response_body",
				Location:    "body",
				Value:       part,
				Description: fmt.Sprintf("在响应体中发现payload关键部分: %s", part),
			})
		}
	}

	// 9. 如果启用了内容分析，进行更深入的分析
	if p.config.EnableContentAnalysis && result.Vulnerable {
		// 检查payload是否在JavaScript上下文中
		if p.isInJavaScriptContext(responseBody, ctx.Payload) {
			result.Confidence = min(1.0, result.Confidence+0.1)
			result.Evidence = append(result.Evidence, vulnscan.Evidence{
				Type:        "context_analysis",
				Location:    "javascript_context",
				Value:       "JavaScript context",
				Description: "Payload出现在JavaScript上下文中",
			})
		}

		// 检查payload是否在HTML属性中
		if p.isInHTMLAttributeContext(responseBody, ctx.Payload) {
			result.Confidence = min(1.0, result.Confidence+0.1)
			result.Evidence = append(result.Evidence, vulnscan.Evidence{
				Type:        "context_analysis",
				Location:    "html_attribute",
				Value:       "HTML attribute",
				Description: "Payload出现在HTML属性中",
			})
		}
	}

	// 10. 如果启用了DOM验证且是GET请求，进行DOM验证（带超时）
	if p.config.EnableDOMVerification && ctx.OriginalRequest.Method == "GET" && result.Vulnerable {
		// 创建一个带超时的上下文，用于DOM验证
		domCtx, domCancel := context.WithTimeout(testCtx, p.config.DOMVerificationTimeout)
		defer domCancel()

		verified, err := p.verifyDOMWithContext(domCtx, ctx.OriginalRequest.URL, ctx.Payload)
		if err == nil && verified {
			result.DOMVerified = true
			result.Confidence = min(1.0, result.Confidence+0.2)
			result.Evidence = append(result.Evidence, vulnscan.Evidence{
				Type:        "dom_verification",
				Location:    "browser",
				Value:       "DOM verified",
				Description: "通过浏览器DOM验证确认XSS漏洞",
			})
		}
	}

	// 更新统计信息
	p.mu.Lock()
	p.stats.TotalRequests++
	if result.Vulnerable {
		p.stats.SuccessfulTests++
	}
	p.mu.Unlock()

	return result, nil
}

// isInJavaScriptContext 检查payload是否在JavaScript上下文中
func (p *XSSPlugin) isInJavaScriptContext(responseBody, payload string) bool {
	// 检查payload是否在<script>标签内
	scriptRegex := regexp.MustCompile(`(?i)<script[^>]*>(.*?)</script>`)
	matches := scriptRegex.FindAllStringSubmatch(responseBody, -1)
	
	for _, match := range matches {
		if len(match) > 1 && strings.Contains(match[1], payload) {
			return true
		}
	}
	
	// 检查payload是否在JavaScript事件处理器中
	eventRegex := regexp.MustCompile(`(?i)on\w+\s*=\s*["'](.*?)["']`)
	matches = eventRegex.FindAllStringSubmatch(responseBody, -1)
	
	for _, match := range matches {
		if len(match) > 1 && strings.Contains(match[1], payload) {
			return true
		}
	}
	
	// 检查payload是否在JavaScript:协议中
	jsProtocolRegex := regexp.MustCompile(`(?i)javascript:\s*(.*?)["';]`)
	matches = jsProtocolRegex.FindAllStringSubmatch(responseBody, -1)
	
	for _, match := range matches {
		if len(match) > 1 && strings.Contains(match[1], payload) {
			return true
		}
	}
	
	return false
}

// isInHTMLAttributeContext 检查payload是否在HTML属性中
func (p *XSSPlugin) isInHTMLAttributeContext(responseBody, payload string) bool {
	// 检查payload是否在HTML属性值中
	attrRegex := regexp.MustCompile(`\w+\s*=\s*["'](.*?)["']`)
	matches := attrRegex.FindAllStringSubmatch(responseBody, -1)
	
	for _, match := range matches {
		if len(match) > 1 && strings.Contains(match[1], payload) {
			return true
		}
	}
	
	// 检查payload是否在未加引号的HTML属性中
	unquotedAttrRegex := regexp.MustCompile(`\w+\s*=\s*([^\s>]+)`)
	matches = unquotedAttrRegex.FindAllStringSubmatch(responseBody, -1)
	
	for _, match := range matches {
		if len(match) > 1 && strings.Contains(match[1], payload) {
			return true
		}
	}
	
	return false
}

// verifyDOMWithContext 验证DOM型XSS（带上下文）
func (p *XSSPlugin) verifyDOMWithContext(ctx context.Context, url, payload string) (bool, error) {
	// 如果没有浏览器服务，跳过验证
	if p.browserService == nil {
		return false, nil
	}

	// 创建浏览器实例
	browser, err := p.browserService.NewBrowser()
	if err != nil {
		return false, err
	}
	defer browser.Close()

	// 访问URL
	err = browser.Navigate(url)
	if err != nil {
		return false, err
	}

	// 获取页面HTML内容
	html, err := browser.GetHTML()
	if err != nil {
		return false, err
	}

	// 检查HTML中是否包含payload
	return strings.Contains(html, payload), nil
}
