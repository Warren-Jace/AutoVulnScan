// Package ai 提供了与人工智能模型（如大型语言模型）交互的功能。
// 它可以用于生成动态的、上下文感知的漏洞扫描payloads，
// 或对扫描结果进行更智能的分析和验证。
package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/tmc/langchaingo/llms"
	"github.com/tmc/langchaingo/llms/ollama"
	"github.com/tmc/langchaingo/llms/openai"
)

// AIProvider AI提供商类型
type AIProvider string

const (
	ProviderOllama  AIProvider = "ollama"
	ProviderOpenAI  AIProvider = "openai"
	ProviderClaude  AIProvider = "claude"
	ProviderGemini  AIProvider = "gemini"
	ProviderLocal   AIProvider = "local"
)

// AIConfig AI配置
type AIConfig struct {
	Provider    AIProvider        `json:"provider"`
	APIKey      string            `json:"api_key"`
	BaseURL     string            `json:"base_url"`
	ModelName   string            `json:"model_name"`
	Temperature float64           `json:"temperature"`
	MaxTokens   int               `json:"max_tokens"`
	Timeout     time.Duration     `json:"timeout"`
	RetryCount  int               `json:"retry_count"`
	RetryDelay  time.Duration     `json:"retry_delay"`
	
	// 高级配置
	EnableCache       bool              `json:"enable_cache"`
	CacheExpiry       time.Duration     `json:"cache_expiry"`
	EnableRateLimit   bool              `json:"enable_rate_limit"`
	RateLimit         int               `json:"rate_limit"` // 每分钟请求数
	CustomPrompts     map[string]string `json:"custom_prompts"`
	
	// 安全配置
	EnableContentFilter bool     `json:"enable_content_filter"`
	BlockedKeywords     []string `json:"blocked_keywords"`
	MaxPayloadLength    int      `json:"max_payload_length"`
}

// PayloadRequest payload生成请求
type PayloadRequest struct {
	VulnType    string            `json:"vuln_type"`
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Parameter   string            `json:"parameter"`
	Context     map[string]string `json:"context"`
	Count       int               `json:"count"`
	Difficulty  string            `json:"difficulty"` // basic, intermediate, advanced
	TargetTech  []string          `json:"target_tech"` // 目标技术栈
}

// AnalysisRequest 分析请求
type AnalysisRequest struct {
	VulnType     string            `json:"vuln_type"`
	URL          string            `json:"url"`
	Payload      string            `json:"payload"`
	Response     string            `json:"response"`
	StatusCode   int               `json:"status_code"`
	ResponseTime time.Duration     `json:"response_time"`
	Context      map[string]string `json:"context"`
}

// PayloadResponse payload生成响应
type PayloadResponse struct {
	Payloads    []GeneratedPayload `json:"payloads"`
	Confidence  float64            `json:"confidence"`
	Reasoning   string             `json:"reasoning"`
	Suggestions []string           `json:"suggestions"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// GeneratedPayload 生成的payload
type GeneratedPayload struct {
	Value       string  `json:"value"`
	Type        string  `json:"type"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description"`
	Category    string  `json:"category"`
	Risk        string  `json:"risk"` // low, medium, high, critical
}

// AnalysisResponse 分析响应
type AnalysisResponse struct {
	IsVulnerable    bool                   `json:"is_vulnerable"`
	Confidence      float64                `json:"confidence"`
	VulnType        string                 `json:"vuln_type"`
	Severity        string                 `json:"severity"`
	Description     string                 `json:"description"`
	Evidence        []string               `json:"evidence"`
	FalsePositive   bool                   `json:"false_positive"`
	Recommendations []string               `json:"recommendations"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// CacheEntry 缓存条目
type CacheEntry struct {
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
	Hash      string      `json:"hash"`
}

// RateLimiter 速率限制器
type RateLimiter struct {
	requests    []time.Time
	limit       int
	window      time.Duration
	mu          sync.Mutex
}

// AIAnalyzer 封装了与AI模型交互的所有逻辑
type AIAnalyzer struct {
	config      AIConfig
	client      llms.Model
	cache       sync.Map // string -> CacheEntry
	rateLimiter *RateLimiter
	
	// 统计信息
	stats       AIStats
	statsMu     sync.RWMutex
	
	// 预编译的正则表达式
	payloadRegex    *regexp.Regexp
	securityRegex   *regexp.Regexp
	
	// 模板和提示词
	promptTemplates map[string]string
	
	// 内容过滤器
	contentFilter *ContentFilter
}

// AIStats AI使用统计
type AIStats struct {
	TotalRequests       int64         `json:"total_requests"`
	SuccessfulRequests  int64         `json:"successful_requests"`
	FailedRequests      int64         `json:"failed_requests"`
	CacheHits           int64         `json:"cache_hits"`
	CacheMisses         int64         `json:"cache_misses"`
	AverageResponseTime time.Duration `json:"average_response_time"`
	TotalTokensUsed     int64         `json:"total_tokens_used"`
	PayloadsGenerated   int64         `json:"payloads_generated"`
	AnalysesPerformed   int64         `json:"analyses_performed"`
	ErrorsByType        map[string]int64 `json:"errors_by_type"`
}

// ContentFilter 内容过滤器
type ContentFilter struct {
	blockedKeywords []string
	blockedPatterns []*regexp.Regexp
	maxLength       int
}

// 默认配置
var defaultAIConfig = AIConfig{
	Provider:          ProviderOllama,
	ModelName:         "llama2",
	Temperature:       0.7,
	MaxTokens:         1000,
	Timeout:           30 * time.Second,
	RetryCount:        3,
	RetryDelay:        2 * time.Second,
	EnableCache:       true,
	CacheExpiry:       1 * time.Hour,
	EnableRateLimit:   true,
	RateLimit:         60, // 每分钟60次请求
	MaxPayloadLength:  1000,
	EnableContentFilter: true,
	BlockedKeywords:   []string{"rm -rf", "format c:", "drop database"},
}

// NewAIAnalyzer 创建并初始化一个新的 AIAnalyzer 实例
func NewAIAnalyzer(config AIConfig) (*AIAnalyzer, error) {
	// 使用默认配置填充未设置的字段
	if config.Temperature == 0 {
		config.Temperature = defaultAIConfig.Temperature
	}
	if config.MaxTokens == 0 {
		config.MaxTokens = defaultAIConfig.MaxTokens
	}
	if config.Timeout == 0 {
		config.Timeout = defaultAIConfig.Timeout
	}
	if config.RetryCount == 0 {
		config.RetryCount = defaultAIConfig.RetryCount
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = defaultAIConfig.RetryDelay
	}
	
	analyzer := &AIAnalyzer{
		config: config,
		stats: AIStats{
			ErrorsByType: make(map[string]int64),
		},
		promptTemplates: make(map[string]string),
	}
	
	// 初始化AI客户端
	client, err := analyzer.initializeClient()
	if err != nil {
		return nil, fmt.Errorf("初始化AI客户端失败: %w", err)
	}
	analyzer.client = client
	
	// 初始化速率限制器
	if config.EnableRateLimit {
		analyzer.rateLimiter = &RateLimiter{
			limit:  config.RateLimit,
			window: time.Minute,
		}
	}
	
	// 初始化内容过滤器
	if config.EnableContentFilter {
		analyzer.contentFilter = &ContentFilter{
			blockedKeywords: config.BlockedKeywords,
			maxLength:       config.MaxPayloadLength,
		}
		analyzer.contentFilter.compilePatterns()
	}
	
	// 编译正则表达式
	analyzer.compileRegexes()
	
	// 加载默认提示词模板
	analyzer.loadDefaultPrompts()
	
	log.Info().
		Str("provider", string(config.Provider)).
		Str("model", config.ModelName).
		Bool("cache_enabled", config.EnableCache).
		Bool("rate_limit_enabled", config.EnableRateLimit).
		Msg("AI分析器初始化完成")
	
	return analyzer, nil
}

// initializeClient 初始化AI客户端
func (a *AIAnalyzer) initializeClient() (llms.Model, error) {
	switch a.config.Provider {
	case ProviderOllama:
		return a.initializeOllamaClient()
	case ProviderOpenAI:
		return a.initializeOpenAIClient()
	default:
		return nil, fmt.Errorf("不支持的AI提供商: %s", a.config.Provider)
	}
}

// initializeOllamaClient 初始化Ollama客户端
func (a *AIAnalyzer) initializeOllamaClient() (llms.Model, error) {
	opts := []ollama.Option{
		ollama.WithModel(a.config.ModelName),
	}
	
	if a.config.BaseURL != "" {
		opts = append(opts, ollama.WithServerURL(a.config.BaseURL))
	}
	
	client, err := ollama.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("初始化Ollama客户端失败: %w", err)
	}
	
	return client, nil
}

// initializeOpenAIClient 初始化OpenAI客户端
func (a *AIAnalyzer) initializeOpenAIClient() (llms.Model, error) {
	opts := []openai.Option{
		openai.WithModel(a.config.ModelName),
		openai.WithToken(a.config.APIKey),
	}
	
	if a.config.BaseURL != "" {
		opts = append(opts, openai.WithBaseURL(a.config.BaseURL))
	}
	
	client, err := openai.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("初始化OpenAI客户端失败: %w", err)
	}
	
	return client, nil
}

// compileRegexes 编译正则表达式
func (a *AIAnalyzer) compileRegexes() {
	var err error
	
	// payload提取正则
	a.payloadRegex, err = regexp.Compile(`(?i)payload[s]?\s*[:：]\s*(.+?)(?:\n|$)`)
	if err != nil {
		log.Warn().Err(err).Msg("编译payload正则失败")
	}
	
	// 安全检查正则
	a.securityRegex, err = regexp.Compile(`(?i)(rm\s+-rf|format\s+c:|drop\s+database|del\s+/|sudo\s+rm)`)
	if err != nil {
		log.Warn().Err(err).Msg("编译安全正则失败")
	}
}

// loadDefaultPrompts 加载默认提示词模板
func (a *AIAnalyzer) loadDefaultPrompts() {
	a.promptTemplates["payload_generation"] = `
你是一个专业的网络安全专家，专门生成用于漏洞测试的payloads。

任务：为 {{.VulnType}} 漏洞生成 {{.Count}} 个测试payloads
目标信息：
- URL: {{.URL}}
- HTTP方法: {{.Method}}
- 参数: {{.Parameter}}
- 难度级别: {{.Difficulty}}
{{if .TargetTech}}
- 目标技术栈: {{range .TargetTech}}{{.}} {{end}}
{{end}}

要求：
1. 生成的payloads必须是实际可用的测试载荷
2. 考虑目标的技术栈和上下文
3. 包含不同复杂度的payloads
4. 避免破坏性操作
5. 以JSON格式返回结果

返回格式：
{
  "payloads": [
    {
      "value": "payload内容",
      "type": "payload类型",
      "confidence": 0.8,
      "description": "payload描述",
      "category": "基础/中级/高级",
      "risk": "low/medium/high"
    }
  ],
  "confidence": 0.85,
  "reasoning": "生成理由",
  "suggestions": ["建议1", "建议2"]
}
`

	a.promptTemplates["vulnerability_analysis"] = `
你是一个专业的网络安全分析师，专门分析漏洞扫描结果。

任务：分析以下HTTP响应是否存在 {{.VulnType}} 漏洞

请求信息：
- URL: {{.URL}}
- Payload: {{.Payload}}
- HTTP状态码: {{.StatusCode}}
- 响应时间: {{.ResponseTime}}

响应内容：
{{.Response}}

请分析并以JSON格式返回结果：
{
  "is_vulnerable": true/false,
  "confidence": 0.0-1.0,
  "vuln_type": "漏洞类型",
  "severity": "low/medium/high/critical",
  "description": "详细描述",
  "evidence": ["证据1", "证据2"],
  "false_positive": true/false,
  "recommendations": ["修复建议1", "修复建议2"]
}
`
}

// GeneratePayloads 生成payloads
func (a *AIAnalyzer) GeneratePayloads(ctx context.Context, req PayloadRequest) (*PayloadResponse, error) {
	startTime := time.Now()
	defer func() {
		a.updateStats(true, time.Since(startTime), 0)
	}()
	
	// 验证请求
	if err := a.validatePayloadRequest(req); err != nil {
		return nil, fmt.Errorf("请求验证失败: %w", err)
	}
	
	// 检查缓存
	if a.config.EnableCache {
		if cached := a.getCachedResponse(req); cached != nil {
			a.incrementCacheHits()
			return cached.(*PayloadResponse), nil
		}
		a.incrementCacheMisses()
	}
	
	// 速率限制检查
	if a.rateLimiter != nil {
		if !a.rateLimiter.Allow() {
			return nil, fmt.Errorf("请求频率超限，请稍后重试")
		}
	}
	
	// 生成提示词
	prompt, err := a.buildPayloadPrompt(req)
	if err != nil {
		return nil, fmt.Errorf("构建提示词失败: %w", err)
	}
	
	// 调用AI模型
	response, err := a.callAIWithRetry(ctx, prompt)
	if err != nil {
		a.incrementErrorStats("ai_call_failed")
		return nil, fmt.Errorf("AI调用失败: %w", err)
	}
	
	// 解析响应
	payloadResp, err := a.parsePayloadResponse(response)
	if err != nil {
		a.incrementErrorStats("parse_failed")
		return nil, fmt.Errorf("解析AI响应失败: %w", err)
	}
	
	// 内容过滤
	if a.contentFilter != nil {
		payloadResp.Payloads = a.contentFilter.FilterPayloads(payloadResp.Payloads)
	}
	
	// 缓存结果
	if a.config.EnableCache {
		a.cacheResponse(req, payloadResp)
	}
	
	a.incrementPayloadStats(int64(len(payloadResp.Payloads)))
	
	log.Info().
		Str("vuln_type", req.VulnType).
		Int("payload_count", len(payloadResp.Payloads)).
		Float64("confidence", payloadResp.Confidence).
		Dur("duration", time.Since(startTime)).
		Msg("成功生成payloads")
	
	return payloadResp, nil
}

// AnalyzeVulnerability 分析漏洞
func (a *AIAnalyzer) AnalyzeVulnerability(ctx context.Context, req AnalysisRequest) (*AnalysisResponse, error) {
	startTime := time.Now()
	defer func() {
		a.updateStats(true, time.Since(startTime), 0)
	}()
	
	// 验证请求
	if err := a.validateAnalysisRequest(req); err != nil {
		return nil, fmt.Errorf("请求验证失败: %w", err)
	}
	
	// 检查缓存
	if a.config.EnableCache {
		if cached := a.getCachedAnalysis(req); cached != nil {
			a.incrementCacheHits()
			return cached.(*AnalysisResponse), nil
		}
		a.incrementCacheMisses()
	}
	
	// 速率限制检查
	if a.rateLimiter != nil {
		if !a.rateLimiter.Allow() {
			return nil, fmt.Errorf("请求频率超限，请稍后重试")
		}
	}
	
	// 生成分析提示词
	prompt, err := a.buildAnalysisPrompt(req)
	if err != nil {
		return nil, fmt.Errorf("构建分析提示词失败: %w", err)
	}
	
	// 调用AI模型
	response, err := a.callAIWithRetry(ctx, prompt)
	if err != nil {
		a.incrementErrorStats("ai_analysis_failed")
		return nil, fmt.Errorf("AI分析失败: %w", err)
	}
	
	// 解析分析响应
	analysisResp, err := a.parseAnalysisResponse(response)
	if err != nil {
		a.incrementErrorStats("analysis_parse_failed")
		return nil, fmt.Errorf("解析AI分析响应失败: %w", err)
	}
	
	// 缓存结果
	if a.config.EnableCache {
		a.cacheAnalysis(req, analysisResp)
	}
	
	a.incrementAnalysisStats()
	
	log.Info().
		Str("vuln_type", req.VulnType).
		Bool("vulnerable", analysisResp.IsVulnerable).
		Float64("confidence", analysisResp.Confidence).
		Str("severity", analysisResp.Severity).
		Dur("duration", time.Since(startTime)).
		Msg("完成漏洞分析")
	
	return analysisResp, nil
}

// buildPayloadPrompt 构建payload生成提示词
func (a *AIAnalyzer) buildPayloadPrompt(req PayloadRequest) (string, error) {
	template := a.promptTemplates["payload_generation"]
	if custom, exists := a.config.CustomPrompts[req.VulnType]; exists {
		template = custom
	}
	
	// 简单的模板替换（实际项目中建议使用template包）
	prompt := strings.ReplaceAll(template, "{{.VulnType}}", req.VulnType)
	prompt = strings.ReplaceAll(prompt, "{{.URL}}", req.URL)
	prompt = strings.ReplaceAll(prompt, "{{.Method}}", req.Method)
	prompt = strings.ReplaceAll(prompt, "{{.Parameter}}", req.Parameter)
	prompt = strings.ReplaceAll(prompt, "{{.Count}}", fmt.Sprintf("%d", req.Count))
	prompt = strings.ReplaceAll(prompt, "{{.Difficulty}}", req.Difficulty)
	
	return prompt, nil
}

// buildAnalysisPrompt 构建分析提示词
func (a *AIAnalyzer) buildAnalysisPrompt(req AnalysisRequest) (string, error) {
	template := a.promptTemplates["vulnerability_analysis"]
	
	prompt := strings.ReplaceAll(template, "{{.VulnType}}", req.VulnType)
	prompt = strings.ReplaceAll(prompt, "{{.URL}}", req.URL)
	prompt = strings.ReplaceAll(prompt, "{{.Payload}}", req.Payload)
	prompt = strings.ReplaceAll(prompt, "{{.StatusCode}}", fmt.Sprintf("%d", req.StatusCode))
	prompt = strings.ReplaceAll(prompt, "{{.ResponseTime}}", req.ResponseTime.String())
	prompt = strings.ReplaceAll(prompt, "{{.Response}}", a.truncateResponse(req.Response, 2000))
	
	return prompt, nil
}

// callAIWithRetry 带重试的AI调用
func (a *AIAnalyzer) callAIWithRetry(ctx context.Context, prompt string) (string, error) {
	var lastErr error
	
	for i := 0; i < a.config.RetryCount; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(a.config.RetryDelay):
			}
		}
		
		// 创建带超时的上下文
		timeoutCtx, cancel := context.WithTimeout(ctx, a.config.Timeout)
		
		response, err := llms.GenerateFromSinglePrompt(
			timeoutCtx,
			a.client,
			prompt,
			llms.WithTemperature(a.config.Temperature),
			llms.WithMaxTokens(a.config.MaxTokens),
		)
		
		cancel()
		
		if err == nil {
			return response, nil
		}
		
		lastErr = err
		log.Warn().
			Err(err).
			Int("attempt", i+1).
			Int("max_attempts", a.config.RetryCount).
			Msg("AI调用失败，准备重试")
	}
	
	return "", fmt.Errorf("AI调用失败，已重试%d次: %w", a.config.RetryCount, lastErr)
}

// parsePayloadResponse 解析payload响应
func (a *AIAnalyzer) parsePayloadResponse(response string) (*PayloadResponse, error) {
	// 尝试解析JSON响应
	var payloadResp PayloadResponse
	if err := json.Unmarshal([]byte(response), &payloadResp); err == nil {
		return &payloadResp, nil
	}
	
	// 如果JSON解析失败，尝试从文本中提取payloads
	payloads := a.extractPayloadsFromText(response)
	
	return &PayloadResponse{
		Payloads: payloads,
		Confidence: 0.6, // 文本提取的置信度较低
		Reasoning: "从AI响应文本中提取",
	}, nil
}

// parseAnalysisResponse 解析分析响应
func (a *AIAnalyzer) parseAnalysisResponse(response string) (*AnalysisResponse, error) {
	var analysisResp AnalysisResponse
	if err := json.Unmarshal([]byte(response), &analysisResp); err != nil {
		// 如果JSON解析失败，尝试从文本中提取信息
		return a.extractAnalysisFromText(response), nil
	}
	
	return &analysisResp, nil
}

// extractPayloadsFromText 从文本中提取payloads
func (a *AIAnalyzer) extractPayloadsFromText(text string) []GeneratedPayload {
	var payloads []GeneratedPayload
	
	// 使用正则表达式提取
	if a.payloadRegex != nil {
		matches := a.payloadRegex.FindAllStringSubmatch(text, -1)
		for _, match := range matches {
			if len(match) > 1 {
				payload := strings.TrimSpace(match[1])
				if payload != "" {
					payloads = append(payloads, GeneratedPayload{
						Value:       payload,
						Type:        "extracted",
						Confidence:  0.5,
						Description: "从AI响应中提取",
						Category:    "unknown",
						Risk:        "medium",
					})
				}
			}
		}
	}
	
	// 如果正则提取失败，按行分割
	if len(payloads) == 0 {
		lines := strings.Split(text, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "//") && !strings.HasPrefix(line, "#") {
				payloads = append(payloads, GeneratedPayload{
					Value:       line,
					Type:        "text_line",
					Confidence:  0.3,
					Description: "从文本行提取",
					Category:    "unknown",
					Risk:        "medium",
				})
			}
		}
	}
	
	return payloads
}

// extractAnalysisFromText 从文本中提取分析结果
func (a *AIAnalyzer) extractAnalysisFromText(text string) *AnalysisResponse {
	// 简单的文本分析逻辑
	textLower := strings.ToLower(text)
	
	isVulnerable := strings.Contains(textLower, "vulnerable") || 
		strings.Contains(textLower, "存在漏洞") ||
		strings.Contains(textLower, "发现漏洞")
	
	confidence := 0.5
	if strings.Contains(textLower, "确认") || strings.Contains(textLower, "明确") {
		confidence = 0.8
	}
	
	severity := "medium"
	if strings.Contains(textLower, "critical") || strings.Contains(textLower, "严重") {
		severity = "critical"
	} else if strings.Contains(textLower, "high") || strings.Contains(textLower, "高") {
		severity = "high"
	} else if strings.Contains(textLower, "low") || strings.Contains(textLower, "低") {
		severity = "low"
	}
	
	return &AnalysisResponse{
		IsVulnerable: isVulnerable,
		Confidence:   confidence,
		Severity:     severity,
		Description:  "基于AI文本响应的分析结果",
		Evidence:     []string{text},
		FalsePositive: false,
	}
}

// validatePayloadRequest 验证payload请求
func (a *AIAnalyzer) validatePayloadRequest(req PayloadRequest) error {
	if req.VulnType == "" {
		return fmt.Errorf("漏洞类型不能为空")
	}
	if req.URL == "" {
		return fmt.Errorf("URL不能为空")
	}
	if req.Count <= 0 || req.Count > 50 {
		return fmt.Errorf("payload数量必须在1-50之间")
	}
	return nil
}

// validateAnalysisRequest 验证分析请求
func (a *AIAnalyzer) validateAnalysisRequest(req AnalysisRequest) error {
	if req.VulnType == "" {
		return fmt.Errorf("漏洞类型不能为空")
	}
	if req.URL == "" {
		return fmt.Errorf("URL不能为空")
	}
	if req.Response == "" {
		return fmt.Errorf("响应内容不能为空")
	}
	return nil
}

// truncateResponse 截断响应内容
func (a *AIAnalyzer) truncateResponse(response string, maxLen int) string {
	if len(response) <= maxLen {
		return response
	}
	return response[:maxLen] + "..."
}

// Allow 速率限制检查
func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	now := time.Now()
	
	// 清理过期的请求记录
	var validRequests []time.Time
	for _, reqTime := range rl.requests {
		if now.Sub(reqTime) < rl.window {
			validRequests = append(validRequests, reqTime)
		}
	}
	rl.requests = validRequests
	
	// 检查是否超过限制
	if len(rl.requests) >= rl.limit {
		return false
	}
	
	// 记录新请求
		// 记录新请求
		rl.requests = append(rl.requests, now)
		return true
	}
	
	// compilePatterns 编译内容过滤模式
	func (cf *ContentFilter) compilePatterns() {
		for _, keyword := range cf.blockedKeywords {
			if regex, err := regexp.Compile("(?i)" + regexp.QuoteMeta(keyword)); err == nil {
				cf.blockedPatterns = append(cf.blockedPatterns, regex)
			}
		}
	}
	
	// FilterPayloads 过滤payloads
	func (cf *ContentFilter) FilterPayloads(payloads []GeneratedPayload) []GeneratedPayload {
		if cf == nil {
			return payloads
		}
		
		var filtered []GeneratedPayload
		for _, payload := range payloads {
			if cf.isPayloadSafe(payload.Value) {
				filtered = append(filtered, payload)
			} else {
				log.Warn().
					Str("payload", payload.Value).
					Msg("Payload被内容过滤器阻止")
			}
		}
		return filtered
	}
	
	// isPayloadSafe 检查payload是否安全
	func (cf *ContentFilter) isPayloadSafe(payload string) bool {
		// 检查长度限制
		if cf.maxLength > 0 && len(payload) > cf.maxLength {
			return false
		}
		
		// 检查阻止的关键词
		payloadLower := strings.ToLower(payload)
		for _, keyword := range cf.blockedKeywords {
			if strings.Contains(payloadLower, strings.ToLower(keyword)) {
				return false
			}
		}
		
		// 检查阻止的模式
		for _, pattern := range cf.blockedPatterns {
			if pattern.MatchString(payload) {
				return false
			}
		}
		
		return true
	}
	
	// 缓存相关方法
	
	// getCachedResponse 获取缓存的payload响应
	func (a *AIAnalyzer) getCachedResponse(req PayloadRequest) interface{} {
		key := a.generatePayloadCacheKey(req)
		if entry, ok := a.cache.Load(key); ok {
			cacheEntry := entry.(CacheEntry)
			if time.Since(cacheEntry.Timestamp) < a.config.CacheExpiry {
				return cacheEntry.Data
			}
			// 缓存过期，删除
			a.cache.Delete(key)
		}
		return nil
	}
	
	// getCachedAnalysis 获取缓存的分析结果
	func (a *AIAnalyzer) getCachedAnalysis(req AnalysisRequest) interface{} {
		key := a.generateAnalysisCacheKey(req)
		if entry, ok := a.cache.Load(key); ok {
			cacheEntry := entry.(CacheEntry)
			if time.Since(cacheEntry.Timestamp) < a.config.CacheExpiry {
				return cacheEntry.Data
			}
			// 缓存过期，删除
			a.cache.Delete(key)
		}
		return nil
	}
	
	// cacheResponse 缓存payload响应
	func (a *AIAnalyzer) cacheResponse(req PayloadRequest, resp *PayloadResponse) {
		key := a.generatePayloadCacheKey(req)
		entry := CacheEntry{
			Data:      resp,
			Timestamp: time.Now(),
			Hash:      key,
		}
		a.cache.Store(key, entry)
	}
	
	// cacheAnalysis 缓存分析结果
	func (a *AIAnalyzer) cacheAnalysis(req AnalysisRequest, resp *AnalysisResponse) {
		key := a.generateAnalysisCacheKey(req)
		entry := CacheEntry{
			Data:      resp,
			Timestamp: time.Now(),
			Hash:      key,
		}
		a.cache.Store(key, entry)
	}
	
	// generatePayloadCacheKey 生成payload缓存键
	func (a *AIAnalyzer) generatePayloadCacheKey(req PayloadRequest) string {
		return fmt.Sprintf("payload_%s_%s_%s_%s_%d_%s",
			req.VulnType, req.URL, req.Method, req.Parameter, req.Count, req.Difficulty)
	}
	
	// generateAnalysisCacheKey 生成分析缓存键
	func (a *AIAnalyzer) generateAnalysisCacheKey(req AnalysisRequest) string {
		return fmt.Sprintf("analysis_%s_%s_%s_%d",
			req.VulnType, req.URL, req.Payload, req.StatusCode)
	}
	
	// 统计相关方法
	
	// updateStats 更新统计信息
	func (a *AIAnalyzer) updateStats(success bool, responseTime time.Duration, tokens int64) {
		a.statsMu.Lock()
		defer a.statsMu.Unlock()
		
		a.stats.TotalRequests++
		if success {
			a.stats.SuccessfulRequests++
		} else {
			a.stats.FailedRequests++
		}
		
		// 更新平均响应时间
		if a.stats.TotalRequests == 1 {
			a.stats.AverageResponseTime = responseTime
		} else {
			total := a.stats.AverageResponseTime * time.Duration(a.stats.TotalRequests-1)
			a.stats.AverageResponseTime = (total + responseTime) / time.Duration(a.stats.TotalRequests)
		}
		
		a.stats.TotalTokensUsed += tokens
	}
	
	// incrementCacheHits 增加缓存命中数
	func (a *AIAnalyzer) incrementCacheHits() {
		a.statsMu.Lock()
		defer a.statsMu.Unlock()
		a.stats.CacheHits++
	}
	
	// incrementCacheMisses 增加缓存未命中数
	func (a *AIAnalyzer) incrementCacheMisses() {
		a.statsMu.Lock()
		defer a.statsMu.Unlock()
		a.stats.CacheMisses++
	}
	
	// incrementPayloadStats 增加payload统计
	func (a *AIAnalyzer) incrementPayloadStats(count int64) {
		a.statsMu.Lock()
		defer a.statsMu.Unlock()
		a.stats.PayloadsGenerated += count
	}
	
	// incrementAnalysisStats 增加分析统计
	func (a *AIAnalyzer) incrementAnalysisStats() {
		a.statsMu.Lock()
		defer a.statsMu.Unlock()
		a.stats.AnalysesPerformed++
	}
	
	// incrementErrorStats 增加错误统计
	func (a *AIAnalyzer) incrementErrorStats(errorType string) {
		a.statsMu.Lock()
		defer a.statsMu.Unlock()
		a.stats.ErrorsByType[errorType]++
	}
	
	// 公共方法
	
	// GetStats 获取统计信息
	func (a *AIAnalyzer) GetStats() AIStats {
		a.statsMu.RLock()
		defer a.statsMu.RUnlock()
		
		// 深拷贝避免并发问题
		stats := a.stats
		stats.ErrorsByType = make(map[string]int64)
		for k, v := range a.stats.ErrorsByType {
			stats.ErrorsByType[k] = v
		}
		
		return stats
	}
	
	// ResetStats 重置统计信息
	func (a *AIAnalyzer) ResetStats() {
		a.statsMu.Lock()
		defer a.statsMu.Unlock()
		
		a.stats = AIStats{
			ErrorsByType: make(map[string]int64),
		}
	}
	
	// ClearCache 清理缓存
	func (a *AIAnalyzer) ClearCache() {
		a.cache.Range(func(key, value interface{}) bool {
			a.cache.Delete(key)
			return true
		})
		
		log.Info().Msg("AI分析器缓存已清理")
	}
	
	// UpdateConfig 更新配置
	func (a *AIAnalyzer) UpdateConfig(config AIConfig) error {
		// 验证新配置
		if config.MaxTokens <= 0 {
			return fmt.Errorf("MaxTokens必须大于0")
		}
		if config.Temperature < 0 || config.Temperature > 2 {
			return fmt.Errorf("Temperature必须在0-2之间")
		}
		if config.RetryCount < 0 {
			return fmt.Errorf("RetryCount不能为负数")
		}
		
		// 更新配置
		a.config = config
		
		// 重新初始化速率限制器
		if config.EnableRateLimit {
			a.rateLimiter = &RateLimiter{
				limit:  config.RateLimit,
				window: time.Minute,
			}
		} else {
			a.rateLimiter = nil
		}
		
		// 重新初始化内容过滤器
		if config.EnableContentFilter {
			a.contentFilter = &ContentFilter{
				blockedKeywords: config.BlockedKeywords,
				maxLength:       config.MaxPayloadLength,
			}
			a.contentFilter.compilePatterns()
		} else {
			a.contentFilter = nil
		}
		
		log.Info().Msg("AI分析器配置已更新")
		return nil
	}
	
	// SetCustomPrompt 设置自定义提示词
	func (a *AIAnalyzer) SetCustomPrompt(vulnType, prompt string) {
		if a.config.CustomPrompts == nil {
			a.config.CustomPrompts = make(map[string]string)
		}
		a.config.CustomPrompts[vulnType] = prompt
		
		log.Info().
			Str("vuln_type", vulnType).
			Msg("设置自定义提示词")
	}
	
	// GetCustomPrompt 获取自定义提示词
	func (a *AIAnalyzer) GetCustomPrompt(vulnType string) (string, bool) {
		if a.config.CustomPrompts == nil {
			return "", false
		}
		prompt, exists := a.config.CustomPrompts[vulnType]
		return prompt, exists
	}
	
	// TestConnection 测试AI连接
	func (a *AIAnalyzer) TestConnection(ctx context.Context) error {
		if a.client == nil {
			return fmt.Errorf("AI客户端未初始化")
		}
		
		testPrompt := "请回复'连接正常'来确认AI服务可用。"
		
		timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		
		response, err := llms.GenerateFromSinglePrompt(
			timeoutCtx,
			a.client,
			testPrompt,
			llms.WithTemperature(0.1),
			llms.WithMaxTokens(10),
		)
		
		if err != nil {
			return fmt.Errorf("AI连接测试失败: %w", err)
		}
		
		if strings.TrimSpace(response) == "" {
			return fmt.Errorf("AI返回空响应")
		}
		
		log.Info().
			Str("response", response).
			Msg("AI连接测试成功")
		
		return nil
	}
	
	// Close 关闭AI分析器
	func (a *AIAnalyzer) Close() error {
		// 清理缓存
		a.ClearCache()
		
		// 重置统计信息
		a.ResetStats()
		
		log.Info().Msg("AI分析器已关闭")
		return nil
	}
	
	// 辅助函数
	
	// GeneratePayloadsFromText 从文本生成payloads（兼容旧版本）
	func (a *AIAnalyzer) GeneratePayloadsFromText(ctx context.Context, vulnType, url, method, param string) ([]string, error) {
		req := PayloadRequest{
			VulnType:  vulnType,
			URL:       url,
			Method:    method,
			Parameter: param,
			Count:     5,
			Difficulty: "basic",
		}
		
		resp, err := a.GeneratePayloads(ctx, req)
		if err != nil {
			return nil, err
		}
		
		var payloads []string
		for _, payload := range resp.Payloads {
			payloads = append(payloads, payload.Value)
		}
		
		return payloads, nil
	}
	
	// BatchGeneratePayloads 批量生成payloads
	func (a *AIAnalyzer) BatchGeneratePayloads(ctx context.Context, requests []PayloadRequest) ([]*PayloadResponse, error) {
		var responses []*PayloadResponse
		var errors []error
		
		// 使用通道控制并发
		semaphore := make(chan struct{}, 3) // 最多3个并发请求
		resultChan := make(chan struct {
			resp *PayloadResponse
			err  error
			idx  int
		}, len(requests))
		
		// 启动并发请求
		for i, req := range requests {
			go func(idx int, request PayloadRequest) {
				semaphore <- struct{}{} // 获取信号量
				defer func() { <-semaphore }() // 释放信号量
				
				resp, err := a.GeneratePayloads(ctx, request)
				resultChan <- struct {
					resp *PayloadResponse
					err  error
					idx  int
				}{resp, err, idx}
			}(i, req)
		}
		
		// 收集结果
		results := make([]*PayloadResponse, len(requests))
		for i := 0; i < len(requests); i++ {
			select {
			case result := <-resultChan:
				if result.err != nil {
					errors = append(errors, fmt.Errorf("请求%d失败: %w", result.idx, result.err))
				} else {
					results[result.idx] = result.resp
				}
			case <-ctx.Done():
				return responses, ctx.Err()
			}
		}
		
		// 过滤成功的结果
		for _, result := range results {
			if result != nil {
				responses = append(responses, result)
			}
		}
		
		if len(errors) > 0 {
			log.Warn().
				Int("success_count", len(responses)).
				Int("error_count", len(errors)).
				Msg("批量生成payloads部分失败")
		}
		
		return responses, nil
	}
	
	// ValidatePayload 验证单个payload
	func (a *AIAnalyzer) ValidatePayload(payload string) error {
		if a.contentFilter == nil {
			return nil
		}
		
		if !a.contentFilter.isPayloadSafe(payload) {
			return fmt.Errorf("payload未通过安全检查")
		}
		
		return nil
	}
	
	// GetSupportedVulnTypes 获取支持的漏洞类型
	func (a *AIAnalyzer) GetSupportedVulnTypes() []string {
		return []string{
			"xss",
			"sqli", 
			"rce",
			"lfi",
			"rfi",
			"xxe",
			"ssrf",
			"csrf",
			"idor",
			"path_traversal",
			"command_injection",
			"ldap_injection",
			"xpath_injection",
			"template_injection",
			"deserialization",
		}
	}
	
	// GetModelInfo 获取模型信息
	func (a *AIAnalyzer) GetModelInfo() map[string]interface{} {
		return map[string]interface{}{
			"provider":     string(a.config.Provider),
			"model_name":   a.config.ModelName,
			"temperature":  a.config.Temperature,
			"max_tokens":   a.config.MaxTokens,
			"timeout":      a.config.Timeout.String(),
			"cache_enabled": a.config.EnableCache,
			"rate_limit_enabled": a.config.EnableRateLimit,
			"content_filter_enabled": a.config.EnableContentFilter,
		}
	}
	
	// ExportStats 导出统计信息为JSON
	func (a *AIAnalyzer) ExportStats() ([]byte, error) {
		stats := a.GetStats()
		return json.MarshalIndent(stats, "", "  ")
	}
	
	// ImportCustomPrompts 导入自定义提示词
	func (a *AIAnalyzer) ImportCustomPrompts(prompts map[string]string) error {
		if a.config.CustomPrompts == nil {
			a.config.CustomPrompts = make(map[string]string)
		}
		
		for vulnType, prompt := range prompts {
			a.config.CustomPrompts[vulnType] = prompt
		}
		
		log.Info().
			Int("imported_count", len(prompts)).
			Msg("导入自定义提示词完成")
		
		return nil
	}
	
	// ExportCustomPrompts 导出自定义提示词
	func (a *AIAnalyzer) ExportCustomPrompts() ([]byte, error) {
		if a.config.CustomPrompts == nil {
			return json.Marshal(map[string]string{})
		}
		
		return json.MarshalIndent(a.config.CustomPrompts, "", "  ")
	}
	