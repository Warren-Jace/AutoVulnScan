// Package requester 提供了一个灵活、高性能的HTTP请求客户端
// 支持连接池、重试机制、请求限流、指标收集等高级功能
package requester

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// 默认配置常量
const (
	DefaultTimeout         = 30 * time.Second
	DefaultMaxIdleConns    = 100
	DefaultMaxConnsPerHost = 10
	DefaultIdleConnTimeout = 90 * time.Second
	DefaultMaxRetries      = 3
	DefaultRetryDelay      = 1 * time.Second
	DefaultRateLimitRPS    = 100
	DefaultUserAgent       = "AutoVulnScan-HTTPClient/1.0"
)

// HTTPClientConfig HTTP客户端配置
type HTTPClientConfig struct {
	// 基础配置
	Timeout         time.Duration     `json:"timeout"`
	Proxy           string            `json:"proxy,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	UserAgent       string            `json:"user_agent"`
	FollowRedirects bool              `json:"follow_redirects"`
	
	// 连接池配置
	MaxIdleConns        int           `json:"max_idle_conns"`
	MaxConnsPerHost     int           `json:"max_conns_per_host"`
	IdleConnTimeout     time.Duration `json:"idle_conn_timeout"`
	TLSHandshakeTimeout time.Duration `json:"tls_handshake_timeout"`
	
	// TLS配置
	InsecureSkipVerify bool     `json:"insecure_skip_verify"`
	TLSMinVersion      uint16   `json:"tls_min_version"`
	TLSMaxVersion      uint16   `json:"tls_max_version"`
	CACertFiles        []string `json:"ca_cert_files,omitempty"`
	ClientCertFile     string   `json:"client_cert_file,omitempty"`
	ClientKeyFile      string   `json:"client_key_file,omitempty"`
	
	// 重试配置
	MaxRetries    int           `json:"max_retries"`
	RetryDelay    time.Duration `json:"retry_delay"`
	RetryBackoff  float64       `json:"retry_backoff"`
	RetryOnStatus []int         `json:"retry_on_status,omitempty"`
	
	// 限流配置
	RateLimitRPS   int           `json:"rate_limit_rps"`
	RateLimitBurst int           `json:"rate_limit_burst"`
	
	// 其他配置
	EnableMetrics    bool `json:"enable_metrics"`
	EnableDebugLog   bool `json:"enable_debug_log"`
	MaxResponseSize  int64 `json:"max_response_size"` // 最大响应大小(字节)
	DisableKeepAlive bool `json:"disable_keep_alive"`
}

// DefaultHTTPClientConfig 返回默认配置
func DefaultHTTPClientConfig() *HTTPClientConfig {
	return &HTTPClientConfig{
		Timeout:             DefaultTimeout,
		UserAgent:           DefaultUserAgent,
		FollowRedirects:     true,
		MaxIdleConns:        DefaultMaxIdleConns,
		MaxConnsPerHost:     DefaultMaxConnsPerHost,
		IdleConnTimeout:     DefaultIdleConnTimeout,
		TLSHandshakeTimeout: 10 * time.Second,
		InsecureSkipVerify:  false,
		TLSMinVersion:       tls.VersionTLS12,
		TLSMaxVersion:       tls.VersionTLS13,
		MaxRetries:          DefaultMaxRetries,
		RetryDelay:          DefaultRetryDelay,
		RetryBackoff:        2.0,
		RetryOnStatus:       []int{429, 500, 502, 503, 504},
		RateLimitRPS:        DefaultRateLimitRPS,
		RateLimitBurst:      DefaultRateLimitRPS * 2,
		EnableMetrics:       true,
		EnableDebugLog:      false,
		MaxResponseSize:     100 * 1024 * 1024, // 100MB
		DisableKeepAlive:    false,
		Headers:             make(map[string]string),
	}
}

// RequestMetrics 请求指标
type RequestMetrics struct {
	TotalRequests    int64         `json:"total_requests"`
	SuccessRequests  int64         `json:"success_requests"`
	FailedRequests   int64         `json:"failed_requests"`
	RetryRequests    int64         `json:"retry_requests"`
	TotalDuration    time.Duration `json:"total_duration"`
	AverageDuration  time.Duration `json:"average_duration"`
	MinDuration      time.Duration `json:"min_duration"`
	MaxDuration      time.Duration `json:"max_duration"`
	StatusCodeCounts map[int]int64 `json:"status_code_counts"`
}

// RateLimiter 简单的令牌桶限流器
type RateLimiter struct {
	tokens    chan struct{}
	ticker    *time.Ticker
	rps       int
	burst     int
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
}

// NewRateLimiter 创建限流器
func NewRateLimiter(rps, burst int) *RateLimiter {
	if rps <= 0 {
		rps = DefaultRateLimitRPS
	}
	if burst <= 0 {
		burst = rps * 2
	}

	ctx, cancel := context.WithCancel(context.Background())
	rl := &RateLimiter{
		tokens: make(chan struct{}, burst),
		ticker: time.NewTicker(time.Second / time.Duration(rps)),
		rps:    rps,
		burst:  burst,
		ctx:    ctx,
		cancel: cancel,
	}

	// 预填充令牌
	for i := 0; i < burst; i++ {
		select {
		case rl.tokens <- struct{}{}:
		default:
			break
		}
	}

	// 启动令牌补充
	go rl.refillTokens()

	return rl
}

// refillTokens 定期补充令牌
func (rl *RateLimiter) refillTokens() {
	defer rl.ticker.Stop()
	
	for {
		select {
		case <-rl.ctx.Done():
			return
		case <-rl.ticker.C:
			select {
			case rl.tokens <- struct{}{}:
			default:
				// 令牌桶已满
			}
		}
	}
}

// Allow 获取令牌，如果没有可用令牌则阻塞
func (rl *RateLimiter) Allow(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-rl.tokens:
		return nil
	}
}

// Close 关闭限流器
func (rl *RateLimiter) Close() {
	rl.closeOnce.Do(func() {
		rl.cancel()
		close(rl.tokens)
	})
}

// HTTPClient 高性能HTTP客户端
type HTTPClient struct {
	client      *http.Client
	config      *HTTPClientConfig
	headers     http.Header
	rateLimiter *RateLimiter
	metrics     *RequestMetrics
	mu          sync.RWMutex
	closed      int32
}

// NewHTTPClient 创建新的HTTP客户端
func NewHTTPClient(config *HTTPClientConfig) (*HTTPClient, error) {
	if config == nil {
		config = DefaultHTTPClientConfig()
	}

	// 创建传输层
	transport, err := createTransport(config)
	if err != nil {
		return nil, fmt.Errorf("创建传输层失败: %w", err)
	}

	// 创建HTTP客户端
	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}

	// 配置重定向策略
	if !config.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// 创建默认头部
	headers := make(http.Header)
	for key, value := range config.Headers {
		headers.Set(key, value)
	}
	if config.UserAgent != "" {
		headers.Set("User-Agent", config.UserAgent)
	}

	// 创建限流器
	rateLimiter := NewRateLimiter(config.RateLimitRPS, config.RateLimitBurst)

	// 创建指标收集器
	metrics := &RequestMetrics{
		StatusCodeCounts: make(map[int]int64),
		MinDuration:      time.Hour, // 初始化为一个大值
	}

	httpClient := &HTTPClient{
		client:      client,
		config:      config,
		headers:     headers,
		rateLimiter: rateLimiter,
		metrics:     metrics,
	}

	log.Info().
		Dur("timeout", config.Timeout).
		Int("max_retries", config.MaxRetries).
		Int("rate_limit_rps", config.RateLimitRPS).
		Msg("HTTP客户端初始化完成")

	return httpClient, nil
}

// createTransport 创建HTTP传输层
func createTransport(config *HTTPClientConfig) (*http.Transport, error) {
	transport := &http.Transport{
		MaxIdleConns:        config.MaxIdleConns,
		MaxIdleConnsPerHost: config.MaxConnsPerHost,
		IdleConnTimeout:     config.IdleConnTimeout,
		TLSHandshakeTimeout: config.TLSHandshakeTimeout,
		DisableKeepAlives:   config.DisableKeepAlive,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	// 配置代理
	if config.Proxy != "" {
		proxyURL, err := url.Parse(config.Proxy)
		if err != nil {
			return nil, fmt.Errorf("解析代理URL失败: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
		log.Info().Str("proxy", config.Proxy).Msg("已配置HTTP代理")
	}

	// 配置TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.InsecureSkipVerify,
		MinVersion:         config.TLSMinVersion,
		MaxVersion:         config.TLSMaxVersion,
	}

	// 加载CA证书
	if len(config.CACertFiles) > 0 {
		// TODO: 实现CA证书加载逻辑
		log.Info().Strs("ca_certs", config.CACertFiles).Msg("CA证书配置")
	}

	// 加载客户端证书
	if config.ClientCertFile != "" && config.ClientKeyFile != "" {
		// TODO: 实现客户端证书加载逻辑
		log.Info().
			Str("cert_file", config.ClientCertFile).
			Str("key_file", config.ClientKeyFile).
			Msg("客户端证书配置")
	}

	transport.TLSClientConfig = tlsConfig
	return transport, nil
}

// Do 执行HTTP请求
func (c *HTTPClient) Do(req *http.Request) (*http.Response, error) {
	return c.DoWithRetry(req.Context(), req)
}

// DoWithRetry 执行HTTP请求（带重试）
func (c *HTTPClient) DoWithRetry(ctx context.Context, req *http.Request) (*http.Response, error) {
	if atomic.LoadInt32(&c.closed) == 1 {
		return nil, fmt.Errorf("HTTP客户端已关闭")
	}

	// 应用限流
	if err := c.rateLimiter.Allow(ctx); err != nil {
		return nil, fmt.Errorf("限流失败: %w", err)
	}

	startTime := time.Now()
	var lastErr error
	var resp *http.Response

	// 重试循环
	for attempt := 0; attempt <= c.config.MaxRetries; attempt++ {
		if attempt > 0 {
			// 计算退避延迟
			delay := time.Duration(float64(c.config.RetryDelay) * 
				(c.config.RetryBackoff * float64(attempt-1)))
			
			log.Debug().
				Int("attempt", attempt).
				Dur("delay", delay).
				Str("url", req.URL.String()).
				Msg("重试请求")

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}

			atomic.AddInt64(&c.metrics.RetryRequests, 1)
		}

		// 克隆请求以支持重试
		reqClone := c.cloneRequest(req)
		
		// 应用默认头部
		c.applyHeaders(reqClone)

		// 执行请求
		resp, lastErr = c.client.Do(reqClone)
		
		// 记录指标
		duration := time.Since(startTime)
		c.updateMetrics(resp, lastErr, duration)

		// 检查是否需要重试
		if lastErr == nil && !c.shouldRetry(resp.StatusCode) {
			break
		}

		// 如果有响应体，需要关闭以释放连接
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
	}

	if c.config.EnableDebugLog {
		c.logRequest(req, resp, lastErr, time.Since(startTime))
	}

	return resp, lastErr
}

// cloneRequest 克隆HTTP请求
func (c *HTTPClient) cloneRequest(req *http.Request) *http.Request {
	reqClone := req.Clone(req.Context())
	
	// 如果有请求体，需要重新设置
	if req.Body != nil && req.GetBody != nil {
		body, err := req.GetBody()
		if err == nil {
			reqClone.Body = body
		}
	}
	
	return reqClone
}

// applyHeaders 应用默认头部
func (c *HTTPClient) applyHeaders(req *http.Request) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for key, values := range c.headers {
		if req.Header.Get(key) == "" {
			req.Header[key] = values
		}
	}
}

// shouldRetry 判断是否应该重试
func (c *HTTPClient) shouldRetry(statusCode int) bool {
	for _, code := range c.config.RetryOnStatus {
		if statusCode == code {
			return true
		}
	}
	return false
}

// updateMetrics 更新请求指标
func (c *HTTPClient) updateMetrics(resp *http.Response, err error, duration time.Duration) {
	if !c.config.EnableMetrics {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	atomic.AddInt64(&c.metrics.TotalRequests, 1)
	c.metrics.TotalDuration += duration

	if c.metrics.MinDuration > duration {
		c.metrics.MinDuration = duration
	}
	if c.metrics.MaxDuration < duration {
		c.metrics.MaxDuration = duration
	}

	if c.metrics.TotalRequests > 0 {
		c.metrics.AverageDuration = c.metrics.TotalDuration / time.Duration(c.metrics.TotalRequests)
	}

	if err != nil {
		atomic.AddInt64(&c.metrics.FailedRequests, 1)
	} else {
		atomic.AddInt64(&c.metrics.SuccessRequests, 1)
		if resp != nil {
			c.metrics.StatusCodeCounts[resp.StatusCode]++
		}
	}
}

// logRequest 记录请求日志
func (c *HTTPClient) logRequest(req *http.Request, resp *http.Response, err error, duration time.Duration) {
	logger := log.Debug().
		Str("method", req.Method).
		Str("url", req.URL.String()).
		Dur("duration", duration)

	if err != nil {
		logger.Err(err).Msg("HTTP请求失败")
	} else if resp != nil {
		logger.Int("status", resp.StatusCode).
			Int64("content_length", resp.ContentLength).
			Msg("HTTP请求完成")
	}
}

// Get 发送GET请求
func (c *HTTPClient) Get(ctx context.Context, urlStr string, headers http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("创建GET请求失败: %w", err)
	}

	if headers != nil {
		for key, values := range headers {
			req.Header[key] = values
		}
	}

	return c.DoWithRetry(ctx, req)
}

// Post 发送POST请求
func (c *HTTPClient) Post(ctx context.Context, urlStr, contentType string, body io.Reader, headers http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, body)
	if err != nil {
		return nil, fmt.Errorf("创建POST请求失败: %w", err)
	}

	if headers != nil {
		for key, values := range headers {
			req.Header[key] = values
		}
	}

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	// 设置GetBody以支持重试
	if body != nil {
		if seeker, ok := body.(io.Seeker); ok {
			req.GetBody = func() (io.ReadCloser, error) {
				seeker.Seek(0, io.SeekStart)
				if closer, ok := body.(io.ReadCloser); ok {
					return closer, nil
				}
				return io.NopCloser(body), nil
			}
		}
	}

	return c.DoWithRetry(ctx, req)
}

// PostForm 发送表单POST请求
func (c *HTTPClient) PostForm(ctx context.Context, urlStr string, data url.Values, headers http.Header) (*http.Response, error) {
	return c.Post(ctx, urlStr, "application/x-www-form-urlencoded", 
		strings.NewReader(data.Encode()), headers)
}

// PostJSON 发送JSON POST请求
func (c *HTTPClient) PostJSON(ctx context.Context, urlStr string, data interface{}, headers http.Header) (*http.Response, error) {
	var body []byte
	var err error

	switch v := data.(type) {
	case []byte:
		body = v
	case string:
		body = []byte(v)
	default:
		body, err = json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("JSON序列化失败: %w", err)
		}
	}

	return c.Post(ctx, urlStr, "application/json", bytes.NewReader(body), headers)
}

// Put 发送PUT请求
func (c *HTTPClient) Put(ctx context.Context, urlStr, contentType string, body io.Reader, headers http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, urlStr, body)
	if err != nil {
		return nil, fmt.Errorf("创建PUT请求失败: %w", err)
	}

	if headers != nil {
		for key, values := range headers {
			req.Header[key] = values
		}
	}

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	return c.DoWithRetry(ctx, req)
}

// Delete 发送DELETE请求
func (c *HTTPClient) Delete(ctx context.Context, urlStr string, headers http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("创建DELETE请求失败: %w", err)
	}

	if headers != nil {
		for key, values := range headers {
			req.Header[key] = values
		}
	}

	return c.DoWithRetry(ctx, req)
}

// Head 发送HEAD请求
func (c *HTTPClient) Head(ctx context.Context, urlStr string, headers http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("创建HEAD请求失败: %w", err)
	}

	if headers != nil {
		for key, values := range headers {
			req.Header[key] = values
		}
	}

	return c.DoWithRetry(ctx, req)
}

// Options 发送OPTIONS请求
func (c *HTTPClient) Options(ctx context.Context, urlStr string, headers http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("创建OPTIONS请求失败: %w", err)
	}

	if headers != nil {
		for key, values := range headers {
			req.Header[key] = values
		}
	}

	return c.DoWithRetry(ctx, req)
}

// NewRequest 创建新的HTTP请求
func (c *HTTPClient) NewRequest(method, urlStr string, body io.Reader) (*http.Request, error) {
	return http.NewRequest(method, urlStr, body)
}

// NewRequestWithContext 创建带上下文的HTTP请求
func (c *HTTPClient) NewRequestWithContext(ctx context.Context, method, urlStr string, body io.Reader) (*http.Request, error) {
	return http.NewRequestWithContext(ctx, method, urlStr, body)
}

// BuildURL 构建URL
func (c *HTTPClient) BuildURL(base, param, payload string) string {
	u, err := url.Parse(base)
	if err != nil {
		log.Error().Err(err).Str("base", base).Msg("解析基础URL失败")
		return base
	}

	q := u.Query()
	q.Set(param, payload)
	u.RawQuery = q.Encode()
	return u.String()
}

// BuildURLWithParams 构建带多个参数的URL
func (c *HTTPClient) BuildURLWithParams(base string, params map[string]string) string {
	u, err := url.Parse(base)
	if err != nil {
		log.Error().Err(err).Str("base", base).Msg("解析基础URL失败")
		return base
	}

	q := u.Query()
	for key, value := range params {
		q.Set(key, value)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// SetHeader 设置默认头部
func (c *HTTPClient) SetHeader(key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.headers.Set(key, value)
}

// SetHeaders 批量设置默认头部
func (c *HTTPClient) SetHeaders(headers map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	for key, value := range headers {
		c.headers.Set(key, value)
	}
}

// GetHeader 获取默认头部
func (c *HTTPClient) GetHeader(key string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.headers.Get(key)
}

// DeleteHeader 删除默认头部
func (c *HTTPClient) DeleteHeader(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.headers.Del(key)
}

// GetMetrics 获取请求指标
func (c *HTTPClient) GetMetrics() *RequestMetrics {
	if !c.config.EnableMetrics {
		return nil
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	// 返回指标的副本
	statusCounts := make(map[int]int64)
	for code, count := range c.metrics.StatusCodeCounts {
		statusCounts[code] = count
	}

	return &RequestMetrics{
		TotalRequests:    atomic.LoadInt64(&c.metrics.TotalRequests),
		SuccessRequests:  atomic.LoadInt64(&c.metrics.SuccessRequests),
		FailedRequests:   atomic.LoadInt64(&c.metrics.FailedRequests),
		RetryRequests:    atomic.LoadInt64(&c.metrics.RetryRequests),
		TotalDuration:    c.metrics.TotalDuration,
		AverageDuration:  c.metrics.AverageDuration,
		MinDuration:      c.metrics.MinDuration,
		MaxDuration:      c.metrics.MaxDuration,
		StatusCodeCounts: statusCounts,
	}
}

// ResetMetrics 重置指标
func (c *HTTPClient) ResetMetrics() {
	if !c.config.EnableMetrics {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	atomic.StoreInt64(&c.metrics.TotalRequests, 0)
	atomic.StoreInt64(&c.metrics.SuccessRequests, 0)
	atomic.StoreInt64(&c.metrics.FailedRequests, 0)
	atomic.StoreInt64(&c.metrics.RetryRequests, 0)
	c.metrics.TotalDuration = 0
	c.metrics.AverageDuration = 0
	c.metrics.MinDuration = time.Hour
	c.metrics.MaxDuration = 0
	c.metrics.StatusCodeCounts = make(map[int]int64)
}

// GetConfig 获取客户端配置
func (c *HTTPClient) GetConfig() *HTTPClientConfig {
	// 返回配置的副本
	config := *c.config
	
	// 深拷贝Headers
	headers := make(map[string]string)
	for k, v := range c.config.Headers {
		headers[k] = v
	}
	config.Headers = headers

	// 深拷贝RetryOnStatus
	retryStatus := make([]int, len(c.config.RetryOnStatus))
	copy(retryStatus, c.config.RetryOnStatus)
	config.RetryOnStatus = retryStatus

	return &config
}

// UpdateConfig 更新客户端配置（部分配置）
func (c *HTTPClient) UpdateConfig(updates map[string]interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for key, value := range updates {
		switch key {
		case "timeout":
			if timeout, ok := value.(time.Duration); ok {
				c.config.Timeout = timeout
				c.client.Timeout = timeout
			}
		case "max_retries":
			if maxRetries, ok := value.(int); ok {
				c.config.MaxRetries = maxRetries
			}
		case "retry_delay":
			if retryDelay, ok := value.(time.Duration); ok {
				c.config.RetryDelay = retryDelay
			}
		case "user_agent":
			if userAgent, ok := value.(string); ok {
				c.config.UserAgent = userAgent
				c.headers.Set("User-Agent", userAgent)
			}
		case "enable_debug_log":
			if enableDebug, ok := value.(bool); ok {
				c.config.EnableDebugLog = enableDebug
			}
		default:
			return fmt.Errorf("不支持的配置项: %s", key)
		}
	}

	return nil
}

// Close 关闭HTTP客户端
func (c *HTTPClient) Close() error {
	if !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		return nil // 已经关闭
	}

	// 关闭限流器
	if c.rateLimiter != nil {
		c.rateLimiter.Close()
	}

	// 关闭空闲连接
	if transport, ok := c.client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}

	log.Info().Msg("HTTP客户端已关闭")
	return nil
}

// IsClosed 检查客户端是否已关闭
func (c *HTTPClient) IsClosed() bool {
	return atomic.LoadInt32(&c.closed) == 1
}

// 便利函数

// ReadResponseBody 安全读取响应体
func ReadResponseBody(resp *http.Response, maxSize int64) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, fmt.Errorf("响应或响应体为空")
	}
	defer resp.Body.Close()

	if maxSize <= 0 {
		maxSize = 10 * 1024 * 1024 // 默认10MB
	}

		// 限制读取大小
		reader := io.LimitReader(resp.Body, maxSize)
	
		body, err := io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("读取响应体失败: %w", err)
		}
	
		return body, nil
	}
	
	// DrainResponseBody 排空响应体（用于连接复用）
	func DrainResponseBody(resp *http.Response) {
		if resp == nil || resp.Body == nil {
			return
		}
		
		// 读取并丢弃剩余数据，最多读取64KB
		io.CopyN(io.Discard, resp.Body, 64*1024)
		resp.Body.Close()
	}
	
	// CheckResponseStatus 检查响应状态
	func CheckResponseStatus(resp *http.Response, expectedStatus ...int) error {
		if resp == nil {
			return fmt.Errorf("响应为空")
		}
	
		if len(expectedStatus) == 0 {
			expectedStatus = []int{http.StatusOK}
		}
	
		for _, status := range expectedStatus {
			if resp.StatusCode == status {
				return nil
			}
		}
	
		return fmt.Errorf("意外的响应状态: %d %s", resp.StatusCode, resp.Status)
	}
	
	// HTTPClientPool HTTP客户端池
	type HTTPClientPool struct {
		pool    sync.Pool
		config  *HTTPClientConfig
		metrics *PoolMetrics
		mu      sync.RWMutex
	}
	
	// PoolMetrics 客户端池指标
	type PoolMetrics struct {
		CreatedClients int64 `json:"created_clients"`
		ActiveClients  int64 `json:"active_clients"`
		PoolHits       int64 `json:"pool_hits"`
		PoolMisses     int64 `json:"pool_misses"`
	}
	
	// NewHTTPClientPool 创建HTTP客户端池
	func NewHTTPClientPool(config *HTTPClientConfig) *HTTPClientPool {
		if config == nil {
			config = DefaultHTTPClientConfig()
		}
	
		pool := &HTTPClientPool{
			config: config,
			metrics: &PoolMetrics{},
		}
	
		pool.pool = sync.Pool{
			New: func() interface{} {
				client, err := NewHTTPClient(config)
				if err != nil {
					log.Error().Err(err).Msg("创建HTTP客户端失败")
					return nil
				}
				atomic.AddInt64(&pool.metrics.CreatedClients, 1)
				atomic.AddInt64(&pool.metrics.PoolMisses, 1)
				return client
			},
		}
	
		return pool
	}
	
	// Get 从池中获取HTTP客户端
	func (p *HTTPClientPool) Get() *HTTPClient {
		client := p.pool.Get()
		if client == nil {
			// 如果池中没有可用客户端，创建新的
			newClient, err := NewHTTPClient(p.config)
			if err != nil {
				log.Error().Err(err).Msg("创建HTTP客户端失败")
				return nil
			}
			atomic.AddInt64(&p.metrics.CreatedClients, 1)
			atomic.AddInt64(&p.metrics.PoolMisses, 1)
			client = newClient
		} else {
			atomic.AddInt64(&p.metrics.PoolHits, 1)
		}
	
		atomic.AddInt64(&p.metrics.ActiveClients, 1)
		return client.(*HTTPClient)
	}
	
	// Put 将HTTP客户端放回池中
	func (p *HTTPClientPool) Put(client *HTTPClient) {
		if client == nil || client.IsClosed() {
			return
		}
	
		// 重置客户端状态
		client.ResetMetrics()
		
		atomic.AddInt64(&p.metrics.ActiveClients, -1)
		p.pool.Put(client)
	}
	
	// GetMetrics 获取池指标
	func (p *HTTPClientPool) GetMetrics() *PoolMetrics {
		p.mu.RLock()
		defer p.mu.RUnlock()
	
		return &PoolMetrics{
			CreatedClients: atomic.LoadInt64(&p.metrics.CreatedClients),
			ActiveClients:  atomic.LoadInt64(&p.metrics.ActiveClients),
			PoolHits:       atomic.LoadInt64(&p.metrics.PoolHits),
			PoolMisses:     atomic.LoadInt64(&p.metrics.PoolMisses),
		}
	}
	
	// Close 关闭客户端池
	func (p *HTTPClientPool) Close() error {
		// 这里可以实现池的清理逻辑
		// 由于sync.Pool没有提供遍历方法，我们只能等待GC回收
		log.Info().Msg("HTTP客户端池已关闭")
		return nil
	}
	
	// RequestBuilder 请求构建器
	type RequestBuilder struct {
		method      string
		url         string
		headers     http.Header
		params      url.Values
		body        io.Reader
		contentType string
		timeout     time.Duration
		ctx         context.Context
	}
	
	// NewRequestBuilder 创建请求构建器
	func NewRequestBuilder() *RequestBuilder {
		return &RequestBuilder{
			headers: make(http.Header),
			params:  make(url.Values),
			ctx:     context.Background(),
		}
	}
	
	// Method 设置请求方法
	func (rb *RequestBuilder) Method(method string) *RequestBuilder {
		rb.method = method
		return rb
	}
	
	// URL 设置请求URL
	func (rb *RequestBuilder) URL(url string) *RequestBuilder {
		rb.url = url
		return rb
	}
	
	// Header 设置请求头
	func (rb *RequestBuilder) Header(key, value string) *RequestBuilder {
		rb.headers.Set(key, value)
		return rb
	}
	
	// Headers 批量设置请求头
	func (rb *RequestBuilder) Headers(headers map[string]string) *RequestBuilder {
		for key, value := range headers {
			rb.headers.Set(key, value)
		}
		return rb
	}
	
	// Param 设置URL参数
	func (rb *RequestBuilder) Param(key, value string) *RequestBuilder {
		rb.params.Set(key, value)
		return rb
	}
	
	// Params 批量设置URL参数
	func (rb *RequestBuilder) Params(params map[string]string) *RequestBuilder {
		for key, value := range params {
			rb.params.Set(key, value)
		}
		return rb
	}
	
	// Body 设置请求体
	func (rb *RequestBuilder) Body(body io.Reader) *RequestBuilder {
		rb.body = body
		return rb
	}
	
	// JSONBody 设置JSON请求体
	func (rb *RequestBuilder) JSONBody(data interface{}) *RequestBuilder {
		jsonData, err := json.Marshal(data)
		if err != nil {
			log.Error().Err(err).Msg("JSON序列化失败")
			return rb
		}
		rb.body = bytes.NewReader(jsonData)
		rb.contentType = "application/json"
		return rb
	}
	
	// FormBody 设置表单请求体
	func (rb *RequestBuilder) FormBody(data url.Values) *RequestBuilder {
		rb.body = strings.NewReader(data.Encode())
		rb.contentType = "application/x-www-form-urlencoded"
		return rb
	}
	
	// ContentType 设置内容类型
	func (rb *RequestBuilder) ContentType(contentType string) *RequestBuilder {
		rb.contentType = contentType
		return rb
	}
	
	// Timeout 设置超时时间
	func (rb *RequestBuilder) Timeout(timeout time.Duration) *RequestBuilder {
		rb.timeout = timeout
		return rb
	}
	
	// Context 设置上下文
	func (rb *RequestBuilder) Context(ctx context.Context) *RequestBuilder {
		rb.ctx = ctx
		return rb
	}
	
	// Build 构建HTTP请求
	func (rb *RequestBuilder) Build() (*http.Request, error) {
		// 构建完整URL
		fullURL := rb.url
		if len(rb.params) > 0 {
			u, err := url.Parse(rb.url)
			if err != nil {
				return nil, fmt.Errorf("解析URL失败: %w", err)
			}
			q := u.Query()
			for key, values := range rb.params {
				for _, value := range values {
					q.Add(key, value)
				}
			}
			u.RawQuery = q.Encode()
			fullURL = u.String()
		}
	
		// 创建请求
		ctx := rb.ctx
		if rb.timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(rb.ctx, rb.timeout)
			_ = cancel // 避免未使用变量警告
		}
	
		req, err := http.NewRequestWithContext(ctx, rb.method, fullURL, rb.body)
		if err != nil {
			return nil, fmt.Errorf("创建请求失败: %w", err)
		}
	
		// 设置头部
		for key, values := range rb.headers {
			req.Header[key] = values
		}
	
		// 设置内容类型
		if rb.contentType != "" {
			req.Header.Set("Content-Type", rb.contentType)
		}
	
		return req, nil
	}
	
	// Execute 执行请求
	func (rb *RequestBuilder) Execute(client *HTTPClient) (*http.Response, error) {
		req, err := rb.Build()
		if err != nil {
			return nil, err
		}
		return client.Do(req)
	}
	
	// 常用的HTTP方法构建器
	
	// GET 创建GET请求构建器
	func GET(url string) *RequestBuilder {
		return NewRequestBuilder().Method(http.MethodGet).URL(url)
	}
	
	// POST 创建POST请求构建器
	func POST(url string) *RequestBuilder {
		return NewRequestBuilder().Method(http.MethodPost).URL(url)
	}
	
	// PUT 创建PUT请求构建器
	func PUT(url string) *RequestBuilder {
		return NewRequestBuilder().Method(http.MethodPut).URL(url)
	}
	
	// DELETE 创建DELETE请求构建器
	func DELETE(url string) *RequestBuilder {
		return NewRequestBuilder().Method(http.MethodDelete).URL(url)
	}
	
	// PATCH 创建PATCH请求构建器
	func PATCH(url string) *RequestBuilder {
		return NewRequestBuilder().Method(http.MethodPatch).URL(url)
	}
	
	// HEAD 创建HEAD请求构建器
	func HEAD(url string) *RequestBuilder {
		return NewRequestBuilder().Method(http.MethodHead).URL(url)
	}
	
	// OPTIONS 创建OPTIONS请求构建器
	func OPTIONS(url string) *RequestBuilder {
		return NewRequestBuilder().Method(http.MethodOptions).URL(url)
	}
	
	// ResponseWrapper 响应包装器
	type ResponseWrapper struct {
		*http.Response
		body []byte
		err  error
	}
	
	// NewResponseWrapper 创建响应包装器
	func NewResponseWrapper(resp *http.Response) *ResponseWrapper {
		wrapper := &ResponseWrapper{Response: resp}
		
		if resp != nil && resp.Body != nil {
			wrapper.body, wrapper.err = ReadResponseBody(resp, 10*1024*1024) // 10MB限制
		}
		
		return wrapper
	}
	
	// Body 获取响应体
	func (rw *ResponseWrapper) Body() ([]byte, error) {
		return rw.body, rw.err
	}
	
	// String 获取响应体字符串
	func (rw *ResponseWrapper) String() (string, error) {
		body, err := rw.Body()
		if err != nil {
			return "", err
		}
		return string(body), nil
	}
	
	// JSON 解析JSON响应
	func (rw *ResponseWrapper) JSON(v interface{}) error {
		body, err := rw.Body()
		if err != nil {
			return err
		}
		return json.Unmarshal(body, v)
	}
	
	// IsSuccess 检查是否成功响应
	func (rw *ResponseWrapper) IsSuccess() bool {
		return rw.Response != nil && rw.StatusCode >= 200 && rw.StatusCode < 300
	}
	
	// IsClientError 检查是否客户端错误
	func (rw *ResponseWrapper) IsClientError() bool {
		return rw.Response != nil && rw.StatusCode >= 400 && rw.StatusCode < 500
	}
	
	// IsServerError 检查是否服务器错误
	func (rw *ResponseWrapper) IsServerError() bool {
		return rw.Response != nil && rw.StatusCode >= 500
	}
	
	// HTTPError HTTP错误
	type HTTPError struct {
		StatusCode int
		Status     string
		Body       []byte
		URL        string
		Method     string
	}
	
	// Error 实现error接口
	func (e *HTTPError) Error() string {
		return fmt.Sprintf("HTTP %d: %s (%s %s)", e.StatusCode, e.Status, e.Method, e.URL)
	}
	
	// NewHTTPError 创建HTTP错误
	func NewHTTPError(resp *http.Response, body []byte) *HTTPError {
		if resp == nil {
			return &HTTPError{
				StatusCode: 0,
				Status:     "No Response",
			}
		}
	
		url := ""
		method := ""
		if resp.Request != nil {
			if resp.Request.URL != nil {
				url = resp.Request.URL.String()
			}
			method = resp.Request.Method
		}
	
		return &HTTPError{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Body:       body,
			URL:        url,
			Method:     method,
		}
	}
	
	// 中间件接口和实现
	
	// Middleware HTTP中间件接口
	type Middleware interface {
		Process(req *http.Request, next func(*http.Request) (*http.Response, error)) (*http.Response, error)
	}
	
	// MiddlewareFunc 中间件函数类型
	type MiddlewareFunc func(*http.Request, func(*http.Request) (*http.Response, error)) (*http.Response, error)
	
	// Process 实现Middleware接口
	func (f MiddlewareFunc) Process(req *http.Request, next func(*http.Request) (*http.Response, error)) (*http.Response, error) {
		return f(req, next)
	}
	
	// LoggingMiddleware 日志中间件
	func LoggingMiddleware() Middleware {
		return MiddlewareFunc(func(req *http.Request, next func(*http.Request) (*http.Response, error)) (*http.Response, error) {
			start := time.Now()
			
			log.Debug().
				Str("method", req.Method).
				Str("url", req.URL.String()).
				Msg("发送HTTP请求")
	
			resp, err := next(req)
			
			duration := time.Since(start)
			logger := log.Debug().
				Str("method", req.Method).
				Str("url", req.URL.String()).
				Dur("duration", duration)
	
			if err != nil {
				logger.Err(err).Msg("HTTP请求失败")
			} else if resp != nil {
				logger.Int("status", resp.StatusCode).Msg("HTTP请求完成")
			}
	
			return resp, err
		})
	}
	
	// RetryMiddleware 重试中间件
	func RetryMiddleware(maxRetries int, retryDelay time.Duration, retryOnStatus []int) Middleware {
		return MiddlewareFunc(func(req *http.Request, next func(*http.Request) (*http.Response, error)) (*http.Response, error) {
			var lastErr error
			var resp *http.Response
	
			for attempt := 0; attempt <= maxRetries; attempt++ {
				if attempt > 0 {
					log.Debug().
						Int("attempt", attempt).
						Dur("delay", retryDelay).
						Str("url", req.URL.String()).
						Msg("重试HTTP请求")
	
					time.Sleep(retryDelay)
				}
	
				resp, lastErr = next(req)
				
				if lastErr == nil && resp != nil {
					shouldRetry := false
					for _, code := range retryOnStatus {
						if resp.StatusCode == code {
							shouldRetry = true
							break
						}
					}
					if !shouldRetry {
						break
					}
				}
	
				if resp != nil && resp.Body != nil {
					resp.Body.Close()
				}
			}
	
			return resp, lastErr
		})
	}
	
	// TimeoutMiddleware 超时中间件
	func TimeoutMiddleware(timeout time.Duration) Middleware {
		return MiddlewareFunc(func(req *http.Request, next func(*http.Request) (*http.Response, error)) (*http.Response, error) {
			ctx, cancel := context.WithTimeout(req.Context(), timeout)
			defer cancel()
			
			req = req.WithContext(ctx)
			return next(req)
		})
	}
	
	// HTTPClientWithMiddleware 带中间件的HTTP客户端
	type HTTPClientWithMiddleware struct {
		*HTTPClient
		middlewares []Middleware
	}
	
	// NewHTTPClientWithMiddleware 创建带中间件的HTTP客户端
	func NewHTTPClientWithMiddleware(config *HTTPClientConfig, middlewares ...Middleware) (*HTTPClientWithMiddleware, error) {
		client, err := NewHTTPClient(config)
		if err != nil {
			return nil, err
		}
	
		return &HTTPClientWithMiddleware{
			HTTPClient:  client,
			middlewares: middlewares,
		}, nil
	}
	
	// Do 执行请求（应用中间件）
	func (c *HTTPClientWithMiddleware) Do(req *http.Request) (*http.Response, error) {
		// 构建中间件链
		handler := func(r *http.Request) (*http.Response, error) {
			return c.HTTPClient.Do(r)
		}
	
		// 从后向前应用中间件
		for i := len(c.middlewares) - 1; i >= 0; i-- {
			middleware := c.middlewares[i]
			currentHandler := handler
			handler = func(r *http.Request) (*http.Response, error) {
				return middleware.Process(r, currentHandler)
			}
		}
	
		return handler(req)
	}
	
	// AddMiddleware 添加中间件
	func (c *HTTPClientWithMiddleware) AddMiddleware(middleware Middleware) {
		c.middlewares = append(c.middlewares, middleware)
	}
	
	// 工具函数
	
	// IsRetryableError 判断是否为可重试的错误
	func IsRetryableError(err error) bool {
		if err == nil {
			return false
		}
	
		// 网络错误通常可以重试
		if netErr, ok := err.(net.Error); ok {
			return netErr.Timeout() || netErr.Temporary()
		}
	
		// 上下文取消不应该重试
		if err == context.Canceled || err == context.DeadlineExceeded {
			return false
		}
	
		return true
	}
	
	// IsRetryableStatusCode 判断状态码是否可重试
	func IsRetryableStatusCode(statusCode int) bool {
		retryableCodes := []int{
			http.StatusTooManyRequests,     // 429
			http.StatusInternalServerError, // 500
			http.StatusBadGateway,          // 502
			http.StatusServiceUnavailable,  // 503
			http.StatusGatewayTimeout,      // 504
		}
	
		for _, code := range retryableCodes {
			if statusCode == code {
				return true
			}
		}
		return false
	}
	
	// ParseContentType 解析Content-Type
	func ParseContentType(contentType string) (mediaType string, params map[string]string, err error) {
		parts := strings.Split(contentType, ";")
		if len(parts) == 0 {
			return "", nil, fmt.Errorf("无效的Content-Type")
		}
	
		mediaType = strings.TrimSpace(parts[0])
		params = make(map[string]string)
	
		for i := 1; i < len(parts); i++ {
			param := strings.TrimSpace(parts[i])
			if param == "" {
				continue
			}
	
			kv := strings.SplitN(param, "=", 2)
			if len(kv) != 2 {
				continue
			}
	
			key := strings.TrimSpace(kv[0])
			value := strings.Trim(strings.TrimSpace(kv[1]), "\"")
			params[key] = value
		}
	
		return mediaType, params, nil
	}
	
	// BuildUserAgent 构建User-Agent字符串
	func BuildUserAgent(appName, appVersion, goVersion string) string {
		if appName == "" {
			appName = "HTTPClient"
		}
		if appVersion == "" {
			appVersion = "1.0"
		}
		if goVersion == "" {
			goVersion = "unknown"
		}
	
		return fmt.Sprintf("%s/%s (Go %s)", appName, appVersion, goVersion)
	}
	
	// ValidateURL 验证URL格式
	func ValidateURL(urlStr string) error {
		if urlStr == "" {
			return fmt.Errorf("URL不能为空")
		}
	
		u, err := url.Parse(urlStr)
		if err != nil {
			return fmt.Errorf("URL格式无效: %w", err)
		}
	
		if u.Scheme == "" {
			return fmt.Errorf("URL缺少协议")
		}
	
		if u.Host == "" {
			return fmt.Errorf("URL缺少主机")
		}
	
		return nil
	}
	
	// SanitizeHeaders 清理HTTP头部
	func SanitizeHeaders(headers http.Header) http.Header {
		cleaned := make(http.Header)
		
		for key, values := range headers {
			// 跳过敏感头部
			lowerKey := strings.ToLower(key)
			if lowerKey == "authorization" || lowerKey == "cookie" || lowerKey == "set-cookie" {
				continue
			}
			
			cleaned[key] = values
		}
		
		return cleaned
	}
	