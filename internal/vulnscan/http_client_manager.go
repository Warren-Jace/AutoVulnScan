// Package vulnscan 提供了核心的漏洞扫描引擎和插件管理机制。
package vulnscan

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/time/rate"
)

// HTTPClientManager HTTP客户端管理器接口
type HTTPClientManager interface {
	// DoRequest 执行HTTP请求
	DoRequest(req *HTTPRequest) (*HTTPResponse, error)
	// DoRequestWithContext 执行带上下文的HTTP请求
	DoRequestWithContext(ctx context.Context, req *HTTPRequest) (*HTTPResponse, error)
	// Get 执行GET请求
	Get(url string, headers map[string]string) (*HTTPResponse, error)
	// Post 执行POST请求
	Post(url string, headers map[string]string, body string) (*HTTPResponse, error)
	// Put 执行PUT请求
	Put(url string, headers map[string]string, body string) (*HTTPResponse, error)
	// Delete 执行DELETE请求
	Delete(url string, headers map[string]string) (*HTTPResponse, error)
	// SetRateLimit 设置速率限制
	SetRateLimit(rps int)
	// SetTimeout 设置超时时间
	SetTimeout(timeout time.Duration)
	// SetRetryPolicy 设置重试策略
	SetRetryPolicy(maxRetries int, retryInterval time.Duration)
	// SetUserAgent 设置用户代理
	SetUserAgent(userAgent string)
	// AddHeader 添加默认请求头
	AddHeader(key, value string)
	// RemoveHeader 移除默认请求头
	RemoveHeader(key string)
	// SetFollowRedirects 设置是否跟随重定向
	SetFollowRedirects(follow bool)
	// SetVerifySSL 设置是否验证SSL证书
	SetVerifySSL(verify bool)
	// GetStats 获取HTTP客户端统计信息
	GetStats() HTTPClientStats
	// ResetStats 重置统计信息
	ResetStats()
}

// HTTPClientStats HTTP客户端统计信息
type HTTPClientStats struct {
	TotalRequests   int64         `json:"total_requests"`
	SuccessfulRequests int64     `json:"successful_requests"`
	FailedRequests  int64         `json:"failed_requests"`
	Retries         int64         `json:"retries"`
	BytesSent       int64         `json:"bytes_sent"`
	BytesReceived   int64         `json:"bytes_received"`
	AverageResponseTime time.Duration `json:"average_response_time"`
	StatusCodes     map[int]int64  `json:"status_codes"`
	Errors          map[string]int64 `json:"errors"`
}

// DefaultHTTPClientManager 默认HTTP客户端管理器
type DefaultHTTPClientManager struct {
	client         *http.Client
	limiter        *rate.Limiter
	timeout        time.Duration
	maxRetries     int
	retryInterval  time.Duration
	defaultHeaders map[string]string
	followRedirects bool
	verifySSL      bool
	userAgent      string
	stats          HTTPClientStats
	mutex          sync.Mutex
}

// NewDefaultHTTPClientManager 创建默认HTTP客户端管理器
func NewDefaultHTTPClientManager() *DefaultHTTPClientManager {
	manager := &DefaultHTTPClientManager{
		timeout:        30 * time.Second,
		maxRetries:     3,
		retryInterval:  1 * time.Second,
		defaultHeaders: make(map[string]string),
		followRedirects: true,
		verifySSL:      false,
		userAgent:      "AutoVulnScan/1.0",
		stats: HTTPClientStats{
			StatusCodes: make(map[int]int64),
			Errors:      make(map[string]int64),
		},
	}

	// 创建HTTP客户端
	manager.createHTTPClient()

	// 设置默认速率限制
	manager.SetRateLimit(10)

	return manager
}

// createHTTPClient 创建HTTP客户端
func (cm *DefaultHTTPClientManager) createHTTPClient() {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !cm.verifySSL,
		},
		DisableKeepAlives:   false,
		DisableCompression:  false,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	cm.client = &http.Client{
		Transport: transport,
		Timeout:   cm.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !cm.followRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// DoRequest 执行HTTP请求
func (cm *DefaultHTTPClientManager) DoRequest(req *HTTPRequest) (*HTTPResponse, error) {
	ctx := context.Background()
	return cm.DoRequestWithContext(ctx, req)
}

// DoRequestWithContext 执行带上下文的HTTP请求
func (cm *DefaultHTTPClientManager) DoRequestWithContext(ctx context.Context, req *HTTPRequest) (*HTTPResponse, error) {
	// 更新统计信息
	cm.mutex.Lock()
	cm.stats.TotalRequests++
	cm.mutex.Unlock()

	// 创建HTTP请求
	httpReq, err := cm.buildHTTPRequest(req)
	if err != nil {
		cm.mutex.Lock()
		cm.stats.FailedRequests++
		cm.stats.Errors["build_request"]++
		cm.mutex.Unlock()
		return nil, fmt.Errorf("构建HTTP请求失败: %w", err)
	}

	// 添加默认请求头
	for k, v := range cm.defaultHeaders {
		if _, exists := httpReq.Header[k]; !exists {
			httpReq.Header.Set(k, v)
		}
	}

	// 设置用户代理
	if httpReq.Header.Get("User-Agent") == "" {
		httpReq.Header.Set("User-Agent", cm.userAgent)
	}

	// 应用速率限制
	if cm.limiter != nil {
		if err := cm.limiter.Wait(ctx); err != nil {
			cm.mutex.Lock()
			cm.stats.FailedRequests++
			cm.stats.Errors["rate_limit"]++
			cm.mutex.Unlock()
			return nil, fmt.Errorf("速率限制等待失败: %w", err)
		}
	}

	// 记录请求开始时间
	startTime := time.Now()

	// 执行请求，包含重试逻辑
	var resp *http.Response
	var retryCount int
	var lastErr error

	for retryCount = 0; retryCount <= cm.maxRetries; retryCount++ {
		if retryCount > 0 {
			// 更新重试统计
			cm.mutex.Lock()
			cm.stats.Retries++
			cm.mutex.Unlock()

			// 等待重试间隔
			time.Sleep(cm.retryInterval)

			log.Debug().Str("url", req.URL).Int("attempt", retryCount+1).Msg("重试HTTP请求")
		}

		// 创建请求上下文
		reqCtx, cancel := context.WithTimeout(ctx, cm.timeout)
		defer cancel()

		// 执行请求
		resp, err = cm.client.Do(httpReq.WithContext(reqCtx))
		if err == nil {
			break
		}

		lastErr = err
		log.Debug().Str("url", req.URL).Int("attempt", retryCount+1).Err(err).Msg("HTTP请求失败")
	}

	// 计算响应时间
	responseTime := time.Since(startTime)

	// 更新平均响应时间
	cm.mutex.Lock()
	if cm.stats.TotalRequests > 0 {
		totalTime := time.Duration(cm.stats.AverageResponseTime) * time.Duration(cm.stats.TotalRequests-1)
		cm.stats.AverageResponseTime = (totalTime + responseTime) / time.Duration(cm.stats.TotalRequests)
	} else {
		cm.stats.AverageResponseTime = responseTime
	}
	cm.mutex.Unlock()

	// 检查请求是否成功
	if err != nil {
		cm.mutex.Lock()
		cm.stats.FailedRequests++
		cm.stats.Errors["request_failed"]++
		cm.mutex.Unlock()
		return nil, fmt.Errorf("HTTP请求失败: %w", lastErr)
	}

	// 更新成功请求统计
	cm.mutex.Lock()
	cm.stats.SuccessfulRequests++
	cm.stats.StatusCodes[resp.StatusCode]++
	cm.mutex.Unlock()

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		resp.Body.Close()
		cm.mutex.Lock()
		cm.stats.FailedRequests++
		cm.stats.Errors["read_response"]++
		cm.mutex.Unlock()
		return nil, fmt.Errorf("读取响应体失败: %w", err)
	}
	resp.Body.Close()

	// 更新接收字节数
	cm.mutex.Lock()
	cm.stats.BytesReceived += int64(len(body))
	cm.mutex.Unlock()

	// 构建响应对象
	response := &HTTPResponse{
		StatusCode: resp.StatusCode,
		Headers:    make(map[string]string),
		Body:       string(body),
		ResponseTime: responseTime,
	}

	// 复制响应头
	for k, v := range resp.Header {
		response.Headers[k] = strings.Join(v, ", ")
	}

	return response, nil
}

// buildHTTPRequest 构建HTTP请求
func (cm *DefaultHTTPClientManager) buildHTTPRequest(req *HTTPRequest) (*http.Request, error) {
	var body io.Reader
	if req.Body != "" {
		body = bytes.NewBufferString(req.Body)
		// 更新发送字节数
		cm.mutex.Lock()
		cm.stats.BytesSent += int64(len(req.Body))
		cm.mutex.Unlock()
	}

	httpReq, err := http.NewRequest(req.Method, req.URL, body)
	if err != nil {
		return nil, err
	}

	// 设置请求头
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	return httpReq, nil
}

// Get 执行GET请求
func (cm *DefaultHTTPClientManager) Get(url string, headers map[string]string) (*HTTPResponse, error) {
	req := &HTTPRequest{
		Method:  "GET",
		URL:     url,
		Headers: headers,
	}
	return cm.DoRequest(req)
}

// Post 执行POST请求
func (cm *DefaultHTTPClientManager) Post(url string, headers map[string]string, body string) (*HTTPResponse, error) {
	req := &HTTPRequest{
		Method:  "POST",
		URL:     url,
		Headers: headers,
		Body:    body,
	}
	return cm.DoRequest(req)
}

// Put 执行PUT请求
func (cm *DefaultHTTPClientManager) Put(url string, headers map[string]string, body string) (*HTTPResponse, error) {
	req := &HTTPRequest{
		Method:  "PUT",
		URL:     url,
		Headers: headers,
		Body:    body,
	}
	return cm.DoRequest(req)
}

// Delete 执行DELETE请求
func (cm *DefaultHTTPClientManager) Delete(url string, headers map[string]string) (*HTTPResponse, error) {
	req := &HTTPRequest{
		Method:  "DELETE",
		URL:     url,
		Headers: headers,
	}
	return cm.DoRequest(req)
}

// SetRateLimit 设置速率限制
func (cm *DefaultHTTPClientManager) SetRateLimit(rps int) {
	if rps <= 0 {
		cm.limiter = nil
		return
	}

	// 创建新的速率限制器
	cm.limiter = rate.NewLimiter(rate.Limit(rps), 1)
}

// SetTimeout 设置超时时间
func (cm *DefaultHTTPClientManager) SetTimeout(timeout time.Duration) {
	cm.timeout = timeout
	cm.createHTTPClient()
}

// SetRetryPolicy 设置重试策略
func (cm *DefaultHTTPClientManager) SetRetryPolicy(maxRetries int, retryInterval time.Duration) {
	cm.maxRetries = maxRetries
	cm.retryInterval = retryInterval
}

// SetUserAgent 设置用户代理
func (cm *DefaultHTTPClientManager) SetUserAgent(userAgent string) {
	cm.userAgent = userAgent
}

// AddHeader 添加默认请求头
func (cm *DefaultHTTPClientManager) AddHeader(key, value string) {
	cm.defaultHeaders[key] = value
}

// RemoveHeader 移除默认请求头
func (cm *DefaultHTTPClientManager) RemoveHeader(key string) {
	delete(cm.defaultHeaders, key)
}

// SetFollowRedirects 设置是否跟随重定向
func (cm *DefaultHTTPClientManager) SetFollowRedirects(follow bool) {
	cm.followRedirects = follow
	cm.createHTTPClient()
}

// SetVerifySSL 设置是否验证SSL证书
func (cm *DefaultHTTPClientManager) SetVerifySSL(verify bool) {
	cm.verifySSL = verify
	cm.createHTTPClient()
}

// GetStats 获取HTTP客户端统计信息
func (cm *DefaultHTTPClientManager) GetStats() HTTPClientStats {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	return cm.stats
}

// ResetStats 重置统计信息
func (cm *DefaultHTTPClientManager) ResetStats() {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	cm.stats = HTTPClientStats{
		StatusCodes: make(map[int]int64),
		Errors:      make(map[string]int64),
	}
}

// BuildURLWithParams 构建带参数的URL
func BuildURLWithParams(baseURL string, params map[string]string) (string, error) {
	// 解析基础URL
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("解析URL失败: %w", err)
	}

	// 获取查询参数
	query := parsedURL.Query()

	// 添加新参数
	for key, value := range params {
		query.Set(key, value)
	}

	// 设置更新后的查询参数
	parsedURL.RawQuery = query.Encode()

	return parsedURL.String(), nil
}

// BuildURLWithPayload 构建带payload的URL
func BuildURLWithPayload(baseURL string, paramName string, payload string) (string, error) {
	// 解析基础URL
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("解析URL失败: %w", err)
	}

	// 获取查询参数
	query := parsedURL.Query()

	// 设置payload参数
	query.Set(paramName, payload)

	// 设置更新后的查询参数
	parsedURL.RawQuery = query.Encode()

	return parsedURL.String(), nil
}

// BuildPOSTBodyWithParams 构建带参数的POST请求体
func BuildPOSTBodyWithParams(params map[string]string) string {
	var body strings.Builder
	first := true

	for key, value := range params {
		if !first {
			body.WriteString("&")
		}
		body.WriteString(url.QueryEscape(key))
		body.WriteString("=")
		body.WriteString(url.QueryEscape(value))
		first = false
	}

	return body.String()
}

// BuildPOSTBodyWithPayload 构建带payload的POST请求体
func BuildPOSTBodyWithPayload(paramName string, payload string, otherParams map[string]string) string {
	var body strings.Builder
	first := true

	// 添加其他参数
	for key, value := range otherParams {
		if !first {
			body.WriteString("&")
		}
		body.WriteString(url.QueryEscape(key))
		body.WriteString("=")
		body.WriteString(url.QueryEscape(value))
		first = false
	}

	// 添加payload参数
	if !first {
		body.WriteString("&")
	}
	body.WriteString(url.QueryEscape(paramName))
	body.WriteString("=")
	body.WriteString(url.QueryEscape(payload))

	return body.String()
}

// ParseContentType 解析Content-Type
func ParseContentType(contentType string) (string, map[string]string) {
	parts := strings.SplitN(contentType, ";", 2)
	mimeType := strings.TrimSpace(parts[0])
	params := make(map[string]string)

	if len(parts) > 1 {
		paramStr := strings.TrimSpace(parts[1])
		paramPairs := strings.Split(paramStr, ";")
		for _, pair := range paramPairs {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 {
				params[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}

	return mimeType, params
}

// IsContentType 检查是否为指定的Content-Type
func IsContentType(contentType, expectedType string) bool {
	actualType, _ := ParseContentType(contentType)
	return strings.EqualFold(actualType, expectedType)
}

// IsJSONContent 检查是否为JSON内容
func IsJSONContent(contentType string) bool {
	return IsContentType(contentType, "application/json") ||
		strings.HasPrefix(strings.ToLower(contentType), "application/json")
}

// IsHTMLContent 检查是否为HTML内容
func IsHTMLContent(contentType string) bool {
	return IsContentType(contentType, "text/html") ||
		strings.HasPrefix(strings.ToLower(contentType), "text/html")
}

// IsXMLContent 检查是否为XML内容
func IsXMLContent(contentType string) bool {
	return IsContentType(contentType, "application/xml") ||
		strings.HasPrefix(strings.ToLower(contentType), "application/xml") ||
		IsContentType(contentType, "text/xml") ||
		strings.HasPrefix(strings.ToLower(contentType), "text/xml")
}

// GetStatusCodeClass 获取状态码类别
func GetStatusCodeClass(statusCode int) string {
	class := statusCode / 100
	switch class {
	case 1:
		return "Informational"
	case 2:
		return "Success"
	case 3:
		return "Redirection"
	case 4:
		return "Client Error"
	case 5:
		return "Server Error"
	default:
		return "Unknown"
	}
}

// IsSuccessStatus 检查是否为成功状态码
func IsSuccessStatus(statusCode int) bool {
	return statusCode >= 200 && statusCode < 300
}

// IsRedirectStatus 检查是否为重定向状态码
func IsRedirectStatus(statusCode int) bool {
	return statusCode >= 300 && statusCode < 400
}

// IsClientErrorStatus 检查是否为客户端错误状态码
func IsClientErrorStatus(statusCode int) bool {
	return statusCode >= 400 && statusCode < 500
}

// IsServerErrorStatus 检查是否为服务器错误状态码
func IsServerErrorStatus(statusCode int) bool {
	return statusCode >= 500 && statusCode < 600
}

// ParseContentLength 解析Content-Length
func ParseContentLength(contentLength string) (int64, error) {
	if contentLength == "" {
		return 0, nil
	}
	return strconv.ParseInt(contentLength, 10, 64)
}