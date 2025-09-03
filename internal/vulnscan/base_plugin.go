// Package vulnscan 提供了核心的漏洞扫描引擎和插件管理机制。
package vulnscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"
	"github.com/rs/zerolog/log"
)

// HTTPRequestBuilder HTTP请求构建器接口
type HTTPRequestBuilder interface {
	BuildHTTPRequest(originalReq *models.Request, paramName, paramValue string) (*http.Request, error)
	BuildPOSTRequest(originalReq *models.Request, paramName, paramValue string) (*http.Request, error)
	BuildGETRequest(originalReq *models.Request, paramName, paramValue string) (*http.Request, error)
}

// ResponseProcessor 响应处理器接口
type ResponseProcessor interface {
	GetResponseInfo(resp *http.Response) (*models.ResponseInfo, error)
	HasSignificantDifference(base, test *models.ResponseInfo, minDiff int, maxRatio float64) bool
	GenerateCacheKey(req *models.Request, paramName, paramValue string) string
}

// CacheManager 缓存管理器接口
type CacheManager interface {
	Store(key string, value interface{})
	Load(key string) (interface{}, bool)
	Delete(key string)
	Range(f func(key, value interface{}) bool)
	Clear()
}

// BaseScanPlugin 基础扫描插件，提供通用功能
type BaseScanPlugin struct {
	*BasePlugin
	httpClient      *requester.HTTPClient
	responseCache   CacheManager
	payloadCache    CacheManager
	requestBuilder  HTTPRequestBuilder
	responseProcessor ResponseProcessor
	mu              sync.RWMutex
}

// NewBaseScanPlugin 创建基础扫描插件
func NewBaseScanPlugin(info PluginInfo) *BaseScanPlugin {
	return &BaseScanPlugin{
		BasePlugin:      NewBasePlugin(info),
		responseCache:   NewSyncMapCache(),
		payloadCache:    NewSyncMapCache(),
		requestBuilder:  &DefaultHTTPRequestBuilder{},
		responseProcessor: &DefaultResponseProcessor{},
	}
}

// SetHTTPClient 设置HTTP客户端
func (bsp *BaseScanPlugin) SetHTTPClient(client *requester.HTTPClient) {
	bsp.httpClient = client
}

// SetRequestBuilder 设置请求构建器
func (bsp *BaseScanPlugin) SetRequestBuilder(builder HTTPRequestBuilder) {
	bsp.requestBuilder = builder
}

// SetResponseProcessor 设置响应处理器
func (bsp *BaseScanPlugin) SetResponseProcessor(processor ResponseProcessor) {
	bsp.responseProcessor = processor
}

// SetCacheManager 设置缓存管理器
func (bsp *BaseScanPlugin) SetCacheManager(responseCache, payloadCache CacheManager) {
	bsp.responseCache = responseCache
	bsp.payloadCache = payloadCache
}

// GetBaselineResponse 获取基线响应
func (bsp *BaseScanPlugin) GetBaselineResponse(req *models.Request, paramName, paramValue string) (*models.ResponseInfo, error) {
	cacheKey := bsp.responseProcessor.GenerateCacheKey(req, paramName, paramValue)

	// 检查缓存
	if cached, ok := bsp.responseCache.Load(cacheKey); ok {
		return cached.(*models.ResponseInfo), nil
	}

	// 构建基线请求
	httpReq, err := bsp.requestBuilder.BuildHTTPRequest(req, paramName, paramValue)
	if err != nil {
		return nil, err
	}

	// 发送请求
	resp, err := bsp.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}

	respInfo, err := bsp.responseProcessor.GetResponseInfo(resp)
	if err != nil {
		return nil, err
	}

	// 缓存响应
	bsp.responseCache.Store(cacheKey, respInfo)

	return respInfo, nil
}

// SendPayloadRequest 发送payload请求
func (bsp *BaseScanPlugin) SendPayloadRequest(req *models.Request, paramName, payload string) (*models.ResponseInfo, error) {
	httpReq, err := bsp.requestBuilder.BuildHTTPRequest(req, paramName, payload)
	if err != nil {
		return nil, err
	}

	bsp.logRequestDebug(httpReq, payload)

	resp, err := bsp.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}

	respInfo, err := bsp.responseProcessor.GetResponseInfo(resp)
	if err != nil {
		return nil, err
	}

	bsp.logResponseDebug(resp, respInfo)

	return respInfo, nil
}

// BuildVulnerableURL 构建包含漏洞的URL
func (bsp *BaseScanPlugin) BuildVulnerableURL(req *models.Request, paramName, payload string) string {
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

// logRequestDebug 记录请求调试信息
func (bsp *BaseScanPlugin) logRequestDebug(req *http.Request, payload string) {
	if log.Debug().Enabled() {
		if dump, err := httputil.DumpRequestOut(req, true); err == nil {
			log.Debug().Str("plugin", bsp.Info().Name).Msgf("Raw Request:\n%s", string(dump))
		}

		log.Debug().
			Str("plugin", bsp.Info().Name).
			Str("method", req.Method).
			Str("url", req.URL.String()).
			Str("payload", payload).
			Msg("Sending test request")
	}
}

// logResponseDebug 记录响应调试信息
func (bsp *BaseScanPlugin) logResponseDebug(resp *http.Response, info *models.ResponseInfo) {
	if !log.Debug().Enabled() || info == nil {
		return
	}

	const previewLen = 200
	preview := string(info.Body)
	if len(preview) > previewLen {
		preview = preview[:previewLen] + "..."
	}

	log.Debug().
		Str("plugin", bsp.Info().Name).
		Int("status", info.StatusCode).
		Int("bodyLen", len(info.Body)).
		Str("bodyPreview", preview).
		Str("respHash", info.Hash).
		Msg("HTTP response received")
}

// DefaultHTTPRequestBuilder 默认HTTP请求构建器
type DefaultHTTPRequestBuilder struct{}

// BuildHTTPRequest 构建HTTP请求
func (b *DefaultHTTPRequestBuilder) BuildHTTPRequest(originalReq *models.Request, paramName, paramValue string) (*http.Request, error) {
	var req *http.Request
	var err error

	if originalReq.Method == "POST" {
		req, err = b.BuildPOSTRequest(originalReq, paramName, paramValue)
	} else {
		req, err = b.BuildGETRequest(originalReq, paramName, paramValue)
	}

	if err != nil {
		return nil, fmt.Errorf("创建HTTP请求失败: %w", err)
	}

	// 复制原始请求头
	if originalReq.Headers != nil {
		req.Header = originalReq.Headers.Clone()
	}

	// 设置超时
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	req = req.WithContext(ctx)

	// 注意：这里不能直接调用cancel()，因为请求可能还在使用
	_ = cancel

	return req, nil
}

// BuildPOSTRequest 构建POST请求
func (b *DefaultHTTPRequestBuilder) BuildPOSTRequest(originalReq *models.Request, paramName, paramValue string) (*http.Request, error) {
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

// BuildGETRequest 构建GET请求
func (b *DefaultHTTPRequestBuilder) BuildGETRequest(originalReq *models.Request, paramName, paramValue string) (*http.Request, error) {
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

// DefaultResponseProcessor 默认响应处理器
type DefaultResponseProcessor struct{}

// GetResponseInfo 获取响应信息并计算hash
func (p *DefaultResponseProcessor) GetResponseInfo(resp *http.Response) (*models.ResponseInfo, error) {
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
		Body:          body,
		StatusCode:    resp.StatusCode,
		Hash:          shortHash,
		Headers:       resp.Header,
		ContentLength: int64(len(body)),
	}, nil
}

// HasSignificantDifference 检查两个响应是否有显著差异
func (p *DefaultResponseProcessor) HasSignificantDifference(base, test *models.ResponseInfo, minDiff int, maxRatio float64) bool {
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
	if lenDiff > minDiff {
		if len(base.Body) > 0 {
			relativeRatio := float64(lenDiff) / float64(len(base.Body))
			return relativeRatio > maxRatio
		}
		return true
	}

	return false
}

// GenerateCacheKey 生成缓存键
func (p *DefaultResponseProcessor) GenerateCacheKey(req *models.Request, paramName, paramValue string) string {
	return fmt.Sprintf("%s_%s_%s_%s", req.Method, req.URL, paramName, paramValue)
}

// SyncMapCache 基于sync.Map的缓存实现
type SyncMapCache struct {
	m sync.Map
}

// NewSyncMapCache 创建新的SyncMapCache
func NewSyncMapCache() *SyncMapCache {
	return &SyncMapCache{}
}

// Store 存储键值对
func (c *SyncMapCache) Store(key string, value interface{}) {
	c.m.Store(key, value)
}

// Load 加载值
func (c *SyncMapCache) Load(key string) (interface{}, bool) {
	return c.m.Load(key)
}

// Delete 删除键值对
func (c *SyncMapCache) Delete(key string) {
	c.m.Delete(key)
}

// Range 遍历所有键值对
func (c *SyncMapCache) Range(f func(key, value interface{}) bool) {
	c.m.Range(f)
}

// Clear 清空缓存
func (c *SyncMapCache) Clear() {
	c.m.Range(func(key, value interface{}) bool {
		c.m.Delete(key)
		return true
	})
}