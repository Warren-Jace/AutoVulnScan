package requester

import (
	"net/http"
	"net/url"
	"time"

	"autovulnscan/internal/config"
	"github.com/rs/zerolog/log"
)

// Requester HTTP请求接口
type Requester interface {
	Get(url string, headers map[string]string) (string, error)
	Post(url string, body string, headers map[string]string) (string, error)
}

// HTTPClient HTTP客户端接口
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// NewRequester 创建新的请求器实例
func NewRequester() (Requester, error) {
	// 简化实现
	return &MockRequester{}, nil
}

// NewHTTPClient 创建新的HTTP客户端实例
func NewHTTPClient() HTTPClient {
	// Load global config to get proxy settings
	globalConfig := config.GetDefaultConfig()
	
	// Create HTTP transport with proxy support
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}
	
	// Configure proxy if enabled
	if globalConfig.Proxy.Enabled && globalConfig.Proxy.URL != "" {
		proxyURL, err := url.Parse(globalConfig.Proxy.URL)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
			log.Info().Str("proxy", globalConfig.Proxy.URL).Msg("Using proxy for HTTP client")
		} else {
			log.Error().Err(err).Str("proxy", globalConfig.Proxy.URL).Msg("Failed to parse proxy URL")
		}
	}
	
	// Create HTTP client with proxy support
	return &RealHTTPClient{
		client: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Second, // 添加5秒超时
		},
	}
}

// MockRequester 模拟请求器
type MockRequester struct{}

// Get 发送GET请求
func (r *MockRequester) Get(url string, headers map[string]string) (string, error) {
	// 简化实现
	return "Mock GET response", nil
}

// Post 发送POST请求
func (r *MockRequester) Post(url string, body string, headers map[string]string) (string, error) {
	// 简化实现
	return "Mock POST response", nil
}

// MockHTTPClient 模拟HTTP客户端
type MockHTTPClient struct{}

// Do 发送HTTP请求
func (c *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	// 简化实现
	return &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Body:       http.NoBody,
	}, nil
}

// RealHTTPClient 真实的HTTP客户端
type RealHTTPClient struct {
	client *http.Client
}

// Do 发送HTTP请求
func (c *RealHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return c.client.Do(req)
}