// Package requester 提供了一个灵活的、用于发送HTTP请求的客户端。
package requester

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPClient 是一个自定义的、线程安全的HTTP客户端。
type HTTPClient struct {
	client  *http.Client
	headers http.Header // 存储所有请求都要使用的通用头
}

// NewHTTPClient 创建一个新的HTTPClient实例。
//
// 参数:
//
//	timeout (int): HTTP请求的超时时间（秒）。
//	headers (map[string]string): 一个包含默认HTTP头的map，这些头将被添加到每个请求中。
func NewHTTPClient(timeout int, headers map[string]string) *HTTPClient {
	// 创建一个 http.Header 对象
	headerObj := make(http.Header)
	for key, value := range headers {
		headerObj.Set(key, value)
	}

	return &HTTPClient{
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		},
		headers: headerObj,
	}
}

// Do 发送一个HTTP请求并返回响应。
// 它会自动将客户端配置的默认头信息应用到请求中。
func (c *HTTPClient) Do(req *http.Request) (*http.Response, error) {
	// 将客户端的通用头复制到请求头中
	// 这样做可以避免并发问题，同时允许为单个请求覆盖头信息
	for key, values := range c.headers {
		if req.Header.Get(key) == "" {
			req.Header[key] = values
		}
	}
	return c.client.Do(req)
}

// Get 发送一个GET请求到指定的URL。
func (c *HTTPClient) Get(ctx context.Context, urlStr string, headers http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return nil, err
	}
	if headers != nil {
		req.Header = headers
	}
	return c.Do(req)
}

// Post 发送一个POST请求到指定的URL。
func (c *HTTPClient) Post(ctx context.Context, urlStr, contentType string, body io.Reader, headers http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", urlStr, body)
	if err != nil {
		return nil, err
	}
	// 合并传入的headers到请求头中。
	if headers != nil {
		for key, values := range headers {
			req.Header[key] = values
		}
	}
	// 设置Content-Type，这可能会覆盖传入headers中的设置，这是预期的行为。
	req.Header.Set("Content-Type", contentType)
	return c.Do(req)
}

// PostForm 发送一个 "application/x-www-form-urlencoded" 类型的POST请求。
func (c *HTTPClient) PostForm(ctx context.Context, urlStr string, data url.Values, headers http.Header) (*http.Response, error) {
	return c.Post(ctx, urlStr, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()), headers)
}

// PostJSON 发送一个 "application/json" 类型的POST请求。
func (c *HTTPClient) PostJSON(ctx context.Context, urlStr string, body []byte, headers http.Header) (*http.Response, error) {
	return c.Post(ctx, urlStr, "application/json", bytes.NewBuffer(body), headers)
}

// NewRequest 是对 http.NewRequest 的一个便捷封装。
func (c *HTTPClient) NewRequest(method, urlStr string, body io.Reader) (*http.Request, error) {
	return http.NewRequest(method, urlStr, body)
}

// BuildURL 构建一个带有给定参数和payload的URL，常用于生成测试用的URL。
// 例如，将参数 "id" 和 payload "123" 添加到 "http://example.com"。
func (c *HTTPClient) BuildURL(base, param, payload string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base // 如果基础URL解析失败，则返回原样。
	}
	q := u.Query()
	q.Set(param, payload)
	u.RawQuery = q.Encode()
	return u.String()
}
