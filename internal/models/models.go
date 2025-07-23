// Package models 包含了 AutoVulnScan 应用程序中使用到的核心数据结构。
package models

import (
	"net/http"
	"net/url"
)

// Request 代表一个被发现的、可用于扫描的HTTP请求。
// 它是一个安全的数据容器，不直接持有像 *http.Request 这样的可变状态。
type Request struct {
	URL     string
	Method  string
	Headers http.Header
	Body    string // 对于POST请求，这里存储URL编码的表单数据
	Params  []Parameter
}

// Parameter 代表一个独立的参数，例如来自查询字符串或表单体。
type Parameter struct {
	Name  string
	Value string
}

// ParameterizedURL 代表一个URL及其识别出的参数。
type ParameterizedURL struct {
	URL    string
	Params []Parameter
}

// NewParameterizedURL 创建一个新的 ParameterizedURL 实例。
func NewParameterizedURL(urlStr string, params []Parameter) ParameterizedURL {
	return ParameterizedURL{
		URL:    urlStr,
		Params: params,
	}
}

// Payload 代表一个用于漏洞测试的攻击载荷。
type Payload struct {
	Value       string `json:"value"`
	Description string `json:"description"`
}

// URLWithParams 返回带有查询参数的完整URL字符串。
// 这个方法主要用于记录和报告。
func (r *Request) URLWithParams() string {
	if r.Method == "GET" && len(r.Params) > 0 {
		baseURL, err := url.Parse(r.URL)
		if err != nil {
			return r.URL // Fallback
		}
		values := url.Values{}
		for _, p := range r.Params {
			values.Add(p.Name, p.Value)
		}
		baseURL.RawQuery = values.Encode()
		return baseURL.String()
	}
	return r.URL
}

// Task 代表一个交给编排器(Orchestrator)处理的工作单元。
// 它可以是一个需要爬取的URL，或是一个需要扫描的HTTP请求。
type Task struct {
	URL     string   // 要处理的URL。
	Depth   int      // 当前的爬取深度。
	Request *Request // 如果非nil，表示这是一个扫描任务；否则为爬取任务。
}
