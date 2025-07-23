// Package models 包含了 AutoVulnScan 应用程序中使用到的核心数据结构。
package models

import (
	"net/http"
	"net/url"
)

// Request 代表一个被发现的HTTP请求及其关联的参数。
// 它通过内嵌 *http.Request 来继承标准库请求的功能。
type Request struct {
	*http.Request
	Params []Parameter
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
	// 仅为 GET 请求附加参数。对于其他方法（如 POST），参数在请求体中，不应附加到URL上。
	if r.Method == "GET" && len(r.Params) > 0 {
		values := url.Values{}
		for _, p := range r.Params {
			values.Add(p.Name, p.Value)
		}
		// 使用 Encode 方法可以正确地处理特殊字符。
		return r.URL.String() + "?" + values.Encode()
	}
	return r.URL.String()
}

// Task 代表一个交给编排器(Orchestrator)处理的工作单元。
// 它可以是一个需要爬取的URL，或是一个需要扫描的HTTP请求。
type Task struct {
	URL     string   // 要处理的URL。
	Depth   int      // 当前的爬取深度。
	Request *Request // 如果非nil，表示这是一个扫描任务；否则为爬取任务。
}
