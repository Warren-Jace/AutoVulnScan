// Package util 提供了各种在项目中共享的辅助函数。
// 这些函数通常是无状态的、纯粹的工具函数，用于处理常见的任务，
// 如URL解析、字符串操作、参数提取等。
package util

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"autovulnscan/internal/models"

	"github.com/chromedp/chromedp"
	"github.com/PuerkitoBio/goquery"
)

// GetAllocContext 创建一个新的 chromedp 执行分配器上下文。
// 这个上下文用于配置和启动一个新的 Chrome 浏览器实例。
//
// 参数:
//
//	headless (bool): 是否以无头模式启动浏览器。
//	proxy (string): 用于浏览器所有请求的代理服务器地址。
//	userAgent (string): 要使用的 User-Agent 字符串。
//
// 返回值:
//
//	context.Context: 配置好的浏览器分配器上下文。
//	context.CancelFunc: 用于取消该上下文的函数，可以用来关闭浏览器。
func GetAllocContext(headless bool, proxy, userAgent string) (context.Context, context.CancelFunc) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", headless),          // 控制无头模式
		chromedp.Flag("disable-gpu", true),           // 禁用GPU加速，在服务器环境中通常是必要的
		chromedp.Flag("no-sandbox", true),            // 禁用沙箱，在某些Linux环境中需要
		chromedp.Flag("disable-dev-shm-usage", true), // 解决某些Docker环境下的资源限制问题
		chromedp.UserAgent(userAgent),                // 设置 User-Agent
	)

	// 如果提供了代理服务器地址，则添加到选项中。
	if proxy != "" {
		opts = append(opts, chromedp.ProxyServer(proxy))
	}

	return chromedp.NewExecAllocator(context.Background(), opts...)
}

// IsInScope 检查给定的URL是否在配置定义的作用域内。
//
// 参数:
//
//	u (*url.URL): 要检查的URL。
//	scopeDomains ([]string): 允许的作用域域名列表。
//	blacklistPatterns ([]string): URL黑名单的正则表达式模式列表。
//
// 返回值:
//
//	bool: 如果URL在作用域内且不在黑名单中，则返回 true。
func IsInScope(u *url.URL, scopeDomains []string, blacklistPatterns []string) bool {
	hostname := u.Hostname()
	fullURL := u.String()

	// 1. 检查URL是否匹配任何黑名单模式。
	for _, pattern := range blacklistPatterns {
		// 使用 MatchString 进行正则表达式匹配。
		if matched, _ := regexp.MatchString(pattern, fullURL); matched {
			return false // 如果匹配黑名单，则立即返回 false。
		}
	}

	// 2. 检查URL的主机名是否属于任何一个作用域域名。
	for _, domain := range scopeDomains {
		// 使用 HasSuffix 检查，这样 'sub.example.com' 可以匹配 'example.com'。
		if strings.HasSuffix(hostname, domain) {
			return true // 如果匹配作用域，则返回 true。
		}
	}

	// 如果不匹配任何作用域，则返回 false。
	return false
}

// ExtractParameters 从给定的字符串内容中提取所有潜在的参数。
// 注意：这是一个非常简化的实现，有很大的改进空间。
//
// 参数:
//
//	content (string): 要从中提取参数的文本内容（例如HTML或JavaScript代码）。
//
// 返回值:
//
//	[]models.Parameter: 提取出的参数列表。
//
// 改进建议:
//   - 使用专门的HTML解析库（如 golang.org/x/net/html）来更准确地从 <input>, <select>, <textarea> 等标签中提取 'name' 属性。
//   - 使用JavaScript解析库（如 "github.com/robertkrimen/otto" 或 "github.com/dop251/goja"）来分析脚本，
//     寻找如 'URLSearchParams', 'FormData' 的使用，或者直接从 AJAX 请求中提取参数。
//   - 扩展正则表达式以覆盖更多情况，例如在JavaScript字符串中定义的参数名。
func ExtractParameters(content string) []models.Parameter {
	// 这个正则表达式非常基础，只能匹配 HTML 中形如 name="..." 或 name='...' 的属性。
	re := regexp.MustCompile(`(?i)(name|id|for)=["']([^"']+)["']`)
	matches := re.FindAllStringSubmatch(content, -1)

	params := make([]models.Parameter, 0)
	// 使用 map 来确保参数名的唯一性。
	seen := make(map[string]struct{})

	for _, match := range matches {
		if len(match) > 2 {
			paramName := match[2]
			if _, ok := seen[paramName]; !ok {
				params = append(params, models.Parameter{Name: paramName})
				seen[paramName] = struct{}{}
			}
		}
	}
	return params
}

// CloneRequest creates a deep copy of a models.Request object.
func CloneRequest(r *models.Request) *models.Request {
	if r == nil {
		return nil
	}
	r2 := &models.Request{
		URL:    r.URL,
		Method: r.Method,
		Body:   r.Body,
	}
	if r.Headers != nil {
		r2.Headers = r.Headers.Clone()
	}
	if r.Params != nil {
		r2.Params = make([]models.Parameter, len(r.Params))
		copy(r2.Params, r.Params)
	}
	return r2
}

// ToAbsoluteURL 将一个可能为相对路径的href字符串，转换为相对于baseURL的绝对URL。
// 它会处理各种边缘情况，例如'javascript:'或'mailto:'链接。
func ToAbsoluteURL(baseURL *url.URL, href string) string {
	if href == "" {
		return ""
	}
	if strings.HasPrefix(href, "http") {
		return href
	}
	absURL, err := baseURL.Parse(href)
	if err != nil {
		return ""
	}
	return absURL.String()
}

// ExtractLinksFromDoc 使用goquery从一个已解析的HTML文档中提取所有'href'属性。
func ExtractLinksFromDoc(doc *goquery.Document) []string {
	var links []string
	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		link, _ := s.Attr("href")
		links = append(links, link)
	})
	return links
}

// ExtractFormsFromDoc 使用goquery从一个已解析的HTML文档中提取所有表单，
// 并将它们转换为 `models.Request` 结构体，以便后续进行扫描。
// 它会处理GET和POST方法，并正确地提取和填充表单中的所有输入字段。
func ExtractFormsFromDoc(doc *goquery.Document, baseURL *url.URL) []*models.Request {
	var requests []*models.Request
	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, _ := s.Attr("action")
		method, _ := s.Attr("method")
		if method == "" {
			method = "GET"
		}
		formURL, err := baseURL.Parse(action)
		if err != nil {
			return
		}
		var params []models.Parameter
		s.Find("input").Each(func(j int, input *goquery.Selection) {
			name, _ := input.Attr("name")
			value, _ := input.Attr("value")
			params = append(params, models.Parameter{Name: name, Value: value})
		})
		requests = append(requests, &models.Request{
			URL:    formURL.String(),
			Method: strings.ToUpper(method),
			Params: params,
		})
	})
	return requests
}

// GetParamsFromURL 从给定的URL字符串中解析出查询参数。
func GetParamsFromURL(urlStr string) ([]models.Parameter, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	var params []models.Parameter
	for k, v := range u.Query() {
		params = append(params, models.Parameter{Name: k, Value: v[0]})
	}
	return params, nil
}

// GetBaseURL 从URL字符串中提取协议和主机部分，得到基础URL。
func GetBaseURL(u string) string {
	parsedURL, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return parsedURL.Scheme + "://" + parsedURL.Host
}

// FilterInScopeLinks 过滤一个链接列表，只返回那些在指定作用域内的链接。
func FilterInScopeLinks(links []string, scopeDomains []string) []string {
	var inScopeLinks []string
	for _, link := range links {
		u, err := url.Parse(link)
		if err != nil {
			continue
		}
		for _, domain := range scopeDomains {
			if strings.HasSuffix(u.Hostname(), domain) {
				inScopeLinks = append(inScopeLinks, link)
				break
			}
		}
	}
	return inScopeLinks
}
