// Package util 提供了一系列用于 AutoVulnScan 应用程序的工具函数。
package util

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"autovulnscan/internal/models"

	"github.com/chromedp/chromedp"
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

// CloneRequest 创建一个 models.Request 对象的深拷贝。
// 在并发扫描中，对请求对象进行修改前应先克隆，以避免数据竞争和插件间的相互干扰。
//
// 参数:
//
//	r (*models.Request): 要克隆的原始请求对象。
//
// 返回值:
//
//	*models.Request: 一个与原始请求完全独立的新请求对象。
func CloneRequest(r *models.Request) *models.Request {
	if r == nil {
		return nil
	}
	r2 := new(models.Request)
	*r2 = *r
	if r.Request != nil {
		r2.Request = r.Request.Clone(context.Background())
	}
	if r.Params != nil {
		r2.Params = make([]models.Parameter, len(r.Params))
		copy(r2.Params, r.Params)
	}
	return r2
}
