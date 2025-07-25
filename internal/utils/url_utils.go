// Package utils 包含了一些通用的工具函数，目前主要是URL处理相关的函数。
package utils

import (
	"net/url"
	"strings"
)

// ToAbsoluteURL 将一个可能为相对路径的href字符串，转换为相对于baseURL的绝对URL。
// 它是一个健壮的转换函数，能够处理多种边缘情况。
func ToAbsoluteURL(baseURL *url.URL, href string) string {
	// 清理href中的前后空格
	trimmedHref := strings.TrimSpace(href)
	if trimmedHref == "" {
		return ""
	}

	// 忽略JavaScript代码、锚点链接和邮件链接
	if strings.HasPrefix(trimmedHref, "javascript:") || strings.HasPrefix(trimmedHref, "#") || strings.HasPrefix(trimmedHref, "mailto:") {
		return ""
	}

	// 解析href
	subURL, err := url.Parse(trimmedHref)
	if err != nil {
		return "" // 如果href本身不是一个有效的URL片段，则忽略
	}

	// 使用baseURL来解析相对URL，得到绝对URL
	// ResolveReference是处理相对路径和绝对路径组合的核心函数。
	absoluteURL := baseURL.ResolveReference(subURL)

	// 再次检查结果，确保它是一个有效的HTTP/HTTPS URL
	if absoluteURL.Scheme == "http" || absoluteURL.Scheme == "https" {
		return absoluteURL.String()
	}

	return ""
}
