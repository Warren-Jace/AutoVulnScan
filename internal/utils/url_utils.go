// Package utils 提供了一系列在整个应用程序中使用的通用工具函数。
package utils

import (
	"crypto/rand"
	"html"
	"math/big"
	"net/url"
	"strings"
)

// ResolveURL 根据一个基础URL来解析一个相对URL。
//
// 参数:
//
//	base (*url.URL): 作为解析基准的URL。
//	href (string): 要解析的相对URL字符串。
//
// 返回值:
//
//	*url.URL: 解析后的绝对URL，如果解析失败或href是页面内锚点，则返回 nil。
func ResolveURL(base *url.URL, href string) *url.URL {
	// 忽略页面内的锚点链接。
	if strings.HasPrefix(href, "#") {
		return nil
	}
	resolved, err := base.Parse(href)
	if err != nil {
		return nil
	}
	return resolved
}

// IsSameHost 检查两个URL是否属于同一个主机。
func IsSameHost(base, target *url.URL) bool {
	if base == nil || target == nil {
		return false
	}
	return base.Host == target.Host
}

// SanitizeURL 通过移除URL中的片段部分（fragment）来净化URL。
// 例如，"http://example.com/page#section" 会被净化为 "http://example.com/page"。
func SanitizeURL(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}
	u.Fragment = ""
	return u
}

// NormalizeURL 通过对路径和查询字符串进行HTML实体解码来规范化URL。
// 这有助于处理被错误编码的URL。
func NormalizeURL(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}
	u.Path = html.UnescapeString(u.Path)
	u.RawQuery = html.UnescapeString(u.RawQuery)
	return u
}

// RandomString 生成一个指定长度的、由字母和数字组成的随机字符串。
// 这个实现使用了 crypto/rand，保证了密码学安全级别的随机性。
func RandomString(length int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	ret := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
	}
	return string(ret), nil
}
