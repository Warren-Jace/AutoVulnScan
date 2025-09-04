// Package utils 提供了通用的工具函数
package utils

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// SanitizeURL 清理和规范化URL
func SanitizeURL(rawURL string) (string, error) {
	// 如果URL没有协议，添加http://
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}

	// 解析URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL: %w", err)
	}

	// 清理URL
	parsedURL.Fragment = "" // 移除片段
	parsedURL.RawQuery = "" // 移除查询参数

	// 规范化路径
	parsedURL.Path = filepath.Clean(parsedURL.Path)
	if parsedURL.Path == "." {
		parsedURL.Path = "/"
	}

	// 返回规范化后的URL
	return parsedURL.String(), nil
}

// IsValidURL 检查URL是否有效
func IsValidURL(rawURL string) bool {
	_, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return false
	}

	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}

	return true
}

// IsSameDomain 检查两个URL是否属于同一域名
func IsSameDomain(url1, url2 string) (bool, error) {
	u1, err := url.Parse(url1)
	if err != nil {
		return false, fmt.Errorf("failed to parse URL1: %w", err)
	}

	u2, err := url.Parse(url2)
	if err != nil {
		return false, fmt.Errorf("failed to parse URL2: %w", err)
	}

	return u1.Hostname() == u2.Hostname(), nil
}

// ExtractDomain 从URL中提取域名
func ExtractDomain(rawURL string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL: %w", err)
	}

	return parsedURL.Hostname(), nil
}

// ExtractPath 从URL中提取路径
func ExtractPath(rawURL string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL: %w", err)
	}

	return parsedURL.Path, nil
}

// JoinURLs 连接两个URL
func JoinURLs(baseURL, relativeURL string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse base URL: %w", err)
	}

	relative, err := url.Parse(relativeURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse relative URL: %w", err)
	}

	return base.ResolveReference(relative).String(), nil
}

// FileExists 检查文件是否存在
func FileExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// DirExists 检查目录是否存在
func DirExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}

// EnsureDir 确保目录存在，如果不存在则创建
func EnsureDir(path string) error {
	return os.MkdirAll(path, 0755)
}

// ReadFile 读取文件内容
func ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// WriteFile 写入文件内容
func WriteFile(path string, data []byte) error {
	// 确保目录存在
	dir := filepath.Dir(path)
	if err := EnsureDir(dir); err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// AppendFile 追加内容到文件
func AppendFile(path string, data []byte) error {
	// 确保目录存在
	dir := filepath.Dir(path)
	if err := EnsureDir(dir); err != nil {
		return err
	}

	// 打开文件并追加内容
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(data)
	return err
}

// ReadLines 读取文件的每一行
func ReadLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines, scanner.Err()
}

// WriteLines 写入多行到文件
func WriteLines(path string, lines []string) error {
	// 确保目录存在
	dir := filepath.Dir(path)
	if err := EnsureDir(dir); err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			return err
		}
	}

	return writer.Flush()
}

// CopyFile 复制文件
func CopyFile(src, dst string) error {
	// 读取源文件
	data, err := ReadFile(src)
	if err != nil {
		return err
	}

	// 写入目标文件
	return WriteFile(dst, data)
}

// GetFileSize 获取文件大小
func GetFileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// HTTPClient 创建一个HTTP客户端
func HTTPClient(timeout time.Duration, skipTLSVerify bool) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: skipTLSVerify,
		},
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

// HTTPRequest 发送HTTP请求
func HTTPRequest(method, url string, headers map[string]string, body io.Reader, timeout time.Duration, skipTLSVerify bool) (*http.Response, error) {
	// 创建请求
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// 设置请求头
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// 发送请求
	client := HTTPClient(timeout, skipTLSVerify)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	return resp, nil
}

// HTTPGet 发送HTTP GET请求
func HTTPGet(url string, headers map[string]string, timeout time.Duration, skipTLSVerify bool) (*http.Response, error) {
	return HTTPRequest("GET", url, headers, nil, timeout, skipTLSVerify)
}

// HTTPPost 发送HTTP POST请求
func HTTPPost(url string, headers map[string]string, body io.Reader, timeout time.Duration, skipTLSVerify bool) (*http.Response, error) {
	return HTTPRequest("POST", url, headers, body, timeout, skipTLSVerify)
}

// HTTPPut 发送HTTP PUT请求
func HTTPPut(url string, headers map[string]string, body io.Reader, timeout time.Duration, skipTLSVerify bool) (*http.Response, error) {
	return HTTPRequest("PUT", url, headers, body, timeout, skipTLSVerify)
}

// HTTPDelete 发送HTTP DELETE请求
func HTTPDelete(url string, headers map[string]string, timeout time.Duration, skipTLSVerify bool) (*http.Response, error) {
	return HTTPRequest("DELETE", url, headers, nil, timeout, skipTLSVerify)
}

// GetResponseBody 获取HTTP响应体
func GetResponseBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// JSONDecode 解码JSON数据
func JSONDecode(data []byte, v interface{}) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(v)
}

// JSONEncode 编码数据为JSON
func JSONEncode(v interface{}) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(v)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// JSONPrettyEncode 编码数据为格式化的JSON
func JSONPrettyEncode(v interface{}) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	err := encoder.Encode(v)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// Contains 检查字符串切片是否包含特定字符串
func Contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// RemoveDuplicates 从字符串切片中移除重复项
func RemoveDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}

	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}

	return list
}

// Filter 过滤字符串切片
func Filter(slice []string, predicate func(string) bool) []string {
	var result []string
	for _, item := range slice {
		if predicate(item) {
			result = append(result, item)
		}
	}
	return result
}

// Map 对字符串切片中的每个元素应用函数
func Map(slice []string, fn func(string) string) []string {
	result := make([]string, len(slice))
	for i, item := range slice {
		result[i] = fn(item)
	}
	return result
}

// Unique 返回唯一的字符串切片
func Unique(slice []string) []string {
	return RemoveDuplicates(slice)
}

// Reverse 反转字符串切片
func Reverse(slice []string) []string {
	result := make([]string, len(slice))
	for i, item := range slice {
		result[len(slice)-1-i] = item
	}
	return result
}

// SplitByWhitespace 按空白字符分割字符串
func SplitByWhitespace(s string) []string {
	return strings.Fields(s)
}

// TrimPrefixes 移除字符串的所有可能前缀
func TrimPrefixes(s string, prefixes []string) string {
	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			return strings.TrimPrefix(s, prefix)
		}
	}
	return s
}

// TrimSuffixes 移除字符串的所有可能后缀
func TrimSuffixes(s string, suffixes []string) string {
	for _, suffix := range suffixes {
		if strings.HasSuffix(s, suffix) {
			return strings.TrimSuffix(s, suffix)
		}
	}
	return s
}

// IsNumeric 检查字符串是否只包含数字
func IsNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

// IsAlpha 检查字符串是否只包含字母
func IsAlpha(s string) bool {
	matched, _ := regexp.MatchString("^[a-zA-Z]+$", s)
	return matched
}

// IsAlphanumeric 检查字符串是否只包含字母和数字
func IsAlphanumeric(s string) bool {
	matched, _ := regexp.MatchString("^[a-zA-Z0-9]+$", s)
	return matched
}

// ExtractRegex 使用正则表达式提取匹配的内容
func ExtractRegex(pattern, text string) ([]string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regex pattern: %w", err)
	}

	matches := re.FindAllStringSubmatch(text, -1)
	if len(matches) == 0 {
		return nil, nil
	}

	var result []string
	for _, match := range matches {
		if len(match) > 1 {
			result = append(result, match[1])
		}
	}

	return result, nil
}

// MatchRegex 检查文本是否匹配正则表达式
func MatchRegex(pattern, text string) (bool, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false, fmt.Errorf("failed to compile regex pattern: %w", err)
	}

	return re.MatchString(text), nil
}

// ReplaceRegex 使用正则表达式替换文本
func ReplaceRegex(pattern, replacement, text string) (string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("failed to compile regex pattern: %w", err)
	}

	return re.ReplaceAllString(text, replacement), nil
}

// RateLimiter 速率限制器
type RateLimiter struct {
	tokens chan struct{}
}

// NewRateLimiter 创建一个新的速率限制器
func NewRateLimiter(rate int) *RateLimiter {
	if rate <= 0 {
		rate = 1
	}

	limiter := &RateLimiter{
		tokens: make(chan struct{}, rate),
	}

	// 初始化令牌
	for i := 0; i < rate; i++ {
		limiter.tokens <- struct{}{}
	}

	// 启动令牌补充协程
	go limiter.refill(rate)

	return limiter
}

// refill 补充令牌
func (r *RateLimiter) refill(rate int) {
	ticker := time.NewTicker(time.Second / time.Duration(rate))
	defer ticker.Stop()

	for range ticker.C {
		select {
		case r.tokens <- struct{}{}:
			// 成功补充令牌
		default:
			// 令牌桶已满，丢弃
		}
	}
}

// Wait 等待获取令牌
func (r *RateLimiter) Wait(ctx context.Context) error {
	select {
	case <-r.tokens:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TryTry 尝试获取令牌，不阻塞
func (r *RateLimiter) Try() bool {
	select {
	case <-r.tokens:
		return true
	default:
		return false
	}
}

// Retry 重试函数
func Retry(attempts int, delay time.Duration, fn func() error) error {
	var err error

	for i := 0; i < attempts; i++ {
		if i > 0 {
			time.Sleep(delay)
		}

		err = fn()
		if err == nil {
			return nil
		}

		log.Debug().Err(err).Int("attempt", i+1).Msg("Retry attempt failed")
	}

	return fmt.Errorf("after %d attempts, last error: %w", attempts, err)
}

// RetryWithContext 带上下文的重试函数
func RetryWithContext(ctx context.Context, attempts int, delay time.Duration, fn func() error) error {
	var err error

	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		err = fn()
		if err == nil {
			return nil
		}

		log.Debug().Err(err).Int("attempt", i+1).Msg("Retry attempt failed")
	}

	return fmt.Errorf("after %d attempts, last error: %w", attempts, err)
}

// SafeClose 安全地关闭通道
func SafeClose(ch chan struct{}) {
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("Recovered from panic while closing channel")
		}
	}()

	close(ch)
}

// SafeSend 安全地向通道发送数据
func SafeSend(ch chan struct{}, data struct{}) bool {
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("Recovered from panic while sending to channel")
		}
	}()

	select {
	case ch <- data:
		return true
	default:
		return false
	}
}

// SafeReceive 安全地从通道接收数据
func SafeReceive(ch chan struct{}) (struct{}, bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("Recovered from panic while receiving from channel")
		}
	}()

	data, ok := <-ch
	return data, ok
}