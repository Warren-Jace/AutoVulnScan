// Package crawler 提供网站爬取功能，包括静态和动态爬取
package crawler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"autovulnscan/internal/config"
	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"
	"autovulnscan/internal/utils"

	"github.com/PuerkitoBio/goquery"
	"github.com/rs/zerolog/log"
	"golang.org/x/time/rate"
)

// Crawler 负责获取网页并从中提取链接和参数
type Crawler struct {
	baseURL        *url.URL              // 基础URL，用于域名限制
	config         *config.SpiderConfig  // 爬虫配置
	httpClient     *requester.HTTPClient // HTTP客户端
	limiter        *rate.Limiter         // 速率限制器
	dynamicCrawler *DynamicCrawler       // 动态爬虫（使用浏览器）
	appConfig      *config.Settings
}

// IsInScope checks if a given URL is within the scope defined by the configuration.
func (c *Crawler) IsInScope(u *url.URL) bool {
	hostname := u.Hostname()

	// Check against blacklist patterns
	for _, pattern := range c.config.Blacklist {
		if matched, _ := regexp.MatchString(pattern, u.String()); matched {
			return false
		}
	}

	// Check against scope domains
	for _, domain := range c.config.Scope {
		if strings.HasSuffix(hostname, domain) {
			return true
		}
	}

	return false
}

// NewCrawler 创建新的爬虫实例
func NewCrawler(baseURL string, appCfg *config.Settings, client *requester.HTTPClient) (*Crawler, error) {
	// 解析基础URL
	parsedBaseURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}
	cfg := &appCfg.Spider
	// 创建速率限制器，控制请求频率
	limiter := rate.NewLimiter(rate.Limit(cfg.Limit), cfg.Concurrency)

	// 创建动态爬虫实例
	dynamicCrawler := NewDynamicCrawler(
		cfg.DynamicCrawler.Headless,
		"", // Proxy is not configured at this level, pass empty string
		time.Duration(cfg.Timeout)*time.Second,
		cfg.UserAgents,
	)

	return &Crawler{
		baseURL:        parsedBaseURL,
		config:         cfg,
		httpClient:     client,
		limiter:        limiter,
		dynamicCrawler: dynamicCrawler,
		appConfig:      appCfg,
	}, nil
}

// Crawl 解析URL内容并提取链接和表单
func (c *Crawler) Crawl(ctx context.Context, crawlURL string, body []byte) ([]string, []*models.Request, error) {
	log.Debug().Str("url", crawlURL).Msg("Crawling page content")

	if c.config.DynamicCrawler.Enabled {
		// 动态爬虫需要在浏览器中运行，不使用预获取的body
		return c.crawlDynamic(ctx, crawlURL)
	}
	// 静态爬虫使用预获取的body
	return c.crawlStatic(ctx, crawlURL, body)
}

// crawlStatic 静态爬取，解析已获取的HTML内容
func (c *Crawler) crawlStatic(ctx context.Context, crawlURL string, body []byte) ([]string, []*models.Request, error) {
	log.Debug().Str("url", crawlURL).Int("size", len(body)).Msg("Statically parsing page")

	// 创建多个reader，因为需要分别用于不同的提取功能
	var body1, body2, body3 bytes.Buffer
	tee1 := io.TeeReader(bytes.NewReader(body), &body1)
	tee2 := io.TeeReader(tee1, &body2)
	if _, err := io.Copy(&body3, tee2); err != nil {
		return nil, nil, fmt.Errorf("failed to copy response body: %w", err)
	}

	// 提取页面中的链接（增强版）
	links := c.extractLinksEnhanced(&body1, crawlURL)
	// 提取页面中的表单（增强版）
	requests := c.extractFormsEnhanced(&body2, crawlURL)
	// 提取API端点和AJAX请求
	apiRequests := c.extractAPIEndpoints(&body3, crawlURL)

	// 合并所有请求
	allRequests := append(requests, apiRequests...)

	log.Debug().Str("url", crawlURL).Int("count", len(links)).Msg("Extracted links (enhanced)")
	log.Debug().Str("url", crawlURL).Int("count", len(allRequests)).Msg("Extracted requests (enhanced)")
	return links, allRequests, nil
}

// crawlDynamic 动态爬取，使用浏览器渲染页面后再解析
func (c *Crawler) crawlDynamic(ctx context.Context, crawlURL string) ([]string, []*models.Request, error) {
	// 使用动态爬虫获取渲染后的HTML内容
	go c.dynamicCrawler.Crawl(crawlURL)
	var links []string
	select {
	case links = <-c.dynamicCrawler.Result:
		log.Debug().Str("url", crawlURL).Int("count", len(links)).Msg("Extracted links (dynamic)")
	case <-time.After(time.Duration(c.config.Timeout) * time.Second):
		return nil, nil, fmt.Errorf("dynamic crawl timed out for %s", crawlURL)
	}

	// For now, dynamic crawler only extracts links, not forms/requests.
	return links, nil, nil
}

// extractFormsEnhanced 增强版表单提取，支持更多现代Web表单特性
func (c *Crawler) extractFormsEnhanced(body io.Reader, pageURL string) []*models.Request {
	requests := []*models.Request{}

	doc, err := goquery.NewDocumentFromReader(body)
	if err != nil {
		return requests
	}

	// 遍历所有表单
	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, _ := s.Attr("action")
		method, _ := s.Attr("method")
		enctype, _ := s.Attr("enctype")

		if method == "" {
			method = "GET"
		}

		formURL, err := url.Parse(pageURL)
		if err != nil {
			return
		}

		actionURL, err := formURL.Parse(action)
		if err != nil {
			return
		}

		params := []models.Parameter{}

		// 扩展的输入字段选择器，包括更多HTML5元素
		s.Find("input, textarea, select, button[type=submit], datalist").Each(func(j int, input *goquery.Selection) {
			name, exists := input.Attr("name")
			if !exists || name == "" {
				// 尝试获取id作为备用name
				if id, hasId := input.Attr("id"); hasId {
					name = id
				} else {
					return
				}
			}

			inputType, _ := input.Attr("type")
			value, _ := input.Attr("value")
			placeholder, _ := input.Attr("placeholder")

			// 根据输入类型设置合适的测试值
			testValue := c.getTestValueByType(inputType, value, placeholder)

			params = append(params, models.Parameter{
				Name:  name,
				Value: testValue,
			})

			// 如果是select元素，提取所有option值
			if input.Is("select") {
				input.Find("option").Each(func(k int, option *goquery.Selection) {
					if optValue, hasValue := option.Attr("value"); hasValue && optValue != "" {
						params = append(params, models.Parameter{
							Name:  name,
							Value: optValue,
						})
					}
				})
			}
		})

		// 处理隐藏字段和CSRF token
		s.Find("input[type=hidden]").Each(func(j int, hidden *goquery.Selection) {
			if name, exists := hidden.Attr("name"); exists && name != "" {
				if value, hasValue := hidden.Attr("value"); hasValue {
					params = append(params, models.Parameter{
						Name:  name,
						Value: value,
					})
				}
			}
		})

		// 创建HTTP请求
		req, err := http.NewRequest(strings.ToUpper(method), actionURL.String(), nil)
		if err != nil {
			return
		}

		// 设置适当的Content-Type
		if strings.ToUpper(method) == "POST" {
			if enctype == "" {
				enctype = "application/x-www-form-urlencoded"
			}
			req.Header.Set("Content-Type", enctype)
		}

		requests = append(requests, &models.Request{
			Request: req,
			Params:  params,
		})
	})

	return requests
}

// getTestValueByType 根据输入类型返回合适的测试值
func (c *Crawler) getTestValueByType(inputType, currentValue, placeholder string) string {
	switch strings.ToLower(inputType) {
	case "email":
		return "test@example.com"
	case "password":
		return "testpass123"
	case "number":
		return "123"
	case "tel", "phone":
		return "1234567890"
	case "url":
		return "https://example.com"
	case "date":
		return "2023-01-01"
	case "time":
		return "12:00"
	case "datetime-local":
		return "2023-01-01T12:00"
	case "color":
		return "#ff0000"
	case "range":
		return "50"
	case "search":
		return "search_test"
	case "hidden":
		// 保持隐藏字段的原始值
		return currentValue
	default:
		// 如果有placeholder，使用它作为提示
		if placeholder != "" {
			return "test_" + strings.ReplaceAll(placeholder, " ", "_")
		}
		return "test"
	}
}

// extractAPIEndpoints 提取页面中的API端点和AJAX请求
func (c *Crawler) extractAPIEndpoints(body io.Reader, pageURL string) []*models.Request {
	var requests []*models.Request

	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return requests
	}

	content := string(bodyBytes)
	base, _ := url.Parse(pageURL)

	// 提取各种API模式
	apiPatterns := []*regexp.Regexp{
		// fetch() API调用
		regexp.MustCompile(`fetch\s*\(\s*['"]([^'"]+)['"]`),
		// XMLHttpRequest
		regexp.MustCompile(`\.open\s*\(\s*['"]([^'"]+)['"]\s*,\s*['"]([^'"]+)['"]`),
		// jQuery AJAX
		regexp.MustCompile(`\$\.(?:ajax|get|post|put|delete)\s*\(\s*['"]([^'"]+)['"]`),
		// axios调用
		regexp.MustCompile(`axios\.(?:get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]`),
		// API路径模式
		regexp.MustCompile(`['"](/api/[^'"\s]+)['"]`),
		regexp.MustCompile(`['"](/v\d+/[^'"\s]+)['"]`),
		// GraphQL端点
		regexp.MustCompile(`['"](/graphql[^'"\s]*)['"]`),
		// WebSocket端点
		regexp.MustCompile(`['"](wss?://[^'"\s]+)['"]`),
	}

	foundEndpoints := make(map[string]string) // URL -> HTTP Method

	for _, pattern := range apiPatterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) >= 2 {
				endpoint := match[1]
				method := "GET" // 默认方法

				// 对于XMLHttpRequest，第一个匹配组是方法，第二个是URL
				if len(match) >= 3 && strings.Contains(pattern.String(), "open") {
					method = strings.ToUpper(match[1])
					endpoint = match[2]
				}

				// 解析为绝对URL
				if resolvedURL := utils.ResolveURL(base, endpoint); resolvedURL != nil {
					if c.IsInScope(resolvedURL) {
						foundEndpoints[resolvedURL.String()] = method
					}
				}
			}
		}
	}

	// 创建请求对象
	for endpoint, method := range foundEndpoints {
		if req, err := http.NewRequest(method, endpoint, nil); err == nil {
			// 为API请求设置适当的头部
			req.Header.Set("Accept", "application/json, text/plain, */*")
			if method != "GET" {
				req.Header.Set("Content-Type", "application/json")
			}

			requests = append(requests, &models.Request{
				Request: req,
				Params:  []models.Parameter{}, // API端点通常通过body传参
			})
		}
	}

	return requests
}

// extractLinksEnhanced 增强版链接提取，支持更多现代Web技术
func (c *Crawler) extractLinksEnhanced(body io.Reader, pageURL string) []string {
	foundURLs := make(map[string]struct{})

	crawlURL, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}

	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return nil
	}

	// 提取JavaScript中的链接（增强版）
	jsLinks := c.extractJSLinksEnhanced(pageURL, bytes.NewReader(bodyBytes))
	for _, link := range jsLinks {
		foundURLs[link] = struct{}{}
	}

	// 解析HTML文档
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(bodyBytes))
	if err != nil {
		urls := make([]string, 0, len(foundURLs))
		for u := range foundURLs {
			urls = append(urls, u)
		}
		return urls
	}

	processAttr := func(attrValue string) {
		if attrValue == "" {
			return
		}

		// 清理URL：移除HTML编码和垃圾字符
		cleanedURL := c.cleanURL(attrValue)
		if cleanedURL == "" {
			return
		}

		resolvedURL := utils.ResolveURL(crawlURL, cleanedURL)
		if resolvedURL == nil {
			return
		}

		if !c.IsInScope(resolvedURL) {
			if c.appConfig.Debug {
				log.Debug().Str("url", resolvedURL.String()).Msg("Link is out of scope")
			}
			return
		}

		normalizedURL := utils.NormalizeURL(resolvedURL)
		if normalizedURL != nil {
			sanitizedURL := utils.SanitizeURL(normalizedURL)
			if sanitizedURL != nil {
				foundURLs[sanitizedURL.String()] = struct{}{}
			}
		}
	}

	// 扩展的HTML标签和属性映射，包括更多现代Web元素
	tags := map[string][]string{
		"a":      {"href"},
		"link":   {"href"},
		"script": {"src"},
		"img":    {"src", "data-src", "data-lazy-src"}, // 支持懒加载
		"iframe": {"src", "data-src"},
		"frame":  {"src"},
		"form":   {"action"},
		"area":   {"href"},
		"base":   {"href"},
		"embed":  {"src"},
		"object": {"data"},
		"source": {"src", "srcset"},
		"track":  {"src"},
		"video":  {"src", "poster"},
		"audio":  {"src"},
		"meta":   {"content"}, // 用于refresh重定向
		"button": {"formaction"},
		"input":  {"formaction"},
	}

	// 遍历所有标签和属性
	for tag, attrs := range tags {
		for _, attr := range attrs {
			selector := fmt.Sprintf("%s[%s]", tag, attr)
			doc.Find(selector).Each(func(i int, s *goquery.Selection) {
				val, _ := s.Attr(attr)

				// 特殊处理srcset属性（可能包含多个URL）
				if attr == "srcset" {
					urls := strings.Split(val, ",")
					for _, u := range urls {
						parts := strings.Fields(strings.TrimSpace(u))
						if len(parts) > 0 {
							processAttr(parts[0])
						}
					}
				} else if attr == "content" && tag == "meta" {
					// 处理meta refresh
					if httpEquiv, _ := s.Attr("http-equiv"); strings.ToLower(httpEquiv) == "refresh" {
						if urlIndex := strings.Index(val, "url="); urlIndex != -1 {
							refreshURL := val[urlIndex+4:]
							processAttr(refreshURL)
						}
					}
				} else {
					processAttr(val)
				}
			})
		}
	}

	// 提取data-*属性中的URL
	doc.Find("*").Each(func(i int, s *goquery.Selection) {
		for _, attr := range []string{"data-url", "data-href", "data-link", "data-target", "data-action"} {
			if val, exists := s.Attr(attr); exists {
				processAttr(val)
			}
		}
	})

	// 转换为切片返回
	urls := make([]string, 0, len(foundURLs))
	for u := range foundURLs {
		urls = append(urls, u)
	}
	return urls
}

// cleanURL 清理URL，移除HTML编码和垃圾字符
func (c *Crawler) cleanURL(rawURL string) string {
	// 移除常见的HTML编码垃圾
	cleanedURL := rawURL

	// 查找第一个HTML编码字符的位置
	htmlEncodePatterns := []string{
		"%22", // "
		"%3C", // <
		"%3E", // >
		"%20", // 空格（但这个可能是合法的）
		"&quot;",
		"&lt;",
		"&gt;",
		"&amp;",
	}

	minIndex := len(cleanedURL)
	for _, pattern := range htmlEncodePatterns {
		if pattern == "%20" {
			continue // 跳过空格编码，因为它可能是合法的
		}
		if index := strings.Index(cleanedURL, pattern); index != -1 && index < minIndex {
			minIndex = index
		}
	}

	// 如果找到了HTML编码，截断URL
	if minIndex < len(cleanedURL) {
		cleanedURL = cleanedURL[:minIndex]
	}

	// 移除尾部的引号和其他垃圾字符
	cleanedURL = strings.TrimRight(cleanedURL, `"'>`)

	// 移除开头的垃圾字符
	cleanedURL = strings.TrimLeft(cleanedURL, `"'<`)

	// 检查URL是否仍然有效
	if cleanedURL == "" || strings.Contains(cleanedURL, "<") || strings.Contains(cleanedURL, ">") {
		return ""
	}

	// 检查是否包含明显的HTML标签
	if strings.Contains(strings.ToLower(cleanedURL), "</") || strings.Contains(strings.ToLower(cleanedURL), "<html") {
		return ""
	}

	return cleanedURL
}

func (c *Crawler) extractRequests(pageURL string, body string) []*models.Request {
	var requests []*models.Request

	parsedURL, err := url.Parse(pageURL)
	if err != nil {
		return requests
	}

	if len(parsedURL.Query()) > 0 {
		var params []models.Parameter

		for name, values := range parsedURL.Query() {
			for _, value := range values {
				params = append(params, models.Parameter{Name: name, Value: value})
			}
		}

		req, err := http.NewRequest("GET", pageURL, nil)
		if err == nil {
			requests = append(requests, &models.Request{
				Request: req,
				Params:  params,
			})
		}
	}

	return requests
}

// 修复的JavaScript链接提取正则表达式
var (
	// 基础URL模式 - 更严格的匹配
	jsLinkRegex = regexp.MustCompile(`['"]((https?://[^\s'"<>]+|/[^\s'"<>]*))['"]`)

	// 路由模式（React Router, Vue Router等）
	routeRegex = regexp.MustCompile(`(?:path|route|to):\s*['"]([^'"<>]+)['"]`)

	// API端点模式
	apiRegex = regexp.MustCompile(`(?:api|endpoint|url):\s*['"]([^'"<>]+)['"]`)
)

// extractJSLinksEnhanced 增强版JavaScript链接提取
func (c *Crawler) extractJSLinksEnhanced(pageURL string, body io.Reader) []string {
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return nil
	}

	foundURLs := make(map[string]struct{})
	base, _ := url.Parse(pageURL)
	content := string(bodyBytes)

	// 应用多个正则表达式模式
	patterns := []*regexp.Regexp{
		jsLinkRegex,
		routeRegex,
		apiRegex,
	}

	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				href := match[1]

				// 清理和验证URL
				href = strings.TrimSpace(href)
				if href == "" || strings.Contains(href, "${") || strings.Contains(href, "%s") {
					continue // 跳过模板变量
				}

				// 使用新的清理函数
				cleanedHref := c.cleanURL(href)
				if cleanedHref == "" {
					continue
				}

				resolvedURL := utils.ResolveURL(base, cleanedHref)
				if resolvedURL == nil {
					continue
				}

				if !c.IsInScope(resolvedURL) {
					if c.appConfig.Debug {
						log.Debug().Str("url", resolvedURL.String()).Msg("JS link is out of scope")
					}
					continue
				}

				normalizedURL := utils.NormalizeURL(resolvedURL)
				if normalizedURL != nil {
					if sanitizedURL := utils.SanitizeURL(resolvedURL); sanitizedURL != nil {
						foundURLs[sanitizedURL.String()] = struct{}{}
					}
				}
			}
		}
	}

	// 单独处理模板字符串（反引号）
	c.extractTemplateStringURLs(content, base, foundURLs)

	// 提取JSON配置中的URL
	c.extractJSONURLs(content, base, foundURLs)

	// 提取注释中的URL（开发者经常在注释中留下API文档链接）
	c.extractCommentURLs(content, base, foundURLs)

	urls := make([]string, 0, len(foundURLs))
	for u := range foundURLs {
		urls = append(urls, u)
	}

	return urls
}

// extractTemplateStringURLs 单独处理模板字符串中的URL
func (c *Crawler) extractTemplateStringURLs(content string, base *url.URL, foundURLs map[string]struct{}) {
	// 使用字符串操作而不是正则表达式来处理反引号
	backtickChar := "`"

	// 查找所有反引号对
	start := 0
	for {
		startIdx := strings.Index(content[start:], backtickChar)
		if startIdx == -1 {
			break
		}
		startIdx += start

		endIdx := strings.Index(content[startIdx+1:], backtickChar)
		if endIdx == -1 {
			break
		}
		endIdx += startIdx + 1

		// 提取模板字符串内容
		templateContent := content[startIdx+1 : endIdx]

		// 在模板字符串中查找URL模式，使用更严格的匹配
		urlPattern := regexp.MustCompile(`(https?://[^\s<>"']+|/[^\s<>"']+)`)
		matches := urlPattern.FindAllString(templateContent, -1)

		for _, match := range matches {
			// 跳过包含模板变量的URL
			if strings.Contains(match, "${") || strings.Contains(match, "%s") {
				continue
			}

			// 清理URL
			cleanedMatch := c.cleanURL(match)
			if cleanedMatch == "" {
				continue
			}

			if resolvedURL := utils.ResolveURL(base, cleanedMatch); resolvedURL != nil {
				if c.IsInScope(resolvedURL) {
					if sanitizedURL := utils.SanitizeURL(resolvedURL); sanitizedURL != nil {
						foundURLs[sanitizedURL.String()] = struct{}{}
					}
				}
			}
		}

		start = endIdx + 1
	}
}

// extractJSONURLs 从JSON配置中提取URL
func (c *Crawler) extractJSONURLs(content string, base *url.URL, foundURLs map[string]struct{}) {
	// 查找JSON对象
	jsonRegex := regexp.MustCompile(`\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}`)
	jsonMatches := jsonRegex.FindAllString(content, -1)

	for _, jsonStr := range jsonMatches {
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(jsonStr), &data); err == nil {
			c.extractURLsFromJSON(data, base, foundURLs)
		}
	}
}

// extractURLsFromJSON 递归提取JSON中的URL
func (c *Crawler) extractURLsFromJSON(data interface{}, base *url.URL, foundURLs map[string]struct{}) {
	switch v := data.(type) {
	case map[string]interface{}:
		for _, value := range v {
			c.extractURLsFromJSON(value, base, foundURLs)
		}
	case []interface{}:
		for _, item := range v {
			c.extractURLsFromJSON(item, base, foundURLs)
		}
	case string:
		if strings.HasPrefix(v, "/") || strings.HasPrefix(v, "http") {
			cleanedURL := c.cleanURL(v)
			if cleanedURL == "" {
				return
			}

			if resolvedURL := utils.ResolveURL(base, cleanedURL); resolvedURL != nil {
				if c.IsInScope(resolvedURL) {
					if sanitizedURL := utils.SanitizeURL(resolvedURL); sanitizedURL != nil {
						foundURLs[sanitizedURL.String()] = struct{}{}
					}
				}
			}
		}
	}
}

// extractCommentURLs 从注释中提取URL
func (c *Crawler) extractCommentURLs(content string, base *url.URL, foundURLs map[string]struct{}) {
	// 单行注释
	singleLineComments := regexp.MustCompile(`//.*$`)
	// 多行注释
	multiLineComments := regexp.MustCompile(`/\*[\s\S]*?\*/`)

	comments := singleLineComments.FindAllString(content, -1)
	comments = append(comments, multiLineComments.FindAllString(content, -1)...)

	urlInCommentRegex := regexp.MustCompile(`(https?://[^\s<>"']+|/[^\s<>"']+)`)

	for _, comment := range comments {
		matches := urlInCommentRegex.FindAllString(comment, -1)
		for _, match := range matches {
			cleanedMatch := c.cleanURL(match)
			if cleanedMatch == "" {
				continue
			}

			if resolvedURL := utils.ResolveURL(base, cleanedMatch); resolvedURL != nil {
				if c.IsInScope(resolvedURL) {
					if sanitizedURL := utils.SanitizeURL(resolvedURL); sanitizedURL != nil {
						foundURLs[sanitizedURL.String()] = struct{}{}
					}
				}
			}
		}
	}
}
