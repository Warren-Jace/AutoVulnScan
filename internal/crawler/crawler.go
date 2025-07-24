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
	"sync"
	"time"

	"autovulnscan/internal/config"
	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"
	"autovulnscan/internal/utils"

	"github.com/PuerkitoBio/goquery"
	"github.com/rs/zerolog/log"
	"golang.org/x/time/rate"
)

// 预编译正则表达式以提高性能
var (
	// JavaScript链接提取正则表达式
	jsLinkRegex = regexp.MustCompile(`['\"]((https?://[^\s'"<>]+|/[^\s'"<>]*))['\"]`)
	routeRegex  = regexp.MustCompile(`(?:path|route|to):\s*['\"]([^'"<>]+)['\"]`)
	apiRegex    = regexp.MustCompile(`(?:api|endpoint|url):\s*['\"]([^'"<>]+)['\"]`)
	
	// API端点提取正则表达式
	apiPatterns = []*regexp.Regexp{
		regexp.MustCompile(`fetch\s*\(\s*['\"]([^'"]+)['\"]`),
		regexp.MustCompile(`\.open\s*\(\s*['\"]([^'"]+)['"]\s*,\s*['\"]([^'"]+)['\"]`),
		regexp.MustCompile(`\$\.(?:ajax|get|post|put|delete)\s*\(\s*['\"]([^'"]+)['\"]`),
		regexp.MustCompile(`axios\.(?:get|post|put|delete|patch)\s*\(\s*['\"]([^'"]+)['\"]`),
		regexp.MustCompile(`['"](/api/[^'"\s]+)['\"]`),
		regexp.MustCompile(`['"](/v\d+/[^'"\s]+)['\"]`),
		regexp.MustCompile(`['"](/graphql[^'"\s]*)['\"]`),
		regexp.MustCompile(`['"](wss?://[^'"\s]+)['\"]`),
	}
	
	// HTML编码清理模式
	htmlEncodePatterns = []string{
		"%22", "%3C", "%3E", "&quot;", "&lt;", "&gt;", "&amp;",
	}
	
	// URL提取正则表达式
	urlInCommentRegex = regexp.MustCompile(`(https?://[^\s<>"']+|/[^\s<>"']+)`)
	jsonRegex        = regexp.MustCompile(`\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}`)
	urlPattern       = regexp.MustCompile(`(https?://[^\s<>"']+|/[^\s<>"']+)`)
	
	// 单行和多行注释正则
	singleLineComments = regexp.MustCompile(`//.*$`)
	multiLineComments  = regexp.MustCompile(`/\*[\s\S]*?\*/`)
)

// Crawler 负责获取网页并从中提取链接和参数
type Crawler struct {
	baseURL        *url.URL              // 基础URL，用于域名限制
	config         *config.SpiderConfig  // 爬虫配置
	httpClient     *requester.HTTPClient // HTTP客户端
	limiter        *rate.Limiter         // 速率限制器
	dynamicCrawler *DynamicCrawler       // 动态爬虫（使用浏览器）
	appConfig      *config.Settings
	
	// 缓存编译的正则表达式
	blacklistRegexes []*regexp.Regexp
	blacklistOnce    sync.Once
}

// IsInScope checks if a given URL is within the scope defined by the configuration.
func (c *Crawler) IsInScope(u *url.URL) bool {
	hostname := u.Hostname()
	urlStr := u.String()

	// 延迟编译黑名单正则表达式
	c.blacklistOnce.Do(func() {
		c.blacklistRegexes = make([]*regexp.Regexp, 0, len(c.config.Blacklist))
		for _, pattern := range c.config.Blacklist {
			if regex, err := regexp.Compile(pattern); err == nil {
				c.blacklistRegexes = append(c.blacklistRegexes, regex)
			}
		}
	})

	// Check against blacklist patterns
	for _, regex := range c.blacklistRegexes {
		if regex.MatchString(urlStr) {
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

	var allLinks []string
	var allRequests []*models.Request
	var err error

	if c.config.DynamicCrawler.Enabled {
		allLinks, allRequests, err = c.crawlDynamic(ctx, crawlURL)
	} else {
		allLinks, allRequests, err = c.crawlStatic(ctx, crawlURL, body)
	}

	if err != nil {
		return nil, nil, err
	}

	// 过滤掉不符合范围的链接
	inScopeLinks := c.filterInScopeLinks(allLinks)

	return inScopeLinks, allRequests, nil
}

// filterInScopeLinks 过滤出符合范围的链接
func (c *Crawler) filterInScopeLinks(links []string) []string {
	var inScopeLinks []string
	for _, link := range links {
		parsedURL, err := url.Parse(link)
		if err != nil {
			log.Warn().Str("url", link).Err(err).Msg("Failed to parse link")
			continue
		}
		if c.IsInScope(parsedURL) {
			inScopeLinks = append(inScopeLinks, link)
		}
	}
	return inScopeLinks
}

// crawlStatic 静态爬取，解析已获取的HTML内容
func (c *Crawler) crawlStatic(ctx context.Context, crawlURL string, body []byte) ([]string, []*models.Request, error) {
	log.Debug().Str("url", crawlURL).Int("size", len(body)).Msg("Statically parsing page")

	// 使用sync.WaitGroup并发处理不同的提取任务
	var wg sync.WaitGroup
	var links []string
	var requests []*models.Request
	var apiRequests []*models.Request
	var mu sync.Mutex

	// 并发提取链接
	wg.Add(1)
	go func() {
		defer wg.Done()
		extractedLinks := c.extractLinksEnhanced(bytes.NewReader(body), crawlURL)
		mu.Lock()
		links = extractedLinks
		mu.Unlock()
	}()

	// 并发提取表单
	wg.Add(1)
	go func() {
		defer wg.Done()
		extractedRequests := c.extractFormsEnhanced(bytes.NewReader(body), crawlURL)
		mu.Lock()
		requests = extractedRequests
		mu.Unlock()
	}()

	// 并发提取API端点
	wg.Add(1)
	go func() {
		defer wg.Done()
		extractedAPIRequests := c.extractAPIEndpoints(bytes.NewReader(body), crawlURL)
		mu.Lock()
		apiRequests = extractedAPIRequests
		mu.Unlock()
	}()

	wg.Wait()

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
	
	select {
	case links := <-c.dynamicCrawler.Result:
		log.Debug().Str("url", crawlURL).Int("count", len(links)).Msg("Extracted links (dynamic)")
		// 过滤范围内的链接
		inScopeLinks := c.filterInScopeLinks(links)
		return inScopeLinks, nil, nil
	case <-time.After(time.Duration(c.config.Timeout) * time.Second):
		return nil, nil, fmt.Errorf("dynamic crawl timed out for %s", crawlURL)
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
}

// extractFormsEnhanced 增强版表单提取，支持更多现代Web表单特性
func (c *Crawler) extractFormsEnhanced(body io.Reader, pageURL string) []*models.Request {
	var requests []*models.Request

	doc, err := goquery.NewDocumentFromReader(body)
	if err != nil {
		return requests
	}

	// 遍历所有表单
	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		request := c.processForm(s, pageURL)
		if request != nil {
			requests = append(requests, request)
		}
	})

	return requests
}

// processForm 处理单个表单
func (c *Crawler) processForm(s *goquery.Selection, pageURL string) *models.Request {
	action, _ := s.Attr("action")
	method, _ := s.Attr("method")
	enctype, _ := s.Attr("enctype")

	if method == "" {
		method = "GET"
	}

	formURL, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}

	actionURL, err := formURL.Parse(action)
	if err != nil {
		return nil
	}

	params := c.extractFormParams(s)

	// 创建HTTP请求
	req, err := http.NewRequest(strings.ToUpper(method), actionURL.String(), nil)
	if err != nil {
		return nil
	}

	// 设置适当的Content-Type
	if strings.ToUpper(method) == "POST" {
		if enctype == "" {
			enctype = "application/x-www-form-urlencoded"
		}
		req.Header.Set("Content-Type", enctype)
	}

	return &models.Request{
		Request: req,
		Params:  params,
	}
}

// extractFormParams 提取表单参数
func (c *Crawler) extractFormParams(s *goquery.Selection) []models.Parameter {
	var params []models.Parameter

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

	return params
}

// getTestValueByType 根据输入类型返回合适的测试值
func (c *Crawler) getTestValueByType(inputType, currentValue, placeholder string) string {
	// 使用map提高查找效率
	testValues := map[string]string{
		"email":          "test@example.com",
		"password":       "testpass123",
		"number":         "123",
		"tel":            "1234567890",
		"phone":          "1234567890",
		"url":            "https://example.com",
		"date":           "2023-01-01",
		"time":           "12:00",
		"datetime-local": "2023-01-01T12:00",
		"color":          "#ff0000",
		"range":          "50",
		"search":         "search_test",
	}

	inputType = strings.ToLower(inputType)
	
	if inputType == "hidden" {
		// 保持隐藏字段的原始值
		return currentValue
	}

	if testValue, exists := testValues[inputType]; exists {
		return testValue
	}

	// 如果有placeholder，使用它作为提示
	if placeholder != "" {
		return "test_" + strings.ReplaceAll(placeholder, " ", "_")
	}
	return "test"
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

	foundEndpoints := make(map[string]string) // URL -> HTTP Method

	// 使用预编译的正则表达式
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

	// 并发提取不同类型的链接
	var wg sync.WaitGroup
	var mu sync.Mutex

	// 提取JavaScript中的链接
	wg.Add(1)
	go func() {
		defer wg.Done()
		jsLinks := c.extractJSLinksEnhanced(pageURL, bytes.NewReader(bodyBytes))
		mu.Lock()
		for _, link := range jsLinks {
			foundURLs[link] = struct{}{}
		}
		mu.Unlock()
	}()

	// 提取HTML中的链接
	wg.Add(1)
	go func() {
		defer wg.Done()
		htmlLinks := c.extractHTMLLinks(bytes.NewReader(bodyBytes), crawlURL)
		mu.Lock()
		for _, link := range htmlLinks {
			foundURLs[link] = struct{}{}
		}
		mu.Unlock()
	}()

	wg.Wait()

	// 转换为切片返回
	urls := make([]string, 0, len(foundURLs))
	for u := range foundURLs {
		urls = append(urls, u)
	}
	return urls
}

// extractHTMLLinks 提取HTML中的链接
func (c *Crawler) extractHTMLLinks(body io.Reader, crawlURL *url.URL) []string {
	var foundURLs []string

	// 解析HTML文档
	doc, err := goquery.NewDocumentFromReader(body)
	if err != nil {
		return foundURLs
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
				foundURLs = append(foundURLs, sanitizedURL.String())
			}
		}
	}

	// 扩展的HTML标签和属性映射
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
					c.processSrcset(val, processAttr)
				} else if attr == "content" && tag == "meta" {
					c.processMetaContent(s, val, processAttr)
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

	return foundURLs
}

// processSrcset 处理srcset属性
func (c *Crawler) processSrcset(val string, processAttr func(string)) {
	urls := strings.Split(val, ",")
	for _, u := range urls {
		parts := strings.Fields(strings.TrimSpace(u))
		if len(parts) > 0 {
			processAttr(parts[0])
		}
	}
}

// processMetaContent 处理meta标签的content属性
func (c *Crawler) processMetaContent(s *goquery.Selection, val string, processAttr func(string)) {
	if httpEquiv, _ := s.Attr("http-equiv"); strings.ToLower(httpEquiv) == "refresh" {
		if urlIndex := strings.Index(val, "url="); urlIndex != -1 {
			refreshURL := val[urlIndex+4:]
			processAttr(refreshURL)
		}
	}
}

// cleanURL 清理URL，移除HTML编码和垃圾字符
func (c *Crawler) cleanURL(rawURL string) string {
	cleanedURL := rawURL

	// 查找第一个HTML编码字符的位置
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

	// 移除尾部和开头的垃圾字符
	cleanedURL = strings.Trim(cleanedURL, `"'><`)

	// 检查URL是否仍然有效
	if cleanedURL == "" || strings.ContainsAny(cleanedURL, "<>") {
		return ""
	}

	// 检查是否包含明显的HTML标签
	lowerURL := strings.ToLower(cleanedURL)
	if strings.Contains(lowerURL, "</") || strings.Contains(lowerURL, "<html") {
		return ""
	}

	return cleanedURL
}

// extractRequests 从URL中提取请求参数
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

// extractJSLinksEnhanced 增强版JavaScript链接提取
func (c *Crawler) extractJSLinksEnhanced(pageURL string, body io.Reader) []string {
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return nil
	}

	foundURLs := make(map[string]struct{})
	base, _ := url.Parse(pageURL)
	content := string(bodyBytes)

	// 使用预编译的正则表达式模式
	patterns := []*regexp.Regexp{jsLinkRegex, routeRegex, apiRegex}

	for _, pattern := range patterns {
		c.processRegexMatches(pattern, content, base, foundURLs)
	}

	// 并发处理其他提取任务
	var wg sync.WaitGroup
	var mu sync.Mutex

	wg.Add(3)

	// 提取模板字符串URL
	go func() {
		defer wg.Done()
		tempURLs := make(map[string]struct{})
		c.extractTemplateStringURLs(content, base, tempURLs)
		mu.Lock()
		for url := range tempURLs {
			foundURLs[url] = struct{}{}
		}
		mu.Unlock()
	}()

	// 提取JSON配置中的URL
	go func() {
		defer wg.Done()
		jsonURLs := make(map[string]struct{})
		c.extractJSONURLs(content, base, jsonURLs)
		mu.Lock()
		for url := range jsonURLs {
			foundURLs[url] = struct{}{}
		}
		mu.Unlock()
	}()

	// 提取注释中的URL
	go func() {
		defer wg.Done()
		commentURLs := make(map[string]struct{})
		c.extractCommentURLs(content, base, commentURLs)
		mu.Lock()
		for url := range commentURLs {
			foundURLs[url] = struct{}{}
		}
		mu.Unlock()
	}()

	wg.Wait()

	urls := make([]string, 0, len(foundURLs))
	for u := range foundURLs {
		urls = append(urls, u)
	}

	return urls
}

// processRegexMatches 处理正则表达式匹配结果
func (c *Crawler) processRegexMatches(pattern *regexp.Regexp, content string, base *url.URL, foundURLs map[string]struct{}) {
	matches := pattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			href := strings.TrimSpace(match[1])
			if href == "" || strings.ContainsAny(href, "${%") {
				continue // 跳过模板变量
			}

			cleanedHref := c.cleanURL(href)
			if cleanedHref == "" {
				continue
			}

			resolvedURL := utils.ResolveURL(base, cleanedHref)
			if resolvedURL == nil || !c.IsInScope(resolvedURL) {
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

// extractTemplateStringURLs 提取模板字符串中的URL
func (c *Crawler) extractTemplateStringURLs(content string, base *url.URL, foundURLs map[string]struct{}) {
	backtickChar := "`"
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

		// 在模板字符串中查找URL模式
		matches := urlPattern.FindAllString(templateContent, -1)

		for _, match := range matches {
			// 跳过包含模板变量的URL
			if strings.ContainsAny(match, "${%") {
				continue
			}

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
	// 提取所有注释
	comments := singleLineComments.FindAllString(content, -1)
	comments = append(comments, multiLineComments.FindAllString(content, -1)...)

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
