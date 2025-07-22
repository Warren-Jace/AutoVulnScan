// Package crawler 提供网站爬取功能，包括静态和动态爬取
package crawler

import (
	"bytes"
	"context"
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
	baseURL        *url.URL                  // 基础URL，用于域名限制
	config         *config.SpiderConfig      // 爬虫配置
	httpClient     *requester.HTTPClient     // HTTP客户端
	limiter        *rate.Limiter             // 速率限制器
	dynamicCrawler *DynamicCrawler           // 动态爬虫（使用浏览器）
}

// NewCrawler 创建新的爬虫实例
func NewCrawler(baseURL string, cfg *config.SpiderConfig, client *requester.HTTPClient) (*Crawler, error) {
	// 解析基础URL
	parsedBaseURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	// 创建速率限制器，控制请求频率
	limiter := rate.NewLimiter(rate.Limit(cfg.Limit), cfg.Concurrency)
	
	// 创建动态爬虫实例
	dynamicCrawler := NewDynamicCrawler(time.Duration(cfg.Timeout) * time.Second)

	return &Crawler{
		baseURL:        parsedBaseURL,
		config:         cfg,
		httpClient:     client,
		limiter:        limiter,
		dynamicCrawler: dynamicCrawler,
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

	// 创建两个reader，因为需要分别用于提取链接和表单
	var body1, body2 bytes.Buffer
	tee := io.TeeReader(bytes.NewReader(body), &body1)
	if _, err := io.Copy(&body2, tee); err != nil {
		return nil, nil, fmt.Errorf("failed to copy response body: %w", err)
	}

	// 提取页面中的链接
	links := c.extractLinks(&body1, crawlURL)
	// 提取页面中的表单
	requests := extractForms(&body2, crawlURL)

	log.Debug().Str("url", crawlURL).Int("count", len(links)).Msg("Extracted links")
	log.Debug().Str("url", crawlURL).Int("count", len(requests)).Msg("Extracted requests")
	return links, requests, nil
}

// crawlDynamic 动态爬取，使用浏览器渲染页面后再解析
func (c *Crawler) crawlDynamic(ctx context.Context, crawlURL string) ([]string, []*models.Request, error) {
	// 使用动态爬虫获取渲染后的HTML内容
	htmlContent, err := c.dynamicCrawler.Crawl(ctx, crawlURL)
	if err != nil {
		return nil, nil, fmt.Errorf("dynamic crawl failed: %w", err)
	}

	// 创建两个reader用于分别处理链接和表单提取
	var body1, body2 bytes.Buffer
	tee := io.TeeReader(strings.NewReader(htmlContent), &body1)
	if _, err := io.Copy(&body2, tee); err != nil {
		return nil, nil, fmt.Errorf("failed to copy response body: %w", err)
	}

	// 提取链接和表单
	links := c.extractLinks(&body1, crawlURL)
	requests := extractForms(&body2, crawlURL)

	log.Debug().Str("url", crawlURL).Int("count", len(links)).Msg("Extracted links (dynamic)")
	log.Debug().Str("url", crawlURL).Int("count", len(requests)).Msg("Extracted requests (dynamic)")
	return links, requests, nil
}

// extractForms 从HTML中提取表单信息并转换为Request对象
// 该函数用于发现页面中的所有表单，并为每个表单创建可用于漏洞扫描的HTTP请求对象
// 参数说明：
//   - body: HTML内容的读取器
//   - pageURL: 当前页面的URL，用于解析表单的相对action路径
// 返回值：
//   - []*models.Request: 包含表单信息的请求对象列表，每个对象代表一个可测试的表单
func extractForms(body io.Reader, pageURL string) []*models.Request {
	// 初始化请求对象切片，用于存储所有提取到的表单请求
	requests := []*models.Request{}
	
	// 使用goquery库解析HTML文档，goquery提供类似jQuery的选择器功能
	doc, err := goquery.NewDocumentFromReader(body)
	if err != nil {
		// HTML解析失败，返回空的请求列表
		return requests
	}

	// 遍历HTML文档中的所有<form>标签
	// 每个form标签代表一个用户可以交互的表单
	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		// 提取表单的关键属性
		action, _ := s.Attr("action") // action属性指定表单提交的目标URL
		method, _ := s.Attr("method") // method属性指定HTTP请求方法（GET/POST等）
		
		// 如果method属性为空，按照HTML标准默认使用GET方法
		if method == "" {
			method = "GET"
		}

		// 解析当前页面URL，作为解析相对action路径的基础
		formURL, err := url.Parse(pageURL)
		if err != nil {
			// 页面URL解析失败，跳过当前表单
			return
		}
		
		// 将表单的action属性解析为完整的绝对URL
		// 这里处理相对路径的情况，如action="/submit" -> "http://example.com/submit"
		actionURL, err := formURL.Parse(action)
		if err != nil {
			// action URL解析失败，跳过当前表单
			return
		}

		// 提取表单中的所有输入字段
		// 这些字段将用于构造测试参数
		params := []models.Parameter{}
		
		// 查找表单内的所有输入元素：input、textarea、select
		s.Find("input, textarea, select").Each(func(j int, input *goquery.Selection) {
			// 获取输入字段的name属性，这是参数的键名
			name, _ := input.Attr("name")
			if name != "" {
				// 只处理有name属性的字段，因为只有这些字段会被提交
				// 注意：这里使用"test"作为默认测试值
				// 在实际的漏洞扫描中，可能需要根据字段类型使用不同的测试payload
				params = append(params, models.Parameter{Name: name, Value: "test"})
			}
		})

		// 创建HTTP请求对象
		// 注意：这里的实现相对简化，实际应用中需要考虑：
		// 1. 不同的Content-Type（application/x-www-form-urlencoded, multipart/form-data等）
		// 2. 文件上传字段的处理
		// 3. 隐藏字段和CSRF token的处理
		req, err := http.NewRequest(strings.ToUpper(method), actionURL.String(), nil)
		if err != nil {
			// HTTP请求创建失败，跳过当前表单
			return
		}

		// 将表单信息封装为自定义的Request对象
		// 这个对象包含了原始的HTTP请求和提取的参数信息
		// 后续的漏洞扫描器可以使用这些信息构造各种测试payload
		requests = append(requests, &models.Request{
			Request: req,    // 原始HTTP请求对象
			Params:  params, // 表单参数列表
		})
	})
	
	return requests
}


// extractLinks 解析HTML内容并提取所有有效链接
// 参数说明：
//   - body: HTML内容的读取器
//   - pageURL: 当前页面的URL，用于解析相对链接
// 返回值：
//   - []string: 提取到的所有有效链接列表
func (c *Crawler) extractLinks(body io.Reader, pageURL string) []string {
	// 使用map存储找到的URL，自动去重（struct{}{}是空结构体，不占用内存）
	foundURLs := make(map[string]struct{}) 
	
	// 解析当前页面URL，用作相对链接的基础URL
	crawlURL, err := url.Parse(pageURL)
	if err != nil {
		// 如果页面URL无效，直接返回空结果
		return nil
	}

	// 将body内容读取到内存中，因为需要多次使用
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		// 读取失败，返回空结果
		return nil
	}

	// 第一步：提取JavaScript代码中的链接
	// JavaScript中可能包含动态生成的URL，如：window.location.href = "/path"
	jsLinks := c.extractJSLinks(pageURL, bytes.NewReader(bodyBytes))
	for _, link := range jsLinks {
		// 将JavaScript中找到的链接添加到结果集中
		foundURLs[link] = struct{}{}
	}

	// 第二步：使用goquery解析HTML文档结构
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(bodyBytes))
	if err != nil {
		// HTML解析失败，但JavaScript链接已提取，返回现有结果
		urls := make([]string, 0, len(foundURLs))
		for u := range foundURLs {
			urls = append(urls, u)
		}
		return urls
	}

	// processAttr 处理单个属性值的内部函数
	// 负责验证、解析和过滤URL
	processAttr := func(attrValue string) {
		if attrValue == "" {
			return
		}

		resolvedURL := utils.ResolveURL(crawlURL, attrValue)
		if resolvedURL == nil {
			return
		}

		for _, blacklisted := range c.config.Blacklist {
			if strings.Contains(resolvedURL.Host, blacklisted) {
				return
			}
		}

		normalizedURL := utils.NormalizeURL(resolvedURL)
		if normalizedURL != nil && utils.IsSameHost(c.baseURL, normalizedURL) {
			sanitizedURL := utils.SanitizeURL(normalizedURL)
			if sanitizedURL != nil {
				foundURLs[sanitizedURL.String()] = struct{}{}
			}
		}
	}

	// 定义需要提取链接的HTML标签和对应的属性
	// 涵盖了HTML中常见的包含URL的标签
	tags := map[string]string{
		"a":      "href",   // 超链接
		"link":   "href",   // 样式表、图标等外部资源
		"script": "src",    // JavaScript文件
		"img":    "src",    // 图片资源
		"iframe": "src",    // 内嵌框架
		"form":   "action", // 表单提交地址
	}

	// 第三步：遍历所有相关标签并提取链接
	for tag, attr := range tags {
		// 构造CSS选择器，查找包含指定属性的标签
		// 例如：a[href] 查找所有包含href属性的a标签
		doc.Find(fmt.Sprintf("%s[%s]", tag, attr)).Each(func(i int, s *goquery.Selection) {
			// 获取属性值
			val, _ := s.Attr(attr)
			// 使用通用处理函数处理这个URL
			processAttr(val)
		})
	}

	// 第四步：将去重后的URL集合转换为字符串切片返回
	urls := make([]string, 0, len(foundURLs))
	for u := range foundURLs {
		urls = append(urls, u)
	}
	return urls
}

func (c *Crawler) extractRequests(pageURL string, body string) []*models.Request {
	var requests []*models.Request
	
	// TODO: 在完整的实现中，这里应该包含以下功能：
	// 1. 解析HTML表单并提取表单参数
	// 2. 分析JavaScript代码中的变量和AJAX请求
	// 3. 识别隐藏的参数和动态生成的请求
	// 目前的实现仅处理URL查询参数作为基础功能
	
	// 解析传入的URL字符串，获取URL各个组成部分
	parsedURL, err := url.Parse(pageURL)
	if err != nil {
		// URL解析失败，返回空的请求列表
		// 这种情况通常发生在URL格式不正确时
		return requests
	}

	// 检查URL是否包含查询参数（问号后面的部分）
	// 例如：http://example.com/page?param1=value1&param2=value2
	if len(parsedURL.Query()) > 0 {
		// 初始化参数切片，用于存储所有查询参数
		var params []models.Parameter
		
		// 遍历URL中的所有查询参数
		// parsedURL.Query()返回map[string][]string类型
		// 键是参数名，值是参数值的切片（支持同名参数多值的情况）
		for name, values := range parsedURL.Query() {
			// 处理每个参数的所有值
			// 例如：?color=red&color=blue 会产生两个color参数
			for _, value := range values {
				// 创建参数对象并添加到参数列表中
				params = append(params, models.Parameter{
					Name:  name,    // 参数名称
					Value: value,   // 参数值
					Type:  "query", // 参数类型标识为查询参数
				})
			}
		}

		// 基于原URL创建HTTP GET请求对象
		// 这个请求对象将用于后续的安全测试和漏洞扫描
		req, err := http.NewRequest("GET", pageURL, nil)
		if err == nil {
			// 请求对象创建成功，将其与提取的参数一起封装
			requests = append(requests, &models.Request{
				Request: req,    // 原始HTTP请求对象
				Params:  params, // 提取的查询参数列表
			})
		}
		// 如果请求创建失败，该URL的参数信息将被忽略
	}
	
	return requests
}

// 用于匹配JavaScript中链接的正则表达式
// 该正则表达式匹配以下模式：
// 1. 单引号或双引号包围的字符串
// 2. 字符串内容为：
//    - 以/开头的相对路径（如：'/api/data', '/images/pic.jpg'）
//    - 完整的HTTP/HTTPS URL（如：'https://example.com/path'）
// 3. 排除包含空白字符的字符串，确保匹配的是有效URL
// 示例匹配：
//   - "'/api/users'" -> 匹配 /api/users
//   - "'https://api.example.com/data'" -> 匹配 https://api.example.com/data
//   - "'/path with space'" -> 不匹配（包含空格）
var jsLinkRegex = regexp.MustCompile(`['\"]((?:/[^'\"\\s]+|https?://[^'\"\\s]+))['\"]`)

// extractJSLinks 从JavaScript代码中提取链接
// 该函数用于分析页面中的JavaScript代码，发现其中可能包含的API端点、资源路径等链接
// 这对于Web安全扫描和爬虫发现隐藏页面非常重要，因为现代Web应用经常在JS中定义动态路由
// 参数说明：
//   - pageURL: 当前页面的URL，用作解析相对链接的基准
//   - body: 包含JavaScript代码的内容读取器（通常是页面HTML或JS文件内容）
// 返回值：
//   - []string: 提取到的去重后的URL列表，所有URL都已转换为绝对路径
func (c *Crawler) extractJSLinks(pageURL string, body io.Reader) []string {
	// 读取所有内容到内存中，便于后续的正则表达式处理
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		// 读取失败，返回空列表
		return nil
	}

	// 使用map进行URL去重，struct{}作为值类型节省内存
	// key为URL字符串，value为空结构体
	foundURLs := make(map[string]struct{})
	
	// 解析当前页面URL作为基准URL，用于将相对路径转换为绝对路径
	base, _ := url.Parse(pageURL)
	
	// 将字节数组转换为字符串，便于正则表达式匹配
	content := string(bodyBytes)

	// 使用预编译的正则表达式查找所有匹配的链接
	// FindAllStringSubmatch返回所有匹配项及其子匹配组
	// -1表示查找所有匹配项，不限制数量
	matches := jsLinkRegex.FindAllStringSubmatch(content, -1)
	
	// 遍历所有匹配结果
	for _, match := range matches {
		if len(match) > 1 {
			href := match[1]
			resolvedURL := utils.ResolveURL(base, href)
			if resolvedURL == nil {
				continue
			}

			shouldSkip := false
			for _, blacklisted := range c.config.Blacklist {
				if strings.Contains(resolvedURL.Host, blacklisted) {
					shouldSkip = true
					break
				}
			}
			if shouldSkip {
				continue
			}

			normalizedURL := utils.NormalizeURL(resolvedURL)
			if normalizedURL != nil && utils.IsSameHost(c.baseURL, normalizedURL) {
				sanitizedURL := utils.SanitizeURL(normalizedURL)
				if sanitizedURL != nil {
					foundURLs[sanitizedURL.String()] = struct{}{}
				}
			}
		}
	}

	urls := make([]string, 0, len(foundURLs))
	for u := range foundURLs {
		urls = append(urls, u)
	}
	
	return urls
}
