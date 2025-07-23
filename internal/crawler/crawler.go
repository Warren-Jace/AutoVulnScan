// Package crawler 提供了网站爬取功能，包括静态和动态爬取。
package crawler

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"autovulnscan/internal/config"
	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"

	// 引入重构后的工具包
	"github.com/PuerkitoBio/goquery"
	"github.com/rs/zerolog/log"
)

// 定义包级别的正则表达式，提高可读性和可维护性。
var (
	// 用于从JavaScript代码中提取链接的各种模式
	jsLinkRegex = regexp.MustCompile(`['"]((https?://[^\s'"<>]+|/[^\s'"<>]*))['"]`)
	routeRegex  = regexp.MustCompile(`(?:path|route|to):\s*['"]([^'"<>]+)['"]`)
	apiRegex    = regexp.MustCompile(`(?:api|endpoint|url):\s*['"]([^'"<>]+)['"]`)

	// 用于从JavaScript代码中提取API端点的模式
	apiPatterns = []*regexp.Regexp{
		regexp.MustCompile(`fetch\s*\(\s*['"]([^'"]+)['"]`),
		regexp.MustCompile(`\.open\s*\(\s*['"]([^'"]+)['"]\s*,\s*['"]([^'"]+)['"]`),
		regexp.MustCompile(`\$\.(?:ajax|get|post|put|delete)\s*\(\s*['"]([^'"]+)['"]`),
		regexp.MustCompile(`axios\.(?:get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]`),
		regexp.MustCompile(`['"](/api/[^'"\s]+)['"]`),
		regexp.MustCompile(`['"](/v\d+/[^'"\s]+)['"]`),
		regexp.MustCompile(`['"](/graphql[^'"\s]*)['"]`),
		regexp.MustCompile(`['"](wss?://[^'"\s]+)['"]`),
	}
)

// Crawler 负责从网页中提取链接和请求。
type Crawler struct {
	targetURL      *url.URL
	config         *config.Settings
	httpClient     *requester.HTTPClient
	dynamicCrawler *DynamicCrawler
}

// NewCrawler 创建并初始化一个新的Crawler实例。
func NewCrawler(targetURL string, cfg *config.Settings, httpClient *requester.HTTPClient) (*Crawler, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("无法解析目标URL: %w", err)
	}

	var dynCrawler *DynamicCrawler
	if cfg.Spider.DynamicCrawler.Enabled {
		// 从主配置中获取User-Agent列表
		var userAgents []string
		if ua, ok := cfg.Headers["User-Agent"]; ok {
			userAgents = append(userAgents, ua)
		}
		// 使用正确的参数初始化动态爬虫
		dynCrawler = NewDynamicCrawler(
			cfg.Spider.DynamicCrawler.Headless,
			cfg.Proxy,
			time.Duration(cfg.Spider.Timeout)*time.Second,
			userAgents,
		)
	}

	return &Crawler{
		targetURL:      parsedURL,
		config:         cfg,
		httpClient:     httpClient,
		dynamicCrawler: dynCrawler,
	}, nil
}

// StaticCrawl 对给定的HTML内容进行静态分析，提取链接和请求。
func (c *Crawler) StaticCrawl(ctx context.Context, pageURL string, body []byte) ([]string, []*models.Request, error) {
	parsedURL, err := url.Parse(pageURL)
	if err != nil {
		return nil, nil, fmt.Errorf("无法解析页面URL: %w", err)
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("无法解析HTML文档: %w", err)
	}

	links := c.extractLinks(doc, parsedURL)
	requests := c.extractForms(doc, parsedURL)

	return links, requests, nil
}

// DynamicCrawl 使用无头浏览器执行动态分析，以发现由JavaScript生成的链接和请求。
func (c *Crawler) DynamicCrawl(ctx context.Context, pageURL string) ([]string, []*models.Request, error) {
	if c.dynamicCrawler == nil {
		return nil, nil, fmt.Errorf("动态爬虫未启用或初始化失败")
	}

	// 启动动态爬取任务
	go c.dynamicCrawler.Crawl(pageURL)

	// 等待结果或超时
	select {
	case result := <-c.dynamicCrawler.Result:
		if result.Error != nil {
			return nil, nil, fmt.Errorf("动态渲染页面失败: %w", result.Error)
		}
		// 对动态渲染后的HTML内容进行静态分析
		log.Info().Str("url", pageURL).Int("size", len(result.RenderedHTML)).Msg("✅ 动态渲染成功，正在提取链接 (Dynamic rendering successful, extracting links)")
		return c.StaticCrawl(ctx, pageURL, []byte(result.RenderedHTML))
	case <-time.After(c.dynamicCrawler.timeout + 5*time.Second): // 增加一些缓冲区时间
		return nil, nil, fmt.Errorf("动态爬取超时: %s", pageURL)
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
}

// extractLinks 从goquery文档中提取所有绝对URL链接。
func (c *Crawler) extractLinks(doc *goquery.Document, baseURL *url.URL) []string {
	var foundUrls []string
	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if !exists {
			return
		}
		absURL := toAbsoluteURL(baseURL, href)
		if absURL != "" {
			foundUrls = append(foundUrls, absURL)
		}
	})
	return foundUrls
}

// extractForms 从goquery文档中提取所有表单并将其转换为Request对象。
func (c *Crawler) extractForms(doc *goquery.Document, baseURL *url.URL) []*models.Request {
	var requests []*models.Request
	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, _ := s.Attr("action")
		method, _ := s.Attr("method")
		if method == "" {
			method = "GET" // 默认为GET请求
		}

		formURL := toAbsoluteURL(baseURL, action)
		if formURL == "" {
			return
		}

		parsedFormURL, err := url.Parse(formURL)
		if err != nil {
			log.Debug().Str("url", formURL).Err(err).Msg("解析表单action URL失败")
			return
		}

		params := make([]models.Parameter, 0)
		s.Find("input, textarea, select").Each(func(j int, el *goquery.Selection) {
			name, exists := el.Attr("name")
			if !exists {
				return
			}
			// 对于示例，我们使用一个占位符值。
			params = append(params, models.Parameter{Name: name, Value: "test"})
		})

		// 创建一个标准的http.Request
		req, err := http.NewRequest(strings.ToUpper(method), parsedFormURL.String(), nil)
		if err != nil {
			log.Warn().Err(err).Msg("创建表单请求失败")
			return
		}

		requests = append(requests, &models.Request{
			Request: req,
			Params:  params,
		})
	})
	return requests
}

// toAbsoluteURL 将相对URL转换为绝对URL。
func toAbsoluteURL(baseURL *url.URL, href string) string {
	if strings.HasPrefix(href, "#") || strings.HasPrefix(href, "javascript:") || strings.HasPrefix(href, "mailto:") {
		return ""
	}
	relURL, err := url.Parse(href)
	if err != nil {
		return ""
	}
	return baseURL.ResolveReference(relURL).String()
}
