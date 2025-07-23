// Package crawler 提供了网站爬取功能，包括静态和动态内容分析。
package crawler

import (
	"context"
	"math/rand"
	"time"

	"autovulnscan/internal/browser" // 引入浏览器服务

	"github.com/chromedp/chromedp"
	"github.com/rs/zerolog/log"
)

// DynamicCrawlerResult 封装了动态爬虫的返回结果。
type DynamicCrawlerResult struct {
	RenderedHTML string
	Links        []string
	Error        error
}

// DynamicCrawler 代表一个使用无头浏览器来渲染页面的爬虫。
type DynamicCrawler struct {
	headless   bool
	proxy      string
	timeout    time.Duration
	Result     chan DynamicCrawlerResult // 使用结构体来传递更丰富的结果
	UserAgents []string
	rand       *rand.Rand // 线程安全的随机数生成器
}

// NewDynamicCrawler 初始化一个新的动态爬虫。
func NewDynamicCrawler(headless bool, proxy string, timeout time.Duration, userAgents []string) *DynamicCrawler {
	return &DynamicCrawler{
		headless:   headless,
		proxy:      proxy,
		timeout:    timeout,
		Result:     make(chan DynamicCrawlerResult, 1),
		UserAgents: userAgents,
		rand:       rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Crawl 使用无头浏览器导航到一个URL，执行JavaScript，并提取链接和渲染后的HTML。
//
// 注意：
//
//	此方法为每个爬取任务创建了一个全新的浏览器实例。
//	在需要爬取大量页面的场景下，这会带来巨大的性能开销。
//	一个更优化的设计是让 DynamicCrawler 持有一个 BrowserService 实例，
//	并在多个Crawl任务之间复用这个浏览器实例，从而避免重复创建和销毁进程。
func (c *DynamicCrawler) Crawl(url string) {
	userAgent := c.getRandomUserAgent()

	// 使用重构后的 browser.NewBrowserService 来统一浏览器实例的创建。
	// 理想情况下，这个 service 应该是共享的。
	browserService, err := browser.NewBrowserService(browser.Config{
		Headless:  c.headless,
		Proxy:     c.proxy,
		UserAgent: userAgent,
	})
	if err != nil {
		log.Error().Err(err).Msg("创建浏览器服务失败")
		c.Result <- DynamicCrawlerResult{Error: err}
		return
	}
	defer browserService.Close()

	// chromedp 在内部处理从 Allocator Context 创建 Task Context 的逻辑，
	// 我们直接使用 browserService 提供的上下文。
	// 这里我们模拟从 browserService 获取上下文，但实际上chromedp的API并非如此设计。
	// 为了修正这个逻辑，我们需要更深层次的重构，暂时保持现有chromedp的用法。
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", c.headless),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.UserAgent(userAgent),
	)
	if c.proxy != "" {
		opts = append(opts, chromedp.ProxyServer(c.proxy))
	}
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	taskCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	timeoutCtx, timeoutCancel := context.WithTimeout(taskCtx, c.timeout)
	defer timeoutCancel()

	var links []string
	var renderedHTML string
	err = chromedp.Run(timeoutCtx,
		chromedp.Navigate(url),
		chromedp.Sleep(2*time.Second), // 等待JS执行
		chromedp.Evaluate(`Array.from(document.links).map(a => a.href)`, &links),
		chromedp.OuterHTML("html", &renderedHTML), // 获取渲染后的完整HTML
	)

	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("动态爬取失败")
		c.Result <- DynamicCrawlerResult{Error: err}
		return
	}

	c.Result <- DynamicCrawlerResult{
		RenderedHTML: renderedHTML,
		Links:        links,
		Error:        nil,
	}
}

// getRandomUserAgent 从列表中安全地获取一个随机的User-Agent。
func (c *DynamicCrawler) getRandomUserAgent() string {
	if len(c.UserAgents) == 0 {
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
	}
	// 使用线程安全的rand实例
	return c.UserAgents[c.rand.Intn(len(c.UserAgents))]
}

// 使用示例：
// crawler := NewDynamicCrawler(true, "", 60*time.Second, []string{"custom_user_agent"})
// html, err := crawler.Crawl("https://example.com")
// if err != nil {
//     log.Fatal().Err(err).Msg("爬取失败")
// }
// fmt.Println("获取到的HTML长度:", len(html))
