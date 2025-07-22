// Package crawler provides web crawling capabilities, including static and dynamic content analysis.
// This package is primarily used for handling dynamic web pages that require JavaScript rendering.
package crawler

import (
	"context"
	"math/rand"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/rs/zerolog/log"
)

// DynamicCrawler represents a crawler that uses a headless browser to render pages.
type DynamicCrawler struct {
	headless   bool
	proxy      string
	timeout    time.Duration
	Result     chan []string
	UserAgents []string
}

// NewDynamicCrawler initializes a new DynamicCrawler.
func NewDynamicCrawler(headless bool, proxy string, timeout time.Duration, userAgents []string) *DynamicCrawler {
	return &DynamicCrawler{
		headless:   headless,
		proxy:      proxy,
		timeout:    timeout,
		Result:     make(chan []string, 1),
		UserAgents: userAgents,
	}
}

// GetAllocContext creates a new chromedp execution allocator context with the specified options.
func GetAllocContext(headless bool, proxy, userAgent string) (context.Context, context.CancelFunc) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", headless),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.UserAgent(userAgent),
	)
	if proxy != "" {
		opts = append(opts, chromedp.ProxyServer(proxy))
	}
	return chromedp.NewExecAllocator(context.Background(), opts...)
}

// Crawl navigates to a URL and extracts all links.
func (c *DynamicCrawler) Crawl(url string) {
	var allocCtx context.Context
	var cancel context.CancelFunc
	userAgent := c.getRandomUserAgent()

	if c.proxy != "" {
		allocCtx, cancel = GetAllocContext(c.headless, c.proxy, userAgent)
	} else {
		allocCtx, cancel = GetAllocContext(c.headless, "", userAgent)
	}
	defer cancel()

	taskCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	timeoutCtx, timeoutCancel := context.WithTimeout(taskCtx, c.timeout)
	defer timeoutCancel()

	var links []string
	err := chromedp.Run(timeoutCtx,
		chromedp.Navigate(url),
		chromedp.Sleep(2*time.Second),
		chromedp.Evaluate(`Array.from(document.links).map(a => a.href)`, &links),
	)

	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed to crawl")
		return
	}

	c.Result <- links
}

func (c *DynamicCrawler) getRandomUserAgent() string {
	if len(c.UserAgents) == 0 {
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
	}
	return c.UserAgents[rand.Intn(len(c.UserAgents))]
}

// 使用示例：
// crawler := NewDynamicCrawler(true, "", 60*time.Second, []string{"custom_user_agent"})
// html, err := crawler.Crawl("https://example.com")
// if err != nil {
//     log.Fatal().Err(err).Msg("爬取失败")
// }
// fmt.Println("获取到的HTML长度:", len(html))
