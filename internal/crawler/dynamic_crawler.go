// Package crawler 提供了网站爬取功能，包括静态和动态爬取。
package crawler

import (
	"fmt"
	"time"

	"github.com/playwright-community/playwright-go"
	"github.com/rs/zerolog/log"
)

// DynamicCrawlerResult 封装了动态爬取的结果，包括渲染后的HTML和可能的错误。
type DynamicCrawlerResult struct {
	RenderedHTML string // 渲染后的HTML内容
	Error        error  // 爬取过程中发生的错误
}

// DynamicCrawler 负责使用无头浏览器动态爬取网页。
// 它可以执行JavaScript，处理由客户端渲染的页面。
type DynamicCrawler struct {
	pw      *playwright.Playwright
	browser playwright.Browser
	Result  chan DynamicCrawlerResult // 用于传递爬取结果的通道
	timeout time.Duration
}

// NewDynamicCrawler 创建并初始化一个新的DynamicCrawler实例。
// 它会启动Playwright和浏览器，并准备好接收爬取任务。
func NewDynamicCrawler(headless bool, proxy string, timeout time.Duration, userAgents []string) *DynamicCrawler {
	pw, err := playwright.Run()
	if err != nil {
		log.Fatal().Err(err).Msg("无法启动Playwright")
	}

	browserOptions := playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(headless),
	}
	if proxy != "" {
		browserOptions.Proxy = &playwright.Proxy{Server: proxy}
	}

	browser, err := pw.Chromium.Launch(browserOptions)
	if err != nil {
		log.Fatal().Err(err).Msg("无法启动浏览器")
	}

	return &DynamicCrawler{
		pw:      pw,
		browser: browser,
		Result:  make(chan DynamicCrawlerResult, 1),
		timeout: timeout,
	}
}

// Crawl 执行动态爬取。它会导航到一个URL，等待页面加载，并提取渲染后的HTML。
func (dc *DynamicCrawler) Crawl(targetURL string) {
	page, err := dc.browser.NewPage()
	if err != nil {
		dc.Result <- DynamicCrawlerResult{Error: fmt.Errorf("无法创建页面: %w", err)}
		return
	}
	defer page.Close()

	_, err = page.Goto(targetURL, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateNetworkidle,
		Timeout:   playwright.Float(float64(dc.timeout.Milliseconds())),
	})
	if err != nil {
		dc.Result <- DynamicCrawlerResult{Error: fmt.Errorf("无法导航到URL: %w", err)}
		return
	}

	// 等待一小段时间，以确保所有动态内容都已加载
	time.Sleep(2 * time.Second)

	html, err := page.Content()
	if err != nil {
		dc.Result <- DynamicCrawlerResult{Error: fmt.Errorf("无法获取页面内容: %w", err)}
		return
	}

	dc.Result <- DynamicCrawlerResult{RenderedHTML: html}
}

// Close 关闭浏览器和Playwright实例，释放资源。
func (dc *DynamicCrawler) Close() {
	if dc.browser != nil {
		dc.browser.Close()
	}
	if dc.pw != nil {
		dc.pw.Stop()
	}
}
