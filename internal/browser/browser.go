// Package browser 提供了与无头浏览器交互的服务。
package browser

import (
	"context"
	"time"

	"github.com/chromedp/chromedp"
)

// BrowserService 封装和管理一个无头Chrome浏览器实例。
type BrowserService struct {
	allocCtx context.Context
	cancel   context.CancelFunc
}

// Config 用于配置新的 BrowserService 实例。
type Config struct {
	Headless  bool
	Proxy     string
	UserAgent string
}

// NewBrowserService 初始化并启动一个新的无头浏览器服务。
// 它根据提供的配置来设置chromedp的执行分配器。
func NewBrowserService(cfg Config) (*BrowserService, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", cfg.Headless),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.UserAgent(cfg.UserAgent),
	)

	if cfg.Proxy != "" {
		opts = append(opts, chromedp.ProxyServer(cfg.Proxy))
	}

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)

	return &BrowserService{
		allocCtx: allocCtx,
		cancel:   cancel,
	}, nil
}

// CheckXSSFromHTML 在浏览器环境中渲染给定的HTML内容，并检查是否触发了XSS。
//
// 此函数的工作原理是：
// 1. 在一个空白页面(about:blank)的上下文中执行。
// 2. 使用 document.write 将传入的 htmlContent 写入页面。
// 3. 等待一小段时间，让HTML中可能包含的脚本执行。
// 4. 检查一个预定义的JavaScript全局变量 `window.__xss_was_triggered` 是否被设置为 true。
//
// 因此，用于测试的XSS payload必须包含将此变量设置为true的JavaScript代码，
// 例如: `<script>window.__xss_was_triggered = true;</script>`。
//
// 参数:
//
//	htmlContent (string): 包含潜在XSS payload的HTML字符串。
//
// 返回值:
//
//	(bool): 如果XSS被触发，则返回 true。
//	(error): 如果在执行过程中发生非超时的错误，则返回错误信息。
func (s *BrowserService) CheckXSSFromHTML(htmlContent string) (bool, error) {
	// 从总的分配器创建一个针对此任务的浏览器上下文。
	taskCtx, cancel := chromedp.NewContext(s.allocCtx)
	defer cancel()

	// 为此任务设置一个超时时间，以防止页面脚本无限期运行。
	taskCtx, cancel = context.WithTimeout(taskCtx, 15*time.Second)
	defer cancel()

	var triggered bool
	err := chromedp.Run(taskCtx,
		// 首先导航到一个空白页面，以建立一个干净的文档环境。
		chromedp.Navigate("about:blank"),
		// 使用JavaScript的document.write将我们的HTML内容动态写入页面。
		// 这里使用反引号 ` ` 来包围htmlContent，可以防止内容中的引号破坏字符串。
		chromedp.Evaluate(`document.write(`+"`"+htmlContent+"`"+`);`, nil),
		// 等待2秒，给予页面上可能存在的异步脚本足够的执行时间。
		chromedp.Sleep(2*time.Second),
		// 检查预定义的标志变量是否被设置为true。
		chromedp.Evaluate(`window.__xss_was_triggered === true`, &triggered),
	)

	// 如果错误是上下文超时，我们可以安全地忽略它。
	// 这通常意味着payload没有成功执行并设置标志，而不是一个程序错误。
	if err != nil && err != context.DeadlineExceeded {
		return false, err
	}

	return triggered, nil
}

// Close 会优雅地关闭浏览器服务和所有相关的浏览器进程。
func (s *BrowserService) Close() {
	s.cancel()
}
