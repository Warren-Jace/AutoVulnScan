// Package crawler 提供网络爬取功能，包括静态和动态内容分析
package crawler

import (
	"context"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/rs/zerolog/log"
)

// DynamicCrawler 使用无头浏览器爬取页面并提取内容
type DynamicCrawler struct {
	Timeout time.Duration // 页面加载超时时间
}

// NewDynamicCrawler 创建新的动态爬虫实例
func NewDynamicCrawler(timeout time.Duration) *DynamicCrawler {
	return &DynamicCrawler{
		Timeout: timeout,
	}
}

// Crawl navigates to the given URL and returns the rendered HTML.
func (d *DynamicCrawler) Crawl(ctx context.Context, url string) (string, error) {
	// 配置Chrome浏览器启动选项
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),           // 无头模式
		chromedp.Flag("disable-gpu", true),        // 禁用GPU加速
		chromedp.Flag("no-sandbox", true),         // 禁用沙盒模式（Docker环境需要）
		chromedp.Flag("disable-dev-shm-usage", true), // 禁用/dev/shm使用
	)

	// 创建Chrome执行器上下文
	allocCtx, cancel := chromedp.NewExecAllocator(ctx, opts...)
	defer cancel()

	// 创建浏览器任务上下文，并设置日志输出
	taskCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	var htmlContent string
	log.Debug().Str("url", url).Msg("Dynamic crawler: navigating to page")
	log.Debug().Bool("headless", true).Dur("timeout", d.Timeout).Msg("Dynamic crawler: browser options")
	err := chromedp.Run(taskCtx,
		chromedp.Navigate(url),
		chromedp.ActionFunc(func(ctx context.Context) error {
			log.Debug().Str("url", url).Dur("duration", d.Timeout).Msg("Dynamic crawler: waiting for JS rendering")
			return nil
		}),
		chromedp.Sleep(2*time.Second), // Wait for JS to render
		chromedp.ActionFunc(func(ctx context.Context) error {
			log.Debug().Str("url", url).Msg("Dynamic crawler: extracting HTML content")
			return nil
		}),
		chromedp.OuterHTML("html", &htmlContent),
	)

	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Dynamic crawler: failed to execute tasks")
		return "", err
	}

	log.Debug().Str("url", url).Int("content_length", len(htmlContent)).Msg("Dynamic crawler: finished successfully")
	return htmlContent, nil
}
