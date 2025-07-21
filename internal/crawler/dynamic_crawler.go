// Package crawler provides functionality for web crawling, including static and dynamic content analysis.
package crawler

import (
	"context"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/rs/zerolog/log"
)

// DynamicCrawler uses a headless browser to crawl pages and extract content.
type DynamicCrawler struct {
	Timeout time.Duration
}

// NewDynamicCrawler creates a new DynamicCrawler.
func NewDynamicCrawler(timeout time.Duration) *DynamicCrawler {
	return &DynamicCrawler{
		Timeout: timeout,
	}
}

// Crawl navigates to the given URL and returns the rendered HTML.
func (d *DynamicCrawler) Crawl(ctx context.Context, url string) (string, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	)

	allocCtx, cancel := chromedp.NewExecAllocator(ctx, opts...)
	defer cancel()

	taskCtx, cancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(log.Printf))
	defer cancel()

	var htmlContent string
	err := chromedp.Run(taskCtx,
		chromedp.Navigate(url),
		chromedp.Sleep(2*time.Second), // Wait for JS to render
		chromedp.OuterHTML("html", &htmlContent),
	)

	if err != nil {
		return "", err
	}

	return htmlContent, nil
} 