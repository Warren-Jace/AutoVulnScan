package browser

import (
	"context"
	"time"

	"github.com/chromedp/chromedp"
)

// BrowserService manages a headless Chrome instance for rendering pages.
type BrowserService struct {
	allocCtx context.Context
	cancel   context.CancelFunc
}

// NewBrowserService initializes and starts a new headless browser service.
func NewBrowserService() (*BrowserService, error) {
	// Create a new chrome instance
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), chromedp.DefaultExecAllocatorOptions[:]...)

	return &BrowserService{
		allocCtx: allocCtx,
		cancel:   cancel,
	}, nil
}

// CheckXSSFromHTML renders the given HTML and checks if a dialog function was called.
func (s *BrowserService) CheckXSSFromHTML(htmlContent string) (bool, error) {
	// Create a new browser context from the allocator.
	taskCtx, cancel := chromedp.NewContext(s.allocCtx)
	defer cancel()

	// Add a timeout to the context
	taskCtx, cancel = context.WithTimeout(taskCtx, 15*time.Second)
	defer cancel()

	var triggered bool
	err := chromedp.Run(taskCtx,
		// Navigate to a blank page first to establish a context
		chromedp.Navigate("about:blank"),
		// Use Evaluate to write our HTML content to the blank page.
		chromedp.Evaluate(`document.write(`+"`"+htmlContent+"`"+`);`, nil),
		// Wait a bit for any scripts to execute.
		chromedp.Sleep(2*time.Second),
		// Check the value of our flag.
		chromedp.Evaluate(`window.__xss_was_triggered === true`, &triggered),
	)

	// We can ignore a context deadline exceeded error, as it simply means the flag was not set in time.
	if err != nil && err != context.DeadlineExceeded {
		return false, err
	}

	return triggered, nil
}

// Close gracefully shuts down the browser service.
func (s *BrowserService) Close() {
	s.cancel()
} 