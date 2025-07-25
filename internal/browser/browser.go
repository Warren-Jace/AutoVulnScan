// Package browser 封装了与无头浏览器（如Chrome）的交互。
// 它提供了一个服务，可以用于执行需要JavaScript渲染或模拟用户交互的任务，
// 例如，验证反射型XSS漏洞是否真的可以在DOM中执行。
package browser

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/playwright-community/playwright-go"
	"github.com/rs/zerolog/log"
)

// BrowserService 管理浏览器实例、上下文和页面的生命周期。
// 它可以被多个并发任务共享，以提高性能和资源利用率。
type BrowserService struct {
	pw      *playwright.Playwright
	browser playwright.Browser
	config  Config
	mu      sync.Mutex // 保护对浏览器实例的并发访问
}

// Config 用于配置BrowserService的行为。
type Config struct {
	Headless  bool   // Headless 控制浏览器是否在无头模式下运行。
	Proxy     string // Proxy 指定浏览器使用的代理服务器。
	UserAgent string // UserAgent 设置浏览器的User-Agent字符串。
}

// NewBrowserService 创建并初始化一个新的BrowserService实例。
// 它会启动Playwright，并根据提供的配置启动一个浏览器实例。
func NewBrowserService(cfg Config) (*BrowserService, error) {
	// 启动 Playwright
	pw, err := playwright.Run()
	if err != nil {
		return nil, fmt.Errorf("无法启动Playwright: %w", err)
	}

	// 配置浏览器启动选项
	browserOptions := playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(cfg.Headless),
	}
	if cfg.Proxy != "" {
		browserOptions.Proxy = &playwright.Proxy{Server: cfg.Proxy}
	}

	// 启动浏览器实例 (这里使用Chromium，也可以选择Firefox或WebKit)
	browser, err := pw.Chromium.Launch(browserOptions)
	if err != nil {
		return nil, fmt.Errorf("无法启动浏览器: %w", err)
	}

	return &BrowserService{
		pw:      pw,
		browser: browser,
		config:  cfg,
	}, nil
}

// VerifyXSS 通过在浏览器中加载一个URL并检查特定的payload是否被执行，来验证XSS漏洞。
//
// 参数:
//
//	ctx (context.Context): 用于控制验证过程的生命周期 (例如, 设置超时)。
//	targetURL (string): 包含潜在XSS payload的URL。
//	payload (string): 预期在页面上执行的payload。
//
// 返回:
//
//	(bool, error): 如果payload被成功检测到，则返回true；否则返回false和可能的错误。
func (s *BrowserService) VerifyXSS(ctx context.Context, targetURL, payload string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 创建一个新的浏览器上下文
	contextOptions := playwright.BrowserNewContextOptions{}
	if s.config.UserAgent != "" {
		contextOptions.UserAgent = playwright.String(s.config.UserAgent)
	}
	browserContext, err := s.browser.NewContext(contextOptions)
	if err != nil {
		return false, fmt.Errorf("创建浏览器上下文失败: %w", err)
	}
	defer browserContext.Close()

	// 在上下文中创建一个新页面
	page, err := browserContext.NewPage()
	if err != nil {
		return false, fmt.Errorf("创建页面失败: %w", err)
	}
	defer page.Close()

	var alertTriggered bool
	var wg sync.WaitGroup
	wg.Add(1)

	// 设置一个对话框监听器，用于捕获由XSS payload触发的 `alert()` 对话框。
	// 这是验证XSS是否成功执行的常用方法。
	var handler func(playwright.Dialog)
	handler = func(dialog playwright.Dialog) {
		defer wg.Done()
		log.Debug().
			Str("type", dialog.Type()).
			Str("message", dialog.Message()).
			Msg("检测到对话框")

		// 检查对话框的消息是否与我们的payload匹配。
		// 在实际场景中，payload可能会被编码或修改，所以需要更健壮的检查。
		if strings.Contains(dialog.Message(), payload) {
			alertTriggered = true
		}
		dialog.Dismiss() // 关闭对话框以允许页面继续处理
		page.RemoveListener("dialog", handler)
	}
	page.On("dialog", handler)

	// 导航到目标URL
	_, err = page.Goto(targetURL)
	if err != nil {
		// 如果导航失败，也需要确保WaitGroup不会死锁
		wg.Done()
		return false, fmt.Errorf("导航到URL失败: %w", err)
	}

	// 等待对话框事件处理完成，或直到超时
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()

	select {
	case <-c:
		// WaitGroup完成，检查alert是否被触发
		return alertTriggered, nil
	case <-ctx.Done():
		// 上下文超时或被取消
		return false, fmt.Errorf("XSS验证超时或被取消: %w", ctx.Err())
	case <-time.After(10 * time.Second): // 添加一个额外的安全超时
		return false, fmt.Errorf("XSS验证超时")
	}
}

// Close 关闭浏览器实例并停止Playwright。
// 这是一个重要的清理步骤，以确保所有浏览器进程都被正确终止。
func (s *BrowserService) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.browser != nil {
		if err := s.browser.Close(); err != nil {
			log.Error().Err(err).Msg("关闭浏览器失败")
			// 即使关闭浏览器失败，我们仍然尝试停止Playwright
		}
	}
	if s.pw != nil {
		if err := s.pw.Stop(); err != nil {
			return fmt.Errorf("停止Playwright失败: %w", err)
		}
	}
	return nil
}
