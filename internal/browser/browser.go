// Package browser 封装了与无头浏览器（如Chrome）的交互。
// 它提供了一个服务，可以用于执行需要JavaScript渲染或模拟用户交互的任务，
// 例如，验证反射型XSS漏洞是否真的可以在DOM中执行。
package browser

import (
	"context"
	"errors"
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
//	ctx (context.Context): 用于控制验证过程的生命周期 (例如, 设置超时)。
//	targetURL (string): 包含潜在XSS payload的URL。
//	payload (string): 预期在页面上执行的payload。
//
// 返回:
//	(bool, error): 如果payload被成功检测到，则返回true；否则返回false和可能的错误。
func (s *BrowserService) VerifyXSS(ctx context.Context, targetURL, payload string) (bool, error) {
	// 参数验证
	if err := s.validateInputs(targetURL, payload); err != nil {
		return false, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// 创建浏览器上下文
	browserContext, err := s.createBrowserContext()
	if err != nil {
		return false, fmt.Errorf("创建浏览器上下文失败: %w", err)
	}
	defer s.closeBrowserContext(browserContext)

	// 创建页面
	page, err := browserContext.NewPage()
	if err != nil {
		return false, fmt.Errorf("创建页面失败: %w", err)
	}
	defer s.closePage(page)

	// 设置对话框监听器并执行XSS检测
	return s.executeXSSDetection(ctx, page, targetURL, payload)
}

// validateInputs 验证输入参数
func (s *BrowserService) validateInputs(targetURL, payload string) error {
	if strings.TrimSpace(targetURL) == "" {
		return fmt.Errorf("目标URL不能为空")
	}
	if strings.TrimSpace(payload) == "" {
		return fmt.Errorf("payload不能为空")
	}
	return nil
}

// createBrowserContext 创建并配置浏览器上下文
func (s *BrowserService) createBrowserContext() (playwright.BrowserContext, error) {
	contextOptions := playwright.BrowserNewContextOptions{}
	if s.config.UserAgent != "" {
		contextOptions.UserAgent = playwright.String(s.config.UserAgent)
	}
	
	return s.browser.NewContext(contextOptions)
}

// closeBrowserContext 安全关闭浏览器上下文
func (s *BrowserService) closeBrowserContext(browserContext playwright.BrowserContext) {
	if browserContext != nil {
		if err := browserContext.Close(); err != nil {
			log.Warn().Err(err).Msg("关闭浏览器上下文失败")
		}
	}
}

// closePage 安全关闭页面
func (s *BrowserService) closePage(page playwright.Page) {
	if page != nil {
		if err := page.Close(); err != nil {
			log.Warn().Err(err).Msg("关闭页面失败")
		}
	}
}

// executeXSSDetection 执行XSS检测逻辑
func (s *BrowserService) executeXSSDetection(ctx context.Context, page playwright.Page, targetURL, payload string) (bool, error) {
	// 创建检测器
	detector := newXSSDetector(payload)
	
	// 设置对话框监听器
	detector.setupDialogHandler(page)
	defer detector.cleanup(page)

	// 导航到目标URL
	if err := s.navigateToURL(page, targetURL); err != nil {
		return false, err
	}

	// 等待对话框事件或超时
	return detector.waitForResult(ctx)
}

// navigateToURL 导航到指定URL
func (s *BrowserService) navigateToURL(page playwright.Page, targetURL string) error {
	if _, err := page.Goto(targetURL); err != nil {
		return fmt.Errorf("导航到URL失败: %w", err)
	}
	return nil
}

// xssDetector XSS检测器结构体
type xssDetector struct {
	payload       string
	alertChan     chan bool
	handlerFunc   func(playwright.Dialog)
	handlerMu     sync.Mutex
	handlerActive bool
}

// newXSSDetector 创建新的XSS检测器
func newXSSDetector(payload string) *xssDetector {
	detector := &xssDetector{
		payload:       payload,
		alertChan:     make(chan bool, 1),
		handlerActive: false,
	}
	
	// 创建对话框处理函数
	detector.handlerFunc = detector.createDialogHandler()
	
	return detector
}

// createDialogHandler 创建对话框处理函数
func (d *xssDetector) createDialogHandler() func(playwright.Dialog) {
	return func(dialog playwright.Dialog) {
		defer func() {
			if err := dialog.Dismiss(); err != nil {
				log.Warn().Err(err).Msg("关闭对话框失败")
			}
		}()

		log.Debug().
			Str("type", dialog.Type()).
			Str("message", dialog.Message()).
			Msg("检测到对话框")

		// 检查对话框消息是否包含payload
		if d.isPayloadDetected(dialog.Message()) {
			select {
			case d.alertChan <- true:
			default:
				// channel已满，忽略重复事件
			}
		}
	}
}

// setupDialogHandler 设置对话框监听器
func (d *xssDetector) setupDialogHandler(page playwright.Page) {
	d.handlerMu.Lock()
	defer d.handlerMu.Unlock()
	
	if !d.handlerActive {
		page.On("dialog", d.handlerFunc)
		d.handlerActive = true
	}
}

// cleanup 清理资源
func (d *xssDetector) cleanup(page playwright.Page) {
	d.handlerMu.Lock()
	defer d.handlerMu.Unlock()
	
	if d.handlerActive {
		page.RemoveListener("dialog", d.handlerFunc)
		d.handlerActive = false
	}
	
	// 关闭channel
	close(d.alertChan)
}

// isPayloadDetected 检查对话框消息是否包含预期的payload
func (d *xssDetector) isPayloadDetected(dialogMessage string) bool {
	// 支持更灵活的payload匹配
	// 可以根据需要扩展匹配逻辑，例如处理编码、大小写等
	return strings.Contains(strings.ToLower(dialogMessage), strings.ToLower(d.payload))
}

// waitForResult 等待XSS检测结果
func (d *xssDetector) waitForResult(ctx context.Context) (bool, error) {
	// 创建一个带有默认超时的上下文
	const defaultTimeout = 10 * time.Second
	timeoutCtx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	select {
	case alertTriggered, ok := <-d.alertChan:
		if !ok {
			return false, fmt.Errorf("检测器已关闭")
		}
		return alertTriggered, nil
	case <-timeoutCtx.Done():
		if errors.Is(timeoutCtx.Err(), context.DeadlineExceeded) {
			return false, fmt.Errorf("XSS验证超时")
		}
		return false, fmt.Errorf("XSS验证被取消: %w", timeoutCtx.Err())
	}
}

// Close 关闭浏览器实例并停止Playwright。
// 这是一个重要的清理步骤，以确保所有浏览器进程都被正确终止。
func (s *BrowserService) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var errs []error

	if s.browser != nil {
		if err := s.browser.Close(); err != nil {
			errs = append(errs, fmt.Errorf("关闭浏览器失败: %w", err))
			log.Error().Err(err).Msg("关闭浏览器失败")
		}
	}

	if s.pw != nil {
		if err := s.pw.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("停止Playwright失败: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("关闭过程中发生错误: %v", errs)
	}

	return nil
}