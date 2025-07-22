// Package crawler 提供网络爬取功能，包括静态和动态内容分析
// 本包主要用于处理需要JavaScript渲染的动态网页内容
package crawler

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/rs/zerolog/log"
)

// DynamicCrawler 使用无头浏览器爬取页面并提取内容
// 适用于需要JavaScript执行后才能获取完整内容的动态网页
type DynamicCrawler struct {
	Timeout time.Duration // 页面加载超时时间，防止页面加载过久导致程序阻塞
}

// NewDynamicCrawler 创建新的动态爬虫实例
// 参数:
//
//	timeout: 页面加载的最大等待时间，建议设置为30秒到2分钟
//
// 返回:
//
//	*DynamicCrawler: 配置好的爬虫实例
func NewDynamicCrawler(timeout time.Duration) *DynamicCrawler {
	return &DynamicCrawler{
		Timeout: timeout,
	}
}

// getRandomUserAgent 返回随机的User-Agent字符串，模拟不同的浏览器
func getRandomUserAgent() string {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
	}
	return userAgents[rand.Intn(len(userAgents))]
}

// getRandomViewport 返回随机的视窗大小，模拟不同的屏幕分辨率
func getRandomViewport() (int, int) {
	viewports := [][2]int{
		{1920, 1080}, {1366, 768}, {1536, 864}, {1440, 900},
		{1280, 720}, {1600, 900}, {1024, 768}, {1280, 1024},
	}
	viewport := viewports[rand.Intn(len(viewports))]
	return viewport[0], viewport[1]
}

// Crawl 导航到指定URL并返回渲染后的HTML内容
// 该方法会启动一个无头Chrome浏览器实例，加载页面并等待JavaScript执行完成
// 参数:
//
//	ctx: 上下文对象，用于控制请求的生命周期和取消操作
//	url: 要爬取的目标网页URL
//
// 返回:
//
//	string: 完整渲染后的HTML内容
//	error: 如果爬取过程中出现错误则返回错误信息
func (d *DynamicCrawler) Crawl(ctx context.Context, url string) (string, error) {
	// 获取随机User-Agent和视窗大小
	userAgent := getRandomUserAgent()
	width, height := getRandomViewport()

	// 配置Chrome浏览器启动选项 - 增强反检测能力
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		// 基础无头模式配置
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),

		// 反检测配置
		chromedp.UserAgent(userAgent),                                   // 随机User-Agent
		chromedp.WindowSize(width, height),                              // 随机窗口大小
		chromedp.Flag("disable-blink-features", "AutomationControlled"), // 隐藏自动化标识
		chromedp.Flag("exclude-switches", "enable-automation"),          // 排除自动化开关
		chromedp.Flag("disable-extensions", true),                       // 禁用扩展
		chromedp.Flag("disable-plugins", true),                          // 禁用插件
		chromedp.Flag("disable-images", false),                          // 允许图片加载（更像真实浏览器）
		chromedp.Flag("disable-javascript", false),                      // 确保JavaScript启用

		// 性能和稳定性配置
		chromedp.Flag("disable-background-timer-throttling", true),                // 禁用后台定时器限制
		chromedp.Flag("disable-backgrounding-occluded-windows", true),             // 禁用后台窗口遮挡
		chromedp.Flag("disable-renderer-backgrounding", true),                     // 禁用渲染器后台化
		chromedp.Flag("disable-features", "TranslateUI,BlinkGenPropertyTrees"),    // 禁用翻译UI等功能
		chromedp.Flag("disable-component-extensions-with-background-pages", true), // 禁用后台扩展

		// 网络配置
		chromedp.Flag("aggressive-cache-discard", true),      // 积极丢弃缓存
		chromedp.Flag("disable-background-networking", true), // 禁用后台网络

		// 内存管理
		chromedp.Flag("memory-pressure-off", true),  // 关闭内存压力检测
		chromedp.Flag("max_old_space_size", "4096"), // 增加V8内存限制
	)

	// 创建Chrome执行器上下文
	allocCtx, cancel := chromedp.NewExecAllocator(ctx, opts...)
	defer cancel()

	// 创建浏览器任务上下文，并设置超时
	taskCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// 设置整体操作超时
	timeoutCtx, timeoutCancel := context.WithTimeout(taskCtx, d.Timeout)
	defer timeoutCancel()

	var htmlContent string

	log.Debug().
		Str("url", url).
		Str("user_agent", userAgent).
		Int("width", width).
		Int("height", height).
		Msg("Dynamic crawler: starting crawl with random fingerprint")

	// 执行浏览器操作序列 - 增加更多反检测措施
	err := chromedp.Run(timeoutCtx,
		// 1. 设置额外的反检测JavaScript
		chromedp.ActionFunc(func(ctx context.Context) error {
			log.Debug().Str("url", url).Msg("Dynamic crawler: setting up anti-detection")
			return nil
		}),

		// 2. 注入反检测脚本
		chromedp.Evaluate(`
			// 隐藏webdriver属性
			Object.defineProperty(navigator, 'webdriver', {
				get: () => undefined,
			});
			
			// 修改plugins长度
			Object.defineProperty(navigator, 'plugins', {
				get: () => [1, 2, 3, 4, 5],
			});
			
			// 修改languages
			Object.defineProperty(navigator, 'languages', {
				get: () => ['en-US', 'en'],
			});
			
			// 隐藏Chrome自动化相关属性
			window.chrome = {
				runtime: {},
			};
			
			// 修改权限查询结果
			if (window.navigator.permissions && window.navigator.permissions.query) {
				const originalQuery = window.navigator.permissions.query;
				window.navigator.permissions.query = (parameters) => (
					parameters.name === 'notifications' ?
						Promise.resolve({ state: Notification.permission }) :
						originalQuery(parameters)
				);
			}
		`, nil),

		// 3. 导航到目标URL
		chromedp.Navigate(url),

		// 4. 等待页面基础加载完成
		chromedp.WaitReady("body", chromedp.ByQuery),

		// 5. 模拟人类行为 - 随机滚动
		chromedp.ActionFunc(func(ctx context.Context) error {
			log.Debug().Str("url", url).Msg("Dynamic crawler: simulating human behavior")
			return nil
		}),

		// 6. 随机滚动页面
		chromedp.Evaluate(`
			window.scrollTo(0, Math.floor(Math.random() * 500));
		`, nil),

		// 7. 等待JavaScript渲染 - 使用随机等待时间
		chromedp.ActionFunc(func(ctx context.Context) error {
			// 随机等待时间：2-5秒
			waitTime := time.Duration(2000+rand.Intn(3000)) * time.Millisecond
			log.Debug().
				Str("url", url).
				Dur("wait_time", waitTime).
				Msg("Dynamic crawler: waiting for JS rendering")
			time.Sleep(waitTime)
			return nil
		}),

		// 8. 检查页面是否完全加载 - 修复后的版本
		chromedp.ActionFunc(func(ctx context.Context) error {
			var readyState string
			err := chromedp.Evaluate(`document.readyState`, &readyState).Do(ctx)
			if err != nil {
				log.Warn().Err(err).Str("url", url).Msg("Failed to check document ready state")
				return nil // 不阻断流程，继续执行
			}

			// 如果页面还没完全加载，等待一下
			if readyState != "complete" {
				log.Debug().
					Str("url", url).
					Str("ready_state", readyState).
					Msg("Document not fully loaded, waiting...")
				time.Sleep(1 * time.Second)
			}
			return nil
		}),

		// 9. 等待所有异步资源加载完成
		chromedp.ActionFunc(func(ctx context.Context) error {
			// 等待网络空闲（没有正在进行的请求）
			var networkIdle bool
			for i := 0; i < 10; i++ { // 最多检查10次
				err := chromedp.Evaluate(`
					(function() {
						// 检查是否有正在进行的fetch请求或XMLHttpRequest
						return performance.getEntriesByType('navigation')[0].loadEventEnd > 0;
					})()
				`, &networkIdle).Do(ctx)

				if err != nil {
					log.Warn().Err(err).Msg("Failed to check network idle state")
					break
				}

				if networkIdle {
					break
				}

				time.Sleep(500 * time.Millisecond)
			}
			return nil
		}),

		// 10. 再次随机滚动
		chromedp.Evaluate(`
			window.scrollTo(0, Math.floor(Math.random() * 200));
		`, nil),

		// 11. 最终等待确保所有异步内容加载
		chromedp.Sleep(time.Duration(500+rand.Intn(1000))*time.Millisecond),

		// 12. 提取HTML内容
		chromedp.ActionFunc(func(ctx context.Context) error {
			log.Debug().Str("url", url).Msg("Dynamic crawler: extracting HTML content")
			return nil
		}),
		chromedp.OuterHTML("html", &htmlContent),
	)

	if err != nil {
		log.Error().
			Err(err).
			Str("url", url).
			Str("user_agent", userAgent).
			Msg("Dynamic crawler: failed to execute tasks")
		return "", fmt.Errorf("crawl failed for %s: %w", url, err)
	}

	log.Debug().
		Str("url", url).
		Int("content_length", len(htmlContent)).
		Str("user_agent", userAgent).
		Msg("Dynamic crawler: finished successfully")

	return htmlContent, nil
}

// 使用示例：
// crawler := NewDynamicCrawler(60 * time.Second)
// html, err := crawler.Crawl(context.Background(), "https://example.com")
// if err != nil {
//     log.Fatal().Err(err).Msg("爬取失败")
// }
// fmt.Println("获取到的HTML长度:", len(html))
