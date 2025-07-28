package cmd

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"autovulnscan/internal/config"
	"autovulnscan/internal/core"
	"autovulnscan/internal/logger"
	"autovulnscan/internal/output"
	"autovulnscan/internal/utils"

	"github.com/spf13/cobra"
)

// SpiderOptions 爬虫扫描选项
type SpiderOptions struct {
	// 输入选项
	URL      string   `json:"url"`
	File     string   `json:"file"`
	URLs     []string `json:"urls"`
	
	// 爬虫配置
	Depth       int           `json:"depth"`
	MaxPages    int           `json:"max_pages"`
	Timeout     time.Duration `json:"timeout"`
	Delay       time.Duration `json:"delay"`
	UserAgent   string        `json:"user_agent"`
	Headers     []string      `json:"headers"`
	Cookies     []string      `json:"cookies"`
	
	// 并发控制
	Workers     int `json:"workers"`
	RateLimit   int `json:"rate_limit"`
	
	// 过滤选项
	IncludePatterns []string `json:"include_patterns"`
	ExcludePatterns []string `json:"exclude_patterns"`
	AllowedDomains  []string `json:"allowed_domains"`
	BlockedDomains  []string `json:"blocked_domains"`
	
	// 输出选项
	OutputDir    string   `json:"output_dir"`
	OutputFormat []string `json:"output_format"`
	Verbose      bool     `json:"verbose"`
	Silent       bool     `json:"silent"`
	
	// 高级选项
	JavaScript    bool     `json:"javascript"`
	Screenshots   bool     `json:"screenshots"`
	SaveResponses bool     `json:"save_responses"`
	FollowRedirects bool   `json:"follow_redirects"`
	IgnoreSSL     bool     `json:"ignore_ssl"`
	Proxy         string   `json:"proxy"`
	
	// 扫描选项
	EnableVulnScan bool     `json:"enable_vuln_scan"`
	ScanModules    []string `json:"scan_modules"`
	
	// 内部状态
	compiledIncludePatterns []*regexp.Regexp
	compiledExcludePatterns []*regexp.Regexp
}

// SpiderStats 爬虫统计信息
type SpiderStats struct {
	StartTime       time.Time `json:"start_time"`
	EndTime         time.Time `json:"end_time"`
	TotalURLs       int       `json:"total_urls"`
	ProcessedURLs   int       `json:"processed_urls"`
	SuccessfulURLs  int       `json:"successful_urls"`
	FailedURLs      int       `json:"failed_urls"`
	UniquePages     int       `json:"unique_pages"`
	TotalRequests   int       `json:"total_requests"`
	TotalBytes      int64     `json:"total_bytes"`
	VulnsFound      int       `json:"vulns_found"`
	Errors          []string  `json:"errors"`
}

// SpiderResult 单个URL的扫描结果
type SpiderResult struct {
	URL           string                 `json:"url"`
	Status        string                 `json:"status"`
	StatusCode    int                    `json:"status_code"`
	ContentLength int64                  `json:"content_length"`
	ResponseTime  time.Duration          `json:"response_time"`
	Title         string                 `json:"title"`
	Technologies  []string               `json:"technologies"`
	Links         []string               `json:"links"`
	Forms         []map[string]interface{} `json:"forms"`
	Vulnerabilities []map[string]interface{} `json:"vulnerabilities"`
	Error         string                 `json:"error,omitempty"`
	Timestamp     time.Time              `json:"timestamp"`
}

// SpiderManager 爬虫管理器
type SpiderManager struct {
	options   *SpiderOptions
	config    *config.Config
	stats     *SpiderStats
	results   []*SpiderResult
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
	semaphore chan struct{}
	reporter  *output.Reporter
}

// NewSpiderManager 创建新的爬虫管理器
func NewSpiderManager(options *SpiderOptions, cfg *config.Config) *SpiderManager {
	ctx, cancel := context.WithCancel(GetGlobalContext())
	
	return &SpiderManager{
		options:   options,
		config:    cfg,
		stats:     &SpiderStats{StartTime: time.Now()},
		results:   make([]*SpiderResult, 0),
		ctx:       ctx,
		cancel:    cancel,
		semaphore: make(chan struct{}, options.Workers),
	}
}

// spiderCmd 实现了 'spider' 子命令
var spiderCmd = &cobra.Command{
	Use:   "spider",
	Short: "智能网站爬虫和漏洞扫描工具",
	Long: `Spider - 智能网站爬虫和漏洞扫描工具

此命令会智能爬取指定的网站，发现所有可访问的端点，并可选择性地对这些端点进行安全漏洞检查。

特性：
  • 深度可控的网站爬取
  • JavaScript 渲染支持
  • 智能去重和过滤
  • 并发控制和速率限制
  • 多种输出格式
  • 集成漏洞扫描

示例：
  # 爬取单个网站
  autovulnscan spider -u https://example.com

  # 从文件批量爬取
  autovulnscan spider -f urls.txt

  # 深度爬取并启用漏洞扫描
  autovulnscan spider -u https://example.com -d 3 --vuln-scan

  # 自定义并发和延迟
  autovulnscan spider -u https://example.com -w 20 --delay 1s`,
	RunE: runSpiderCommand,
}

// runSpiderCommand 执行爬虫命令
func runSpiderCommand(cmd *cobra.Command, args []string) error {
	// 解析命令行参数
	options, err := parseSpiderFlags(cmd)
	if err != nil {
		return fmt.Errorf("解析命令参数失败: %w", err)
	}
	
	// 验证参数
	if err := validateSpiderOptions(options); err != nil {
		return fmt.Errorf("参数验证失败: %w", err)
	}
	
	// 收集目标URL
	urls, err := collectTargetURLs(options)
	if err != nil {
		return fmt.Errorf("收集目标URL失败: %w", err)
	}
	
	if len(urls) == 0 {
		return fmt.Errorf("没有找到有效的目标URL")
	}
	
	options.URLs = urls
	
	// 创建爬虫管理器
	manager := NewSpiderManager(options, GetGlobalConfig())
	
	// 初始化报告器
	if err := manager.initReporter(); err != nil {
		return fmt.Errorf("初始化报告器失败: %w", err)
	}
	defer manager.cleanup()
	
	// 开始爬取
	logger.Info("开始爬虫扫描",
		"total_urls", len(urls),
		"workers", options.Workers,
		"depth", options.Depth,
		"max_pages", options.MaxPages,
	)
	
	if err := manager.Start(); err != nil {
		return fmt.Errorf("爬虫扫描失败: %w", err)
	}
	
	// 生成报告
	if err := manager.generateReport(); err != nil {
		logger.Error("生成报告失败", "error", err)
	}
	
	// 打印统计信息
	manager.printStats()
	
	return nil
}

// parseSpiderFlags 解析命令行标志
func parseSpiderFlags(cmd *cobra.Command) (*SpiderOptions, error) {
	options := &SpiderOptions{}
	
	// 基本选项
	options.URL, _ = cmd.Flags().GetString("url")
	options.File, _ = cmd.Flags().GetString("file")
	options.OutputDir, _ = cmd.Flags().GetString("output-dir")
	options.Verbose, _ = cmd.Flags().GetBool("verbose")
	options.Silent, _ = cmd.Flags().GetBool("silent")
	
	// 爬虫配置
	options.Depth, _ = cmd.Flags().GetInt("depth")
	options.MaxPages, _ = cmd.Flags().GetInt("max-pages")
	options.Workers, _ = cmd.Flags().GetInt("workers")
	options.RateLimit, _ = cmd.Flags().GetInt("rate-limit")
	options.UserAgent, _ = cmd.Flags().GetString("user-agent")
	options.Proxy, _ = cmd.Flags().GetString("proxy")
	
	// 解析超时和延迟
	if timeoutStr, _ := cmd.Flags().GetString("timeout"); timeoutStr != "" {
		if timeout, err := time.ParseDuration(timeoutStr); err == nil {
			options.Timeout = timeout
		}
	}
	
	if delayStr, _ := cmd.Flags().GetString("delay"); delayStr != "" {
		if delay, err := time.ParseDuration(delayStr); err == nil {
			options.Delay = delay
		}
	}
	
	// 解析数组选项
	options.Headers, _ = cmd.Flags().GetStringSlice("headers")
	options.Cookies, _ = cmd.Flags().GetStringSlice("cookies")
	options.IncludePatterns, _ = cmd.Flags().GetStringSlice("include")
	options.ExcludePatterns, _ = cmd.Flags().GetStringSlice("exclude")
	options.AllowedDomains, _ = cmd.Flags().GetStringSlice("allowed-domains")
	options.BlockedDomains, _ = cmd.Flags().GetStringSlice("blocked-domains")
	options.OutputFormat, _ = cmd.Flags().GetStringSlice("format")
	options.ScanModules, _ = cmd.Flags().GetStringSlice("scan-modules")
	
	// 布尔选项
	options.JavaScript, _ = cmd.Flags().GetBool("javascript")
	options.Screenshots, _ = cmd.Flags().GetBool("screenshots")
	options.SaveResponses, _ = cmd.Flags().GetBool("save-responses")
	options.FollowRedirects, _ = cmd.Flags().GetBool("follow-redirects")
	options.IgnoreSSL, _ = cmd.Flags().GetBool("ignore-ssl")
	options.EnableVulnScan, _ = cmd.Flags().GetBool("vuln-scan")
	
	// 设置默认值
	setDefaultSpiderOptions(options)
	
	// 编译正则表达式
	if err := compilePatterns(options); err != nil {
		return nil, fmt.Errorf("编译正则表达式失败: %w", err)
	}
	
	return options, nil
}

// setDefaultSpiderOptions 设置默认选项
func setDefaultSpiderOptions(options *SpiderOptions) {
	if options.Depth == 0 {
		options.Depth = 3
	}
	if options.MaxPages == 0 {
		options.MaxPages = 1000
	}
	if options.Workers == 0 {
		options.Workers = 10
	}
	if options.Timeout == 0 {
		options.Timeout = 30 * time.Second
	}
	if options.Delay == 0 {
		options.Delay = 100 * time.Millisecond
	}
	if options.UserAgent == "" {
		options.UserAgent = "AutoVulnScan/1.0 (Spider)"
	}
	if len(options.OutputFormat) == 0 {
		options.OutputFormat = []string{"json", "html"}
	}
	if options.RateLimit == 0 {
		options.RateLimit = 50 // 每秒最多50个请求
	}
}

// validateSpiderOptions 验证爬虫选项
func validateSpiderOptions(options *SpiderOptions) error {
	// 检查输入源
	if options.URL == "" && options.File == "" {
		return fmt.Errorf("请使用 -u <url> 或 -f <file> 指定目标")
	}
	
	// 检查互斥选项
	if options.Verbose && options.Silent {
		return fmt.Errorf("--verbose 和 --silent 不能同时使用")
	}
	
	// 验证数值范围
	if options.Depth < 0 || options.Depth > 10 {
		return fmt.Errorf("爬取深度必须在 0-10 之间")
	}
	
	if options.MaxPages < 1 || options.MaxPages > 100000 {
		return fmt.Errorf("最大页面数必须在 1-100000 之间")
	}
	
	if options.Workers < 1 || options.Workers > 100 {
		return fmt.Errorf("工作线程数必须在 1-100 之间")
	}
	
	if options.RateLimit < 1 || options.RateLimit > 1000 {
		return fmt.Errorf("速率限制必须在 1-1000 之间")
	}
	
	// 验证代理URL
	if options.Proxy != "" {
		if _, err := url.Parse(options.Proxy); err != nil {
			return fmt.Errorf("无效的代理URL: %w", err)
		}
	}
	
	// 验证输出格式
	validFormats := map[string]bool{
		"json": true, "xml": true, "html": true, "csv": true, "txt": true,
	}
	for _, format := range options.OutputFormat {
		if !validFormats[strings.ToLower(format)] {
			return fmt.Errorf("不支持的输出格式: %s", format)
		}
	}
	
	return nil
}

// compilePatterns 编译正则表达式模式
func compilePatterns(options *SpiderOptions) error {
	// 编译包含模式
	for _, pattern := range options.IncludePatterns {
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("编译包含模式失败 '%s': %w", pattern, err)
		}
		options.compiledIncludePatterns = append(options.compiledIncludePatterns, regex)
	}
	
	// 编译排除模式
	for _, pattern := range options.ExcludePatterns {
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("编译排除模式失败 '%s': %w", pattern, err)
		}
		options.compiledExcludePatterns = append(options.compiledExcludePatterns, regex)
	}
	
	return nil
}

// collectTargetURLs 收集目标URL
func collectTargetURLs(options *SpiderOptions) ([]string, error) {
	var urls []string
	
	// 从命令行URL添加
	if options.URL != "" {
		if err := validateURL(options.URL); err != nil {
			return nil, fmt.Errorf("无效的URL '%s': %w", options.URL, err)
		}
		urls = append(urls, options.URL)
	}
	
	// 从文件读取URL
	if options.File != "" {
		fileURLs, err := readURLsFromFile(options.File)
		if err != nil {
			return nil, fmt.Errorf("从文件读取URL失败: %w", err)
		}
		
		// 验证文件中的URL
		for _, u := range fileURLs {
			if err := validateURL(u); err != nil {
				logger.Warn("跳过无效URL", "url", u, "error", err)
				continue
			}
			urls = append(urls, u)
		}
	}
	
	// 去重
	urls = utils.UniqueStrings(urls)
	
	return urls, nil
}

// validateURL 验证URL格式
func validateURL(rawURL string) error {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("解析URL失败: %w", err)
	}
	
	if parsedURL.Scheme == "" {
		return fmt.Errorf("URL缺少协议")
	}
	
	if parsedURL.Host == "" {
		return fmt.Errorf("URL缺少主机")
	}
	
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("不支持的协议: %s", parsedURL.Scheme)
	}
	
	return nil
}

// readURLsFromFile 从文件读取URL列表
func readURLsFromFile(filename string) ([]string, error) {
	// 检查文件是否存在
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return nil, fmt.Errorf("文件不存在: %s", filename)
	}
	
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %w", err)
	}
	defer file.Close()
	
	var urls []string
	scanner := bufio.NewScanner(file)
	lineNum := 0
	
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		
		// 跳过空行和注释
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		urls = append(urls, line)
	}
	
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取文件时出错: %w", err)
	}
	
	if len(urls) == 0 {
		return nil, fmt.Errorf("文件中没有找到有效的URL")
	}
	
	logger.Info("从文件读取URL", "file", filename, "count", len(urls))
	return urls, nil
}

// Start 开始爬虫扫描
func (sm *SpiderManager) Start() error {
	sm.stats.StartTime = time.Now()
	sm.stats.TotalURLs = len(sm.options.URLs)
	
	// 创建工作池
	jobs := make(chan string, len(sm.options.URLs))
	var wg sync.WaitGroup
	
	// 启动工作协程
	for i := 0; i < sm.options.Workers; i++ {
		wg.Add(1)
		go sm.worker(&wg, jobs)
	}
	
	// 发送任务
	for _, targetURL := range sm.options.URLs {
		select {
		case jobs <- targetURL:
		case <-sm.ctx.Done():
			close(jobs)
			return fmt.Errorf("扫描被取消")
		}
	}
	close(jobs)
	
	// 等待所有工作完成
	wg.Wait()
	
	sm.stats.EndTime = time.Now()
	return nil
}

// worker 工作协程
func (sm *SpiderManager) worker(wg *sync.WaitGroup, jobs <-chan string) {
	defer wg.Done()
	
	for targetURL := range jobs {
		select {
		case <-sm.ctx.Done():
			return
		default:
			sm.processURL(targetURL)
			
			// 速率限制
			if sm.options.Delay > 0 {
				time.Sleep(sm.options.Delay)
			}
		}
	}
}

// processURL 处理单个URL
func (sm *SpiderManager) processURL(targetURL string) {
	result := &SpiderResult{
		URL:       targetURL,
		Timestamp: time.Now(),
	}
	
	defer func() {
		sm.mu.Lock()
		sm.results = append(sm.results, result)
		sm.stats.ProcessedURLs++
		sm.mu.Unlock()
		
		// 实时报告进度
		if !sm.options.Silent {
			logger.Info("处理URL",
				"url", targetURL,
				"status", result.Status,
				"progress", fmt.Sprintf("%d/%d", sm.stats.ProcessedURLs, sm.stats.TotalURLs),
			)
		}
	}()
	
	startTime := time.Now()
	
	// 创建编排器
	orchestrator, err := core.NewOrchestrator(sm.config, targetURL)
	if err != nil {
		result.Status = "error"
		result.Error = fmt.Sprintf("创建编排器失败: %v", err)
		sm.stats.FailedURLs++
		logger.Error("创建编排器失败", "url", targetURL, "error", err)
		return
	}
	
	// 配置编排器
	sm.configureOrchestrator(orchestrator)
	
	// 执行扫描
	scanResult, err := orchestrator.Scan(sm.ctx)
	if err != nil {
		result.Status = "error"
		result.Error = fmt.Sprintf("扫描失败: %v", err)
		sm.stats.FailedURLs++
		logger.Error("扫描失败", "url", targetURL, "error", err)
		return
	}
	
	// 处理扫描结果
	result.Status = "success"
	result.StatusCode = scanResult.StatusCode
	result.ContentLength = scanResult.ContentLength
	result.ResponseTime = time.Since(startTime)
	result.Title = scanResult.Title
	result.Technologies = scanResult.Technologies
	result.Links = scanResult.Links
	result.Forms = scanResult.Forms
	
	// 漏洞扫描结果
	if sm.options.EnableVulnScan {
		result.Vulnerabilities = scanResult.Vulnerabilities
		sm.stats.VulnsFound += len(scanResult.Vulnerabilities)
	}
	
	sm.stats.SuccessfulURLs++
	sm.stats.TotalBytes += result.ContentLength
	sm.stats.TotalRequests++
	
	// 保存到报告器
	if sm.reporter != nil {
		sm.reporter.AddResult(result)
	}
}

// configureOrchestrator 配置编排器
func (sm *SpiderManager) configureOrchestrator(orchestrator *core.Orchestrator) {
	// 设置爬虫选项
	orchestrator.SetDepth(sm.options.Depth)
	orchestrator.SetMaxPages(sm.options.MaxPages)
	orchestrator.SetUserAgent(sm.options.UserAgent)
	orchestrator.SetTimeout(sm.options.Timeout)
	orchestrator.SetProxy(sm.options.Proxy)
	orchestrator.SetJavaScript(sm.options.JavaScript)
	orchestrator.SetFollowRedirects(sm.options.FollowRedirects)
	orchestrator.SetIgnoreSSL(sm.options.IgnoreSSL)
	
	// 设置过滤器
	orchestrator.SetIncludePatterns(sm.options.compiledIncludePatterns)
	orchestrator.SetExcludePatterns(sm.options.compiledExcludePatterns)
	orchestrator.SetAllowedDomains(sm.options.AllowedDomains)
	orchestrator.SetBlockedDomains(sm.options.BlockedDomains)
	
	// 设置扫描模块
	if sm.options.EnableVulnScan {
		orchestrator.EnableVulnScan(sm.options.ScanModules)
	}
	
	// 设置请求头和Cookie
	for _, header := range sm.options.Headers {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			orchestrator.SetHeader(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
	
	for _, cookie := range sm.options.Cookies {
		orchestrator.SetCookie(cookie)
	}
}

// initReporter 初始化报告器
func (sm *SpiderManager) initReporter() error {
	if sm.options.OutputDir == "" {
		return nil
	}
	
	// 创建输出目录
	if err := os.MkdirAll(sm.options.OutputDir, 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}
	
	// 创建报告器
	reporterConfig := &output.ReporterConfig{
		OutputDir:    sm.options.OutputDir,
		Formats:      sm.options.OutputFormat,
		Template:     "spider",
		Timestamp:    true,
		Screenshots:  sm.options.Screenshots,
		SaveResponses: sm.options.SaveResponses,
	}
	
	reporter, err := output.NewReporter(reporterConfig)
	if err != nil {
		return fmt.Errorf("创建报告器失败: %w", err)
	}
	
	sm.reporter = reporter
	return nil
}

// generateReport 生成最终报告
func (sm *SpiderManager) generateReport() error {
	if sm.reporter == nil {
		return nil
	}
	
	// 生成汇总报告
	summary := map[string]interface{}{
		"stats":   sm.stats,
		"results": sm.results,
		"options": sm.options,
	}
	
	return sm.reporter.GenerateSummary(summary)
}

// printStats 打印统计信息
func (sm *SpiderManager) printStats() {
	duration := sm.stats.EndTime.Sub(sm.stats.StartTime)
	
	fmt.Printf("\n=== 爬虫扫描统计 ===\n")
	fmt.Printf("总耗时: %v\n", duration)
	fmt.Printf("目标URL数: %d\n", sm.stats.TotalURLs)
	fmt.Printf("已处理: %d\n", sm.stats.ProcessedURLs)
	fmt.Printf("成功: %d\n", sm.stats.SuccessfulURLs)
	fmt.Printf("失败: %d\n", sm.stats.FailedURLs)
	fmt.Printf("唯一页面: %d\n", sm.stats.UniquePages)
	fmt.Printf("总请求数: %d\n", sm.stats.TotalRequests)
	fmt.Printf("总字节数: %s\n", utils.FormatBytes(sm.stats.TotalBytes))
	
	if sm.options.EnableVulnScan {
		fmt.Printf("发现漏洞: %d\n", sm.stats.VulnsFound)
	}
	
	if len(sm.stats.Errors) > 0 {
		fmt.Printf("错误数: %d\n", len(sm.stats.Errors))
	}
	
	if duration > 0 {
		rps := float64(sm.stats.TotalRequests) / duration.Seconds()
		fmt.Printf("平均速率: %.2f 请求/秒\n", rps)
	}
	
	fmt.Printf("==================\n\n")
}

// cleanup 清理资源
func (sm *SpiderManager) cleanup() {
	if sm.cancel != nil {
		sm.cancel()
	}
	
	if sm.reporter != nil {
		sm.reporter.Close()
	}
}

func init() {
	rootCmd.AddCommand(spiderCmd)
	
	// 基本选项
	spiderCmd.Flags().StringP("url", "u", "", "需要扫描的目标URL")
	spiderCmd.Flags().StringP("file", "f", "", "包含URL列表的文件路径")
	spiderCmd.Flags().StringP("output-dir", "o", "", "输出目录路径")
	spiderCmd.Flags().BoolP("verbose", "v", false, "启用详细输出")
	spiderCmd.Flags().Bool("silent", false, "启用静默模式")
	
	// 爬虫配置
	spiderCmd.Flags().IntP("depth", "d", 3, "爬取深度 (0-10)")
	spiderCmd.Flags().Int("max-pages", 1000, "最大页面数 (1-100000)")
	spiderCmd.Flags().IntP("workers", "w", 10, "并发工作线程数 (1-100)")
	spiderCmd.Flags().Int("rate-limit", 50, "每秒最大请求数 (1-1000)")
	spiderCmd.Flags().String("timeout", "30s", "请求超时时间")
	spiderCmd.Flags().String("delay", "100ms", "请求间延迟")
	spiderCmd.Flags().String("user-agent", "", "自定义User-Agent")
	spiderCmd.Flags().String("proxy", "", "代理服务器地址")
	
	// 过滤选项
	spiderCmd.Flags().StringSlice("include", []string{}, "包含URL模式 (正则表达式)")
	spiderCmd.Flags().StringSlice("exclude", []string{}, "排除URL模式 (正则表达式)")
	spiderCmd.Flags().StringSlice("allowed-domains", []string{}, "允许的域名列表")
	spiderCmd.Flags().StringSlice("blocked-domains", []string{}, "阻止的域名列表")
	
	// HTTP选项
	spiderCmd.Flags().StringSlice("headers", []string{}, "自定义HTTP头 (格式: 'Name: Value')")
	spiderCmd.Flags().StringSlice("cookies", []string{}, "自定义Cookie")
	spiderCmd.Flags().Bool("follow-redirects", true, "跟随HTTP重定向")
	spiderCmd.Flags().Bool("ignore-ssl", false, "忽略SSL证书错误")
	
	// 高级功能
	spiderCmd.Flags().Bool("javascript", false, "启用JavaScript渲染")
	spiderCmd.Flags().Bool("screenshots", false, "保存页面截图")
	spiderCmd.Flags().Bool("save-responses", false, "保存HTTP响应")
	
	// 输出选项
	spiderCmd.Flags().StringSlice("format", []string{"json", "html"}, "输出格式 (json,xml,html,csv,txt)")
	
	// 漏洞扫描选项
	spiderCmd.Flags().Bool("vuln-scan", false, "启用漏洞扫描")
	spiderCmd.Flags().StringSlice("scan-modules", []string{}, "指定扫描模块")
	
	// 标志互斥
	spiderCmd.MarkFlagsMutuallyExclusive("verbose", "silent")
	spiderCmd.MarkFlagsRequiredTogether("vuln-scan", "scan-modules")
}

// 添加一些辅助函数

// SpiderURLFilter URL过滤器
type SpiderURLFilter struct {
	includePatterns []*regexp.Regexp
	excludePatterns []*regexp.Regexp
	allowedDomains  map[string]bool
	blockedDomains  map[string]bool
}

// NewSpiderURLFilter 创建URL过滤器
func NewSpiderURLFilter(options *SpiderOptions) *SpiderURLFilter {
	filter := &SpiderURLFilter{
		includePatterns: options.compiledIncludePatterns,
		excludePatterns: options.compiledExcludePatterns,
		allowedDomains:  make(map[string]bool),
		blockedDomains:  make(map[string]bool),
	}
	
	// 构建域名映射
	for _, domain := range options.AllowedDomains {
		filter.allowedDomains[strings.ToLower(domain)] = true
	}
	
	for _, domain := range options.BlockedDomains {
		filter.blockedDomains[strings.ToLower(domain)] = true
	}
	
	return filter
}

// ShouldProcess 判断是否应该处理该URL
func (f *SpiderURLFilter) ShouldProcess(rawURL string) bool {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	
	domain := strings.ToLower(parsedURL.Host)
	
	// 检查被阻止的域名
	if len(f.blockedDomains) > 0 && f.blockedDomains[domain] {
		return false
	}
	
	// 检查允许的域名
	if len(f.allowedDomains) > 0 && !f.allowedDomains[domain] {
		return false
	}
	
	// 检查排除模式
	for _, pattern := range f.excludePatterns {
		if pattern.MatchString(rawURL) {
			return false
		}
	}
	
	// 检查包含模式
	if len(f.includePatterns) > 0 {
		matched := false
		for _, pattern := range f.includePatterns {
			if pattern.MatchString(rawURL) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	
	return true
}

// SpiderRateLimiter 速率限制器
type SpiderRateLimiter struct {
	rate     int
	interval time.Duration
	tokens   chan struct{}
	ticker   *time.Ticker
	stop     chan struct{}
}

// NewSpiderRateLimiter 创建速率限制器
func NewSpiderRateLimiter(requestsPerSecond int) *SpiderRateLimiter {
	if requestsPerSecond <= 0 {
		requestsPerSecond = 10 // 默认限制
	}
	
	rl := &SpiderRateLimiter{
		rate:     requestsPerSecond,
		interval: time.Second / time.Duration(requestsPerSecond),
		tokens:   make(chan struct{}, requestsPerSecond),
		stop:     make(chan struct{}),
	}
	
	// 初始填充令牌
	for i := 0; i < requestsPerSecond; i++ {
		rl.tokens <- struct{}{}
	}
	
	// 启动令牌补充协程
	rl.ticker = time.NewTicker(rl.interval)
	go rl.refillTokens()
	
	return rl
}

// refillTokens 补充令牌
func (rl *SpiderRateLimiter) refillTokens() {
	for {
		select {
		case <-rl.ticker.C:
			select {
			case rl.tokens <- struct{}{}:
			default:
				// 令牌桶已满
			}
		case <-rl.stop:
			rl.ticker.Stop()
			return
		}
	}
}

// Wait 等待获取令牌
func (rl *SpiderRateLimiter) Wait(ctx context.Context) error {
	select {
	case <-rl.tokens:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Stop 停止速率限制器
func (rl *SpiderRateLimiter) Stop() {
	close(rl.stop)
}

// SpiderProgress 进度跟踪器
type SpiderProgress struct {
	total     int
	processed int
	mu        sync.RWMutex
	startTime time.Time
	lastPrint time.Time
}

// NewSpiderProgress 创建进度跟踪器
func NewSpiderProgress(total int) *SpiderProgress {
	return &SpiderProgress{
		total:     total,
		startTime: time.Now(),
		lastPrint: time.Now(),
	}
}

// Update 更新进度
func (p *SpiderProgress) Update() {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	p.processed++
	
	// 每秒最多打印一次进度
	now := time.Now()
	if now.Sub(p.lastPrint) >= time.Second {
		p.printProgress()
		p.lastPrint = now
	}
}

// printProgress 打印进度信息
func (p *SpiderProgress) printProgress() {
	percentage := float64(p.processed) / float64(p.total) * 100
	elapsed := time.Since(p.startTime)
	
	var eta time.Duration
	if p.processed > 0 {
		avgTime := elapsed / time.Duration(p.processed)
		remaining := p.total - p.processed
		eta = avgTime * time.Duration(remaining)
	}
	
	logger.Info("扫描进度",
		"processed", p.processed,
		"total", p.total,
		"percentage", fmt.Sprintf("%.1f%%", percentage),
		"elapsed", elapsed.Round(time.Second),
		"eta", eta.Round(time.Second),
	)
}

// Finish 完成进度跟踪
func (p *SpiderProgress) Finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	elapsed := time.Since(p.startTime)
	logger.Info("扫描完成",
		"total", p.total,
		"processed", p.processed,
		"elapsed", elapsed.Round(time.Second),
	)
}

// SpiderHealthChecker 健康检查器
type SpiderHealthChecker struct {
	maxErrors    int
	errorCount   int
	errorWindow  time.Duration
	errors       []time.Time
	mu           sync.Mutex
}

// NewSpiderHealthChecker 创建健康检查器
func NewSpiderHealthChecker(maxErrors int, window time.Duration) *SpiderHealthChecker {
	return &SpiderHealthChecker{
		maxErrors:   maxErrors,
		errorWindow: window,
		errors:      make([]time.Time, 0),
	}
}

// RecordError 记录错误
func (hc *SpiderHealthChecker) RecordError() bool {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	
	now := time.Now()
	hc.errors = append(hc.errors, now)
	hc.errorCount++
	
	// 清理过期错误
	cutoff := now.Add(-hc.errorWindow)
	validErrors := make([]time.Time, 0)
	for _, errorTime := range hc.errors {
		if errorTime.After(cutoff) {
			validErrors = append(validErrors, errorTime)
		}
	}
	hc.errors = validErrors
	
	// 检查是否超过阈值
	return len(hc.errors) >= hc.maxErrors
}

// IsHealthy 检查是否健康
func (hc *SpiderHealthChecker) IsHealthy() bool {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	
	now := time.Now()
	cutoff := now.Add(-hc.errorWindow)
	
	recentErrors := 0
	for _, errorTime := range hc.errors {
		if errorTime.After(cutoff) {
			recentErrors++
		}
	}
	
	return recentErrors < hc.maxErrors
}

// GetStats 获取统计信息
func (hc *SpiderHealthChecker) GetStats() (int, int) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	
	now := time.Now()
	cutoff := now.Add(-hc.errorWindow)
	
	recentErrors := 0
	for _, errorTime := range hc.errors {
		if errorTime.After(cutoff) {
			recentErrors++
		}
	}
	
	return hc.errorCount, recentErrors
}

// 添加更多的辅助函数和工具类

// SpiderCache 简单的内存缓存
type SpiderCache struct {
	data map[string]interface{}
	mu   sync.RWMutex
	ttl  time.Duration
}

// NewSpiderCache 创建缓存
func NewSpiderCache(ttl time.Duration) *SpiderCache {
	return &SpiderCache{
		data: make(map[string]interface{}),
		ttl:  ttl,
	}
}

// Get 获取缓存值
func (c *SpiderCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	value, exists := c.data[key]
	return value, exists
}

// Set 设置缓存值
func (c *SpiderCache) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.data[key] = value
}

// Delete 删除缓存值
func (c *SpiderCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	delete(c.data, key)
}

// Clear 清空缓存
func (c *SpiderCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.data = make(map[string]interface{})
}

// Size 获取缓存大小
func (c *SpiderCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	return len(c.data)
}
