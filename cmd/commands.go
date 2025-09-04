// Package cmd 提供了命令行命令实现
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"autovulnscan/internal/api"
	"autovulnscan/internal/config"
	"autovulnscan/internal/crawler"
	"autovulnscan/internal/database"
	"autovulnscan/internal/logger"
	"autovulnscan/internal/models"
	"autovulnscan/internal/plugin"
	"autovulnscan/internal/proxy"
	"autovulnscan/internal/report"
	"autovulnscan/internal/utils"
	"autovulnscan/internal/vulnscan"
)

// GlobalConfig 全局配置
var GlobalConfig *config.GlobalConfig

// Logger 日志记录器
var Logger *logger.Logger

// PluginManager 插件管理器
var PluginManager *plugin.PluginManager

// Database 数据库
var Database *database.DB

// VulnScanEngine 漏洞扫描引擎
var VulnScanEngine *vulnscan.Engine

// CrawlerEngine 爬虫引擎
var CrawlerEngine *crawler.Crawler

// ProxyServer 代理服务器
var ProxyServer *proxy.Proxy

// ReportGenerator 报告生成器
var ReportGenerator *report.Generator

// APIServer API服务器
var APIServer *api.Server

// vulnScanCmd 漏洞扫描命令
var vulnScanCmd = &cobra.Command{
	Use:   "vulnscan [target]",
	Short: "Start a vulnerability scan",
	Long:  `Start a vulnerability scan on the specified target. The target can be a URL, IP address, or domain name.`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]

		// 获取扫描选项
		scanType, _ := cmd.Flags().GetString("type")
		output, _ := cmd.Flags().GetString("output")
		format, _ := cmd.Flags().GetString("format")
		timeout, _ := cmd.Flags().GetInt("timeout")
		concurrency, _ := cmd.Flags().GetInt("concurrency")
		depth, _ := cmd.Flags().GetInt("depth")
		followRedirects, _ := cmd.Flags().GetBool("follow-redirects")
		rateLimit, _ := cmd.Flags().GetInt("rate-limit")
		plugins, _ := cmd.Flags().GetStringSlice("plugins")
		headers, _ := cmd.Flags().GetStringSlice("header")
		cookies, _ := cmd.Flags().GetStringSlice("cookie")

		// 创建扫描配置
		scanConfig := &models.ScanConfig{
			Target:           target,
			Type:             scanType,
			Timeout:          time.Duration(timeout) * time.Second,
			Concurrency:      concurrency,
			Depth:            depth,
			FollowRedirects:  followRedirects,
			RateLimit:        rateLimit,
			Plugins:          plugins,
			Headers:          parseHeaders(headers),
			Cookies:          parseCookies(cookies),
			OutputFile:       output,
			OutputFormat:     format,
			StartTime:        time.Now(),
		}

		// 执行扫描
		result, err := executeScan(scanConfig)
		if err != nil {
			log.Error().Err(err).Msg("Failed to execute scan")
			os.Exit(1)
		}

		// 输出结果
		if err := outputScanResult(result, output, format); err != nil {
			log.Error().Err(err).Msg("Failed to output scan result")
			os.Exit(1)
		}
	},
}

// allCmd 全扫描命令
var allCmd = &cobra.Command{
	Use:   "all [target]",
	Short: "Start a comprehensive scan (crawl + scan)",
	Long:  `Start a comprehensive scan that includes crawling the target and then performing vulnerability scanning.`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]

		// 获取扫描选项
		output, _ := cmd.Flags().GetString("output")
		format, _ := cmd.Flags().GetString("format")
		timeout, _ := cmd.Flags().GetInt("timeout")
		concurrency, _ := cmd.Flags().GetInt("concurrency")
		depth, _ := cmd.Flags().GetInt("depth")
		followRedirects, _ := cmd.Flags().GetBool("follow-redirects")
		rateLimit, _ := cmd.Flags().GetInt("rate-limit")
		maxPages, _ := cmd.Flags().GetInt("max-pages")
		plugins, _ := cmd.Flags().GetStringSlice("plugins")
		headers, _ := cmd.Flags().GetStringSlice("header")
		cookies, _ := cmd.Flags().GetStringSlice("cookie")

		// 创建爬取配置
		crawlConfig := &crawler.Config{
			StartURL:         target,
			MaxDepth:        depth,
			MaxPages:        maxPages,
			Concurrency:     concurrency,
			RateLimit:       rateLimit,
			Timeout:         time.Duration(timeout) * time.Second,
			FollowRedirects: followRedirects,
			Headers:         parseHeaders(headers),
			Cookies:         parseCookies(cookies),
		}

		// 创建扫描配置
		scanConfig := &models.ScanConfig{
			Target:           target,
			Type:             "comprehensive",
			Timeout:          time.Duration(timeout) * time.Second,
			Concurrency:      concurrency,
			Depth:            depth,
			FollowRedirects:  followRedirects,
			RateLimit:        rateLimit,
			Plugins:          plugins,
			Headers:          parseHeaders(headers),
			Cookies:          parseCookies(cookies),
			OutputFile:       output,
			OutputFormat:     format,
			StartTime:        time.Now(),
		}

		// 执行全扫描
		result, err := executeAllScan(crawlConfig, scanConfig)
		if err != nil {
			log.Error().Err(err).Msg("Failed to execute comprehensive scan")
			os.Exit(1)
		}

		// 输出结果
		if err := outputScanResult(result, output, format); err != nil {
			log.Error().Err(err).Msg("Failed to output scan result")
			os.Exit(1)
		}
	},
}

// reportCmd 报告命令
var reportCmd = &cobra.Command{
	Use:   "report [input]",
	Short: "Generate a report from scan results",
	Long:  `Generate a report from scan results. The input can be a JSON file containing scan results.`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		input := args[0]

		// 获取报告选项
		output, _ := cmd.Flags().GetString("output")
		format, _ := cmd.Flags().GetString("format")
		template, _ := cmd.Flags().GetString("template")
		title, _ := cmd.Flags().GetString("title")

		// 创建报告配置
		reportConfig := &models.ReportConfig{
			InputFile:   input,
			OutputFile:  output,
			Format:      format,
			Template:    template,
			Title:       title,
			GeneratedAt: time.Now(),
		}

		// 生成报告
		if err := generateReport(reportConfig); err != nil {
			log.Error().Err(err).Msg("Failed to generate report")
			os.Exit(1)
		}

		log.Info().Str("output", output).Msg("Report generated successfully")
	},
}

// configCmd 配置命令
var configCmd = &cobra.Command{
	Use:   "config [action]",
	Short: "Manage configuration",
	Long:  `Manage configuration. Actions include show, set, reset, and validate.`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		action := args[0]

		switch action {
		case "show":
			showConfig()
		case "set":
			if len(args) < 3 {
				log.Error().Msg("Usage: config set <key> <value>")
				os.Exit(1)
			}
			key := args[1]
			value := args[2]
			setConfig(key, value)
		case "reset":
			resetConfig()
		case "validate":
			validateConfig()
		default:
			log.Error().Str("action", action).Msg("Unknown config action")
			os.Exit(1)
		}
	},
}

// proxyCmd 代理命令
var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Start the proxy server",
	Long:  `Start the proxy server for intercepting and analyzing HTTP/HTTPS traffic.`,
	Run: func(cmd *cobra.Command, args []string) {
		// 获取代理选项
		port, _ := cmd.Flags().GetInt("port")
		host, _ := cmd.Flags().GetString("host")
		auth, _ := cmd.Flags().GetBool("auth")
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		certDir, _ := cmd.Flags().GetString("cert-dir")
		output, _ := cmd.Flags().GetString("output")

		// 创建代理配置
		proxyConfig := &config.ProxyConfig{
			Port:      port,
			Host:      host,
			Verbose:   true,
			EnableHTTPS: true,
			CertDir:   certDir,
			OutputFile: output,
		}

		if auth {
			proxyConfig.Auth = &config.AuthConfig{
				Username: username,
				Password: password,
			}
		}

		// 启动代理服务器
		if err := startProxy(proxyConfig); err != nil {
			log.Error().Err(err).Msg("Failed to start proxy server")
			os.Exit(1)
		}
	},
}

// apiCmd API命令
var apiCmd = &cobra.Command{
	Use:   "api",
	Short: "Start the API server",
	Long:  `Start the API server for remote control and data access.`,
	Run: func(cmd *cobra.Command, args []string) {
		// 获取API选项
		port, _ := cmd.Flags().GetInt("port")
		host, _ := cmd.Flags().GetString("host")
		auth, _ := cmd.Flags().GetBool("auth")
		token, _ := cmd.Flags().GetString("token")
		cors, _ := cmd.Flags().GetBool("cors")

		// 创建API配置
		apiConfig := &config.APIConfig{
			Port:  port,
			Host:  host,
			CORS:  cors,
		}

		if auth {
			apiConfig.Auth = config.APIAuthConfig{
				Enabled: true,
				Token:   token,
			}
		}

		// 更新全局配置
		GlobalConfig.API = *apiConfig

		// 启动API服务器
		if err := startAPI(); err != nil {
			log.Error().Err(err).Msg("Failed to start API server")
			os.Exit(1)
		}
	},
}

// llmQueryCmd LLM查询命令
var llmQueryCmd = &cobra.Command{
	Use:   "llm-query [prompt]",
	Short: "Query the LLM for vulnerability analysis",
	Long:  `Query the LLM for vulnerability analysis. The prompt should describe the vulnerability or code you want to analyze.`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		prompt := strings.Join(args, " ")

		// 获取LLM选项
		provider, _ := cmd.Flags().GetString("provider")
		model, _ := cmd.Flags().GetString("model")
		apiKey, _ := cmd.Flags().GetString("api-key")
		output, _ := cmd.Flags().GetString("output")

		// 创建LLM配置
		llmConfig := &config.LLMConfig{
			Provider: provider,
			Model:    model,
			APIKey:   apiKey,
		}

		// 查询LLM
		response, err := queryLLM(prompt, llmConfig)
		if err != nil {
			log.Error().Err(err).Msg("Failed to query LLM")
			os.Exit(1)
		}

		// 输出结果
		if output != "" {
			if err := os.WriteFile(output, []byte(response), 0644); err != nil {
				log.Error().Err(err).Str("output", output).Msg("Failed to write output")
				os.Exit(1)
			}
			log.Info().Str("output", output).Msg("LLM response saved")
		} else {
			fmt.Println(response)
		}
	},
}

// pluginCmd 插件命令
var pluginCmd = &cobra.Command{
	Use:   "plugin [action] [path]",
	Short: "Manage plugins",
	Long:  `Manage plugins. Actions include list, load, unload, enable, disable, and reload.`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		action := args[0]

		switch action {
		case "list":
			listPlugins()
		case "load":
			if len(args) < 2 {
				log.Error().Msg("Usage: plugin load <path>")
				os.Exit(1)
			}
			path := args[1]
			loadPlugin(path)
		case "unload":
			if len(args) < 2 {
				log.Error().Msg("Usage: plugin unload <name>")
				os.Exit(1)
			}
			name := args[1]
			unloadPlugin(name)
		case "enable":
			if len(args) < 2 {
				log.Error().Msg("Usage: plugin enable <name>")
				os.Exit(1)
			}
			name := args[1]
			enablePlugin(name)
		case "disable":
			if len(args) < 2 {
				log.Error().Msg("Usage: plugin disable <name>")
				os.Exit(1)
			}
			name := args[1]
			disablePlugin(name)
		case "reload":
			if len(args) < 2 {
				log.Error().Msg("Usage: plugin reload <name>")
				os.Exit(1)
			}
			name := args[1]
			reloadPlugin(name)
		default:
			log.Error().Str("action", action).Msg("Unknown plugin action")
			os.Exit(1)
		}
	},
}

// dbCmd 数据库命令
var dbCmd = &cobra.Command{
	Use:   "db [action]",
	Short: "Manage database",
	Long:  `Manage database. Actions include init, migrate, backup, restore, and clean.`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		action := args[0]

		switch action {
		case "init":
			initDatabase()
		case "migrate":
			migrateDatabase()
		case "backup":
			if len(args) < 2 {
				log.Error().Msg("Usage: db backup <output>")
				os.Exit(1)
			}
			output := args[1]
			backupDatabase(output)
		case "restore":
			if len(args) < 2 {
				log.Error().Msg("Usage: db restore <input>")
				os.Exit(1)
			}
			input := args[1]
			restoreDatabase(input)
		case "clean":
			cleanDatabase()
		default:
			log.Error().Str("action", action).Msg("Unknown database action")
			os.Exit(1)
		}
	},
}

// versionCmd 版本命令
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Long:  `Show version information for AutoVulnScan.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("AutoVulnScan %s\n", "1.0.0")
		fmt.Printf("Build: %s\n", "dev")
		fmt.Printf("Go: %s\n", "1.19")
	},
}

// init 初始化命令
func init() {
	// 注册漏洞扫描命令
	rootCmd.AddCommand(vulnScanCmd)
	
	// 添加漏洞扫描命令的标志
	vulnScanCmd.Flags().StringP("type", "t", "xss", "Scan type (xss, sqli, csrf, all)")
	vulnScanCmd.Flags().StringP("output", "o", "", "Output file path")
	vulnScanCmd.Flags().StringP("format", "f", "json", "Output format (json, xml, html, csv)")
	vulnScanCmd.Flags().IntP("timeout", "T", 30, "Request timeout in seconds")
	vulnScanCmd.Flags().IntP("concurrency", "c", 10, "Concurrency level")
	vulnScanCmd.Flags().IntP("depth", "d", 3, "Scan depth")
	vulnScanCmd.Flags().BoolP("follow-redirects", "r", false, "Follow redirects")
	vulnScanCmd.Flags().IntP("rate-limit", "R", 10, "Rate limit (requests per second)")
	vulnScanCmd.Flags().StringSliceP("plugins", "p", []string{}, "Plugins to use")
	vulnScanCmd.Flags().StringSliceP("header", "H", []string{}, "Custom headers (format: key:value)")
	vulnScanCmd.Flags().StringSliceP("cookie", "C", []string{}, "Custom cookies (format: name=value)")

	// 注册全扫描命令
	rootCmd.AddCommand(allCmd)
	
	// 添加全扫描命令的标志
	allCmd.Flags().StringP("output", "o", "", "Output file path")
	allCmd.Flags().StringP("format", "f", "json", "Output format (json, xml, html, csv)")
	allCmd.Flags().IntP("timeout", "T", 30, "Request timeout in seconds")
	allCmd.Flags().IntP("concurrency", "c", 10, "Concurrency level")
	allCmd.Flags().IntP("depth", "d", 3, "Crawl depth")
	allCmd.Flags().BoolP("follow-redirects", "r", false, "Follow redirects")
	allCmd.Flags().IntP("rate-limit", "R", 10, "Rate limit (requests per second)")
	allCmd.Flags().IntP("max-pages", "m", 100, "Maximum pages to crawl")
	allCmd.Flags().StringSliceP("plugins", "p", []string{}, "Plugins to use")
	allCmd.Flags().StringSliceP("header", "H", []string{}, "Custom headers (format: key:value)")
	allCmd.Flags().StringSliceP("cookie", "C", []string{}, "Custom cookies (format: name=value)")

	// 注册报告命令
	rootCmd.AddCommand(reportCmd)
	
	// 添加报告命令的标志
	reportCmd.Flags().StringP("output", "o", "", "Output file path")
	reportCmd.Flags().StringP("format", "f", "html", "Output format (html, pdf, json, csv, markdown)")
	reportCmd.Flags().StringP("template", "t", "", "Template file path")
	reportCmd.Flags().StringP("title", "i", "Vulnerability Scan Report", "Report title")

	// 注册配置命令
	rootCmd.AddCommand(configCmd)

	// 注册代理命令
	rootCmd.AddCommand(proxyCmd)
	
	// 添加代理命令的标志
	proxyCmd.Flags().IntP("port", "p", 8080, "Proxy port")
	proxyCmd.Flags().StringP("host", "H", "127.0.0.1", "Proxy host")
	proxyCmd.Flags().BoolP("auth", "a", false, "Enable authentication")
	proxyCmd.Flags().StringP("username", "u", "", "Username for authentication")
	proxyCmd.Flags().StringP("password", "P", "", "Password for authentication")
	proxyCmd.Flags().StringP("cert-dir", "c", "", "Certificate directory")
	proxyCmd.Flags().StringP("output", "o", "", "Output file path")

	// 注册API命令
	rootCmd.AddCommand(apiCmd)
	
	// 添加API命令的标志
	apiCmd.Flags().IntP("port", "p", 8081, "API port")
	apiCmd.Flags().StringP("host", "H", "127.0.0.1", "API host")
	apiCmd.Flags().BoolP("auth", "a", false, "Enable authentication")
	apiCmd.Flags().StringP("token", "t", "", "Token for authentication")
	apiCmd.Flags().BoolP("cors", "c", true, "Enable CORS")

	// 注册LLM查询命令
	rootCmd.AddCommand(llmQueryCmd)
	
	// 添加LLM查询命令的标志
	llmQueryCmd.Flags().StringP("provider", "p", "openai", "LLM provider (openai, deepseek)")
	llmQueryCmd.Flags().StringP("model", "m", "gpt-3.5-turbo", "LLM model")
	llmQueryCmd.Flags().StringP("api-key", "k", "", "API key")
	llmQueryCmd.Flags().StringP("output", "o", "", "Output file path")

	// 注册插件命令
	rootCmd.AddCommand(pluginCmd)

	// 注册数据库命令
	rootCmd.AddCommand(dbCmd)

	// 注册版本命令
	rootCmd.AddCommand(versionCmd)
}

// GetCommands 获取所有命令
func GetCommands() []*cobra.Command {
	return []*cobra.Command{
		vulnScanCmd,
		allCmd,
		reportCmd,
		configCmd,
		proxyCmd,
		apiCmd,
		llmQueryCmd,
		pluginCmd,
		dbCmd,
		versionCmd,
	}
}

// executeScan 执行扫描
func executeScan(config *models.ScanConfig) (*models.ScanResult, error) {
	log.Info().Str("target", config.Target).Str("type", config.Type).Msg("Starting scan")

	// 初始化扫描引擎
	if VulnScanEngine == nil {
		engineConfig := &vulnscan.EngineConfig{
			Concurrency: config.Concurrency,
			Timeout:      config.Timeout,
			RateLimit:    config.RateLimit,
			Plugins:      config.Plugins,
		}

		var err error
		VulnScanEngine, err = vulnscan.NewEngine(engineConfig, PluginManager)
		if err != nil {
			return nil, fmt.Errorf("failed to create scan engine: %w", err)
		}

		// 启动扫描引擎
		if err := VulnScanEngine.Start(); err != nil {
			return nil, fmt.Errorf("failed to start scan engine: %w", err)
		}

		// 确保在函数返回时关闭扫描引擎
		defer VulnScanEngine.Close()
	}

	// 创建扫描请求
	request := &vulnscan.ScanRequest{
		Target:  config.Target,
		Type:    config.Type,
		Options: map[string]interface{}{
			"depth":            config.Depth,
			"follow_redirects":  config.FollowRedirects,
			"headers":          config.Headers,
			"cookies":          config.Cookies,
		},
	}

	// 执行扫描
	result, err := VulnScanEngine.Scan(request)
	if err != nil {
		return nil, fmt.Errorf("failed to scan: %w", err)
	}

	// 创建扫描结果
	scanResult := &models.ScanResult{
		ID:          generateID(),
		Target:      config.Target,
		Type:        config.Type,
		StartTime:   config.StartTime,
		EndTime:     time.Now(),
		Vulnerabilities: result,
		Stats: &models.ScanStats{
			TotalRequests:    len(result),
			TotalVulnerabilities: len(result),
		},
	}

	// 保存扫描结果到数据库
	if Database != nil {
		if err := Database.SaveScanResult(scanResult); err != nil {
			log.Error().Err(err).Msg("Failed to save scan result")
		}
	}

	log.Info().Str("target", config.Target).Int("vulnerabilities", len(result)).Msg("Scan completed")

	return scanResult, nil
}

// executeAllScan 执行全扫描
func executeAllScan(crawlConfig *crawler.Config, scanConfig *models.ScanConfig) (*models.ScanResult, error) {
	log.Info().Str("target", crawlConfig.StartURL).Msg("Starting comprehensive scan")

	// 初始化爬虫引擎
	if CrawlerEngine == nil {
		var err error
		CrawlerEngine, err = crawler.NewCrawler(crawlConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create crawler engine: %w", err)
		}

		// 启动爬虫引擎
		if err := CrawlerEngine.Start(); err != nil {
			return nil, fmt.Errorf("failed to start crawler engine: %w", err)
		}

		// 确保在函数返回时关闭爬虫引擎
		defer CrawlerEngine.Stop()
	}

	// 爬取目标
	crawlResults, err := CrawlerEngine.Crawl(crawlConfig.StartURL)
	if err != nil {
		return nil, fmt.Errorf("failed to crawl: %w", err)
	}

	log.Info().Int("pages", len(crawlResults)).Msg("Crawling completed")

	// 初始化扫描引擎
	if VulnScanEngine == nil {
		engineConfig := &vulnscan.EngineConfig{
			Concurrency: scanConfig.Concurrency,
			Timeout:      scanConfig.Timeout,
			RateLimit:    scanConfig.RateLimit,
			Plugins:      scanConfig.Plugins,
		}

		var err error
		VulnScanEngine, err = vulnscan.NewEngine(engineConfig, PluginManager)
		if err != nil {
			return nil, fmt.Errorf("failed to create scan engine: %w", err)
		}

		// 启动扫描引擎
		if err := VulnScanEngine.Start(); err != nil {
			return nil, fmt.Errorf("failed to start scan engine: %w", err)
		}

		// 确保在函数返回时关闭扫描引擎
		defer VulnScanEngine.Close()
	}

	// 扫描所有爬取的页面
	var allVulnerabilities []*models.Vulnerability
	for _, result := range crawlResults {
		request := &vulnscan.ScanRequest{
			Target:  result.URL,
			Type:    scanConfig.Type,
			Options: map[string]interface{}{
				"depth":            scanConfig.Depth,
				"follow_redirects":  scanConfig.FollowRedirects,
				"headers":          scanConfig.Headers,
				"cookies":          scanConfig.Cookies,
			},
		}

		// 执行扫描
		vulnerabilities, err := VulnScanEngine.Scan(request)
		if err != nil {
			log.Error().Err(err).Str("url", result.URL).Msg("Failed to scan URL")
			continue
		}

		allVulnerabilities = append(allVulnerabilities, vulnerabilities...)
	}

	// 创建扫描结果
	scanResult := &models.ScanResult{
		ID:          generateID(),
		Target:      crawlConfig.StartURL,
		Type:        scanConfig.Type,
		StartTime:   scanConfig.StartTime,
		EndTime:     time.Now(),
		Vulnerabilities: allVulnerabilities,
		Stats: &models.ScanStats{
			TotalRequests:    len(crawlResults),
			TotalVulnerabilities: len(allVulnerabilities),
		},
	}

	// 保存扫描结果到数据库
	if Database != nil {
		if err := Database.SaveScanResult(scanResult); err != nil {
			log.Error().Err(err).Msg("Failed to save scan result")
		}
	}

	log.Info().Str("target", crawlConfig.StartURL).Int("vulnerabilities", len(allVulnerabilities)).Msg("Comprehensive scan completed")

	return scanResult, nil
}

// outputScanResult 输出扫描结果
func outputScanResult(result *models.ScanResult, outputPath, format string) error {
	if outputPath == "" {
		// 输出到控制台
		switch format {
		case "json":
			data, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal result: %w", err)
			}
			fmt.Println(string(data))
		case "xml":
			// 简化实现，实际应该使用XML编码器
			fmt.Printf("<result>\n  <id>%s</id>\n  <target>%s</target>\n  <type>%s</type>\n  <vulnerabilities>%d</vulnerabilities>\n</result>\n", result.ID, result.Target, result.Type, len(result.Vulnerabilities))
		case "html":
			// 简化实现，实际应该使用HTML模板
			fmt.Printf("<html><body><h1>Scan Result</h1><p>Target: %s</p><p>Type: %s</p><p>Vulnerabilities: %d</p></body></html>\n", result.Target, result.Type, len(result.Vulnerabilities))
		case "csv":
			// 简化实现，实际应该使用CSV编码器
			fmt.Println("ID,Target,Type,Severity,Description")
			for _, vuln := range result.Vulnerabilities {
				fmt.Printf("%s,%s,%s,%s,%s\n", vuln.ID, result.Target, vuln.Type, vuln.Severity, vuln.Description)
			}
		default:
			return fmt.Errorf("unsupported output format: %s", format)
		}
	} else {
		// 输出到文件
		if ReportGenerator == nil {
			var err error
			ReportGenerator, err = report.NewGenerator(&models.ReportConfig{
				Format: format,
			})
			if err != nil {
				return fmt.Errorf("failed to create report generator: %w", err)
			}
		}

		// 生成报告
		data, err := ReportGenerator.Generate(result, &models.ReportConfig{
			Format:     format,
			OutputFile: outputPath,
		})
		if err != nil {
			return fmt.Errorf("failed to generate report: %w", err)
		}

		// 写入文件
		if err := os.WriteFile(outputPath, data, 0644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
	}

	return nil
}

// generateReport 生成报告
func generateReport(config *models.ReportConfig) error {
	// 读取输入文件
	data, err := os.ReadFile(config.InputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	// 解析扫描结果
	var scanResult models.ScanResult
	if err := json.Unmarshal(data, &scanResult); err != nil {
		return fmt.Errorf("failed to parse scan result: %w", err)
	}

	// 创建报告生成器
	if ReportGenerator == nil {
		ReportGenerator, err = report.NewGenerator(config)
		if err != nil {
			return fmt.Errorf("failed to create report generator: %w", err)
		}
	}

	// 生成报告
	reportData, err := ReportGenerator.Generate(&scanResult, config)
	if err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	// 写入输出文件
	if err := os.WriteFile(config.OutputFile, reportData, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	return nil
}

// showConfig 显示配置
func showConfig() {
	data, err := json.MarshalIndent(GlobalConfig, "", "  ")
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal config")
		os.Exit(1)
	}

	fmt.Println(string(data))
}

// setConfig 设置配置
func setConfig(key, value string) {
	// 简化实现，实际应该使用更复杂的配置更新逻辑
	switch key {
	case "scanner.concurrency":
		if concurrency, err := strconv.Atoi(value); err == nil {
			GlobalConfig.Scanner.Concurrency = concurrency
		} else {
			log.Error().Str("value", value).Msg("Invalid concurrency value")
			os.Exit(1)
		}
	case "scanner.timeout":
		if timeout, err := strconv.Atoi(value); err == nil {
			GlobalConfig.Scanner.Timeout = timeout
		} else {
			log.Error().Str("value", value).Msg("Invalid timeout value")
			os.Exit(1)
		}
	case "llm.provider":
		GlobalConfig.LLM.Provider = value
	case "llm.model":
		GlobalConfig.LLM.Model = value
	case "llm.api_key":
		GlobalConfig.LLM.APIKey = value
	default:
		log.Error().Str("key", key).Msg("Unknown config key")
		os.Exit(1)
	}

	// 保存配置
	if err := config.SaveConfig(GlobalConfig); err != nil {
		log.Error().Err(err).Msg("Failed to save config")
		os.Exit(1)
	}

	log.Info().Str("key", key).Str("value", value).Msg("Config updated")
}

// resetConfig 重置配置
func resetConfig() {
	// 重置为默认配置
	GlobalConfig = config.GetDefaultConfig()

	// 保存配置
	if err := config.SaveConfig(GlobalConfig); err != nil {
		log.Error().Err(err).Msg("Failed to save config")
		os.Exit(1)
	}

	log.Info().Msg("Config reset to defaults")
}

// validateConfig 验证配置
func validateConfig() {
	// 验证配置
	if err := config.ValidateConfig(GlobalConfig); err != nil {
		log.Error().Err(err).Msg("Config validation failed")
		os.Exit(1)
	}

	log.Info().Msg("Config validation passed")
}

// startProxy 启动代理服务器
func startProxy(config *config.ProxyConfig) error {
	var err error
	ProxyServer, err = proxy.NewProxy(config)
	if err != nil {
		return fmt.Errorf("failed to create proxy server: %w", err)
	}

	// 启动代理服务器
	if err := ProxyServer.Start(); err != nil {
		return fmt.Errorf("failed to start proxy server: %w", err)
	}

	log.Info().Str("host", config.Host).Int("port", config.Port).Msg("Proxy server started")

	// 等待中断信号
	waitForInterrupt()

	// 停止代理服务器
	if err := ProxyServer.Stop(); err != nil {
		return fmt.Errorf("failed to stop proxy server: %w", err)
	}

	return nil
}

// startAPI 启动API服务器
func startAPI() error {
	// 创建API服务器
	APIServer = api.NewServer(GlobalConfig, PluginManager, Database, Database)

	// 启动API服务器
	if err := APIServer.Start(); err != nil {
		return fmt.Errorf("failed to start API server: %w", err)
	}

	log.Info().Str("host", GlobalConfig.API.Host).Int("port", GlobalConfig.API.Port).Msg("API server started")

	// 等待中断信号
	waitForInterrupt()

	// 停止API服务器
	if err := APIServer.Stop(); err != nil {
		return fmt.Errorf("failed to stop API server: %w", err)
	}

	return nil
}

// queryLLM 查询LLM
func queryLLM(prompt string, config *config.LLMConfig) (string, error) {
	// 创建LLM客户端
	// 简化实现，实际应该使用LLM客户端
	log.Info().Str("provider", config.Provider).Str("model", config.Model).Msg("Querying LLM")

	// 模拟LLM响应
	response := fmt.Sprintf("LLM response for prompt: %s", prompt)

	return response, nil
}

// listPlugins 列出插件
func listPlugins() {
	if PluginManager == nil {
		log.Error().Msg("Plugin manager is not initialized")
		os.Exit(1)
	}

	plugins := PluginManager.ListPlugins()

	fmt.Printf("Name\tVersion\tType\tEnabled\tDescription\n")
	for _, pluginInfo := range plugins {
		fmt.Printf("%s\t%s\t%s\t%t\t%s\n", pluginInfo.Name, pluginInfo.Version, pluginInfo.Type, pluginInfo.Enabled, pluginInfo.Description)
	}
}

// loadPlugin 加载插件
func loadPlugin(path string) {
	if PluginManager == nil {
		log.Error().Msg("Plugin manager is not initialized")
		os.Exit(1)
	}

	// 加载插件
	_, err := PluginManager.LoadPlugin(path)
	if err != nil {
		log.Error().Err(err).Str("path", path).Msg("Failed to load plugin")
		os.Exit(1)
	}

	log.Info().Str("path", path).Msg("Plugin loaded")
}

// unloadPlugin 卸载插件
func unloadPlugin(name string) {
	if PluginManager == nil {
		log.Error().Msg("Plugin manager is not initialized")
		os.Exit(1)
	}

	// 卸载插件
	if err := PluginManager.UnloadPlugin(name); err != nil {
		log.Error().Err(err).Str("name", name).Msg("Failed to unload plugin")
		os.Exit(1)
	}

	log.Info().Str("name", name).Msg("Plugin unloaded")
}

// enablePlugin 启用插件
func enablePlugin(name string) {
	if PluginManager == nil {
		log.Error().Msg("Plugin manager is not initialized")
		os.Exit(1)
	}

	// 启用插件
	if err := PluginManager.EnablePlugin(name); err != nil {
		log.Error().Err(err).Str("name", name).Msg("Failed to enable plugin")
		os.Exit(1)
	}

	log.Info().Str("name", name).Msg("Plugin enabled")
}

// disablePlugin 禁用插件
func disablePlugin(name string) {
	if PluginManager == nil {
		log.Error().Msg("Plugin manager is not initialized")
		os.Exit(1)
	}

	// 禁用插件
	if err := PluginManager.DisablePlugin(name); err != nil {
		log.Error().Err(err).Str("name", name).Msg("Failed to disable plugin")
		os.Exit(1)
	}

	log.Info().Str("name", name).Msg("Plugin disabled")
}

// reloadPlugin 重新加载插件
func reloadPlugin(name string) {
	if PluginManager == nil {
		log.Error().Msg("Plugin manager is not initialized")
		os.Exit(1)
	}

	// 重新加载插件
	_, err := PluginManager.ReloadPlugin(name)
	if err != nil {
		log.Error().Err(err).Str("name", name).Msg("Failed to reload plugin")
		os.Exit(1)
	}

	log.Info().Str("name", name).Msg("Plugin reloaded")
}

// initDatabase 初始化数据库
func initDatabase() {
	if Database == nil {
		var err error
		Database, err = database.NewDB(&GlobalConfig.Database)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create database")
			os.Exit(1)
		}
	}

	// 初始化数据库
	if err := Database.Init(); err != nil {
		log.Error().Err(err).Msg("Failed to initialize database")
		os.Exit(1)
	}

	log.Info().Msg("Database initialized")
}

// migrateDatabase 迁移数据库
func migrateDatabase() {
	if Database == nil {
		var err error
		Database, err = database.NewDB(&GlobalConfig.Database)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create database")
			os.Exit(1)
		}
	}

	// 迁移数据库
	if err := Database.Migrate(); err != nil {
		log.Error().Err(err).Msg("Failed to migrate database")
		os.Exit(1)
	}

	log.Info().Msg("Database migrated")
}

// backupDatabase 备份数据库
func backupDatabase(output string) {
	if Database == nil {
		var err error
		Database, err = database.NewDB(&GlobalConfig.Database)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create database")
			os.Exit(1)
		}
	}

	// 备份数据库
	if err := Database.Backup(output); err != nil {
		log.Error().Err(err).Msg("Failed to backup database")
		os.Exit(1)
	}

	log.Info().Str("output", output).Msg("Database backed up")
}

// restoreDatabase 恢复数据库
func restoreDatabase(input string) {
	if Database == nil {
		var err error
		Database, err = database.NewDB(&GlobalConfig.Database)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create database")
			os.Exit(1)
		}
	}

	// 恢复数据库
	if err := Database.Restore(input); err != nil {
		log.Error().Err(err).Msg("Failed to restore database")
		os.Exit(1)
	}

	log.Info().Str("input", input).Msg("Database restored")
}

// cleanDatabase 清理数据库
func cleanDatabase() {
	if Database == nil {
		var err error
		Database, err = database.NewDB(&GlobalConfig.Database)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create database")
			os.Exit(1)
		}
	}

	// 清理数据库
	if err := Database.Clean(); err != nil {
		log.Error().Err(err).Msg("Failed to clean database")
		os.Exit(1)
	}

	log.Info().Msg("Database cleaned")
}

// parseHeaders 解析请求头
func parseHeaders(headers []string) map[string]string {
	headerMap := make(map[string]string)

	for _, header := range headers {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			headerMap[key] = value
		}
	}

	return headerMap
}

// parseCookies 解析Cookie
func parseCookies(cookies []string) map[string]string {
	cookieMap := make(map[string]string)

	for _, cookie := range cookies {
		parts := strings.SplitN(cookie, "=", 2)
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			cookieMap[name] = value
		}
	}

	return cookieMap
}

// generateID 生成ID
func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// waitForInterrupt 等待中断信号
func waitForInterrupt() {
	// 创建一个通道来接收信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// 等待信号
	<-sigChan
}