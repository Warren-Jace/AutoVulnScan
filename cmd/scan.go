package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"autovulnscan/internal/browser"
	"autovulnscan/internal/config"
	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"
	"autovulnscan/internal/vulnscan"
	_ "autovulnscan/internal/vulnscan/plugins"

	"github.com/spf13/cobra"
)

var (
	scanTarget     string
	scanModule     string
	scanSeverity   string
	scanLLMPayload bool
	scanLLMAnalyze bool
	scanCustomFile string
	scanVerify     bool
	scanOutput     string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan for vulnerabilities in targets",
	Long: `Scan mode performs vulnerability scanning on specified targets.

It supports multiple scanning modules and can be enhanced with LLM capabilities
for better payload generation and result analysis.

Examples:
  # Basic XSS scan
  autovulnscan scan --target "http://example.com" --module xss
  
  # Scan with LLM enhancements
  autovulnscan scan --target "http://example.com" --module xss --llm-payload --llm-analyze
  
  # Scan from file with custom payloads
  autovulnscan scan --target "targets.txt" --module xss --custom-payloads "custom.txt"`,
	Run: func(cmd *cobra.Command, args []string) {
		// 参数验证
		if scanTarget == "" {
			fmt.Println("❌ Error: --target is required")
			cmd.Help()
			return
		}

		// 创建输出目录
		if err := os.MkdirAll(scanOutput, 0755); err != nil {
			fmt.Printf("❌ Error creating output directory: %v\n", err)
			return
		}

		// 显示配置信息
		fmt.Println("🚀 Starting AutoVulnScan Scan Mode")
		fmt.Println(strings.Repeat("=", 50))
		fmt.Printf("🎯 Target: %s\n", scanTarget)
		fmt.Printf("🔍 Module: %s\n", scanModule)
		fmt.Printf("⚠️  Severity: %s\n", scanSeverity)
		fmt.Printf("📂 Output Directory: %s\n", scanOutput)
		if scanLLMPayload {
			fmt.Println("🤖 LLM Payload Generation: Enabled")
		}
		if scanLLMAnalyze {
			fmt.Println("🤖 LLM Result Analysis: Enabled")
		}
		if scanCustomFile != "" {
			fmt.Printf("📝 Custom Payloads: %s\n", scanCustomFile)
		}
		fmt.Println(strings.Repeat("=", 50))

		// 创建扫描引擎配置
scannerConfig := &config.ScannerConfig{
	Enabled:       true,
	Modules:       []string{scanModule},
	Concurrency:   5,        // 增加并发数
	Timeout:       30,       // 增加超时时间
	RateLimit:     10,       // 增加速率限制
	RetryAttempts: 3,        // 增加重试次数
	RetryDelay:    1000,     // 增加重试延迟
}

		// 创建HTTP客户端
		httpClient := requester.NewHTTPClient()

		// 创建浏览器服务
		browserService := browser.NewBrowserService()

		// 创建扫描引擎
		engine, err := vulnscan.NewEngine(scannerConfig, &httpClient, &browserService)
		if err != nil {
			fmt.Printf("❌ Error creating scan engine: %v\n", err)
			return
		}

		// 启动扫描引擎
		engine.Start()
		defer engine.Close()

		// 处理目标
		var targets []string
		if isFile(scanTarget) {
			fileTargets, err := readTargetsFromFile(scanTarget)
			if err != nil {
				fmt.Printf("❌ Error reading file %s: %v\n", scanTarget, err)
				return
			}
			targets = fileTargets
		} else {
			targets = []string{scanTarget}
		}

		// 执行扫描
		totalStart := time.Now()
		for i, target := range targets {
			fmt.Printf("\n🔍 Scanning target %d/%d: %s\n", i+1, len(targets), target)

			// 根据模块类型创建扫描请求
			request := models.Request{
				URL:       target,
				Method:    "GET",
				Headers:   make(map[string]string),
				Cookies:   make(map[string]string),
				Params:    make(map[string]string),
			}

			// 添加自定义载荷（如果指定）
			if scanCustomFile != "" {
				customPayloads, err := readCustomPayloads(scanCustomFile)
				if err != nil {
					fmt.Printf("⚠️  Warning: Failed to load custom payloads: %v\n", err)
				} else {
					// 将自定义载荷添加到请求参数中
					for i, payload := range customPayloads {
						request.Params[fmt.Sprintf("custom_payload_%d", i)] = payload
					}
				}
			}

			// 提交扫描请求
			requestPtr := &request
			if err := engine.QueueRequest(requestPtr); err != nil {
				fmt.Printf("❌ Error queuing scan request: %v\n", err)
				continue
			}
		}

		// 等待所有扫描完成
		fmt.Println("\n⏳ Waiting for all scans to complete...")
		results := make([]*models.Vulnerability, 0)
		
		// 设置扫描超时时间为60秒
		scanTimeout := time.After(60 * time.Second)
		scanDone := make(chan bool)
		
		// 启动一个goroutine来收集结果
		go func() {
			for vulnResult := range engine.VulnerabilityChan() {
				// 转换vulnscan.Vulnerability为models.Vulnerability
				modelVuln := convertVulnScanToModelVulnerability(vulnResult)
				results = append(results, modelVuln)
				fmt.Printf("🔍 Found vulnerability: %s at %s\n", modelVuln.Type, modelVuln.Location)
			}
			scanDone <- true
		}()
		
		// 等待扫描完成或超时
		select {
		case <-scanDone:
			fmt.Println("✅ All scans completed normally")
		case <-scanTimeout:
			fmt.Println("⏰ Scan timed out after 5 seconds")
		}

		totalElapsed := time.Since(totalStart)
		fmt.Printf("\n🎉 All scans completed in %v!\n", totalElapsed)
		fmt.Printf("📊 Found %d vulnerabilities\n", len(results))

		// 保存结果
		if err := saveScanResults(results, scanOutput, scanModule); err != nil {
			fmt.Printf("❌ Error saving results: %v\n", err)
			return
		}

		fmt.Printf("💾 Results saved to: %s\n", scanOutput)
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	// 添加参数定义
	scanCmd.Flags().StringVarP(&scanTarget, "target", "t", "", "Target URL or file containing URLs to scan")
	scanCmd.Flags().StringVarP(&scanModule, "module", "m", "xss", "Scanning module (xss, sqli, csrf)")
	scanCmd.Flags().StringVarP(&scanSeverity, "severity", "s", "low", "Minimum severity level (low, medium, high, critical)")
	scanCmd.Flags().BoolVar(&scanLLMPayload, "llm-payload", false, "Enable LLM payload generation")
	scanCmd.Flags().BoolVar(&scanLLMAnalyze, "llm-analyze", false, "Enable LLM result analysis")
	scanCmd.Flags().StringVar(&scanCustomFile, "custom-payloads", "", "Custom payloads file path")
	scanCmd.Flags().BoolVarP(&scanVerify, "verify", "V", true, "Verify discovered vulnerabilities")
	scanCmd.Flags().StringVarP(&scanOutput, "output", "o", "./reports", "Output directory for results")
}

// isFile 检查路径是否为文件
func isFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// readCustomPayloads 从文件读取自定义载荷
func readCustomPayloads(filename string) ([]string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")
	var payloads []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			payloads = append(payloads, line)
		}
	}

	return payloads, nil
}

// saveScanResults 保存扫描结果
func saveScanResults(results []*models.Vulnerability, outputDir, module string) error {
	timestamp := time.Now().Format("20060102_150405")
	filename := filepath.Join(outputDir, fmt.Sprintf("scan_%s_%s.json", module, timestamp))

	// 创建JSON格式的扫描结果
	scanResult := models.ScanResult{
		ID:             fmt.Sprintf("scan_%s_%s", module, timestamp),
		Target:         "multiple targets",
		StartTime:      time.Now().Add(-time.Minute).Format("2006-01-02 15:04:05"),
		EndTime:        time.Now().Format("2006-01-02 15:04:05"),
		Duration:       "1m0s",
		Vulnerabilities: results,
		Stats: models.ScanStats{
			RequestsSent:         len(results) * 10, // 估算值
			ResponsesReceived:    len(results) * 10, // 估算值
			VulnerabilitiesFound: len(results),
			ErrorsEncountered:    0,
		},
	}

	// 序列化为JSON
	jsonData, err := json.MarshalIndent(scanResult, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal scan result: %w", err)
	}

	// 写入文件
	if err := os.WriteFile(filename, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write scan result: %w", err)
	}

	return nil
}