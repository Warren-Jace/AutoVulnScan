package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"autovulnscan/internal/vulnscan"
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
		config := vulnscan.EngineConfig{
			Concurrency: 5,
			Timeout:     30 * time.Second,
			RateLimit:   10,
			RetryCount:  3,
			LLMEnabled:  scanLLMPayload || scanLLMAnalyze,
			LLMConfig: vulnscan.LLMConfig{
				Provider:           "deepseek",
				APIKey:             "sk-bb716bfbdb56496aa8eba12fd7400a70",
				Model:              "deepseek-v3",
				PayloadGeneration:  scanLLMPayload,
				ResultAnalysis:     scanLLMAnalyze,
				ConfidenceThreshold: 0.7,
				MaxAnalysisTime:    300,
				BatchSize:          10,
			},
		}

		// 创建扫描引擎
		engine, err := vulnscan.NewEngine(config)
		if err != nil {
			fmt.Printf("❌ Error creating scan engine: %v\n", err)
			return
		}

		// 启动扫描引擎
		if err := engine.Start(); err != nil {
			fmt.Printf("❌ Error starting scan engine: %v\n", err)
			return
		}
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
			request := vulnscan.ScanRequest{
				URL:       target,
				Module:    scanModule,
				Severity:  scanSeverity,
				Verify:    scanVerify,
				Timeout:   30 * time.Second,
			}

			// 添加自定义载荷（如果指定）
			if scanCustomFile != "" {
				customPayloads, err := readCustomPayloads(scanCustomFile)
				if err != nil {
					fmt.Printf("⚠️  Warning: Failed to load custom payloads: %v\n", err)
				} else {
					request.CustomPayloads = customPayloads
				}
			}

			// 提交扫描请求
			if err := engine.QueueRequest(request); err != nil {
				fmt.Printf("❌ Error queuing scan request: %v\n", err)
				continue
			}
		}

		// 等待所有扫描完成
		fmt.Println("\n⏳ Waiting for all scans to complete...")
		results := make([]vulnscan.Vulnerability, 0)
		for result := range engine.VulnerabilityChan() {
			results = append(results, result)
			fmt.Printf("🔍 Found vulnerability: %s at %s\n", result.Type, result.URL)
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
func saveScanResults(results []vulnscan.Vulnerability, outputDir, module string) error {
	timestamp := time.Now().Format("20060102_150405")
	filename := filepath.Join(outputDir, fmt.Sprintf("scan_%s_%s.json", module, timestamp))

	// 这里简化为JSON格式，实际实现中应该支持多种格式
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// 写入结果
	for _, result := range results {
		fmt.Fprintf(file, "URL: %s\n", result.URL)
		fmt.Fprintf(file, "Type: %s\n", result.Type)
		fmt.Fprintf(file, "Severity: %s\n", result.Severity)
		fmt.Fprintf(file, "Description: %s\n", result.Description)
		fmt.Fprintf(file, "---\n")
	}

	return nil
}