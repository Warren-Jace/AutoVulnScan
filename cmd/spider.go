package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"autovulnscan/internal/crawler"
	"autovulnscan/internal/dedup"

	"github.com/spf13/cobra"
)

var spiderCmd = &cobra.Command{
	Use:   "spider",
	Short: "Spider mode: crawl and scan for vulnerabilities",
	Long: `Spider mode crawls a website starting from the given URL, 
discovers links, and performs vulnerability scanning on the found pages.

Examples:
  # Basic crawling
  autovulnscan spider --url "http://example.com" --max-pages 10
  
  # With custom timeout and debug
  autovulnscan spider --url "http://example.com" --timeout 30s --debug
  
  # From file with custom settings
  autovulnscan spider --file urls.txt --max-pages 50 --concurrency 10`,
	Run: func(cmd *cobra.Command, args []string) {
		// 获取参数
		targetURL, _ := cmd.Flags().GetString("url")
		targetFile, _ := cmd.Flags().GetString("file")
		maxPages, _ := cmd.Flags().GetInt("max-pages")
		timeout, _ := cmd.Flags().GetDuration("timeout")
		concurrency, _ := cmd.Flags().GetInt("concurrency")
		debug, _ := cmd.Flags().GetBool("debug")
		outputDir, _ := cmd.Flags().GetString("output-dir")

		// 参数验证
		if targetURL == "" && targetFile == "" {
			fmt.Println("❌ Error: Either --url or --file must be specified")
			cmd.Help()
			return
		}

		// 创建输出目录
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			fmt.Printf("❌ Error creating output directory: %v\n", err)
			return
		}

		// 显示配置信息
		fmt.Println("🚀 Starting AutoVulnScan Spider Mode")
		fmt.Println(strings.Repeat("=", 50))
		if targetURL != "" {
			fmt.Printf("🎯 Target URL: %s\n", targetURL)
		}
		if targetFile != "" {
			fmt.Printf("📁 Target File: %s\n", targetFile)
		}
		fmt.Printf("📊 Max Pages: %d\n", maxPages)
		fmt.Printf("⏱️  Timeout: %v\n", timeout)
		fmt.Printf("🔄 Concurrency: %d\n", concurrency)
		fmt.Printf("📂 Output Directory: %s\n", outputDir)
		if debug {
			fmt.Println("🐛 Debug Mode: Enabled")
		}
		fmt.Println(strings.Repeat("=", 50))

		// 处理目标
		var targets []string
		if targetFile != "" {
			fileTargets, err := readTargetsFromFile(targetFile)
			if err != nil {
				fmt.Printf("❌ Error reading file %s: %v\n", targetFile, err)
				return
			}
			targets = fileTargets
		} else {
			targets = []string{targetURL}
		}

		// 创建爬虫配置
		config := crawler.Config{
			MaxPages:    maxPages,
			Timeout:     timeout,
			UserAgent:   "AutoVulnScan/2.0.0",
			MaxDepth:    5, // 减少深度，避免无限循环
			Concurrency: 1, // 减少并发，便于调试
			Delay:       0, // 无延迟
			SimilarityConfig: dedup.SimilarityConfig{
				Enabled:          false, // 暂时关闭相似度去重
				Threshold:        5,
				Similarity:       0.95,
				VectorDimension:  128,
				MinElements:      100,
				ContentThreshold: 0.8,
				MinContentLength: 500,
			},
		}

		// 执行爬虫
		allResults := make(map[string][]string)
		totalStart := time.Now()

		for i, target := range targets {
			fmt.Printf("\n🔍 Processing target %d/%d: %s\n", i+1, len(targets), target)

			start := time.Now()
			crawler := crawler.New(config)

			if err := crawler.Start(target); err != nil {
				fmt.Printf("❌ Error crawling %s: %v\n", target, err)
				continue
			}

			elapsed := time.Since(start)
			results := crawler.GetResults()
			stats := crawler.GetStats()

			fmt.Printf("✅ Crawl completed in %v!\n", elapsed)
			fmt.Printf("📊 Found %d URLs\n", len(results))
			fmt.Printf("📈 Stats: %+v\n", stats)

			allResults[target] = results
		}

		totalElapsed := time.Since(totalStart)
		fmt.Printf("\n🎉 All targets completed in %v!\n", totalElapsed)

		// 保存结果
		if err := saveResults(allResults, outputDir); err != nil {
			fmt.Printf("❌ Error saving results: %v\n", err)
			return
		}

		fmt.Printf("💾 Results saved to: %s\n", outputDir)
	},
}

func init() {
	rootCmd.AddCommand(spiderCmd)

	// 添加参数定义
	spiderCmd.Flags().StringP("url", "u", "", "Target URL to scan")
	spiderCmd.Flags().StringP("file", "f", "", "File containing list of target URLs")
	spiderCmd.Flags().IntP("max-pages", "m", 100, "Maximum pages to crawl per target")
	spiderCmd.Flags().DurationP("timeout", "t", 30*time.Second, "Request timeout")
	spiderCmd.Flags().IntP("concurrency", "c", 5, "Number of concurrent requests")
	spiderCmd.Flags().BoolP("debug", "d", false, "Enable debug mode")
	spiderCmd.Flags().String("output-dir", "./reports", "Output directory for results")
}

// readTargetsFromFile reads URLs from a file
func readTargetsFromFile(filename string) ([]string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")
	var targets []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}

	return targets, nil
}

// saveResults saves crawling results to files
func saveResults(allResults map[string][]string, outputDir string) error {
	timestamp := time.Now().Format("20060102_150405")

	// Save summary
	summaryFile := filepath.Join(outputDir, fmt.Sprintf("spider_summary_%s.txt", timestamp))
	summary, err := os.Create(summaryFile)
	if err != nil {
		return err
	}
	defer summary.Close()

	fmt.Fprintf(summary, "AutoVulnScan Spider Results - %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(summary, "%s\n\n", strings.Repeat("=", 60))

	for target, results := range allResults {
		fmt.Fprintf(summary, "Target: %s\n", target)
		fmt.Fprintf(summary, "Found URLs: %d\n", len(results))
		fmt.Fprintf(summary, "%s\n", strings.Repeat("-", 40))

		for i, url := range results {
			fmt.Fprintf(summary, "%d. %s\n", i+1, url)
		}
		fmt.Fprintf(summary, "\n")
	}

	// Save individual target results
	for target, results := range allResults {
		safeTarget := strings.ReplaceAll(target, "://", "_")
		safeTarget = strings.ReplaceAll(safeTarget, "/", "_")
		safeTarget = strings.ReplaceAll(safeTarget, ".", "_")

		targetFile := filepath.Join(outputDir, fmt.Sprintf("spider_%s_%s.txt", safeTarget, timestamp))
		if err := os.WriteFile(targetFile, []byte(strings.Join(results, "\n")), 0644); err != nil {
			return err
		}
	}

	return nil
}
