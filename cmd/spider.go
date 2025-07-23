package cmd

import (
	"bufio"
	"fmt"
	"os"
	"sync"

	"autovulnscan/internal/config"
	"autovulnscan/internal/core"
	"autovulnscan/internal/logger"
	"autovulnscan/internal/output"

	"github.com/spf13/cobra"
)

// spiderCmd 定义爬虫命令
var spiderCmd = &cobra.Command{
	Use:   "spider",
	Short: "爬取网站并扫描漏洞",
	Long:  `爬虫模式爬取给定的 URL，发现端点，并执行漏洞检查。`,
	Run: func(cmd *cobra.Command, args []string) {
		// 获取命令行参数
		url, _ := cmd.Flags().GetString("url")
		file, _ := cmd.Flags().GetString("file")

		// 验证输入参数
		if url == "" && file == "" {
			fmt.Println("请使用 -u 标志提供 URL 或使用 -f 标志提供文件。")
			os.Exit(1)
		}

		// 加载配置文件
		cfg, err := config.LoadConfig(configFile)
		if err != nil {
			fmt.Printf("加载配置时出错: %v\n", err)
			os.Exit(1)
		}

		// 如果提供了输出目录，则覆盖配置中的设置
		if outputDir != "" {
			cfg.Reporting.Path = outputDir
		}

		// 设置日志记录器
		logger.Init(cfg.Debug)

		// 处理 URL 列表
		var urls []string
		
		// 添加单个 URL
		if url != "" {
			urls = append(urls, url)
		}
		
		// 从文件读取 URL 列表
		if file != "" {
			fileUrls, err := readLines(file)
			if err != nil {
				fmt.Printf("从文件读取 URL 时出错: %v\n", err)
				os.Exit(1)
			}
			urls = append(urls, fileUrls...)
		}

		// 使用协程并发扫描多个 URL
		var wg sync.WaitGroup
		for _, u := range urls {
			wg.Add(1)
			go func(targetURL string) {
				defer wg.Done()
				scanURL(targetURL, cfg) // 扫描单个 URL
			}(u)
		}
		wg.Wait() // 等待所有扫描完成
	},
}

// scanURL 扫描单个 URL
func scanURL(url string, cfg *config.Settings) {
	// 创建编排器实例
	orchestrator, err := core.NewOrchestrator(cfg, url)
	if err != nil || orchestrator == nil {
		fmt.Printf("为 %s 创建编排器时出错: %v\n", url, err)
		return
	}

	// 创建报告器实例
	reporter, err := output.NewReporter(cfg.Reporting)
	if err != nil {
		fmt.Printf("为 %s 创建报告器时出错: %v\n", url, err)
		return
	}
	defer reporter.Close() // 确保报告器正确关闭

	// 开始扫描
	orchestrator.Start(reporter)
}

// readLines 从文件中读取所有行
func readLines(path string) ([]string, error) {
	// 打开文件
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// 逐行读取文件内容
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// init 初始化函数，注册 spider 命令和其标志
func init() {
	// 将 spider 命令添加到根命令
	rootCmd.AddCommand(spiderCmd)
	
	// 添加命令特定的标志
	spiderCmd.Flags().StringP("url", "u", "", "要扫描的目标 URL")
	spiderCmd.Flags().StringP("file", "f", "", "包含要扫描的 URL 列表的文件")
	spiderCmd.Flags().StringVarP(&outputDir, "output-dir", "o", "", "保存输出文件的目录（覆盖配置）")
}
