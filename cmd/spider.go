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

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// spiderCmd 实现了 'spider' 子命令，用于爬取网站并进行漏洞扫描。
var spiderCmd = &cobra.Command{
	Use:   "spider",
	Short: "对一个或多个目标URL进行爬取和漏洞扫描",
	Long:  `此命令会爬取指定的一个或多个URL，发现可访问的端点，并对这些端点进行一系列的安全漏洞检查。`,
	Run: func(cmd *cobra.Command, args []string) {
		// 从命令行标志中获取URL和文件路径
		url, _ := cmd.Flags().GetString("url")
		file, _ := cmd.Flags().GetString("file")

		// 确保至少提供了一个输入源
		if url == "" && file == "" {
			fmt.Println("错误: 请使用 -u <url> 或 -f <file> 标志指定目标。")
			os.Exit(1)
		}

		// 加载应用程序的配置
		cfg, err := config.LoadConfig(configFile)
		if err != nil {
			log.Fatal().Err(err).Msg("加载配置文件失败")
		}

		// 如果通过命令行指定了输出目录，它将覆盖配置文件中的设置
		if outputDir != "" {
			cfg.Reporting.Path = outputDir
		}

		// 根据配置初始化日志系统
		logger.Init(cfg.Debug)

		// 收集所有待扫描的URL
		var urls []string
		if url != "" {
			urls = append(urls, url)
		}
		if file != "" {
			fileUrls, err := readLines(file)
			if err != nil {
				log.Fatal().Err(err).Msgf("从文件 %s 读取URL失败", file)
			}
			urls = append(urls, fileUrls...)
		}

		// 使用 worker pool 模式来控制并发扫描
		numWorkers := 10 // 可以根据需要调整并发数，或将其设为可配置
		jobs := make(chan string, len(urls))
		var wg sync.WaitGroup

		for i := 0; i < numWorkers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for targetURL := range jobs {
					scanURL(targetURL, cfg)
				}
			}()
		}

		for _, u := range urls {
			jobs <- u
		}
		close(jobs)

		wg.Wait()
		log.Info().Msg("所有扫描任务完成。")
	},
}

// scanURL 负责对单个URL进行完整的扫描流程。
func scanURL(url string, cfg config.Settings) {
	log.Info().Msgf("开始扫描: %s", url)

	// 创建一个新的编排器实例来管理扫描过程
	orchestrator, err := core.NewOrchestrator(&cfg, url)
	if err != nil {
		log.Error().Err(err).Msgf("为 %s 创建编排器失败", url)
		return
	}

	// 创建一个新的报告器来处理扫描结果的输出
	reporter, err := output.NewReporter(cfg.Reporting, url)
	if err != nil {
		log.Error().Err(err).Msgf("为 %s 创建报告器失败", url)
		return
	}
	defer reporter.Close()

	// 启动扫描过程
	orchestrator.Start(reporter)
	log.Info().Msgf("完成扫描: %s", url)
}

// readLines 是一个辅助函数，用于从指定的文件路径逐行读取内容。
func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %w", err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("扫描文件时出错: %w", err)
	}
	return lines, nil
}

func init() {
	rootCmd.AddCommand(spiderCmd)

	// 为 spider 命令定义命令行标志
	spiderCmd.Flags().StringP("url", "u", "", "需要扫描的单个目标URL")
	spiderCmd.Flags().StringP("file", "f", "", "一个文件，包含每行一个的待扫描URL列表")
	spiderCmd.Flags().StringVarP(&outputDir, "output-dir", "o", "", "用于保存报告的目录 (此选项会覆盖配置文件中的设置)")
}
