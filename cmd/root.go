// Package cmd 包含了 AutoVulnScan 的所有命令行相关逻辑。
// 本项目使用 Cobra 库来构建强大的命令行应用程序。
package cmd

import (
	"fmt"
	"os"

	"autovulnscan/internal/config"
	"autovulnscan/internal/logger"

	"github.com/spf13/cobra"
)

// Version 定义了当前应用的版本号。
const Version = "1.0.0"

var (
	configFile string // configFile 用于存储配置文件的路径。
	outputDir  string // outputDir 用于存储扫描结果的输出目录。

	// rootCmd 代表了应用程序的根命令。
	// 当没有其他子命令被指定时，这个命令将被执行。
	rootCmd = &cobra.Command{
		Use:     "autovulnscan",
		Short:   "AutoVulnScan 是一个智能的自动化漏洞扫描工具",
		Long:    `一个综合性的模块化漏洞扫描工具，结合了动态爬取、参数分析和 AI 驱动的检测功能。`,
		Version: Version,
	}
)

// Execute 函数是命令行的主入口点。
// 它负责执行 rootCmd。
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	// cobra.OnInitialize 注册一个或多个在命令执行前运行的函数。
	// 这里我们用它来调用 initConfig 函数，初始化配置。
	cobra.OnInitialize(initConfig)

	// PersistentFlags 是指该命令及其所有子命令都可见的标志。
	// 这里我们定义了一个 "config" 标志，用于指定配置文件。
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "配置文件路径 (默认为 config.yaml)")

	// 设置自定义的版本模板。
	rootCmd.SetVersionTemplate(`{{printf "%s\n" .Version}}`)
}

// initConfig 函数用于处理配置的初始化。
// 目前，它只打印出正在使用的配置文件路径。
// 在未来，这里可以扩展以加载和解析配置文件。
func initConfig() {
	// 1. 加载配置
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: 无法加载配置文件: %v\n", err)
		os.Exit(1)
	}

	// 2. 初始化日志记录器
	logger.Init(cfg.Debug, cfg.Log.FilePath)
}
