// Package cmd 包含 AutoVulnScan 的命令行界面逻辑
// 它使用 Cobra 库创建强大且灵活的 CLI
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version 定义应用程序版本号
const Version = "1.0.0"

var (
	configFile string // 配置文件路径
	outputDir  string // 输出目录路径

	// rootCmd 定义根命令
	rootCmd = &cobra.Command{
		Use:   "autovulnscan",
		Short: "AutoVulnScan 是一个智能的自动化漏洞扫描器",
		Long: `一个综合性的模块化漏洞扫描工具，结合了动态爬取、参数分析和 AI 驱动的检测功能。`,
		Version: Version,
	}
)

// Execute 将所有子命令添加到根命令并适当设置标志
// 这由 main.main() 调用，只需要对 rootCmd 执行一次
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

// init 初始化函数，设置全局标志和配置
func init() {
	// 设置初始化配置回调
	cobra.OnInitialize(initConfig)
	
	// 添加持久性标志（所有子命令都可使用）
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "配置文件路径（默认为 config.yaml）")
	
	// 设置版本输出模板
	rootCmd.SetVersionTemplate(`{{printf "%s\n" .Version}}`)
}

// initConfig 读取配置文件和环境变量（如果设置了的话）
func initConfig() {
	if configFile != "" {
		// 使用标志指定的配置文件
		fmt.Fprintln(os.Stderr, "使用配置文件:", configFile)
	}
}
