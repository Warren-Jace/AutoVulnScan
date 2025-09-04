// Package cmd 提供命令行接口
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// reportCmd 在 commands.go 中定义

// GetReportCmd 返回报告命令
func GetReportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "report",
		Short: "报告管理",
		Long:  `报告管理命令用于生成和管理漏洞扫描报告。`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("报告命令功能待实现")
			fmt.Println("可用子命令:")
			fmt.Println("  generate - 生成报告")
			fmt.Println("  list     - 列出报告")
			fmt.Println("  view     - 查看报告")
			fmt.Println("  export   - 导出报告")
		},
	}
}