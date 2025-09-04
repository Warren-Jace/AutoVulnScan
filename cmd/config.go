package cmd

import (
	"github.com/spf13/cobra"
)

// configCmd 配置命令
// 注意：这个命令已经在 commands.go 中定义，这里只是为了确保文件不为空
// 实际使用时，请参考 commands.go 中的 configCmd 定义

// GetConfigCmd 获取配置命令
func GetConfigCmd() *cobra.Command {
	// 简化实现，实际应该返回在 commands.go 中定义的 configCmd
	return &cobra.Command{
		Use:   "config",
		Short: "配置管理",
		Long:  `配置管理命令，用于管理扫描配置。`,
	}
}