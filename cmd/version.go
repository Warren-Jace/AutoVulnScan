// Package cmd 提供命令行接口
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// GetVersionCmd 返回版本命令
func GetVersionCmd() *cobra.Command {
	var versionCmd = &cobra.Command{
		Use:   "version",
		Short: "显示版本信息",
		Long:  `显示应用程序的版本信息`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("AutoVulnScan v1.0.0")
			fmt.Println("Build: 2023-01-01")
			fmt.Println("Go Version: go1.19")
		},
	}

	return versionCmd
}