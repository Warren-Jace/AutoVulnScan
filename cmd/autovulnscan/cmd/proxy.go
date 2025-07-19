// Package cmd provides the command-line interface for AutoVulnScan.
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// proxyCmd represents the proxy command
var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Run in passive proxy mode to scan traffic",
	Long: `In proxy mode, AutoVulnScan acts as a local HTTP proxy,
passively scanning all traffic that passes through it for vulnerabilities.
This mode is ideal for manual testing or for integrating with other tools.

This feature is not yet implemented.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Proxy mode is not yet implemented. Coming soon!")
	},
}

func init() {
	rootCmd.AddCommand(proxyCmd)
}
