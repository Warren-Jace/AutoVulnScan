package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Start a passive proxy to scan for XSS vulnerabilities",
	Long:  `Proxy mode starts a local HTTP proxy to passively scan all traffic for XSS vulnerabilities.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Proxy command executed")
		// Entry point for proxy logic
	},
}

func init() {
	rootCmd.AddCommand(proxyCmd)
	proxyCmd.Flags().Bool("generate-ca", false, "Generate a new CA certificate and key")
} 