// Package cmd provides the command-line interface for AutoVulnScan.
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// agentCmd represents the agent command
var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Run as a distributed scanning agent",
	Long: `In agent mode, AutoVulnScan runs as a worker node,
connecting to a central management server to receive and execute scanning tasks.
This allows for scalable, distributed scanning across multiple machines.

This feature is not yet implemented.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Agent mode is not yet implemented. Coming soon!")
	},
}

func init() {
	rootCmd.AddCommand(agentCmd)
}
