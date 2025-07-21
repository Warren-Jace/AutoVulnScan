// Package cmd contains the command-line interface logic for AutoVulnScan.
// It uses the Cobra library to create a powerful and flexible CLI.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const Version = "1.0.0"

var (
	configFile string
	outputDir  string

	rootCmd = &cobra.Command{
		Use:   "autovulnscan",
		Short: "AutoVulnScan is an intelligent, automated vulnerability scanner.",
		Long: `A comprehensive and modular vulnerability scanning tool that combines
dynamic crawling, parameter analysis, and AI-powered detection.`,
		Version: Version,
	}
)

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "Path to the configuration file (default is config.yaml)")
	rootCmd.PersistentFlags().StringVarP(&outputDir, "output", "o", "", "Directory to save output files (overrides config)")
	rootCmd.SetVersionTemplate(`{{printf "%s\n" .Version}}`)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if configFile != "" {
		// Use config file from the flag.
		fmt.Fprintln(os.Stderr, "Using config file:", configFile)
	}
} 