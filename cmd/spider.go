package cmd

import (
	"fmt"
	"os"

	"autovulnscan/internal/config"
	"autovulnscan/internal/core"
	"autovulnscan/internal/logger"
	"autovulnscan/internal/output"

	"github.com/spf13/cobra"
)

var spiderCmd = &cobra.Command{
	Use:   "spider",
	Short: "Crawl a website and scan for vulnerabilities",
	Long:  `Spider mode crawls a given URL, discovers endpoints, and performs vulnerability checks.`,
	Run: func(cmd *cobra.Command, args []string) {
		url, _ := cmd.Flags().GetString("url")
		if url == "" {
			fmt.Println("Please provide a URL with the -u flag.")
			os.Exit(1)
		}

		// Load configuration
		cfg, err := config.LoadConfig(configFile)
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			os.Exit(1)
		}

		// Setup logger
		logger.Setup(logger.Config{
			Level:      "info",
			File:       "autovulnscan.log",
			JSONFormat: false,
		})

		// Create orchestrator
		orchestrator, err := core.NewOrchestrator(&cfg, url)
		if err != nil {
			fmt.Printf("Error creating orchestrator: %v\n", err)
			os.Exit(1)
		}

		// Create reporter
		reporter, err := output.NewReporter(cfg.Reporting)
		if err != nil {
			fmt.Printf("Error creating reporter: %v\n", err)
			os.Exit(1)
		}
		defer reporter.Close()

		// Start scan
		orchestrator.Start(reporter)
	},
}

func init() {
	rootCmd.AddCommand(spiderCmd)
	spiderCmd.Flags().StringP("url", "u", "", "Target URL to scan")
	spiderCmd.Flags().StringP("file", "f", "", "File containing a list of URLs to scan")
} 