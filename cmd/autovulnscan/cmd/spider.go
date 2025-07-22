// Package cmd provides the command-line interface for AutoVulnScan.
package cmd

import (
	"fmt"
	"os"
	"sync"

	"autovulnscan/internal/config"
	"autovulnscan/internal/core"
	"autovulnscan/internal/logger"
	"autovulnscan/internal/output"
	"autovulnscan/internal/requester"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// NewSpiderCmd creates the spider command.
func NewSpiderCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "spider",
		Short: "Run the spider to crawl and scan a website",
		Run: func(cmd *cobra.Command, args []string) {
			targetURL, _ := cmd.Flags().GetString("url")
			if targetURL == "" {
				fmt.Println("Please provide a target URL with -u or --url")
				os.Exit(1)
			}

			cfg, err := config.Load()
			if err != nil {
				log.Fatal().Err(err).Msg("Failed to load settings")
			}

			logger.Init(cfg.Log.Level, cfg.Log.File)
			log.Info().Msg("Logger initialized")

			// 1. Create dependencies
			httpClient := requester.NewHTTPClient(cfg.Spider.Timeout, cfg.Spider.UserAgents)
			reporter, err := output.NewReporter(cfg.Reporting)
			if err != nil {
				log.Fatal().Err(err).Msg("Failed to create reporter")
			}

			// 2. Create the orchestrator with its dependencies
			orchestrator, err := core.NewOrchestrator(cfg, httpClient, reporter, targetURL)
			if err != nil {
				log.Fatal().Err(err).Msg("Failed to create orchestrator")
			}

			// 3. Start the process and wait for it to complete
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				orchestrator.Start()
			}()
			wg.Wait()

			// 4. Cleanly close resources
			reporter.Close()
			log.Info().Msg("Scan finished.")
		},
	}

	cmd.Flags().StringP("url", "u", "", "Target URL to scan")
	cmd.MarkFlagRequired("url")

	return cmd
}
