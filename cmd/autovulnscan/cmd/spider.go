// Package cmd contains the command-line interface logic for the AutoVulnScan application.
package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"autovulnscan/internal/config"
	"autovulnscan/internal/core"
	"autovulnscan/internal/logger"

	"github.com/go-redis/redis/v8"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	url string
)

// spiderCmd represents the scan command
var spiderCmd = &cobra.Command{
	Use:   "spider -u <target-url>",
	Short: "Crawl a website and perform a vulnerability scan (active mode)",
	Long: `The spider command initiates a full vulnerability scan by actively crawling
the target website, discovering parameters, and testing for vulnerabilities.
This is the primary mode for active scanning.`,
	Run: func(cmd *cobra.Command, args []string) {
		if url == "" {
			fmt.Println("Error: A target URL must be provided with the -u or --url flag.")
			cmd.Help()
			os.Exit(1)
		}

		// --- Phase 1: Initialization ---
		logger.Setup()
		log.Info().Msg("[Phase 1/3] Starting Initialization...")

		configPath := "config"
		if configFile != "" {
			configPath = configFile
		}
		cfg, err := config.LoadConfig(configPath)
		if err != nil {
			log.Fatal().Err(err).Msg("[Phase 1/3] Failed to load configuration")
		}
		log.Info().Str("file", "config/vuln_config.yaml").Msg("[Phase 1/3] Configuration loaded.")

		// Override reporting path if outputDir is provided via flag
		if outputDir != "" {
			cfg.Reporting.Path = outputDir
		}

		// --- Redis Initialization ---
		var redisClient *redis.Client
		if cfg.Redis.Enabled {
			// Create a context for the Redis connection attempt
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// Use the original go-redis client directly
			opts, err := redis.ParseURL(cfg.Redis.URL)
			if err != nil {
				log.Warn().Err(err).Msg("[Phase 1/3] Failed to parse Redis URL. Proceeding without Redis.")
				cfg.Redis.Enabled = false
			} else {
				redisClient = redis.NewClient(opts)
				if err := redisClient.Ping(ctx).Err(); err != nil {
					log.Warn().Err(err).Msg("[Phase 1/3] Failed to connect to Redis. Proceeding without Redis.")
					cfg.Redis.Enabled = false
					redisClient = nil
				} else {
					log.Info().Msg("[Phase 1/3] Successfully connected to Redis.")
				}
			}
		} else {
			log.Info().Msg("[Phase 1/3] Redis is disabled in the configuration.")
		}

		log.Info().Msg("[Phase 1/3] Initialization complete.")

		// --- Phase 2 & 3: Orchestration ---
		log.Info().Msg("Starting Orchestrator...")
		orchestrator, err := core.NewOrchestrator(&cfg, url)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to create orchestrator")
		}
		orchestrator.Start()
		log.Info().Msg("Orchestrator finished.")
	},
}

func init() {
	rootCmd.AddCommand(spiderCmd)
	spiderCmd.Flags().StringVarP(&url, "url", "u", "", "Target URL for the scan (required)")
	spiderCmd.MarkFlagRequired("url")
}
