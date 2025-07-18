package cmd

import (
	"context"
	"fmt"
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

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run a vulnerability scan on a target URL",
	Long: `The scan command initiates a full vulnerability scan, including crawling,
parameter analysis, and exploitation, against the specified target URL.`,
	Run: func(cmd *cobra.Command, args []string) {
		// --- Phase 1: Initialization ---
		logger.Setup()
		log.Info().Msg("[Phase 1/3] Starting Initialization...")

		cfg, err := config.LoadConfig("config")
		if err != nil {
			log.Fatal().Err(err).Msg("[Phase 1/3] Failed to load configuration")
		}
		log.Info().Msg("[Phase 1/3] Configuration loaded.")

		// Override config with flags if provided
		if url != "" {
			cfg.Target.URL = url
		}

		var redisClient *redis.Client
		if cfg.Redis.Enabled {
			opts, err := redis.ParseURL(cfg.Redis.URL)
			if err != nil {
				log.Fatal().Err(fmt.Errorf("failed to parse Redis URL: %w", err)).Msg("")
			}

			redisClient = redis.NewClient(opts)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if _, err = redisClient.Ping(ctx).Result(); err != nil {
				log.Warn().Err(err).Msg("Failed to connect to Redis, proceeding without it.")
				redisClient = nil // Disable redis if connection fails
			} else {
				log.Info().Msg("Successfully connected to Redis.")
				if err = redisClient.Del(ctx, "crawled_urls").Err(); err != nil {
					log.Warn().Err(err).Msg("Failed to clear previous scan data from Redis.")
				} else {
					log.Info().Msg("Cleared previous scan data from Redis.")
				}
			}
		}

		log.Info().Msg("[Phase 1/3] Initialization complete.")

		// --- Create and Run Orchestrator ---
		orchestrator := core.NewOrchestrator(&cfg, redisClient)
		orchestrator.Run(context.Background())
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringVarP(&url, "url", "u", "", "Target URL to scan")
}
