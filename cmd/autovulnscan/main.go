// Package main is the entry point for the AutoVulnScan application.
package main

import (
	"autovulnscan/internal/config"
	"autovulnscan/internal/core"
	"autovulnscan/internal/logger"
	"context"
	"fmt"
	"os"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/rs/zerolog/log"
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "Caught panic: %v\n", r)
			// Optionally print stack trace
			// debug.PrintStack()
		}
	}()
	// --- Phase 1: Initialization ---
	logger.Setup()
	log.Info().Msg("[Phase 1/3] Starting Initialization...")

	cfg, err := config.LoadConfig("config")
	if err != nil {
		log.Fatal().Err(err).Msg("[Phase 1/3] Failed to load configuration")
	}
	log.Info().Msg("[Phase 1/3] Configuration loaded.")

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
}
