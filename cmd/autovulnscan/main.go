package main

import (
	"autovulnscan/internal/config"
	"autovulnscan/internal/core"
	"autovulnscan/internal/logger"
	"context"

	"github.com/go-redis/redis/v8"
	"github.com/rs/zerolog/log"
)

func main() {
	// --- Phase 1: Initialization ---
	logger.Setup()
	log.Info().Msg("[Phase 1/3] Starting Initialization...")

	cfg, err := config.LoadConfig("config/vuln_config.yaml")
	if err != nil {
		log.Fatal().Err(err).Msg("[Phase 1/3] Failed to load configuration")
	}
	log.Info().Msg("[Phase 1/3] Configuration loaded.")

	var redisClient *redis.Client
	// TODO: Add proper Redis connection string to config
	// if cfg.Redis.Enabled {
	// 	client, err := redis.NewClient(context.Background(), cfg.Redis.URL)
	// 	if err != nil {
	// 		log.Warn().Err(err).Msg("Failed to connect to Redis, proceeding without it.")
	// 	} else {
	// 		log.Info().Msg("Successfully connected to Redis.")
	// 		redisClient = client.Client
	// 	}
	// }

	log.Info().Msg("[Phase 1/3] Initialization complete.")

	// --- Create and Run Orchestrator ---
	orchestrator := core.NewOrchestrator(cfg, redisClient)
	orchestrator.Run(context.Background())
}