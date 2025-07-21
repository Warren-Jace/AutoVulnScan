package main

import (
	"fmt"
	"os"

	"autovulnscan/internal/config"
	"autovulnscan/internal/core"
	"autovulnscan/internal/logger"
	"autovulnscan/internal/output"
)

func main() {
	url := "http://testphp.vulnweb.com/"
	configFile := "config.yaml"

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
} 