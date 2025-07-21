// Package logger provides logging functionalities for the AutoVulnScan application.
package logger

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Config holds the configuration for the logger.
type Config struct {
	Level      string `mapstructure:"level"`
	File       string `mapstructure:"file"`
	JSONFormat bool   `mapstructure:"json_format"`
}

// Setup configures the global logger based on the provided configuration.
func Setup(cfg Config) {
	var writers []io.Writer

	// Console writer
	consoleWriter := zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}
	writers = append(writers, consoleWriter)

	// File writer
	if cfg.File != "" {
		logFile, err := os.OpenFile(cfg.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to open log file")
		}
		if cfg.JSONFormat {
			writers = append(writers, logFile)
		} else {
			writers = append(writers, zerolog.ConsoleWriter{Out: logFile, TimeFormat: time.RFC3339, NoColor: true})
		}
	}

	multiWriter := zerolog.MultiLevelWriter(writers...)
	log.Logger = zerolog.New(multiWriter).With().Timestamp().Logger()

	SetLevel(cfg.Level)

	log.Info().Msg("Logger initialized")
}

// SetLevel sets the global logging level.
func SetLevel(level string) {
	lvl, err := zerolog.ParseLevel(level)
	if err != nil {
		log.Warn().Msgf("Unknown log level '%s', defaulting to 'info'", level)
		lvl = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(lvl)
}
