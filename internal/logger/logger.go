// Package logger provides logging functionalities for the AutoVulnScan application.
package logger

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Setup configures the global logger with a file and console writer.
func Setup() {
	logFile, err := os.OpenFile("autovulnscan.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to open log file")
	}

	consoleWriter := zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}
	multiWriter := zerolog.MultiLevelWriter(consoleWriter, logFile)

	log.Logger = zerolog.New(multiWriter).With().Timestamp().Logger()
	zerolog.SetGlobalLevel(zerolog.DebugLevel) // Set to Debug to see all logs

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
