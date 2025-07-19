package logger

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Setup initializes the global logger with a file-based and console-based writer.
func Setup() {
	logFile, err := os.OpenFile("autovulnscan.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to open log file")
	}

	consoleWriter := zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}
	multi := zerolog.MultiLevelWriter(consoleWriter, logFile)

	// Set the global log level to Info, so we see all important messages.
	logger := zerolog.New(multi).Level(zerolog.InfoLevel).With().Timestamp().Logger()

	log.Logger = logger
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
