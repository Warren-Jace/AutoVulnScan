package logger

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Setup initializes the global logger.
func Setup() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

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
