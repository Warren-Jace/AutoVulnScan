// Package logger provides a flexible logging setup for the application.
package logger

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Init initializes the global logger.
func Init(debug bool) {
	logLevel := zerolog.InfoLevel
	if debug {
		logLevel = zerolog.DebugLevel
	}
	zerolog.SetGlobalLevel(logLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
}
