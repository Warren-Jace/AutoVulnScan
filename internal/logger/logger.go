// Package logger 提供了对应用程序日志记录功能的封装。
// 它基于 "github.com/rs/zerolog" 库，这是一个高性能、结构化的JSON日志库。
package logger

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Init 函数用于初始化全局的日志记录器。
func Init(debug bool, logFilePath string) {
	logLevel := zerolog.InfoLevel
	if debug {
		logLevel = zerolog.DebugLevel
	}
	zerolog.SetGlobalLevel(logLevel)

	var writers []io.Writer

	// 控制台输出
	consoleWriter := zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: "2006-01-02T15:04:05Z07:00",
		NoColor:    false,
	}
	consoleWriter.FormatLevel = func(i interface{}) string {
		return strings.ToUpper(fmt.Sprintf("| %-6s|", i))
	}
	consoleWriter.FormatCaller = func(i interface{}) string {
		s, ok := i.(string)
		if !ok {
			return "???:0 >"
		}
		parts := strings.Split(s, "/")
		if len(parts) > 2 {
			s = strings.Join(parts[len(parts)-2:], "/")
		}
		return s + " >"
	}
	consoleWriter.FormatMessage = func(i interface{}) string {
		return fmt.Sprintf(" %-40s |", i)
	}
	writers = append(writers, consoleWriter)

	// 文件输出
	if logFilePath != "" {
		file, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
		if err == nil {
			writers = append(writers, file)
		} else {
			log.Error().Err(err).Msg("无法打开日志文件")
		}
	}

	multiWriter := io.MultiWriter(writers...)
	log.Logger = zerolog.New(multiWriter).With().Timestamp().Caller().Logger()
}
