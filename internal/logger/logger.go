// Package logger 封装了日志记录功能，使用了zerolog库。
// 它提供了一个可配置的日志记录器，支持不同的日志级别（如debug, info, warn, error），
// 并能将日志输出到控制台和文件中。
package logger

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Init 初始化全局日志记录器。
//
// 参数:
//
//	debug (bool): 如果为true，日志级别将设置为Debug，否则为Info。
//
// 此函数会配置zerolog以同时向控制台和名为 "autovulnscan.log" 的文件写入日志。
// 控制台输出是彩色的、人类可读的格式，而文件输出是JSON格式，便于机器解析。
func Init(debug bool) {
	// 默认日志级别为Info
	logLevel := zerolog.InfoLevel
	if debug {
		// 如果启用了debug模式，则将日志级别设置为Debug
		logLevel = zerolog.DebugLevel
	}

	// 配置控制台输出
	// ConsoleWriter 提供了彩色的、人类友好的日志格式。
	consoleWriter := zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: time.RFC3339, // 设置时间格式
	}

	// 配置文件输出
	// 日志将以追加模式写入 "autovulnscan.log" 文件。
	// 如果文件不存在，则会自动创建。
	logFile, err := os.OpenFile("autovulnscan.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
	if err != nil {
		// 如果打开日志文件失败，程序将以致命错误退出。
		log.Fatal().Err(err).Msg("无法打开日志文件")
	}

	// 创建一个MultiLevelWriter，将日志同时写入控制台和文件。
	multi := io.MultiWriter(consoleWriter, logFile)

	// 设置全局日志记录器
	// With().Timestamp() 会为每条日志自动添加时间戳。
	// Caller() 会记录调用日志函数的文件名和行号。
	log.Logger = zerolog.New(multi).
		Level(logLevel).
		With().
		Timestamp().
		Caller().
		Logger()

	log.Info().Msg("日志系统初始化完成")
}
