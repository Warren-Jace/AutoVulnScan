// Package logger 提供了对应用程序日志记录功能的封装。
// 它基于 "github.com/rs/zerolog" 库，这是一个高性能、结构化的JSON日志库。
package logger

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Init 函数用于初始化全局的日志记录器。
// 它应该在应用程序启动时尽早被调用。
//
// 参数:
//
//	debug (bool): 一个布尔值，如果为 true，日志级别将设置为 Debug，否则设置为 Info。
//
// 注意:
//
//	此函数直接配置了 zerolog 的全局 logger (log.Logger)。
//	在大型或复杂的应用中，更好的做法可能是创建一个 logger 实例并通过依赖注入的方式传递它，
//	以避免对全局状态的依赖。但对于当前项目规模，使用全局 logger 是一个简单有效的方案。
func Init(debug bool) {
	// 默认日志级别为 Info。
	logLevel := zerolog.InfoLevel
	if debug {
		// 如果开启了调试模式，将日志级别设置为 Debug。
		logLevel = zerolog.DebugLevel
	}

	// 设置全局日志级别。
	zerolog.SetGlobalLevel(logLevel)

	// 配置日志输出格式。
	// ConsoleWriter 提供了更易于人类阅读的彩色输出。
	output := zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}

	// 自定义日志字段的格式
	output.FormatLevel = func(i interface{}) string {
		return strings.ToUpper(fmt.Sprintf("| %-6s|", i))
	}
	output.FormatMessage = func(i interface{}) string {
		return fmt.Sprintf("%s", i)
	}
	output.FormatFieldName = func(i interface{}) string {
		return fmt.Sprintf("%s:", i)
	}
	output.FormatFieldValue = func(i interface{}) string {
		return fmt.Sprintf("%s", i)
	}

	// 创建一个包含时间戳和调用者信息的 logger 实例
	log.Logger = zerolog.New(output).With().Timestamp().Caller().Logger()
}
