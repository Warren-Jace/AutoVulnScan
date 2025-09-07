// Package logger 提供了日志记录功能
package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Config 日志配置
type Config struct {
	Level      string `json:"level" yaml:"level"`           // 日志级别: debug, info, warn, error, fatal
	Format     string `json:"format" yaml:"format"`         // 日志格式: json, console
	Output     string `json:"output" yaml:"output"`         // 输出: stdout, file, both
	File       string `json:"file" yaml:"file"`             // 日志文件路径
	MaxSize    int    `json:"max_size" yaml:"max_size"`     // 单个日志文件最大大小(MB)
	MaxBackups int    `json:"max_backups" yaml:"max_backups"` // 保留的旧日志文件最大数量
	MaxAge     int    `json:"max_age" yaml:"max_age"`       // 保留的旧日志文件最大天数
	Compress   bool   `json:"compress" yaml:"compress"`     // 是否压缩/归档旧日志文件
	TimeFormat string `json:"time_format" yaml:"time_format"` // 时间格式
	Caller     bool   `json:"caller" yaml:"caller"`         // 是否显示调用者信息
	NoColor    bool   `json:"no_color" yaml:"no_color"`     // 是否禁用颜色
}

// Logger 日志记录器
type Logger struct {
	logger zerolog.Logger
	config *Config
}

// NewLogger 创建一个新的日志记录器
func NewLogger(config *Config) (*Logger, error) {
	// 设置默认值
	if config.Level == "" {
		config.Level = "info"
	}
	if config.Format == "" {
		config.Format = "console"
	}
	if config.Output == "" {
		config.Output = "stdout"
	}
	if config.File == "" {
		config.File = "logs/autovulnscan.log"
	}
	if config.MaxSize == 0 {
		config.MaxSize = 100
	}
	if config.MaxBackups == 0 {
		config.MaxBackups = 3
	}
	if config.MaxAge == 0 {
		config.MaxAge = 28
	}
	if config.TimeFormat == "" {
		config.TimeFormat = time.RFC3339
	}

	// 设置日志级别
	level, err := parseLevel(config.Level)
	if err != nil {
		return nil, fmt.Errorf("failed to parse log level: %w", err)
	}
	zerolog.SetGlobalLevel(level)

	// 创建zerolog日志记录器
	var zlog zerolog.Logger

	// 根据格式设置日志记录器
	switch strings.ToLower(config.Format) {
	case "json":
		zlog = zerolog.New(os.Stderr).With().Timestamp().Logger()
	case "console":
		zlog = zerolog.New(zerolog.ConsoleWriter{
			Out:        os.Stderr,
			TimeFormat: config.TimeFormat,
			NoColor:    config.NoColor,
		}).With().Timestamp().Logger()
	default:
		return nil, fmt.Errorf("unsupported log format: %s", config.Format)
	}

	// 设置调用者信息
	if config.Caller {
		zlog = zlog.With().Caller().Logger()
	}

	// 设置输出
	var writers []zerolog.LevelWriter

	switch strings.ToLower(config.Output) {
	case "stdout":
		writers = append(writers, zerolog.MultiLevelWriter(os.Stderr))
	case "file":
		fileWriter, err := createFileWriter(config)
		if err != nil {
			return nil, fmt.Errorf("failed to create file writer: %w", err)
		}
		writers = append(writers, zerolog.MultiLevelWriter(fileWriter))
	case "both":
		writers = append(writers, zerolog.MultiLevelWriter(os.Stderr))
		fileWriter, err := createFileWriter(config)
		if err != nil {
			return nil, fmt.Errorf("failed to create file writer: %w", err)
		}
		writers = append(writers, zerolog.MultiLevelWriter(fileWriter))
	default:
		return nil, fmt.Errorf("unsupported log output: %s", config.Output)
	}

	// 设置多输出
	if len(writers) > 1 {
		// 将[]zerolog.LevelWriter转换为[]io.Writer
		ioWriters := make([]io.Writer, len(writers))
		for i, w := range writers {
			ioWriters[i] = w
		}
		zlog = zlog.Output(zerolog.MultiLevelWriter(ioWriters...))
	} else if len(writers) == 1 {
		zlog = zlog.Output(writers[0])
	}

	// 创建Logger实例
	logger := &Logger{
		logger: zlog,
		config: config,
	}

	// 设置全局日志记录器
	log.Logger = zlog

	return logger, nil
}

// createFileWriter 创建文件写入器
func createFileWriter(config *Config) (*lumberjack.Logger, error) {
	// 确保目录存在
	dir := filepath.Dir(config.File)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// 创建文件写入器
	return &lumberjack.Logger{
		Filename:   config.File,
		MaxSize:    config.MaxSize,
		MaxBackups: config.MaxBackups,
		MaxAge:     config.MaxAge,
		Compress:   config.Compress,
	}, nil
}

// parseLevel 解析日志级别
func parseLevel(level string) (zerolog.Level, error) {
	switch strings.ToLower(level) {
	case "debug":
		return zerolog.DebugLevel, nil
	case "info":
		return zerolog.InfoLevel, nil
	case "warn", "warning":
		return zerolog.WarnLevel, nil
	case "error":
		return zerolog.ErrorLevel, nil
	case "fatal":
		return zerolog.FatalLevel, nil
	case "panic":
		return zerolog.PanicLevel, nil
	case "trace":
		return zerolog.TraceLevel, nil
	default:
		return zerolog.InfoLevel, fmt.Errorf("unknown log level: %s", level)
	}
}

// Debug 记录调试级别的日志
func (l *Logger) Debug() *zerolog.Event {
	return l.logger.Debug()
}

// Info 记录信息级别的日志
func (l *Logger) Info() *zerolog.Event {
	return l.logger.Info()
}

// Warn 记录警告级别的日志
func (l *Logger) Warn() *zerolog.Event {
	return l.logger.Warn()
}

// Error 记录错误级别的日志
func (l *Logger) Error() *zerolog.Event {
	return l.logger.Error()
}

// Fatal 记录致命级别的日志
func (l *Logger) Fatal() *zerolog.Event {
	return l.logger.Fatal()
}

// Panic 记录恐慌级别的日志
func (l *Logger) Panic() *zerolog.Event {
	return l.logger.Panic()
}

// Trace 记录跟踪级别的日志
func (l *Logger) Trace() *zerolog.Event {
	return l.logger.Trace()
}

// With 创建带有额外字段的日志事件
func (l *Logger) With() zerolog.Context {
	return l.logger.With()
}

// Log 记录指定级别的日志
func (l *Logger) Log(level zerolog.Level) *zerolog.Event {
	return l.logger.WithLevel(level)
}

// SetLevel 设置日志级别
func (l *Logger) SetLevel(level string) error {
	logLevel, err := parseLevel(level)
	if err != nil {
		return err
	}

	zerolog.SetGlobalLevel(logLevel)
	l.config.Level = level
	return nil
}

// GetLevel 获取日志级别
func (l *Logger) GetLevel() string {
	return l.config.Level
}

// GetConfig 获取日志配置
func (l *Logger) GetConfig() *Config {
	return l.config
}

// UpdateConfig 更新日志配置
func (l *Logger) UpdateConfig(config *Config) error {
	newLogger, err := NewLogger(config)
	if err != nil {
		return err
	}

	l.logger = newLogger.logger
	l.config = newLogger.config
	log.Logger = l.logger

	return nil
}

// Close 关闭日志记录器
func (l *Logger) Close() error {
	// 对于zerolog，不需要显式关闭
	return nil
}

// GetCallerInfo 获取调用者信息
func GetCallerInfo() (string, string, int) {
	// 跳过3帧: GetCallerInfo, 调用者包装函数, 实际调用者
	_, file, line, ok := runtime.Caller(3)
	if !ok {
		return "", "", 0
	}

	dir, filename := filepath.Split(file)
	pkg := filepath.Base(dir)

	return pkg, filename, line
}

// DebugWithContext 记录带有上下文的调试日志
func (l *Logger) DebugWithContext(ctx map[string]interface{}, msg string) {
	event := l.Debug()
	for k, v := range ctx {
		event = event.Interface(k, v)
	}
	event.Msg(msg)
}

// InfoWithContext 记录带有上下文的信息日志
func (l *Logger) InfoWithContext(ctx map[string]interface{}, msg string) {
	event := l.Info()
	for k, v := range ctx {
		event = event.Interface(k, v)
	}
	event.Msg(msg)
}

// WarnWithContext 记录带有上下文的警告日志
func (l *Logger) WarnWithContext(ctx map[string]interface{}, msg string) {
	event := l.Warn()
	for k, v := range ctx {
		event = event.Interface(k, v)
	}
	event.Msg(msg)
}

// ErrorWithContext 记录带有上下文的错误日志
func (l *Logger) ErrorWithContext(ctx map[string]interface{}, msg string) {
	event := l.Error()
	for k, v := range ctx {
		event = event.Interface(k, v)
	}
	event.Msg(msg)
}

// FatalWithContext 记录带有上下文的致命日志
func (l *Logger) FatalWithContext(ctx map[string]interface{}, msg string) {
	event := l.Fatal()
	for k, v := range ctx {
		event = event.Interface(k, v)
	}
	event.Msg(msg)
}

// PanicWithContext 记录带有上下文的恐慌日志
func (l *Logger) PanicWithContext(ctx map[string]interface{}, msg string) {
	event := l.Panic()
	for k, v := range ctx {
		event = event.Interface(k, v)
	}
	event.Msg(msg)
}

// TraceWithContext 记录带有上下文的跟踪日志
func (l *Logger) TraceWithContext(ctx map[string]interface{}, msg string) {
	event := l.Trace()
	for k, v := range ctx {
		event = event.Interface(k, v)
	}
	event.Msg(msg)
}

// Debugf 记录格式化的调试日志
func (l *Logger) Debugf(format string, v ...interface{}) {
	l.Debug().Msgf(format, v...)
}

// Infof 记录格式化的信息日志
func (l *Logger) Infof(format string, v ...interface{}) {
	l.Info().Msgf(format, v...)
}

// Warnf 记录格式化的警告日志
func (l *Logger) Warnf(format string, v ...interface{}) {
	l.Warn().Msgf(format, v...)
}

// Errorf 记录格式化的错误日志
func (l *Logger) Errorf(format string, v ...interface{}) {
	l.Error().Msgf(format, v...)
}

// Fatalf 记录格式化的致命日志
func (l *Logger) Fatalf(format string, v ...interface{}) {
	l.Fatal().Msgf(format, v...)
}

// Panicf 记录格式化的恐慌日志
func (l *Logger) Panicf(format string, v ...interface{}) {
	l.Panic().Msgf(format, v...)
}

// Tracef 记录格式化的跟踪日志
func (l *Logger) Tracef(format string, v ...interface{}) {
	l.Trace().Msgf(format, v...)
}

// DebugErr 记录带有错误的调试日志
func (l *Logger) DebugErr(err error, msg string) {
	l.Debug().Err(err).Msg(msg)
}

// InfoErr 记录带有错误的信息日志
func (l *Logger) InfoErr(err error, msg string) {
	l.Info().Err(err).Msg(msg)
}

// WarnErr 记录带有错误的警告日志
func (l *Logger) WarnErr(err error, msg string) {
	l.Warn().Err(err).Msg(msg)
}

// ErrorErr 记录带有错误的错误日志
func (l *Logger) ErrorErr(err error, msg string) {
	l.Error().Err(err).Msg(msg)
}

// FatalErr 记录带有错误的致命日志
func (l *Logger) FatalErr(err error, msg string) {
	l.Fatal().Err(err).Msg(msg)
}

// PanicErr 记录带有错误的恐慌日志
func (l *Logger) PanicErr(err error, msg string) {
	l.Panic().Err(err).Msg(msg)
}

// TraceErr 记录带有错误的跟踪日志
func (l *Logger) TraceErr(err error, msg string) {
	l.Trace().Err(err).Msg(msg)
}

// DebugErrf 记录带有错误的格式化调试日志
func (l *Logger) DebugErrf(err error, format string, v ...interface{}) {
	l.Debug().Err(err).Msgf(format, v...)
}

// InfoErrf 记录带有错误的格式化信息日志
func (l *Logger) InfoErrf(err error, format string, v ...interface{}) {
	l.Info().Err(err).Msgf(format, v...)
}

// WarnErrf 记录带有错误的格式化警告日志
func (l *Logger) WarnErrf(err error, format string, v ...interface{}) {
	l.Warn().Err(err).Msgf(format, v...)
}

// ErrorErrf 记录带有错误的格式化错误日志
func (l *Logger) ErrorErrf(err error, format string, v ...interface{}) {
	l.Error().Err(err).Msgf(format, v...)
}

// FatalErrf 记录带有错误的格式化致命日志
func (l *Logger) FatalErrf(err error, format string, v ...interface{}) {
	l.Fatal().Err(err).Msgf(format, v...)
}

// PanicErrf 记录带有错误的格式化恐慌日志
func (l *Logger) PanicErrf(err error, format string, v ...interface{}) {
	l.Panic().Err(err).Msgf(format, v...)
}

// TraceErrf 记录带有错误的格式化跟踪日志
func (l *Logger) TraceErrf(err error, format string, v ...interface{}) {
	l.Trace().Err(err).Msgf(format, v...)
}

// 全局日志记录器实例
var globalLogger *Logger

// InitLogger 初始化全局日志记录器
func InitLogger(config *Config) error {
	logger, err := NewLogger(config)
	if err != nil {
		return err
	}

	globalLogger = logger
	return nil
}

// GetGlobalLogger 获取全局日志记录器
func GetGlobalLogger() *Logger {
	if globalLogger == nil {
		// 如果全局日志记录器未初始化，使用默认配置初始化
		defaultConfig := &Config{
			Level:      "info",
			Format:     "console",
			Output:     "stdout",
			File:       "logs/autovulnscan.log",
			MaxSize:    100,
			MaxBackups: 3,
			MaxAge:     28,
			Compress:   true,
			TimeFormat: time.RFC3339,
			Caller:     true,
			NoColor:    false,
		}

		logger, err := NewLogger(defaultConfig)
		if err != nil {
			// 如果初始化失败，使用最简单的日志记录器
			zerolog.SetGlobalLevel(zerolog.InfoLevel)
			globalLogger = &Logger{
				logger: zerolog.New(os.Stderr).With().Timestamp().Logger(),
				config: defaultConfig,
			}
			log.Logger = globalLogger.logger
			return globalLogger
		}

		globalLogger = logger
		log.Logger = globalLogger.logger
	}

	return globalLogger
}

// Debug 记录调试级别的日志
func Debug() *zerolog.Event {
	logger := GetGlobalLogger()
	return logger.Debug()
}

// Info 记录信息级别的日志
func Info() *zerolog.Event {
	logger := GetGlobalLogger()
	return logger.Info()
}

// Warn 记录警告级别的日志
func Warn() *zerolog.Event {
	logger := GetGlobalLogger()
	return logger.Warn()
}

// Error 记录错误级别的日志
func Error() *zerolog.Event {
	logger := GetGlobalLogger()
	return logger.Error()
}

// Fatal 记录致命级别的日志
func Fatal() *zerolog.Event {
	logger := GetGlobalLogger()
	return logger.Fatal()
}

// Panic 记录恐慌级别的日志
func Panic() *zerolog.Event {
	logger := GetGlobalLogger()
	return logger.Panic()
}

// Trace 记录跟踪级别的日志
func Trace() *zerolog.Event {
	logger := GetGlobalLogger()
	return logger.Trace()
}

// With 创建带有额外字段的日志事件
func With() zerolog.Context {
	logger := GetGlobalLogger()
	return logger.With()
}

// Log 记录指定级别的日志
func Log(level zerolog.Level) *zerolog.Event {
	logger := GetGlobalLogger()
	return logger.Log(level)
}

// Debugf 记录格式化的调试日志
func Debugf(format string, v ...interface{}) {
	Debug().Msgf(format, v...)
}

// Infof 记录格式化的信息日志
func Infof(format string, v ...interface{}) {
	Info().Msgf(format, v...)
}

// Warnf 记录格式化的警告日志
func Warnf(format string, v ...interface{}) {
	Warn().Msgf(format, v...)
}

// Errorf 记录格式化的错误日志
func Errorf(format string, v ...interface{}) {
	Error().Msgf(format, v...)
}

// Fatalf 记录格式化的致命日志
func Fatalf(format string, v ...interface{}) {
	Fatal().Msgf(format, v...)
}

// Panicf 记录格式化的恐慌日志
func Panicf(format string, v ...interface{}) {
	Panic().Msgf(format, v...)
}

// Tracef 记录格式化的跟踪日志
func Tracef(format string, v ...interface{}) {
	Trace().Msgf(format, v...)
}

// DebugErr 记录带有错误的调试日志
func DebugErr(err error, msg string) {
	Debug().Err(err).Msg(msg)
}

// InfoErr 记录带有错误的信息日志
func InfoErr(err error, msg string) {
	Info().Err(err).Msg(msg)
}

// WarnErr 记录带有错误的警告日志
func WarnErr(err error, msg string) {
	Warn().Err(err).Msg(msg)
}

// ErrorErr 记录带有错误的错误日志
func ErrorErr(err error, msg string) {
	Error().Err(err).Msg(msg)
}

// FatalErr 记录带有错误的致命日志
func FatalErr(err error, msg string) {
	Fatal().Err(err).Msg(msg)
}

// PanicErr 记录带有错误的恐慌日志
func PanicErr(err error, msg string) {
	Panic().Err(err).Msg(msg)
}

// TraceErr 记录带有错误的跟踪日志
func TraceErr(err error, msg string) {
	Trace().Err(err).Msg(msg)
}