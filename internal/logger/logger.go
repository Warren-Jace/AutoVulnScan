// Package logger 提供了对应用程序日志记录功能的封装。
// 它基于 "github.com/rs/zerolog" 库，这是一个高性能、结构化的JSON日志库。
package logger

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"
	"gopkg.in/natefinch/lumberjack.v2"
)

// LogLevel 日志级别类型
type LogLevel string

const (
	// 日志级别常量
	LevelTrace LogLevel = "trace"
	LevelDebug LogLevel = "debug"
	LevelInfo  LogLevel = "info"
	LevelWarn  LogLevel = "warn"
	LevelError LogLevel = "error"
	LevelFatal LogLevel = "fatal"
	LevelPanic LogLevel = "panic"
)

// LogFormat 日志格式类型
type LogFormat string

const (
	FormatJSON    LogFormat = "json"
	FormatConsole LogFormat = "console"
	FormatText    LogFormat = "text"
)

// Config 日志配置结构
type Config struct {
	// 基础配置
	Level       LogLevel  `json:"level" yaml:"level"`             // 日志级别
	Format      LogFormat `json:"format" yaml:"format"`           // 日志格式
	EnableColor bool      `json:"enable_color" yaml:"enable_color"` // 是否启用颜色

	// 输出配置
	EnableConsole bool   `json:"enable_console" yaml:"enable_console"` // 是否输出到控制台
	EnableFile    bool   `json:"enable_file" yaml:"enable_file"`       // 是否输出到文件
	FilePath      string `json:"file_path" yaml:"file_path"`           // 日志文件路径

	// 文件轮转配置
	MaxSize    int  `json:"max_size" yaml:"max_size"`       // 单个文件最大大小(MB)
	MaxAge     int  `json:"max_age" yaml:"max_age"`         // 文件保留天数
	MaxBackups int  `json:"max_backups" yaml:"max_backups"` // 最大备份文件数
	Compress   bool `json:"compress" yaml:"compress"`       // 是否压缩备份文件

	// 高级配置
	EnableCaller     bool              `json:"enable_caller" yaml:"enable_caller"`         // 是否显示调用者信息
	EnableStackTrace bool              `json:"enable_stack_trace" yaml:"enable_stack_trace"` // 是否启用堆栈跟踪
	TimeFormat       string            `json:"time_format" yaml:"time_format"`             // 时间格式
	Fields           map[string]string `json:"fields" yaml:"fields"`                       // 全局字段
	
	// 性能配置
	BufferSize   int           `json:"buffer_size" yaml:"buffer_size"`     // 缓冲区大小
	FlushTimeout time.Duration `json:"flush_timeout" yaml:"flush_timeout"` // 刷新超时时间
}

// DefaultConfig 返回默认配置
func DefaultConfig() *Config {
	return &Config{
		Level:            LevelInfo,
		Format:           FormatConsole,
		EnableColor:      true,
		EnableConsole:    true,
		EnableFile:       false,
		MaxSize:          100,
		MaxAge:           30,
		MaxBackups:       10,
		Compress:         true,
		EnableCaller:     true,
		EnableStackTrace: false,
		TimeFormat:       time.RFC3339,
		Fields:           make(map[string]string),
		BufferSize:       4096,
		FlushTimeout:     5 * time.Second,
	}
}

// Logger 日志记录器结构
type Logger struct {
	config     *Config
	logger     zerolog.Logger
	writers    []io.Writer
	fileWriter *lumberjack.Logger
	mu         sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
}

var (
	globalLogger *Logger
	once         sync.Once
)

// Init 初始化全局日志记录器（向后兼容）
func Init(debug bool, logFilePath string) {
	config := DefaultConfig()
	if debug {
		config.Level = LevelDebug
	}
	if logFilePath != "" {
		config.EnableFile = true
		config.FilePath = logFilePath
	}
	
	InitWithConfig(config)
}

// InitWithConfig 使用配置初始化全局日志记录器
func InitWithConfig(config *Config) {
	once.Do(func() {
		var err error
		globalLogger, err = NewLogger(config)
		if err != nil {
			panic(fmt.Sprintf("初始化日志记录器失败: %v", err))
		}
		
		// 设置全局日志记录器
		log.Logger = globalLogger.logger
	})
}

// NewLogger 创建新的日志记录器实例
func NewLogger(config *Config) (*Logger, error) {
	if config == nil {
		config = DefaultConfig()
	}
	
	// 验证配置
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("配置验证失败: %w", err)
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	logger := &Logger{
		config: config,
		ctx:    ctx,
		cancel: cancel,
	}
	
	if err := logger.setupLogger(); err != nil {
		cancel()
		return nil, fmt.Errorf("设置日志记录器失败: %w", err)
	}
	
	return logger, nil
}

// validateConfig 验证配置
func validateConfig(config *Config) error {
	if config.EnableFile && config.FilePath == "" {
		return fmt.Errorf("启用文件输出时必须指定文件路径")
	}
	
	if config.MaxSize <= 0 {
		config.MaxSize = 100
	}
	
	if config.MaxAge <= 0 {
		config.MaxAge = 30
	}
	
	if config.MaxBackups < 0 {
		config.MaxBackups = 0
	}
	
	if config.TimeFormat == "" {
		config.TimeFormat = time.RFC3339
	}
	
	return nil
}

// setupLogger 设置日志记录器
func (l *Logger) setupLogger() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	// 设置全局级别
	level := l.parseLogLevel(l.config.Level)
	zerolog.SetGlobalLevel(level)
	
	// 启用错误堆栈跟踪
	if l.config.EnableStackTrace {
		zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	}
	
	// 设置时间格式
	zerolog.TimeFieldFormat = l.config.TimeFormat
	
	var writers []io.Writer
	
	// 控制台输出
	if l.config.EnableConsole {
		consoleWriter := l.createConsoleWriter()
		writers = append(writers, consoleWriter)
	}
	
	// 文件输出
	if l.config.EnableFile {
		fileWriter, err := l.createFileWriter()
		if err != nil {
			return fmt.Errorf("创建文件写入器失败: %w", err)
		}
		l.fileWriter = fileWriter
		writers = append(writers, fileWriter)
	}
	
	if len(writers) == 0 {
		return fmt.Errorf("至少需要启用一种输出方式")
	}
	
	l.writers = writers
	multiWriter := io.MultiWriter(writers...)
	
	// 创建日志记录器
	logger := zerolog.New(multiWriter)
	
	// 添加时间戳
	logger = logger.With().Timestamp().Logger()
	
	// 添加调用者信息
	if l.config.EnableCaller {
		logger = logger.With().Caller().Logger()
	}
	
	// 添加全局字段
	for key, value := range l.config.Fields {
		logger = logger.With().Str(key, value).Logger()
	}
	
	// 添加进程信息
	logger = logger.With().
		Int("pid", os.Getpid()).
		Str("hostname", getHostname()).
		Logger()
	
	l.logger = logger
	return nil
}

// createConsoleWriter 创建控制台写入器
func (l *Logger) createConsoleWriter() zerolog.ConsoleWriter {
	consoleWriter := zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: l.config.TimeFormat,
		NoColor:    !l.config.EnableColor,
	}
	
	// 自定义格式化函数
	consoleWriter.FormatLevel = func(i interface{}) string {
		level := strings.ToUpper(fmt.Sprintf("%s", i))
		switch level {
		case "TRACE":
			return colorize("TRACE", 90) // 灰色
		case "DEBUG":
			return colorize("DEBUG", 36) // 青色
		case "INFO":
			return colorize("INFO ", 32) // 绿色
		case "WARN":
			return colorize("WARN ", 33) // 黄色
		case "ERROR":
			return colorize("ERROR", 31) // 红色
		case "FATAL":
			return colorize("FATAL", 35) // 紫色
		case "PANIC":
			return colorize("PANIC", 41) // 红色背景
		default:
			return level
		}
	}
	
	consoleWriter.FormatCaller = func(i interface{}) string {
		s, ok := i.(string)
		if !ok {
			return "???:0"
		}
		
		// 简化文件路径显示
		parts := strings.Split(s, "/")
		if len(parts) > 2 {
			s = strings.Join(parts[len(parts)-2:], "/")
		}
		
		return colorize(s, 90) // 灰色
	}
	
	consoleWriter.FormatMessage = func(i interface{}) string {
		return fmt.Sprintf("%s", i)
	}
	
	consoleWriter.FormatFieldName = func(i interface{}) string {
		return colorize(fmt.Sprintf("%s=", i), 90) // 灰色
	}
	
	consoleWriter.FormatFieldValue = func(i interface{}) string {
		return fmt.Sprintf("%s", i)
	}
	
	return consoleWriter
}

// createFileWriter 创建文件写入器
func (l *Logger) createFileWriter() (*lumberjack.Logger, error) {
	// 确保目录存在
	dir := filepath.Dir(l.config.FilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("创建日志目录失败: %w", err)
	}
	
	return &lumberjack.Logger{
		Filename:   l.config.FilePath,
		MaxSize:    l.config.MaxSize,
		MaxAge:     l.config.MaxAge,
		MaxBackups: l.config.MaxBackups,
		Compress:   l.config.Compress,
		LocalTime:  true,
	}, nil
}

// parseLogLevel 解析日志级别
func (l *Logger) parseLogLevel(level LogLevel) zerolog.Level {
	switch level {
	case LevelTrace:
		return zerolog.TraceLevel
	case LevelDebug:
		return zerolog.DebugLevel
	case LevelInfo:
		return zerolog.InfoLevel
	case LevelWarn:
		return zerolog.WarnLevel
	case LevelError:
		return zerolog.ErrorLevel
	case LevelFatal:
		return zerolog.FatalLevel
	case LevelPanic:
		return zerolog.PanicLevel
	default:
		return zerolog.InfoLevel
	}
}

// colorize 为文本添加颜色
func colorize(text string, color int) string {
	return fmt.Sprintf("\x1b[%dm%s\x1b[0m", color, text)
}

// getHostname 获取主机名
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

// 日志记录方法

// Trace 记录跟踪级别日志
func (l *Logger) Trace() *zerolog.Event {
	return l.logger.Trace()
}

// Debug 记录调试级别日志
func (l *Logger) Debug() *zerolog.Event {
	return l.logger.Debug()
}

// Info 记录信息级别日志
func (l *Logger) Info() *zerolog.Event {
	return l.logger.Info()
}

// Warn 记录警告级别日志
func (l *Logger) Warn() *zerolog.Event {
	return l.logger.Warn()
}

// Error 记录错误级别日志
func (l *Logger) Error() *zerolog.Event {
	return l.logger.Error()
}

// Fatal 记录致命级别日志
func (l *Logger) Fatal() *zerolog.Event {
	return l.logger.Fatal()
}

// Panic 记录恐慌级别日志
func (l *Logger) Panic() *zerolog.Event {
	return l.logger.Panic()
}

// WithContext 创建带上下文的日志记录器
func (l *Logger) WithContext(ctx context.Context) *Logger {
	newLogger := *l
	newLogger.logger = l.logger.With().Logger()
	return &newLogger
}

// WithField 添加字段
func (l *Logger) WithField(key string, value interface{}) *Logger {
	newLogger := *l
	newLogger.logger = l.logger.With().Interface(key, value).Logger()
	return &newLogger
}

// WithFields 添加多个字段
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	newLogger := *l
	ctx := l.logger.With()
	for key, value := range fields {
		ctx = ctx.Interface(key, value)
	}
	newLogger.logger = ctx.Logger()
	return &newLogger
}

// WithError 添加错误字段
func (l *Logger) WithError(err error) *Logger {
	newLogger := *l
	newLogger.logger = l.logger.With().Err(err).Logger()
	return &newLogger
}

// UpdateLevel 动态更新日志级别
func (l *Logger) UpdateLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	l.config.Level = level
	zerolog.SetGlobalLevel(l.parseLogLevel(level))
}

// GetLevel 获取当前日志级别
func (l *Logger) GetLevel() LogLevel {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.config.Level
}

// Sync 同步日志输出
func (l *Logger) Sync() error {
	if l.fileWriter != nil {
		return l.fileWriter.Close()
	}
	return nil
}

// Close 关闭日志记录器
func (l *Logger) Close() error {
	if l.cancel != nil {
		l.cancel()
	}
	
	return l.Sync()
}

// 全局日志记录函数（向后兼容）

// Trace 全局跟踪日志
func Trace() *zerolog.Event {
	if globalLogger != nil {
		return globalLogger.Trace()
	}
	return log.Trace()
}

// Debug 全局调试日志
func Debug() *zerolog.Event {
	if globalLogger != nil {
		return globalLogger.Debug()
	}
	return log.Debug()
}

// Info 全局信息日志
func Info() *zerolog.Event {
	if globalLogger != nil {
		return globalLogger.Info()
	}
	return log.Info()
}

// Warn 全局警告日志
func Warn() *zerolog.Event {
	if globalLogger != nil {
		return globalLogger.Warn()
	}
	return log.Warn()
}

// Error 全局错误日志
func Error() *zerolog.Event {
	if globalLogger != nil {
		return globalLogger.Error()
	}
	return log.Error()
}

// Fatal 全局致命日志
func Fatal() *zerolog.Event {
	if globalLogger != nil {
		return globalLogger.Fatal()
	}
	return log.Fatal()
}

// Panic 全局恐慌日志
func Panic() *zerolog.Event {
	if globalLogger != nil {
		return globalLogger.Panic()
	}
	return log.Panic()
}

// WithField 全局添加字段
func WithField(key string, value interface{}) *Logger {
	if globalLogger != nil {
		return globalLogger.WithField(key, value)
	}
	// 返回默认实现
	newLogger, _ := NewLogger(DefaultConfig())
	return newLogger.WithField(key, value)
}

// WithFields 全局添加多个字段
func WithFields(fields map[string]interface{}) *Logger {
	if globalLogger != nil {
		return globalLogger.WithFields(fields)
	}
	// 返回默认实现
	newLogger, _ := NewLogger(DefaultConfig())
	return newLogger.WithFields(fields)
}

// WithError 全局添加错误字段
func WithError(err error) *Logger {
	if globalLogger != nil {
		return globalLogger.WithError(err)
	}
	// 返回默认实现
	newLogger, _ := NewLogger(DefaultConfig())
	return newLogger.WithError(err)
}

// GetGlobalLogger 获取全局日志记录器
func GetGlobalLogger() *Logger {
	return globalLogger
}

// SetGlobalLogger 设置全局日志记录器
func SetGlobalLogger(logger *Logger) {
	globalLogger = logger
	log.Logger = logger.logger
}

// 性能监控相关

// LoggerStats 日志记录器统计信息
type LoggerStats struct {
	LogCount     map[string]int64  `json:"log_count"`     // 各级别日志计数
	ErrorCount   int64             `json:"error_count"`   // 错误计数
	LastLogTime  time.Time         `json:"last_log_time"` // 最后日志时间
	StartTime    time.Time         `json:"start_time"`    // 启动时间
	FileSize     int64             `json:"file_size"`     // 日志文件大小
	FileRotated  int               `json:"file_rotated"`  // 文件轮转次数
}

// GetStats 获取统计信息
func (l *Logger) GetStats() *LoggerStats {
	stats := &LoggerStats{
		LogCount:    make(map[string]int64),
		StartTime:   time.Now(), // 这里应该记录实际启动时间
		LastLogTime: time.Now(),
	}
	
	// 获取文件大小
	if l.config.EnableFile && l.config.FilePath != "" {
		if fileInfo, err := os.Stat(l.config.FilePath); err == nil {
			stats.FileSize = fileInfo.Size()
		}
	}
	
	return stats
}

// HealthCheck 健康检查
func (l *Logger) HealthCheck() map[string]interface{} {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now(),
		"config":    l.config,
	}
	
	// 检查文件写入权限
	if l.config.EnableFile {
		if _, err := os.Stat(l.config.FilePath); err != nil {
			health["status"] = "unhealthy"
			health["error"] = fmt.Sprintf("日志文件不可访问: %v", err)
		}
	}
	
	return health
}

// 工具函数

// GetCallerInfo 获取调用者信息
func GetCallerInfo(skip int) (string, int, string) {
	pc, file, line, ok := runtime.Caller(skip + 1)
	if !ok {
		return "???", 0, "???"
	}
	
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return file, line, "???"
	}
	
	return file, line, fn.Name()
}

// FormatDuration 格式化持续时间
func FormatDuration(d time.Duration) string {
	if d < time.Microsecond {
		return fmt.Sprintf("%.2fns", float64(d.Nanoseconds()))
	} else if d < time.Millisecond {
		return fmt.Sprintf("%.2fμs", float64(d.Nanoseconds())/1000)
	} else if d < time.Second {
		return fmt.Sprintf("%.2fms", float64(d.Nanoseconds())/1000000)
	}
	return d.String()
}

// 中间件支持

// HTTPMiddleware HTTP日志中间件
func (l *Logger) HTTPMiddleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			
			// 包装ResponseWriter以捕获状态码
			wrapped := &responseWriter{ResponseWriter: w, statusCode: 200}
			
			// 记录请求开始
			l.Info().
				Str("method", r.Method).
				Str("url", r.URL.String()).
				Str("remote_addr", r.RemoteAddr).
				Str("user_agent", r.UserAgent()).
				Msg("HTTP请求开始")
			
			// 执行下一个处理器
			next.ServeHTTP(wrapped, r)
			
			// 记录请求完成
			duration := time.Since(start)
			event := l.Info().
				Str("method", r.Method).
				Str("url", r.URL.String()).
				Int("status", wrapped.statusCode).
				Dur("duration", duration).
				Str("duration_human", FormatDuration(duration))
			
			if wrapped.statusCode >= 400 {
				event = l.Error().
					Str("method", r.Method).
					Str("url", r.URL.String()).
					Int("status", wrapped.statusCode).
					Dur("duration", duration)
			}
			
			event.Msg("HTTP请求完成")
		})
	}
}

// responseWriter 包装ResponseWriter以捕获状态码
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *responseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}
