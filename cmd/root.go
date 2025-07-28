// Package cmd 包含了 AutoVulnScan 的所有命令行相关逻辑。
// 本项目使用 Cobra 库来构建强大的命令行应用程序。
package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"autovulnscan/internal/config"
	"autovulnscan/internal/logger"
	"autovulnscan/internal/version"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// 应用程序信息
var (
	// Version 应用版本号，通过构建时注入
	Version = "dev"
	// BuildTime 构建时间，通过构建时注入
	BuildTime = "unknown"
	// GitCommit Git提交哈希，通过构建时注入
	GitCommit = "unknown"
	// GoVersion Go版本信息
	GoVersion = runtime.Version()
)

// 全局配置变量
var (
	configFile string // 配置文件路径
	outputDir  string // 输出目录
	verbose    bool   // 详细输出模式
	quiet      bool   // 静默模式
	logLevel   string // 日志级别
	profile    bool   // 性能分析模式
	
	// 全局配置实例
	globalConfig *config.Config
	// 全局上下文
	globalCtx    context.Context
	globalCancel context.CancelFunc
)

// rootCmd 代表了应用程序的根命令
var rootCmd = &cobra.Command{
	Use:     "autovulnscan",
	Short:   "AutoVulnScan 是一个智能的自动化漏洞扫描工具",
	Long: `AutoVulnScan - 智能自动化漏洞扫描工具

一个综合性的模块化漏洞扫描工具，结合了动态爬取、参数分析和 AI 驱动的检测功能。

特性：
  • 智能爬虫引擎，支持 JavaScript 渲染
  • 多种漏洞检测模块（SQL注入、XSS、命令注入等）
  • AI 驱动的漏洞分析和误报检测
  • 灵活的配置系统和插件架构
  • 详细的报告生成和统计分析

示例：
  autovulnscan scan -t https://example.com
  autovulnscan spider -u https://example.com -d 3
  autovulnscan proxy -l :8080`,
	Version: getVersionInfo(),
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return initializeApp(cmd)
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		cleanupApp()
	},
}

// Execute 函数是命令行的主入口点
func Execute() {
	// 设置信号处理
	setupSignalHandling()
	
	// 执行根命令
	if err := rootCmd.Execute(); err != nil {
		logger.Error("命令执行失败", "error", err)
		os.Exit(1)
	}
}

// getVersionInfo 获取版本信息
func getVersionInfo() string {
	var parts []string
	
	if Version != "" && Version != "dev" {
		parts = append(parts, fmt.Sprintf("版本: %s", Version))
	} else {
		parts = append(parts, "版本: 开发版本")
	}
	
	if BuildTime != "" && BuildTime != "unknown" {
		parts = append(parts, fmt.Sprintf("构建时间: %s", BuildTime))
	}
	
	if GitCommit != "" && GitCommit != "unknown" {
		commitShort := GitCommit
		if len(GitCommit) > 8 {
			commitShort = GitCommit[:8]
		}
		parts = append(parts, fmt.Sprintf("Git提交: %s", commitShort))
	}
	
	parts = append(parts, fmt.Sprintf("Go版本: %s", GoVersion))
	parts = append(parts, fmt.Sprintf("系统架构: %s/%s", runtime.GOOS, runtime.GOARCH))
	
	return strings.Join(parts, "\n")
}

// setupSignalHandling 设置信号处理
func setupSignalHandling() {
	globalCtx, globalCancel = context.WithCancel(context.Background())
	
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	
	go func() {
		sig := <-sigChan
		logger.Info("收到终止信号，正在优雅关闭...", "signal", sig.String())
		globalCancel()
		
		// 给应用程序一些时间来清理
		time.Sleep(2 * time.Second)
		
		// 如果还没有退出，强制退出
		logger.Warn("强制退出应用程序")
		os.Exit(130) // 128 + SIGINT(2)
	}()
}

// initializeApp 初始化应用程序
func initializeApp(cmd *cobra.Command) error {
	// 1. 验证命令行参数
	if err := validateFlags(); err != nil {
		return fmt.Errorf("参数验证失败: %w", err)
	}
	
	// 2. 初始化配置
	if err := initConfig(); err != nil {
		return fmt.Errorf("配置初始化失败: %w", err)
	}
	
	// 3. 初始化日志系统
	if err := initLogger(); err != nil {
		return fmt.Errorf("日志系统初始化失败: %w", err)
	}
	
	// 4. 创建输出目录
	if err := createOutputDirectory(); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}
	
	// 5. 性能分析初始化
	if profile {
		if err := initProfiling(); err != nil {
			logger.Warn("性能分析初始化失败", "error", err)
		}
	}
	
	// 6. 打印启动信息
	printStartupInfo(cmd)
	
	return nil
}

// validateFlags 验证命令行参数
func validateFlags() error {
	// 检查互斥参数
	if verbose && quiet {
		return fmt.Errorf("--verbose 和 --quiet 参数不能同时使用")
	}
	
	// 验证日志级别
	validLogLevels := []string{"trace", "debug", "info", "warn", "error", "fatal"}
	if logLevel != "" {
		valid := false
		for _, level := range validLogLevels {
			if strings.ToLower(logLevel) == level {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("无效的日志级别: %s，有效值: %s", logLevel, strings.Join(validLogLevels, ", "))
		}
	}
	
	// 验证配置文件路径
	if configFile != "" {
		if _, err := os.Stat(configFile); os.IsNotExist(err) {
			return fmt.Errorf("配置文件不存在: %s", configFile)
		}
	}
	
	return nil
}

// initConfig 初始化配置
func initConfig() error {
	// 设置配置文件搜索路径
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	
	// 添加配置文件搜索路径
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")
	viper.AddConfigPath("$HOME/.autovulnscan")
	viper.AddConfigPath("/etc/autovulnscan")
	
	// 设置环境变量前缀
	viper.SetEnvPrefix("AUTOVULNSCAN")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	
	// 如果指定了配置文件，使用指定的文件
	if configFile != "" {
		viper.SetConfigFile(configFile)
	}
	
	// 尝试读取配置文件
	if err := viper.ReadInConfig(); err != nil {
		// 如果是明确指定的配置文件，则报错
		if configFile != "" {
			return fmt.Errorf("读取配置文件失败: %w", err)
		}
		// 否则使用默认配置
		logger.Info("未找到配置文件，使用默认配置")
	} else {
		logger.Info("使用配置文件", "file", viper.ConfigFileUsed())
	}
	
	// 加载配置到结构体
	cfg, err := config.LoadFromViper()
	if err != nil {
		return fmt.Errorf("解析配置失败: %w", err)
	}
	
	// 应用命令行参数覆盖
	applyFlagOverrides(cfg)
	
	// 验证配置
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("配置验证失败: %w", err)
	}
	
	globalConfig = cfg
	return nil
}

// applyFlagOverrides 应用命令行参数覆盖配置
func applyFlagOverrides(cfg *config.Config) {
	if outputDir != "" {
		cfg.Reporting.OutputDirectory = outputDir
	}
	
	if verbose {
		cfg.Logging.Level = "debug"
		cfg.App.Debug = true
	}
	
	if quiet {
		cfg.Logging.Level = "error"
	}
	
	if logLevel != "" {
		cfg.Logging.Level = strings.ToLower(logLevel)
	}
}

// initLogger 初始化日志系统
func initLogger() error {
	logConfig := logger.Config{
		Level:      globalConfig.Logging.Level,
		Format:     globalConfig.Logging.Structured.Format,
		Output:     "console",
		Colored:    globalConfig.Logging.Output.Console.Colored,
		TimeFormat: globalConfig.Logging.Output.Console.TimestampFormat,
	}
	
	// 如果配置了日志文件
	if globalConfig.Logging.Output.File.Enabled && globalConfig.Logging.Output.File.Path != "" {
		logConfig.Output = "file"
		logConfig.FilePath = globalConfig.Logging.Output.File.Path
		logConfig.MaxSize = globalConfig.Logging.Output.File.MaxSize
		logConfig.MaxBackups = globalConfig.Logging.Output.File.MaxBackups
		logConfig.MaxAge = globalConfig.Logging.Output.File.MaxAge
		logConfig.Compress = globalConfig.Logging.Output.File.Compress
	}
	
	return logger.InitWithConfig(logConfig)
}

// createOutputDirectory 创建输出目录
func createOutputDirectory() error {
	if globalConfig.Reporting.OutputDirectory == "" {
		return nil
	}
	
	// 创建输出目录
	if err := os.MkdirAll(globalConfig.Reporting.OutputDirectory, 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}
	
	// 检查目录权限
	if !isDirWritable(globalConfig.Reporting.OutputDirectory) {
		return fmt.Errorf("输出目录不可写: %s", globalConfig.Reporting.OutputDirectory)
	}
	
	return nil
}

// isDirWritable 检查目录是否可写
func isDirWritable(dir string) bool {
	testFile := filepath.Join(dir, ".write_test")
	file, err := os.Create(testFile)
	if err != nil {
		return false
	}
	file.Close()
	os.Remove(testFile)
	return true
}

// initProfiling 初始化性能分析
func initProfiling() error {
	// 这里可以初始化 pprof 或其他性能分析工具
	logger.Info("性能分析模式已启用")
	return nil
}

// printStartupInfo 打印启动信息
func printStartupInfo(cmd *cobra.Command) {
	if quiet {
		return
	}
	
	logger.Info("AutoVulnScan 启动",
		"version", Version,
		"command", cmd.Name(),
		"config_file", viper.ConfigFileUsed(),
		"output_dir", globalConfig.Reporting.OutputDirectory,
		"log_level", globalConfig.Logging.Level,
	)
	
	if globalConfig.App.Debug {
		logger.Debug("调试模式已启用")
		logger.Debug("运行时信息",
			"go_version", GoVersion,
			"os", runtime.GOOS,
			"arch", runtime.GOARCH,
			"cpus", runtime.NumCPU(),
		)
	}
}

// cleanupApp 清理应用程序资源
func cleanupApp() {
	if globalCancel != nil {
		globalCancel()
	}
	
	// 清理日志资源
	logger.Cleanup()
	
	// 其他清理逻辑
	if profile {
		logger.Info("性能分析结束")
	}
}

// GetGlobalConfig 获取全局配置
func GetGlobalConfig() *config.Config {
	return globalConfig
}

// GetGlobalContext 获取全局上下文
func GetGlobalContext() context.Context {
	if globalCtx == nil {
		return context.Background()
	}
	return globalCtx
}

// 自定义帮助模板
const helpTemplate = `{{with (or .Long .Short)}}{{. | trimTrailingWhitespaces}}

{{end}}{{if or .Runnable .HasSubCommands}}{{.UsageString}}{{end}}`

// 自定义使用模板
const usageTemplate = `使用方法:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

别名:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

示例:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}

可用命令:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

标志:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

全局标志:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

其他帮助主题:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

使用 "{{.CommandPath}} [command] --help" 获取更多关于命令的信息。{{end}}
`

func init() {
	// 设置自定义模板
	rootCmd.SetHelpTemplate(helpTemplate)
	rootCmd.SetUsageTemplate(usageTemplate)
	
	// 全局持久标志
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "配置文件路径")
	rootCmd.PersistentFlags().StringVarP(&outputDir, "output", "o", "", "输出目录路径")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "启用详细输出")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "启用静默模式")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "", "日志级别 (trace,debug,info,warn,error,fatal)")
	rootCmd.PersistentFlags().BoolVar(&profile, "profile", false, "启用性能分析")
	
	// 标志互斥组
	rootCmd.MarkFlagsMutuallyExclusive("verbose", "quiet")
	
	// 设置自定义版本模板
	rootCmd.SetVersionTemplate(`{{.Version}}
`)
	
	// 禁用自动排序
	rootCmd.DisableFlagsInUseLine = false
	
	// 设置完成命令
	rootCmd.CompletionOptions.DisableDefaultCmd = false
	rootCmd.CompletionOptions.HiddenDefaultCmd = true
}

// 版本命令
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "显示版本信息",
	Long:  "显示 AutoVulnScan 的详细版本信息",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(getVersionInfo())
		
		// 如果是详细模式，显示更多信息
		if verbose {
			fmt.Printf("\n构建信息:\n")
			fmt.Printf("  二进制路径: %s\n", os.Args[0])
			
			if exe, err := os.Executable(); err == nil {
				if stat, err := os.Stat(exe); err == nil {
					fmt.Printf("  文件大小: %d 字节\n", stat.Size())
					fmt.Printf("  修改时间: %s\n", stat.ModTime().Format("2006-01-02 15:04:05"))
				}
			}
			
			fmt.Printf("\n运行时信息:\n")
			fmt.Printf("  CPU 核心数: %d\n", runtime.NumCPU())
			fmt.Printf("  Goroutine 数量: %d\n", runtime.NumGoroutine())
			
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			fmt.Printf("  内存使用: %.2f MB\n", float64(m.Alloc)/1024/1024)
		}
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
