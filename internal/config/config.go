// Package config 提供了配置管理功能
// 支持从文件、环境变量和命令行参数加载配置
package config

import (
	"fmt"
	"sync"

	"github.com/spf13/viper"
)

var (
	globalConfig *GlobalConfig
	configMutex  sync.RWMutex
)

// Config 表示应用程序的完整配置
type Config struct {
	// 全局配置
	Global GlobalConfig `json:"global" yaml:"global"`

	// 爬虫配置
	Crawler CrawlerConfig `json:"crawler" yaml:"crawler"`

	// 扫描器配置
	Scanner ScannerConfig `json:"scanner" yaml:"scanner"`

	// LLM配置
	LLM LLMConfig `json:"llm" yaml:"llm"`

	// 报告配置
	Report ReportConfig `json:"report" yaml:"report"`

	// 代理配置
	Proxy ProxyConfig `json:"proxy" yaml:"proxy"`

	// 数据库配置
	Database DatabaseConfig `json:"database" yaml:"database"`
}

// GlobalConfig 表示全局配置
type GlobalConfig struct {
	Debug       bool           `json:"debug" yaml:"debug"`
	Verbose     bool           `json:"verbose" yaml:"verbose"`
	LogLevel    string         `json:"log_level" yaml:"log_level"`
	OutputDir   string         `json:"output_dir" yaml:"output_dir"`
	DataDir     string         `json:"data_dir" yaml:"data_dir"`
	MaxFileSize int64          `json:"max_file_size" yaml:"max_file_size"` // 最大文件大小(字节)
	API         APIConfig      `json:"api" yaml:"api"`
	Crawler     CrawlerConfig  `json:"crawler" yaml:"crawler"`
	Scanner     ScannerConfig  `json:"scanner" yaml:"scanner"`
	LLM         LLMConfig      `json:"llm" yaml:"llm"`
	Report      ReportConfig   `json:"report" yaml:"report"`
	Proxy       ProxyConfig    `json:"proxy" yaml:"proxy"`
	Database    DatabaseConfig `json:"database" yaml:"database"`
}

// CrawlerConfig 表示爬虫配置
type CrawlerConfig struct {
	Enabled         bool     `json:"enabled" yaml:"enabled"`
	MaxPages        int      `json:"max_pages" yaml:"max_pages"`
	MaxDepth        int      `json:"max_depth" yaml:"max_depth"`
	Timeout         int      `json:"timeout" yaml:"timeout"`           // 超时时间(秒)
	Delay           int      `json:"delay" yaml:"delay"`               // 请求延迟(毫秒)
	Concurrency     int      `json:"concurrency" yaml:"concurrency"`
	FollowRedirects bool     `json:"follow_redirects" yaml:"follow_redirects"`
	IncludeForms    bool     `json:"include_forms" yaml:"include_forms"`
	IncludeAPIs     bool     `json:"include_apis" yaml:"include_apis"`
	RespectRobots   bool     `json:"respect_robots" yaml:"respect_robots"`
	UserAgent       string   `json:"user_agent" yaml:"user_agent"`
	AllowedDomains  []string `json:"allowed_domains" yaml:"allowed_domains"`
	ExcludedPaths   []string `json:"excluded_paths" yaml:"excluded_paths"`
	CustomHeaders   map[string]string `json:"custom_headers" yaml:"custom_headers"`
}

// PayloadConfig 表示有效载荷配置
type PayloadConfig struct {
	Value       string `json:"value" yaml:"value"`
	Description string `json:"description" yaml:"description"`
}

// PayloadGroup 表示一组有效载荷
type PayloadGroup struct {
	Basic        []PayloadConfig `json:"basic" yaml:"basic"`
	Intermediate []PayloadConfig `json:"intermediate" yaml:"intermediate"`
	Advanced     []PayloadConfig `json:"advanced" yaml:"advanced"`
}

// VulnerabilityConfig 表示漏洞配置
type VulnerabilityConfig struct {
	Enabled         bool         `json:"enabled" yaml:"enabled"`
	DetectionLevel  string       `json:"detection_level" yaml:"detection_level"`
	Timeout         int          `json:"timeout" yaml:"timeout"`
	Payloads        PayloadGroup `json:"payloads" yaml:"payloads"`
}

// VulnerabilitiesConfig 表示所有漏洞配置
type VulnerabilitiesConfig struct {
	SQLInjection     VulnerabilityConfig `json:"sql_injection" yaml:"sql_injection"`
	XSS              VulnerabilityConfig `json:"xss" yaml:"xss"`
	CommandInjection VulnerabilityConfig `json:"command_injection" yaml:"command_injection"`
	FileInclusion    VulnerabilityConfig `json:"file_inclusion" yaml:"file_inclusion"`
	OpenRedirect     VulnerabilityConfig `json:"open_redirect" yaml:"open_redirect"`
}

// ScannerConfig 表示扫描器配置
type ScannerConfig struct {
	Enabled       bool                 `json:"enabled" yaml:"enabled"`
	Modules       []string             `json:"modules" yaml:"modules"`
	Concurrency   int                  `json:"concurrency" yaml:"concurrency"`
	Timeout       int                  `json:"timeout" yaml:"timeout"`         // 超时时间(秒)
	RateLimit     int                  `json:"rate_limit" yaml:"rate_limit"`   // 每秒请求数限制
	RetryAttempts int                  `json:"retry_attempts" yaml:"retry_attempts"`
	RetryDelay    int                  `json:"retry_delay" yaml:"retry_delay"` // 重试延迟(毫秒)
	Vulnerabilities VulnerabilitiesConfig `json:"vulnerabilities" yaml:"vulnerabilities"`
}

// LLMConfig 表示LLM配置
type LLMConfig struct {
	Enabled     bool    `json:"enabled" yaml:"enabled"`
	Provider    string  `json:"provider" yaml:"provider"`
	APIKey      string  `json:"api_key" yaml:"api_key"`
	Model       string  `json:"model" yaml:"model"`
	Endpoint    string  `json:"endpoint" yaml:"endpoint"`
	MaxTokens   int     `json:"max_tokens" yaml:"max_tokens"`
	Temperature float64 `json:"temperature" yaml:"temperature"`
	Timeout     int     `json:"timeout" yaml:"timeout"` // 超时时间(秒)
}

// ReportConfig 表示报告配置
type ReportConfig struct {
	Format      string   `json:"format" yaml:"format"`       // 报告格式 (HTML, PDF, JSON, CSV, Markdown)
	IncludeData []string `json:"include_data" yaml:"include_data"`  // 包含的数据类型
	Template    string   `json:"template" yaml:"template"`      // 报告模板
	OutputPath  string   `json:"output_path" yaml:"output_path"`  // 输出路径
	Title       string   `json:"title" yaml:"title"`         // 报告标题
	Description string   `json:"description" yaml:"description"`   // 报告描述
}

// APIConfig 表示API配置
type APIConfig struct {
	Host     string `json:"host" yaml:"host"`
	Port     int    `json:"port" yaml:"port"`
	Enabled  bool   `json:"enabled" yaml:"enabled"`
	Auth     bool   `json:"auth" yaml:"auth"`
	Username string `json:"username" yaml:"username"`
	Password string `json:"password" yaml:"password"`
}

// ProxyConfig 表示代理配置
type ProxyConfig struct {
	Enabled     bool   `json:"enabled" yaml:"enabled"`     // 是否启用代理
	URL         string `json:"url" yaml:"url"`             // 代理URL
	Username    string `json:"username" yaml:"username"`   // 代理用户名
	Password    string `json:"password" yaml:"password"`   // 代理密码
	Timeout     int    `json:"timeout" yaml:"timeout"`     // 超时时间(秒)
	ListenAddress   string            `json:"listen_address" yaml:"listen_address"`   // 监听地址
	MaxConnections  int               `json:"max_connections" yaml:"max_connections"`  // 最大连接数
	EnableHTTPS     bool              `json:"enable_https" yaml:"enable_https"`     // 是否启用HTTPS
	EnableAuth      bool              `json:"enable_auth" yaml:"enable_auth"`      // 是否启用认证
	AuthUsername    string            `json:"auth_username" yaml:"auth_username"`    // 认证用户名
	AuthPassword    string            `json:"auth_password" yaml:"auth_password"`    // 认证密码
	EnableLogging   bool              `json:"enable_logging" yaml:"enable_logging"`   // 是否启用日志
	LogPath         string            `json:"log_path" yaml:"log_path"`         // 日志路径
	FilterRules     []ProxyFilterRule `json:"filter_rules" yaml:"filter_rules"`     // 过滤规则
}

// ProxyFilterRule 表示代理过滤规则
type ProxyFilterRule struct {
	Name          string            `json:"name" yaml:"name"`          // 规则名称
	Type          string            `json:"type" yaml:"type"`          // 规则类型 (blacklist, whitelist)
	Pattern       string            `json:"pattern" yaml:"pattern"`       // 匹配模式
	Description   string            `json:"description" yaml:"description"`    // 规则描述
	Enabled       bool              `json:"enabled" yaml:"enabled"`       // 是否启用
	Priority      int               `json:"priority" yaml:"priority"`      // 优先级
	HeaderFilters map[string]string `json:"header_filters" yaml:"header_filters"` // 请求头过滤
	ResponseCodes []int             `json:"response_codes" yaml:"response_codes"`  // 响应码过滤
	ContentTypes  []string          `json:"content_types" yaml:"content_types"`   // 内容类型过滤
	Action        string            `json:"action" yaml:"action"`        // 动作
}

// DatabaseConfig 表示数据库配置
type DatabaseConfig struct {
	Driver   string `json:"driver" yaml:"driver"`     // 数据库驱动 (sqlite, mysql, postgres, redis)
	Host     string `json:"host" yaml:"host"`         // 主机地址
	Port     int    `json:"port" yaml:"port"`         // 端口号
	Username string `json:"username" yaml:"username"`   // 用户名
	Password string `json:"password" yaml:"password"`   // 密码
	Database string `json:"database" yaml:"database"`   // 数据库名
	FilePath string `json:"file_path" yaml:"file_path"` // 文件路径 (仅SQLite)
	MaxOpenConns int `json:"max_open_conns" yaml:"max_open_conns"` // 最大打开连接数
	MaxIdleConns int `json:"max_idle_conns" yaml:"max_idle_conns"` // 最大空闲连接数
	ConnMaxLifetime int `json:"conn_max_lifetime" yaml:"conn_max_lifetime"` // 连接最大生命周期(秒)
	Enabled  bool   `json:"enabled" yaml:"enabled"`     // 是否启用数据库
	Type     string `json:"type" yaml:"type"`         // 数据库类型 (sqlite, mysql, postgres, redis)
	Redis    RedisConfig `json:"redis" yaml:"redis"`   // Redis特定配置
	SQLite   SQLiteConfig `json:"sqlite" yaml:"sqlite"` // SQLite特定配置
	MySQL    MySQLConfig `json:"mysql" yaml:"mysql"`   // MySQL特定配置
	Postgres PostgresConfig `json:"postgres" yaml:"postgres"` // PostgreSQL特定配置
}

// RedisConfig 表示Redis特定配置
type RedisConfig struct {
	Host            string `json:"host" yaml:"host"`
	Port            int    `json:"port" yaml:"port"`
	Password        string `json:"password" yaml:"password"`
	Database        int    `json:"database" yaml:"database"`
	MaxOpenConns    int    `json:"max_open_conns" yaml:"max_open_conns"`
	MaxIdleConns    int    `json:"max_idle_conns" yaml:"max_idle_conns"`
	ConnMaxLifetime int    `json:"conn_max_lifetime" yaml:"conn_max_lifetime"`
}

// SQLiteConfig 表示SQLite特定配置
type SQLiteConfig struct {
	FilePath string `json:"file_path" yaml:"file_path"`
}

// MySQLConfig 表示MySQL特定配置
type MySQLConfig struct {
	Host     string `json:"host" yaml:"host"`
	Port     int    `json:"port" yaml:"port"`
	Username string `json:"username" yaml:"username"`
	Password string `json:"password" yaml:"password"`
	Database string `json:"database" yaml:"database"`
}

// PostgresConfig 表示PostgreSQL特定配置
type PostgresConfig struct {
	Host     string `json:"host" yaml:"host"`
	Port     int    `json:"port" yaml:"port"`
	Username string `json:"username" yaml:"username"`
	Password string `json:"password" yaml:"password"`
	Database string `json:"database" yaml:"database"`
}

// GetDefaultConfig 返回默认配置
func GetDefaultConfig() *GlobalConfig {
	return &GlobalConfig{
		Debug:       false,
		Verbose:     false,
		LogLevel:    "info",
		OutputDir:   "./reports",
		DataDir:     "./data",
		MaxFileSize: 10485760, // 10MB
		API: APIConfig{
			Host:     "127.0.0.1",
			Port:     8081,
			Enabled:  false,
			Auth:     false,
			Username: "",
			Password: "",
		},
		Crawler: CrawlerConfig{
			Enabled:         true,
			MaxPages:        100,
			MaxDepth:        3,
			Timeout:         30,
			Delay:           100,
			Concurrency:     5,
			FollowRedirects: true,
			IncludeForms:    true,
			IncludeAPIs:     true,
			RespectRobots:   true,
			UserAgent:       "AutoVulnScan/1.0",
			AllowedDomains:  []string{},
			ExcludedPaths:   []string{},
			CustomHeaders:   map[string]string{},
		},
		Scanner: ScannerConfig{
			Enabled:       true,
			Modules:       []string{"xss", "sqli", "csrf"},
			Concurrency:   10,
			Timeout:       30,
			RateLimit:     10,
			RetryAttempts: 3,
			RetryDelay:    1000,
		},
		LLM: LLMConfig{
			Enabled:     false,
			Provider:    "openai",
			APIKey:      "",
			Model:       "gpt-3.5-turbo",
			Endpoint:    "https://api.openai.com/v1/chat/completions",
			MaxTokens:   1000,
			Temperature: 0.7,
			Timeout:     30,
		},
		Report: ReportConfig{
			Format:      "html",
			IncludeData: []string{"vulnerabilities", "stats"},
			Template:    "",
			OutputPath:  "./reports",
			Title:       "Vulnerability Scan Report",
			Description: "AutoVulnScan vulnerability scan results",
		},
		Proxy: ProxyConfig{
			Enabled:        false,
			URL:            "",
			Username:       "",
			Password:       "",
			Timeout:        30,
			ListenAddress:  "127.0.0.1:8080",
			MaxConnections: 100,
			EnableHTTPS:    false,
			EnableAuth:     false,
			AuthUsername:   "",
			AuthPassword:   "",
			EnableLogging:  true,
			LogPath:        "./logs/proxy.log",
			FilterRules:    []ProxyFilterRule{},
		},
		Database: DatabaseConfig{
			Driver:          "redis",
			Host:            "127.0.0.1",
			Port:            6379,
			Username:        "",
			Password:        "",
			Database:        "",
			FilePath:        "./data/autovulnscan.db",
			MaxOpenConns:    10,
			MaxIdleConns:    5,
			ConnMaxLifetime: 3600,
			Enabled:         true,
			Type:            "redis",
			Redis: RedisConfig{
				Host:            "127.0.0.1",
				Port:            6379,
				Password:        "",
				Database:        0,
				MaxOpenConns:    10,
				MaxIdleConns:    5,
				ConnMaxLifetime: 3600,
			},
			SQLite: SQLiteConfig{
				FilePath: "./data/autovulnscan.db",
			},
			MySQL: MySQLConfig{
				Host:     "127.0.0.1",
				Port:     3306,
				Username: "root",
				Password: "",
				Database: "autovulnscan",
			},
			Postgres: PostgresConfig{
				Host:     "127.0.0.1",
				Port:     5432,
				Username: "postgres",
				Password: "",
				Database: "autovulnscan",
			},
		},
	}
}

// SaveConfig 保存配置到文件
func SaveConfig(config *GlobalConfig) error {
	viper.Set("debug", config.Debug)
	viper.Set("verbose", config.Verbose)
	viper.Set("log_level", config.LogLevel)
	viper.Set("output_dir", config.OutputDir)
	viper.Set("data_dir", config.DataDir)
	viper.Set("max_file_size", config.MaxFileSize)
	
	// 保存API配置
	viper.Set("api.host", config.API.Host)
	viper.Set("api.port", config.API.Port)
	viper.Set("api.enabled", config.API.Enabled)
	viper.Set("api.auth", config.API.Auth)
	viper.Set("api.username", config.API.Username)
	viper.Set("api.password", config.API.Password)
	
	// 保存爬虫配置
	viper.Set("crawler.enabled", config.Crawler.Enabled)
	viper.Set("crawler.max_pages", config.Crawler.MaxPages)
	viper.Set("crawler.max_depth", config.Crawler.MaxDepth)
	viper.Set("crawler.timeout", config.Crawler.Timeout)
	viper.Set("crawler.delay", config.Crawler.Delay)
	viper.Set("crawler.concurrency", config.Crawler.Concurrency)
	viper.Set("crawler.follow_redirects", config.Crawler.FollowRedirects)
	viper.Set("crawler.include_forms", config.Crawler.IncludeForms)
	viper.Set("crawler.include_apis", config.Crawler.IncludeAPIs)
	viper.Set("crawler.respect_robots", config.Crawler.RespectRobots)
	viper.Set("crawler.user_agent", config.Crawler.UserAgent)
	viper.Set("crawler.allowed_domains", config.Crawler.AllowedDomains)
	viper.Set("crawler.excluded_paths", config.Crawler.ExcludedPaths)
	viper.Set("crawler.custom_headers", config.Crawler.CustomHeaders)
	
	// 保存扫描器配置
	viper.Set("scanner.enabled", config.Scanner.Enabled)
	viper.Set("scanner.modules", config.Scanner.Modules)
	viper.Set("scanner.concurrency", config.Scanner.Concurrency)
	viper.Set("scanner.timeout", config.Scanner.Timeout)
	viper.Set("scanner.rate_limit", config.Scanner.RateLimit)
	viper.Set("scanner.retry_attempts", config.Scanner.RetryAttempts)
	viper.Set("scanner.retry_delay", config.Scanner.RetryDelay)
	
	// 保存LLM配置
	viper.Set("llm.enabled", config.LLM.Enabled)
	viper.Set("llm.provider", config.LLM.Provider)
	viper.Set("llm.api_key", config.LLM.APIKey)
	viper.Set("llm.model", config.LLM.Model)
	viper.Set("llm.endpoint", config.LLM.Endpoint)
	viper.Set("llm.max_tokens", config.LLM.MaxTokens)
	viper.Set("llm.temperature", config.LLM.Temperature)
	viper.Set("llm.timeout", config.LLM.Timeout)
	
	// 保存报告配置
	viper.Set("report.format", config.Report.Format)
	viper.Set("report.include_data", config.Report.IncludeData)
	viper.Set("report.template", config.Report.Template)
	viper.Set("report.output_path", config.Report.OutputPath)
	viper.Set("report.title", config.Report.Title)
	viper.Set("report.description", config.Report.Description)
	
	// 保存代理配置
	viper.Set("proxy.listen_address", config.Proxy.ListenAddress)
	viper.Set("proxy.timeout", config.Proxy.Timeout)
	viper.Set("proxy.max_connections", config.Proxy.MaxConnections)
	viper.Set("proxy.enable_https", config.Proxy.EnableHTTPS)
	viper.Set("proxy.enable_auth", config.Proxy.EnableAuth)
	viper.Set("proxy.auth_username", config.Proxy.AuthUsername)
	viper.Set("proxy.auth_password", config.Proxy.AuthPassword)
	viper.Set("proxy.enable_logging", config.Proxy.EnableLogging)
	viper.Set("proxy.log_path", config.Proxy.LogPath)
	viper.Set("proxy.filter_rules", config.Proxy.FilterRules)
	
	// 保存数据库配置
	viper.Set("database.driver", config.Database.Driver)
	viper.Set("database.host", config.Database.Host)
	viper.Set("database.port", config.Database.Port)
	viper.Set("database.username", config.Database.Username)
	viper.Set("database.password", config.Database.Password)
	viper.Set("database.database", config.Database.Database)
	viper.Set("database.file_path", config.Database.FilePath)
	viper.Set("database.max_open_conns", config.Database.MaxOpenConns)
	viper.Set("database.max_idle_conns", config.Database.MaxIdleConns)
	viper.Set("database.conn_max_lifetime", config.Database.ConnMaxLifetime)
	viper.Set("database.enabled", config.Database.Enabled)
	viper.Set("database.type", config.Database.Type)
	viper.Set("database.redis.host", config.Database.Redis.Host)
	viper.Set("database.redis.port", config.Database.Redis.Port)
	viper.Set("database.redis.password", config.Database.Redis.Password)
	viper.Set("database.redis.database", config.Database.Redis.Database)
	viper.Set("database.redis.max_open_conns", config.Database.Redis.MaxOpenConns)
	viper.Set("database.redis.max_idle_conns", config.Database.Redis.MaxIdleConns)
	viper.Set("database.redis.conn_max_lifetime", config.Database.Redis.ConnMaxLifetime)
	viper.Set("database.sqlite.file_path", config.Database.SQLite.FilePath)
	viper.Set("database.mysql.host", config.Database.MySQL.Host)
	viper.Set("database.mysql.port", config.Database.MySQL.Port)
	viper.Set("database.mysql.username", config.Database.MySQL.Username)
	viper.Set("database.mysql.password", config.Database.MySQL.Password)
	viper.Set("database.mysql.database", config.Database.MySQL.Database)
	viper.Set("database.postgres.host", config.Database.Postgres.Host)
	viper.Set("database.postgres.port", config.Database.Postgres.Port)
	viper.Set("database.postgres.username", config.Database.Postgres.Username)
	viper.Set("database.postgres.password", config.Database.Postgres.Password)
	viper.Set("database.postgres.database", config.Database.Postgres.Database)
	
	// 保存到配置文件
	return viper.WriteConfig()
}

// ValidateConfig 验证配置
func ValidateConfig(config *GlobalConfig) error {
	// 验证必要的目录
	if config.OutputDir == "" {
		return fmt.Errorf("output directory is required")
	}
	if config.DataDir == "" {
		return fmt.Errorf("data directory is required")
	}
	
	// 验证API配置
	if config.API.Enabled {
		if config.API.Host == "" {
			return fmt.Errorf("API host is required when API is enabled")
		}
		if config.API.Port <= 0 {
			return fmt.Errorf("API port must be greater than 0")
		}
		if config.API.Auth {
			if config.API.Username == "" {
				return fmt.Errorf("API username is required when API auth is enabled")
			}
			if config.API.Password == "" {
				return fmt.Errorf("API password is required when API auth is enabled")
			}
		}
	}
	
	// 验证数据库配置
	if config.Database.Enabled {
		if config.Database.Type == "" {
			return fmt.Errorf("database type is required when database is enabled")
		}
		if config.Database.Host == "" {
			return fmt.Errorf("database host is required when database is enabled")
		}
		if config.Database.Port <= 0 {
			return fmt.Errorf("database port must be greater than 0")
		}
		
		// 验证特定数据库类型的配置
		switch config.Database.Type {
		case "redis":
			if config.Database.Redis.Host == "" {
				return fmt.Errorf("redis host is required when redis is enabled")
			}
			if config.Database.Redis.Port <= 0 {
				return fmt.Errorf("redis port must be greater than 0")
			}
		case "sqlite":
			if config.Database.SQLite.FilePath == "" {
				return fmt.Errorf("sqlite file path is required when sqlite is enabled")
			}
		case "mysql":
			if config.Database.MySQL.Host == "" {
				return fmt.Errorf("mysql host is required when mysql is enabled")
			}
			if config.Database.MySQL.Port <= 0 {
				return fmt.Errorf("mysql port must be greater than 0")
			}
			if config.Database.MySQL.Username == "" {
				return fmt.Errorf("mysql username is required when mysql is enabled")
			}
			if config.Database.MySQL.Database == "" {
				return fmt.Errorf("mysql database name is required when mysql is enabled")
			}
		case "postgres":
			if config.Database.Postgres.Host == "" {
				return fmt.Errorf("postgres host is required when postgres is enabled")
			}
			if config.Database.Postgres.Port <= 0 {
				return fmt.Errorf("postgres port must be greater than 0")
			}
			if config.Database.Postgres.Username == "" {
				return fmt.Errorf("postgres username is required when postgres is enabled")
			}
			if config.Database.Postgres.Database == "" {
				return fmt.Errorf("postgres database name is required when postgres is enabled")
			}
		default:
			return fmt.Errorf("unsupported database type: %s", config.Database.Type)
		}
	}
	
	// 验证LLM配置
	if config.LLM.Enabled {
		if config.LLM.Provider == "" {
			return fmt.Errorf("LLM provider is required when LLM is enabled")
		}
		if config.LLM.APIKey == "" {
			return fmt.Errorf("LLM API key is required when LLM is enabled")
		}
		if config.LLM.Model == "" {
			return fmt.Errorf("LLM model is required when LLM is enabled")
		}
		if config.LLM.Endpoint == "" {
			return fmt.Errorf("LLM endpoint is required when LLM is enabled")
		}
	}
	
	// 验证代理配置
	if config.Proxy.ListenAddress == "" {
		return fmt.Errorf("proxy listen address is required")
	}
	if config.Proxy.Timeout <= 0 {
		return fmt.Errorf("proxy timeout must be greater than 0")
	}
	if config.Proxy.MaxConnections <= 0 {
		return fmt.Errorf("proxy max connections must be greater than 0")
	}
	
	// 验证爬虫配置
	if config.Crawler.Enabled {
		if config.Crawler.MaxPages <= 0 {
			return fmt.Errorf("crawler max pages must be greater than 0")
		}
		if config.Crawler.MaxDepth <= 0 {
			return fmt.Errorf("crawler max depth must be greater than 0")
		}
		if config.Crawler.Timeout <= 0 {
			return fmt.Errorf("crawler timeout must be greater than 0")
		}
		if config.Crawler.Concurrency <= 0 {
			return fmt.Errorf("crawler concurrency must be greater than 0")
		}
	}
	
	// 验证扫描器配置
	if config.Scanner.Enabled {
		if len(config.Scanner.Modules) == 0 {
			return fmt.Errorf("at least one scanner module is required when scanner is enabled")
		}
		if config.Scanner.Concurrency <= 0 {
			return fmt.Errorf("scanner concurrency must be greater than 0")
		}
		if config.Scanner.Timeout <= 0 {
			return fmt.Errorf("scanner timeout must be greater than 0")
		}
		if config.Scanner.RateLimit <= 0 {
			return fmt.Errorf("scanner rate limit must be greater than 0")
		}
		if config.Scanner.RetryAttempts < 0 {
			return fmt.Errorf("scanner retry attempts must be greater than or equal to 0")
		}
		if config.Scanner.RetryDelay < 0 {
			return fmt.Errorf("scanner retry delay must be greater than or equal to 0")
		}
	}
	
	// 验证报告配置
	if config.Report.Format == "" {
		return fmt.Errorf("report format is required")
	}
	if len(config.Report.IncludeData) == 0 {
		return fmt.Errorf("at least one data type must be included in the report")
	}
	if config.Report.OutputPath == "" {
		return fmt.Errorf("report output path is required")
	}
	if config.Report.Title == "" {
		return fmt.Errorf("report title is required")
	}
	
	return nil
}

// SetGlobalConfig 设置全局配置
func SetGlobalConfig(config *GlobalConfig) {
	configMutex.Lock()
	defer configMutex.Unlock()
	globalConfig = config
}

// GetGlobalConfig 获取全局配置
func GetGlobalConfig() *GlobalConfig {
	configMutex.RLock()
	defer configMutex.RUnlock()
	return globalConfig
}