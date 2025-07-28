// Package config 负责加载和解析应用程序的配置。
// 提供了完整的配置管理功能，包括验证、热重载、环境变量支持等。
package config

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"
	
	"github.com/BurntSushi/toml"
	"github.com/fsnotify/fsnotify"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)


// ConfigVersion 配置版本，用于兼容性检查
const ConfigVersion = "1.0"

// Settings 定义了 AutoVulnScan 应用程序的整体配置结构。
// 它包括调试、代理、HTTP头、爬虫、扫描器、报告、Redis、AI模块和漏洞插件的设置。
type Settings struct {
	// Version 配置文件版本
	Version string `mapstructure:"version" validate:"required"`
	
	// Debug 开启或关闭调试模式，提供更详细的输出。
	Debug bool `mapstructure:"debug"`
	
	// Proxy 指定用于所有网络请求的代理服务器URL。
	Proxy string `mapstructure:"proxy" validate:"omitempty,url"`
	
	// Headers 定义了每个请求中要发送的自定义HTTP头。
	Headers map[string]string `mapstructure:"headers"`
	
	// Scope 定义了扫描范围内的域。
	Scope []string `mapstructure:"scope" validate:"required,min=1,dive,required"`
	
	// Blacklist 定义了不应被扫描的URL模式。
	Blacklist []string `mapstructure:"blacklist"`
	
	// Whitelist 定义了允许扫描的URL模式。
	Whitelist []string `mapstructure:"whitelist"`
	
	// RateLimit 请求速率限制配置
	RateLimit RateLimitConfig `mapstructure:"rate_limit"`
	
	// Log 定义了日志记录相关的配置。
	Log LogConfig `mapstructure:"log"`
	
	// Spider 保存了所有与爬取和发现阶段相关的配置。
	Spider SpiderConfig `mapstructure:"spider"`
	
	// Scanner 保存了所有与漏洞扫描阶段相关的配置。
	Scanner ScannerConfig `mapstructure:"scanner"`
	
	// Reporting 定义了生成漏洞报告的设置。
	Reporting ReportingConfig `mapstructure:"reporting"`
	
	// Redis 保存了连接到Redis服务器以进行数据存储的配置。
	Redis RedisConfig `mapstructure:"redis"`
	
	// Database 数据库配置
	Database DatabaseConfig `mapstructure:"database"`
	
	// AIModule 配置了AI驱动的分析功能。
	AIModule AIModuleConfig `mapstructure:"ai_module"`
	
	// Security 安全相关配置
	Security SecurityConfig `mapstructure:"security"`
	
	// Performance 性能相关配置
	Performance PerformanceConfig `mapstructure:"performance"`
	
	// Notifications 通知配置
	Notifications NotificationConfig `mapstructure:"notifications"`
	
	// Plugins 插件配置
	Plugins PluginConfig `mapstructure:"plugins"`
}

// RateLimitConfig 速率限制配置
type RateLimitConfig struct {
	// Enabled 是否启用速率限制
	Enabled bool `mapstructure:"enabled"`
	// RequestsPerSecond 每秒请求数限制
	RequestsPerSecond int `mapstructure:"requests_per_second" validate:"min=1"`
	// BurstSize 突发请求大小
	BurstSize int `mapstructure:"burst_size" validate:"min=1"`
	// PerHost 是否按主机限制
	PerHost bool `mapstructure:"per_host"`
}

// LogConfig 定义了日志记录的设置。
type LogConfig struct {
	// FilePath 是日志文件的保存路径。如果为空，则不输出到文件。
	FilePath string `mapstructure:"file_path"`
	
	// Level 定义了日志级别 (e.g., "debug", "info", "warn", "error")。
	Level string `mapstructure:"level" validate:"oneof=debug info warn error fatal panic"`
	
	// Format 日志格式 (json, text)
	Format string `mapstructure:"format" validate:"oneof=json text"`
	
	// MaxSize 日志文件最大大小(MB)
	MaxSize int `mapstructure:"max_size" validate:"min=1"`
	
	// MaxAge 日志文件最大保存天数
	MaxAge int `mapstructure:"max_age" validate:"min=1"`
	
	// MaxBackups 最大备份文件数
	MaxBackups int `mapstructure:"max_backups" validate:"min=0"`
	
	// Compress 是否压缩旧日志文件
	Compress bool `mapstructure:"compress"`
	
	// EnableConsole 是否启用控制台输出
	EnableConsole bool `mapstructure:"enable_console"`
}

// SpiderConfig 保存了所有与爬虫阶段相关的配置。
type SpiderConfig struct {
	// Concurrency 是要运行的并发爬虫的数量。
	Concurrency int `mapstructure:"concurrency" validate:"min=1,max=100"`
	
	// Limit 是要爬取的最大页面数。
	Limit int `mapstructure:"limit" validate:"min=1"`
	
	// Timeout 是每个HTTP请求的超时时间（秒）。
	Timeout time.Duration `mapstructure:"timeout" validate:"min=1s"`
	
	// MaxDepth 是最大爬取深度。
	MaxDepth int `mapstructure:"max_depth" validate:"min=1,max=10"`
	
	// MaxPageVisitPerSite 是每个站点要访问的最大页面数。
	MaxPageVisitPerSite int `mapstructure:"max_page_visit_per_site" validate:"min=1"`
	
	// Cookies 是爬虫要使用的cookie映射。
	Cookies map[string]string `mapstructure:"cookies"`
	
	// UserAgents 用户代理列表
	UserAgents []string `mapstructure:"user_agents"`
	
	// RandomizeUserAgent 是否随机化用户代理
	RandomizeUserAgent bool `mapstructure:"randomize_user_agent"`
	
	// Delay 请求间延迟
	Delay time.Duration `mapstructure:"delay"`
	
	// RandomDelay 随机延迟范围
	RandomDelay time.Duration `mapstructure:"random_delay"`
	
	// SimilarityPageDom 配置了DOM相似性算法以避免冗余爬取。
	SimilarityPageDom SimilarityPageDomConfig `mapstructure:"similarity_page_dom"`
	
	// DynamicCrawler 保存了基于无头浏览器的动态爬虫的设置。
	DynamicCrawler DynamicCrawlerConfig `mapstructure:"dynamic_crawler"`
	
	// Sources 是用于发现URL的来源列表（例如，"robotstxt", "sitemapxml"）。
	Sources []string `mapstructure:"sources"`
	
	// FileExtensions 要爬取的文件扩展名
	FileExtensions []string `mapstructure:"file_extensions"`
	
	// ExcludeExtensions 要排除的文件扩展名
	ExcludeExtensions []string `mapstructure:"exclude_extensions"`
	
	// MaxFileSize 最大文件大小(字节)
	MaxFileSize int64 `mapstructure:"max_file_size" validate:"min=1"`
	
	// FollowRedirects 是否跟随重定向
	FollowRedirects bool `mapstructure:"follow_redirects"`
	
	// MaxRedirects 最大重定向次数
	MaxRedirects int `mapstructure:"max_redirects" validate:"min=0,max=10"`
}

// SimilarityPageDomConfig 配置了DOM相似性算法。
type SimilarityPageDomConfig struct {
	// Use 启用或禁用DOM相似性检查。
	Use bool `mapstructure:"use"`
	
	// Threshold 是考虑相似性检查的最小DOM元素数。
	Threshold int `mapstructure:"threshold" validate:"min=1"`
	
	// Similarity 是将页面视为重复的相似性阈值（0.0到1.0）。
	Similarity float64 `mapstructure:"similarity" validate:"min=0,max=1"`
	
	// VectorDim 是用于相似性计算的向量维度。
	VectorDim int `mapstructure:"vector_dim" validate:"min=1"`
	
	// Algorithm 相似性算法类型
	Algorithm string `mapstructure:"algorithm" validate:"oneof=cosine jaccard euclidean"`
	
	// CacheSize 相似性缓存大小
	CacheSize int `mapstructure:"cache_size" validate:"min=1"`
}

// DynamicCrawlerConfig 保存了基于无头浏览器的动态爬虫的设置。
type DynamicCrawlerConfig struct {
	// Enabled 决定是否使用动态爬虫。
	Enabled bool `mapstructure:"enabled"`
	
	// Headless 决定是否以无头模式运行浏览器。
	Headless bool `mapstructure:"headless"`
	
	// BrowserType 浏览器类型
	BrowserType string `mapstructure:"browser_type" validate:"oneof=chromium firefox webkit"`
	
	// MaxInstances 最大浏览器实例数
	MaxInstances int `mapstructure:"max_instances" validate:"min=1,max=10"`
	
	// PageTimeout 页面超时时间
	PageTimeout time.Duration `mapstructure:"page_timeout" validate:"min=1s"`
	
	// WaitTime 页面加载等待时间
	WaitTime time.Duration `mapstructure:"wait_time"`
	
	// EnableJavaScript 是否启用JavaScript
	EnableJavaScript bool `mapstructure:"enable_javascript"`
	
	// EnableImages 是否加载图片
	EnableImages bool `mapstructure:"enable_images"`
	
	// EnableCSS 是否加载CSS
	EnableCSS bool `mapstructure:"enable_css"`
	
	// ViewportWidth 视口宽度
	ViewportWidth int `mapstructure:"viewport_width" validate:"min=1"`
	
	// ViewportHeight 视口高度
	ViewportHeight int `mapstructure:"viewport_height" validate:"min=1"`
	
	// ScreenshotOnError 错误时是否截图
	ScreenshotOnError bool `mapstructure:"screenshot_on_error"`
}

// ScannerConfig 定义了漏洞扫描器的设置。
type ScannerConfig struct {
	// Concurrency 是并发扫描任务的数量。
	Concurrency int `mapstructure:"concurrency" validate:"min=1,max=50"`
	
	// Limit 是要扫描的最大URL数。
	Limit int `mapstructure:"limit" validate:"min=1"`
	
	// FilterThreshold 是用于过滤掉相似页面的阈值。
	FilterThreshold int `mapstructure:"filter_threshold" validate:"min=1"`
	
	// FoundHiddenParameter 启用或禁用隐藏参数的发现。
	FoundHiddenParameter bool `mapstructure:"found_hidden_parameter"`
	
	// FoundHiddenParameterFromJS 启用或禁用从JavaScript文件中发现隐藏参数。
	FoundHiddenParameterFromJS bool `mapstructure:"found_hidden_parameter_from_js"`
	
	// ParameterGroupSize 是在单个测试中分组的参数数量。
	ParameterGroupSize int `mapstructure:"parameter_group_size" validate:"min=1"`
	
	// Timeout 是每个扫描请求的超时时间。
	Timeout time.Duration `mapstructure:"timeout" validate:"min=1s"`
	
	// PluginTimeout 是每个单独插件的超时时间。
	PluginTimeout time.Duration `mapstructure:"plugin_timeout" validate:"min=1s"`
	
	// Position 是要测试漏洞的位置列表（例如，"get", "post"）。
	Position []string `mapstructure:"position" validate:"dive,oneof=get post cookie header path"`
	
	// MaxPayloadSize 最大payload大小
	MaxPayloadSize int `mapstructure:"max_payload_size" validate:"min=1"`
	
	// RetryCount 重试次数
	RetryCount int `mapstructure:"retry_count" validate:"min=0,max=5"`
	
	// RetryDelay 重试延迟
	RetryDelay time.Duration `mapstructure:"retry_delay"`
	
	// SkipSSLVerification 是否跳过SSL验证
	SkipSSLVerification bool `mapstructure:"skip_ssl_verification"`
	
	// FollowRedirects 是否跟随重定向
	FollowRedirects bool `mapstructure:"follow_redirects"`
	
	// Output 配置扫描输出中包含哪些信息。
	Output ScannerOutputConfig `mapstructure:"output"`
	
	// HiddenParameters 是要被视为隐藏的参数名称列表。
	HiddenParameters []string `mapstructure:"hidden_parameters"`
	
	// Vulnerabilities 是扫描器要使用的漏洞配置列表。
	Vulnerabilities []VulnConfig `mapstructure:"vulnerabilities" validate:"dive"`
	
	// FalsePositiveFilters 误报过滤器
	FalsePositiveFilters []FilterConfig `mapstructure:"false_positive_filters"`
}

// ScannerOutputConfig 扫描输出配置
type ScannerOutputConfig struct {
	// Response 决定是否在报告中包含完整的HTTP响应。
	Response bool `mapstructure:"response"`
	
	// ResponseHeader 决定是否在报告中包含响应头。
	ResponseHeader bool `mapstructure:"response_header"`
	
	// Request 是否包含请求信息
	Request bool `mapstructure:"request"`
	
	// Evidence 是否包含证据信息
	Evidence bool `mapstructure:"evidence"`
	
	// Payload 是否包含payload信息
	Payload bool `mapstructure:"payload"`
	
	// Verbose 详细输出模式
	Verbose bool `mapstructure:"verbose"`
}

// FilterConfig 过滤器配置
type FilterConfig struct {
	// Type 过滤器类型
	Type string `mapstructure:"type" validate:"required"`
	
	// Pattern 过滤模式
	Pattern string `mapstructure:"pattern" validate:"required"`
	
	// Enabled 是否启用
	Enabled bool `mapstructure:"enabled"`
	
	// Description 描述
	Description string `mapstructure:"description"`
}

// ReportingConfig 定义了生成报告的设置。
type ReportingConfig struct {
	// Path 是将保存报告的目录。
	Path string `mapstructure:"path" validate:"required"`
	
	// VulnReportFile 是漏洞报告的文件名。
	VulnReportFile string `mapstructure:"vuln_report_file"`
	
	// SpiderFile 是爬虫输出文件的文件名。
	SpiderFile string `mapstructure:"spider_file"`
	
	// UnscopedSpiderFile 是爬虫发现的作用域外URL的文件名。
	UnscopedSpiderFile string `mapstructure:"unscoped_spider_file"`
	
	// SpiderDeDuplicateFile 是去重后爬虫输出的文件名。
	SpiderDeDuplicateFile string `mapstructure:"spider_deduplicate_file"`
	
	// SpiderParamsFile 是爬虫参数输出的文件名。
	SpiderParamsFile string `mapstructure:"spider_params_file"`
	
	// JSONReportFile 是JSON格式报告的文件名。
	JSONReportFile string `mapstructure:"json_report_file"`
	
	// HTMLReportFile 是HTML格式报告的文件名。
	HTMLReportFile string `mapstructure:"html_report_file"`
	
	// XMLReportFile 是XML格式报告的文件名。
	XMLReportFile string `mapstructure:"xml_report_file"`
	
	// CSVReportFile 是CSV格式报告的文件名。
	CSVReportFile string `mapstructure:"csv_report_file"`
	
	// PDFReportFile 是PDF格式报告的文件名。
	PDFReportFile string `mapstructure:"pdf_report_file"`
	
	// Template 报告模板配置
	Template TemplateConfig `mapstructure:"template"`
	
	// Compression 报告压缩配置
	Compression CompressionConfig `mapstructure:"compression"`
	
	// AutoCleanup 自动清理旧报告
	AutoCleanup AutoCleanupConfig `mapstructure:"auto_cleanup"`
}

// TemplateConfig 模板配置
type TemplateConfig struct {
	// HTMLTemplate HTML模板路径
	HTMLTemplate string `mapstructure:"html_template"`
	
	// CustomCSS 自定义CSS路径
	CustomCSS string `mapstructure:"custom_css"`
	
	// Logo 报告Logo路径
	Logo string `mapstructure:"logo"`
	
	// CompanyName 公司名称
	CompanyName string `mapstructure:"company_name"`
}

// CompressionConfig 压缩配置
type CompressionConfig struct {
	// Enabled 是否启用压缩
	Enabled bool `mapstructure:"enabled"`
	
	// Format 压缩格式
	Format string `mapstructure:"format" validate:"oneof=zip tar.gz"`
	
	// Level 压缩级别
	Level int `mapstructure:"level" validate:"min=1,max=9"`
}

// AutoCleanupConfig 自动清理配置
type AutoCleanupConfig struct {
	// Enabled 是否启用自动清理
	Enabled bool `mapstructure:"enabled"`
	
	// MaxAge 最大保存天数
	MaxAge time.Duration `mapstructure:"max_age"`
	
	// MaxCount 最大文件数量
	MaxCount int `mapstructure:"max_count" validate:"min=1"`
}

// RedisConfig 定义了Redis连接的设置。
type RedisConfig struct {
	// Enabled 决定是否使用Redis进行存储。
	Enabled bool `mapstructure:"enabled"`
	
	// URL 是Redis服务器的连接字符串。
	URL string `mapstructure:"url" validate:"required_if=Enabled true"`
	
	// Password Redis密码
	Password string `mapstructure:"password"`
	
	// Database Redis数据库编号
	Database int `mapstructure:"database" validate:"min=0,max=15"`
	
	// MaxRetries 最大重试次数
	MaxRetries int `mapstructure:"max_retries" validate:"min=0"`
	
	// PoolSize 连接池大小
	PoolSize int `mapstructure:"pool_size" validate:"min=1"`
	
	// MinIdleConns 最小空闲连接数
	MinIdleConns int `mapstructure:"min_idle_conns" validate:"min=0"`
	
	// MaxIdleTime 最大空闲时间
	MaxIdleTime time.Duration `mapstructure:"max_idle_time"`
	
	// ConnMaxLifetime 连接最大生存时间
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
	
	// KeyPrefix 键前缀
	KeyPrefix string `mapstructure:"key_prefix"`
	
	// EnableCluster 是否启用集群模式
	EnableCluster bool `mapstructure:"enable_cluster"`
	
	// ClusterAddrs 集群地址列表
	ClusterAddrs []string `mapstructure:"cluster_addrs"`
}

// DatabaseConfig 数据库配置
type DatabaseConfig struct {
	// Type 数据库类型
	Type string `mapstructure:"type" validate:"oneof=sqlite mysql postgres"`
	
	// DSN 数据库连接字符串
	DSN string `mapstructure:"dsn" validate:"required"`
	
	// MaxOpenConns 最大打开连接数
	MaxOpenConns int `mapstructure:"max_open_conns" validate:"min=1"`
	
	// MaxIdleConns 最大空闲连接数
	MaxIdleConns int `mapstructure:"max_idle_conns" validate:"min=1"`
	
	// ConnMaxLifetime 连接最大生存时间
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
	
	// EnableMigration 是否启用自动迁移
	EnableMigration bool `mapstructure:"enable_migration"`
	
	// LogLevel 日志级别
	LogLevel string `mapstructure:"log_level" validate:"oneof=silent error warn info"`
}

// AIModuleConfig 保存了可选的AI驱动分析模块的设置。
type AIModuleConfig struct {
	// Enabled 决定是否使用AI模块。
	Enabled bool `mapstructure:"enabled"`
	
	// Provider AI服务提供商
	Provider string `mapstructure:"provider" validate:"required_if=Enabled true,oneof=openai deepseek anthropic"`
	
	// Model 是要使用的AI模型的名称（例如，"deepseek/deepseek-v3"）。
	Model string `mapstructure:"model" validate:"required_if=Enabled true"`
	
	// APIKey 是AI服务的API密钥。
	APIKey string `mapstructure:"api_key" validate:"required_if=Enabled true"`
	
	// BaseURL API基础URL
	BaseURL string `mapstructure:"base_url"`
	
	// MaxTokens 最大token数
	MaxTokens int `mapstructure:"max_tokens" validate:"min=1"`
	
	// Temperature 温度参数
	Temperature float64 `mapstructure:"temperature" validate:"min=0,max=2"`
	
	// Timeout 请求超时时间
	Timeout time.Duration `mapstructure:"timeout" validate:"min=1s"`
	
	// MaxRetries 最大重试次数
	MaxRetries int `mapstructure:"max_retries" validate:"min=0,max=5"`
	
	// EnableCache 是否启用缓存
	EnableCache bool `mapstructure:"enable_cache"`
	
	// CacheExpiry 缓存过期时间
	CacheExpiry time.Duration `mapstructure:"cache_expiry"`
	
	// Features 启用的AI功能
	Features AIFeaturesConfig `mapstructure:"features"`
}

// AIFeaturesConfig AI功能配置
type AIFeaturesConfig struct {
	// VulnAnalysis 漏洞分析
	VulnAnalysis bool `mapstructure:"vuln_analysis"`
	
	// PayloadGeneration payload生成
	PayloadGeneration bool `mapstructure:"payload_generation"`
	
	// FalsePositiveDetection 误报检测
	FalsePositiveDetection bool `mapstructure:"false_positive_detection"`
	
	// ReportGeneration 报告生成
	ReportGeneration bool `mapstructure:"report_generation"`
	
	// ThreatIntelligence 威胁情报
	ThreatIntelligence bool `mapstructure:"threat_intelligence"`
}

// SecurityConfig 安全配置
type SecurityConfig struct {
	// EnableHTTPS 是否强制HTTPS
	EnableHTTPS bool `mapstructure:"enable_https"`
	
	// TLSConfig TLS配置
	TLSConfig TLSConfig `mapstructure:"tls_config"`
	
	// Authentication 认证配置
	Authentication AuthConfig `mapstructure:"authentication"`
	
	// Authorization 授权配置
	Authorization AuthzConfig `mapstructure:"authorization"`
	
	// Encryption 加密配置
	Encryption EncryptionConfig `mapstructure:"encryption"`
	
	// AuditLog 审计日志配置
	AuditLog AuditLogConfig `mapstructure:"audit_log"`
}

// TLSConfig TLS配置
type TLSConfig struct {
	// MinVersion 最小TLS版本
	MinVersion string `mapstructure:"min_version" validate:"oneof=1.0 1.1 1.2 1.3"`
	
	// CertFile 证书文件路径
	CertFile string `mapstructure:"cert_file"`
	
	// KeyFile 私钥文件路径
	KeyFile string `mapstructure:"key_file"`
	
	// CAFile CA证书文件路径
	CAFile string `mapstructure:"ca_file"`
	
	// InsecureSkipVerify 是否跳过证书验证
	InsecureSkipVerify bool `mapstructure:"insecure_skip_verify"`
}

// AuthConfig 认证配置
type AuthConfig struct {
	// Type 认证类型
	Type string `mapstructure:"type" validate:"oneof=none basic jwt oauth2"`
	
	// BasicAuth 基础认证配置
	BasicAuth BasicAuthConfig `mapstructure:"basic_auth"`
	
	// JWT JWT配置
	JWT JWTConfig `mapstructure:"jwt"`
	
	// OAuth2 OAuth2配置
	OAuth2 OAuth2Config `mapstructure:"oauth2"`
}

// BasicAuthConfig 基础认证配置
type BasicAuthConfig struct {
	// Username 用户名
	Username string `mapstructure:"username"`
	
	// Password 密码
	Password string `mapstructure:"password"`
}

// JWTConfig JWT配置
type JWTConfig struct {
	// Secret JWT密钥
	Secret string `mapstructure:"secret"`
	
	// Expiry 过期时间
	Expiry time.Duration `mapstructure:"expiry"`
	
	// Issuer 签发者
	Issuer string `mapstructure:"issuer"`
}

// OAuth2Config OAuth2配置
type OAuth2Config struct {
	// ClientID 客户端ID
	ClientID string `mapstructure:"client_id"`
	
	// ClientSecret 客户端密钥
	ClientSecret string `mapstructure:"client_secret"`
	
	// RedirectURL 重定向URL
	RedirectURL string `mapstructure:"redirect_url"`
	
	// Scopes 权限范围
	Scopes []string `mapstructure:"scopes"`
}

// AuthzConfig 授权配置
type AuthzConfig struct {
	// Type 授权类型
	Type string `mapstructure:"type" validate:"oneof=none rbac abac"`
	
	// Roles 角色配置
	Roles []RoleConfig `mapstructure:"roles"`
	
	// Policies 策略配置
	Policies []PolicyConfig `mapstructure:"policies"`
}

// RoleConfig 角色配置
type RoleConfig struct {
	// Name 角色名称
	Name string `mapstructure:"name" validate:"required"`
	
	// Permissions 权限列表
	Permissions []string `mapstructure:"permissions"`
	
	// Description 描述
	Description string `mapstructure:"description"`
}

// PolicyConfig 策略配置
type PolicyConfig struct {
	// Name 策略名称
	Name string `mapstructure:"name" validate:"required"`
	
	// Effect 效果 (allow/deny)
	Effect string `mapstructure:"effect" validate:"oneof=allow deny"`
	
	// Actions 动作列表
	Actions []string `mapstructure:"actions"`
	
	// Resources 资源列表
	Resources []string `mapstructure:"resources"`
	
	// Conditions 条件
	Conditions map[string]interface{} `mapstructure:"conditions"`
}

// EncryptionConfig 加密配置
type EncryptionConfig struct {
	// Algorithm 加密算法
	Algorithm string `mapstructure:"algorithm" validate:"oneof=aes-256-gcm chacha20-poly1305"`
	
	// Key 加密密钥
	Key string `mapstructure:"key"`
	
	// KeyFile 密钥文件路径
	KeyFile string `mapstructure:"key_file"`
	
	// EnableAtRest 是否启用静态加密
	EnableAtRest bool `mapstructure:"enable_at_rest"`
	
	// EnableInTransit 是否启用传输加密
	EnableInTransit bool `mapstructure:"enable_in_transit"`
}

// AuditLogConfig 审计日志配置
type AuditLogConfig struct {
	// Enabled 是否启用审计日志
	Enabled bool `mapstructure:"enabled"`
	
	// FilePath 审计日志文件路径
	FilePath string `mapstructure:"file_path"`
	
	// MaxSize 最大文件大小(MB)
	MaxSize int `mapstructure:"max_size" validate:"min=1"`
	
	// MaxAge 最大保存天数
	MaxAge int `mapstructure:"max_age" validate:"min=1"`
	
	// Events 要记录的事件类型
	Events []string `mapstructure:"events"`
}

// PerformanceConfig 性能配置
// PerformanceConfig 性能配置
type PerformanceConfig struct {
	// MaxMemory 最大内存使用量(MB)
	MaxMemory int `mapstructure:"max_memory" validate:"min=1"`
	
	// MaxCPU 最大CPU使用率(百分比)
	MaxCPU int `mapstructure:"max_cpu" validate:"min=1,max=100"`
	
	// GCPercent 垃圾回收百分比
	GCPercent int `mapstructure:"gc_percent" validate:"min=1,max=1000"`
	
	// MaxGoroutines 最大协程数
	MaxGoroutines int `mapstructure:"max_goroutines" validate:"min=1"`
	
	// BufferSize 缓冲区大小
	BufferSize int `mapstructure:"buffer_size" validate:"min=1"`
	
	// CacheConfig 缓存配置
	Cache CacheConfig `mapstructure:"cache"`
	
	// ConnectionPool 连接池配置
	ConnectionPool ConnectionPoolConfig `mapstructure:"connection_pool"`
	
	// Profiling 性能分析配置
	Profiling ProfilingConfig `mapstructure:"profiling"`
}

// CacheConfig 缓存配置
type CacheConfig struct {
	// Type 缓存类型
	Type string `mapstructure:"type" validate:"oneof=memory redis"`
	
	// Size 缓存大小
	Size int `mapstructure:"size" validate:"min=1"`
	
	// TTL 缓存过期时间
	TTL time.Duration `mapstructure:"ttl"`
	
	// CleanupInterval 清理间隔
	CleanupInterval time.Duration `mapstructure:"cleanup_interval"`
	
	// EnableCompression 是否启用压缩
	EnableCompression bool `mapstructure:"enable_compression"`
}

// ConnectionPoolConfig 连接池配置
type ConnectionPoolConfig struct {
	// MaxIdle 最大空闲连接数
	MaxIdle int `mapstructure:"max_idle" validate:"min=1"`
	
	// MaxActive 最大活跃连接数
	MaxActive int `mapstructure:"max_active" validate:"min=1"`
	
	// IdleTimeout 空闲超时时间
	IdleTimeout time.Duration `mapstructure:"idle_timeout"`
	
	// ConnectTimeout 连接超时时间
	ConnectTimeout time.Duration `mapstructure:"connect_timeout"`
	
	// ReadTimeout 读取超时时间
	ReadTimeout time.Duration `mapstructure:"read_timeout"`
	
	// WriteTimeout 写入超时时间
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
}

// ProfilingConfig 性能分析配置
type ProfilingConfig struct {
	// Enabled 是否启用性能分析
	Enabled bool `mapstructure:"enabled"`
	
	// Port 性能分析端口
	Port int `mapstructure:"port" validate:"min=1,max=65535"`
	
	// CPUProfile 是否启用CPU分析
	CPUProfile bool `mapstructure:"cpu_profile"`
	
	// MemProfile 是否启用内存分析
	MemProfile bool `mapstructure:"mem_profile"`
	
	// BlockProfile 是否启用阻塞分析
	BlockProfile bool `mapstructure:"block_profile"`
	
	// MutexProfile 是否启用互斥锁分析
	MutexProfile bool `mapstructure:"mutex_profile"`
}

// NotificationConfig 通知配置
type NotificationConfig struct {
	// Enabled 是否启用通知
	Enabled bool `mapstructure:"enabled"`
	
	// Channels 通知渠道配置
	Channels NotificationChannels `mapstructure:"channels"`
	
	// Rules 通知规则
	Rules []NotificationRule `mapstructure:"rules"`
	
	// Templates 通知模板
	Templates map[string]string `mapstructure:"templates"`
}

// NotificationChannels 通知渠道
type NotificationChannels struct {
	// Email 邮件通知配置
	Email EmailConfig `mapstructure:"email"`
	
	// Slack Slack通知配置
	Slack SlackConfig `mapstructure:"slack"`
	
	// Webhook Webhook通知配置
	Webhook WebhookConfig `mapstructure:"webhook"`
	
	// SMS 短信通知配置
	SMS SMSConfig `mapstructure:"sms"`
	
	// DingTalk 钉钉通知配置
	DingTalk DingTalkConfig `mapstructure:"dingtalk"`
	
	// WeChat 微信通知配置
	WeChat WeChatConfig `mapstructure:"wechat"`
}

// EmailConfig 邮件配置
type EmailConfig struct {
	// Enabled 是否启用邮件通知
	Enabled bool `mapstructure:"enabled"`
	
	// SMTPHost SMTP服务器地址
	SMTPHost string `mapstructure:"smtp_host" validate:"required_if=Enabled true"`
	
	// SMTPPort SMTP端口
	SMTPPort int `mapstructure:"smtp_port" validate:"required_if=Enabled true,min=1,max=65535"`
	
	// Username 用户名
	Username string `mapstructure:"username" validate:"required_if=Enabled true"`
	
	// Password 密码
	Password string `mapstructure:"password" validate:"required_if=Enabled true"`
	
	// From 发件人地址
	From string `mapstructure:"from" validate:"required_if=Enabled true,email"`
	
	// To 收件人地址列表
	To []string `mapstructure:"to" validate:"required_if=Enabled true,dive,email"`
	
	// CC 抄送地址列表
	CC []string `mapstructure:"cc" validate:"dive,email"`
	
	// BCC 密送地址列表
	BCC []string `mapstructure:"bcc" validate:"dive,email"`
	
	// EnableTLS 是否启用TLS
	EnableTLS bool `mapstructure:"enable_tls"`
	
	// EnableHTML 是否启用HTML格式
	EnableHTML bool `mapstructure:"enable_html"`
}

// SlackConfig Slack配置
type SlackConfig struct {
	// Enabled 是否启用Slack通知
	Enabled bool `mapstructure:"enabled"`
	
	// WebhookURL Webhook URL
	WebhookURL string `mapstructure:"webhook_url" validate:"required_if=Enabled true,url"`
	
	// Channel 频道名称
	Channel string `mapstructure:"channel"`
	
	// Username 用户名
	Username string `mapstructure:"username"`
	
	// IconEmoji 图标表情
	IconEmoji string `mapstructure:"icon_emoji"`
	
	// IconURL 图标URL
	IconURL string `mapstructure:"icon_url" validate:"omitempty,url"`
}

// WebhookConfig Webhook配置
type WebhookConfig struct {
	// Enabled 是否启用Webhook通知
	Enabled bool `mapstructure:"enabled"`
	
	// URL Webhook URL
	URL string `mapstructure:"url" validate:"required_if=Enabled true,url"`
	
	// Method HTTP方法
	Method string `mapstructure:"method" validate:"oneof=GET POST PUT PATCH DELETE"`
	
	// Headers 请求头
	Headers map[string]string `mapstructure:"headers"`
	
	// Timeout 超时时间
	Timeout time.Duration `mapstructure:"timeout"`
	
	// RetryCount 重试次数
	RetryCount int `mapstructure:"retry_count" validate:"min=0,max=5"`
	
	// Secret 签名密钥
	Secret string `mapstructure:"secret"`
}

// SMSConfig 短信配置
type SMSConfig struct {
	// Enabled 是否启用短信通知
	Enabled bool `mapstructure:"enabled"`
	
	// Provider 短信服务提供商
	Provider string `mapstructure:"provider" validate:"required_if=Enabled true,oneof=aliyun tencent twilio"`
	
	// AccessKey 访问密钥
	AccessKey string `mapstructure:"access_key" validate:"required_if=Enabled true"`
	
	// SecretKey 密钥
	SecretKey string `mapstructure:"secret_key" validate:"required_if=Enabled true"`
	
	// SignName 签名名称
	SignName string `mapstructure:"sign_name" validate:"required_if=Enabled true"`
	
	// TemplateCode 模板代码
	TemplateCode string `mapstructure:"template_code" validate:"required_if=Enabled true"`
	
	// PhoneNumbers 手机号码列表
	PhoneNumbers []string `mapstructure:"phone_numbers" validate:"required_if=Enabled true,dive,required"`
}

// DingTalkConfig 钉钉配置
type DingTalkConfig struct {
	// Enabled 是否启用钉钉通知
	Enabled bool `mapstructure:"enabled"`
	
	// WebhookURL Webhook URL
	WebhookURL string `mapstructure:"webhook_url" validate:"required_if=Enabled true,url"`
	
	// Secret 密钥
	Secret string `mapstructure:"secret"`
	
	// AtMobiles @的手机号列表
	AtMobiles []string `mapstructure:"at_mobiles"`
	
	// AtUserIds @的用户ID列表
	AtUserIds []string `mapstructure:"at_user_ids"`
	
	// IsAtAll 是否@所有人
	IsAtAll bool `mapstructure:"is_at_all"`
}

// WeChatConfig 微信配置
type WeChatConfig struct {
	// Enabled 是否启用微信通知
	Enabled bool `mapstructure:"enabled"`
	
	// WebhookURL Webhook URL
	WebhookURL string `mapstructure:"webhook_url" validate:"required_if=Enabled true,url"`
	
	// MentionedList @的用户列表
	MentionedList []string `mapstructure:"mentioned_list"`
	
	// MentionedMobileList @的手机号列表
	MentionedMobileList []string `mapstructure:"mentioned_mobile_list"`
}

// NotificationRule 通知规则
type NotificationRule struct {
	// Name 规则名称
	Name string `mapstructure:"name" validate:"required"`
	
	// Enabled 是否启用
	Enabled bool `mapstructure:"enabled"`
	
	// Conditions 触发条件
	Conditions []NotificationCondition `mapstructure:"conditions" validate:"dive"`
	
	// Channels 通知渠道
	Channels []string `mapstructure:"channels" validate:"required,dive,oneof=email slack webhook sms dingtalk wechat"`
	
	// Template 通知模板
	Template string `mapstructure:"template"`
	
	// Throttle 节流配置
	Throttle ThrottleConfig `mapstructure:"throttle"`
}

// NotificationCondition 通知条件
type NotificationCondition struct {
	// Field 字段名
	Field string `mapstructure:"field" validate:"required"`
	
	// Operator 操作符
	Operator string `mapstructure:"operator" validate:"required,oneof=eq ne gt lt ge le contains starts_with ends_with"`
	
	// Value 值
	Value interface{} `mapstructure:"value" validate:"required"`
	
	// LogicalOperator 逻辑操作符
	LogicalOperator string `mapstructure:"logical_operator" validate:"oneof=and or"`
}

// ThrottleConfig 节流配置
type ThrottleConfig struct {
	// Enabled 是否启用节流
	Enabled bool `mapstructure:"enabled"`
	
	// Interval 节流间隔
	Interval time.Duration `mapstructure:"interval"`
	
	// MaxCount 最大次数
	MaxCount int `mapstructure:"max_count" validate:"min=1"`
}

// PluginConfig 插件配置
type PluginConfig struct {
	// Enabled 是否启用插件系统
	Enabled bool `mapstructure:"enabled"`
	
	// Directory 插件目录
	Directory string `mapstructure:"directory"`
	
	// AutoLoad 是否自动加载插件
	AutoLoad bool `mapstructure:"auto_load"`
	
	// LoadOrder 加载顺序
	LoadOrder []string `mapstructure:"load_order"`
	
	// Plugins 插件列表
	Plugins []PluginInfo `mapstructure:"plugins" validate:"dive"`
	
	// GlobalConfig 全局插件配置
	GlobalConfig map[string]interface{} `mapstructure:"global_config"`
}

// PluginInfo 插件信息
type PluginInfo struct {
	// Name 插件名称
	Name string `mapstructure:"name" validate:"required"`
	
	// Enabled 是否启用
	Enabled bool `mapstructure:"enabled"`
	
	// Path 插件路径
	Path string `mapstructure:"path"`
	
	// Version 插件版本
	Version string `mapstructure:"version"`
	
	// Config 插件配置
	Config map[string]interface{} `mapstructure:"config"`
	
	// Dependencies 依赖列表
	Dependencies []string `mapstructure:"dependencies"`
	
	// Priority 优先级
	Priority int `mapstructure:"priority"`
}

// VulnConfig 指定要扫描哪些漏洞及其配置。
type VulnConfig struct {
	// Type 是漏洞的类型（例如，"sqli", "xss"）。
	Type string `mapstructure:"type" validate:"required"`
	
	// Enabled 是否启用该漏洞检测
	Enabled bool `mapstructure:"enabled"`
	
	// Severity 漏洞严重程度
	Severity string `mapstructure:"severity" validate:"oneof=low medium high critical"`
	
	// Payloads 是该漏洞类型的攻击载荷列表。
	Payloads []Payload `mapstructure:"payloads" validate:"dive"`
	
	// CustomRules 自定义规则
	CustomRules []CustomRule `mapstructure:"custom_rules" validate:"dive"`
	
	// Config 漏洞特定配置
	Config map[string]interface{} `mapstructure:"config"`
	
	// Timeout 检测超时时间
	Timeout time.Duration `mapstructure:"timeout"`
	
	// MaxAttempts 最大尝试次数
	MaxAttempts int `mapstructure:"max_attempts" validate:"min=1,max=10"`
}

// Payload 定义了单个攻击载荷及其值和描述。
type Payload struct {
	// Value 是实际的载荷字符串。
	Value string `mapstructure:"value" validate:"required"`
	
	// Description 提供了关于载荷的上下文。
	Description string `mapstructure:"description"`
	
	// Type 载荷类型
	Type string `mapstructure:"type"`
	
	// Severity 载荷严重程度
	Severity string `mapstructure:"severity" validate:"oneof=low medium high critical"`
	
	// Tags 标签
	Tags []string `mapstructure:"tags"`
	
	// Encoded 是否已编码
	Encoded bool `mapstructure:"encoded"`
	
	// ExpectedResponse 期望的响应模式
	ExpectedResponse []string `mapstructure:"expected_response"`
	
	// AvoidResponse 要避免的响应模式
	AvoidResponse []string `mapstructure:"avoid_response"`
}

// CustomRule 自定义规则
type CustomRule struct {
	// Name 规则名称
	Name string `mapstructure:"name" validate:"required"`
	
	// Pattern 匹配模式
	Pattern string `mapstructure:"pattern" validate:"required"`
	
	// Type 规则类型
	Type string `mapstructure:"type" validate:"oneof=regex xpath css"`
	
	// Severity 严重程度
	Severity string `mapstructure:"severity" validate:"oneof=low medium high critical"`
	
	// Description 描述
	Description string `mapstructure:"description"`
	
	// Tags 标签
	Tags []string `mapstructure:"tags"`
}

// ConfigManager 配置管理器
type ConfigManager struct {
	config    *Settings
	validator *validator.Validate
	mu        sync.RWMutex
	watchers  []func(*Settings)
	filePath  string
}

// NewConfigManager 创建新的配置管理器
func NewConfigManager() *ConfigManager {
	return &ConfigManager{
		validator: validator.New(),
		watchers:  make([]func(*Settings), 0),
	}
}

// LoadConfig 从给定路径的文件中读取配置并将其解析到 Settings 结构体中
func (cm *ConfigManager) LoadConfig(path string) (*Settings, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	cm.filePath = path
	
	// 设置默认值
	cm.setDefaults()
	
	var c Settings
	if path != "" {
		viper.SetConfigFile(path)
	} else {
		viper.AddConfigPath(".")
		viper.AddConfigPath("./config")
		viper.AddConfigPath("/etc/autovulnscan")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	// 设置环境变量支持
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()
	viper.SetEnvPrefix("AVS") // AutoVulnScan prefix

	// 读取配置文件
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Warn().Msg("配置文件未找到，使用默认配置")
		} else {
			return nil, fmt.Errorf("读取配置文件失败: %w", err)
		}
	}

	// 解析配置
	if err := viper.Unmarshal(&c); err != nil {
		return nil, fmt.Errorf("解析配置失败: %w", err)
	}

	// 验证配置
	if err := cm.validateConfig(&c); err != nil {
		return nil, fmt.Errorf("配置验证失败: %w", err)
	}

	// 后处理配置
	if err := cm.postProcessConfig(&c); err != nil {
		return nil, fmt.Errorf("配置后处理失败: %w", err)
	}

	cm.config = &c
	
	log.Info().
		Str("config_file", viper.ConfigFileUsed()).
		Str("version", c.Version).
		Msg("配置加载成功")

	return &c, nil
}

// setDefaults 设置默认配置值
func (cm *ConfigManager) setDefaults() {
	// 基础配置默认值
	viper.SetDefault("version", ConfigVersion)
	viper.SetDefault("debug", false)
	viper.SetDefault("scope", []string{})
	viper.SetDefault("blacklist", []string{})
	viper.SetDefault("whitelist", []string{})
	
	// 速率限制默认值
	viper.SetDefault("rate_limit.enabled", true)
	viper.SetDefault("rate_limit.requests_per_second", 10)
	viper.SetDefault("rate_limit.burst_size", 20)
	viper.SetDefault("rate_limit.per_host", true)
	
	// 日志默认值
	viper.SetDefault("log.level", "info")
	viper.SetDefault("log.format", "json")
	viper.SetDefault("log.max_size", 100)
	viper.SetDefault("log.max_age", 30)
	viper.SetDefault("log.max_backups", 10)
	viper.SetDefault("log.compress", true)
	viper.SetDefault("log.enable_console", true)
	
	// 爬虫默认值
	viper.SetDefault("spider.concurrency", 10)
	viper.SetDefault("spider.limit", 1000)
	viper.SetDefault("spider.timeout", "30s")
	viper.SetDefault("spider.max_depth", 3)
	viper.SetDefault("spider.max_page_visit_per_site", 100)
	viper.SetDefault("spider.delay", "1s")
	viper.SetDefault("spider.random_delay", "2s")
	viper.SetDefault("spider.max_file_size", 10*1024*1024) // 10MB
	viper.SetDefault("spider.follow_redirects", true)
	viper.SetDefault("spider.max_redirects", 5)
	viper.SetDefault("spider.randomize_user_agent", true)
	viper.SetDefault("spider.user_agents", []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
	})
	
	// 相似性检测默认值
	viper.SetDefault("spider.similarity_page_dom.use", true)
	viper.SetDefault("spider.similarity_page_dom.threshold", 100)
	viper.SetDefault("spider.similarity_page_dom.similarity", 0.8)
	viper.SetDefault("spider.similarity_page_dom.vector_dim", 128)
	viper.SetDefault("spider.similarity_page_dom.algorithm", "cosine")
	viper.SetDefault("spider.similarity_page_dom.cache_size", 1000)
	
	// 动态爬虫默认值
	viper.SetDefault("spider.dynamic_crawler.enabled", false)
	viper.SetDefault("spider.dynamic_crawler.headless", true)
	viper.SetDefault("spider.dynamic_crawler.browser_type", "chromium")
	viper.SetDefault("spider.dynamic_crawler.max_instances", 3)
	viper.SetDefault("spider.dynamic_crawler.page_timeout", "30s")
	viper.SetDefault("spider.dynamic_crawler.wait_time", "2s")
	viper.SetDefault("spider.dynamic_crawler.enable_javascript", true)
	viper.SetDefault("spider.dynamic_crawler.enable_images", false)
	viper.SetDefault("spider.dynamic_crawler.enable_css", false)
	viper.SetDefault("spider.dynamic_crawler.viewport_width", 1920)
	viper.SetDefault("spider.dynamic_crawler.viewport_height", 1080)
	viper.SetDefault("spider.dynamic_crawler.screenshot_on_error", false)
	
	// 扫描器默认值
	viper.SetDefault("scanner.concurrency", 5)
	viper.SetDefault("scanner.limit", 500)
	viper.SetDefault("scanner.filter_threshold", 10)
	viper.SetDefault("scanner.found_hidden_parameter", true)
	viper.SetDefault("scanner.found_hidden_parameter_from_js", true)
	viper.SetDefault("scanner.parameter_group_size", 5)
	viper.SetDefault("scanner.timeout", "30s")
	viper.SetDefault("scanner.plugin_timeout", "10s")
	viper.SetDefault("scanner.max_payload_size", 8192)
	viper.SetDefault("scanner.retry_count", 2)
	viper.SetDefault("scanner.retry_delay", "1s")
	viper.SetDefault("scanner.skip_ssl_verification", false)
	viper.SetDefault("scanner.follow_redirects", true)
	viper.SetDefault("scanner.position", []string{"get", "post", "cookie", "header"})
	
	// 扫描器输出默认值
	viper.SetDefault("scanner.output.response", false)
	viper.SetDefault("scanner.output.response_header", true)
	viper.SetDefault("scanner.output.request", true)
	viper.SetDefault("scanner.output.evidence", true)
	viper.SetDefault("scanner.output.payload", true)
	viper.SetDefault("scanner.output.verbose", false)
	
	// 报告默认值
	viper.SetDefault("reporting.path", "./reports")
	viper.SetDefault("reporting.vuln_report_file", "vulnerabilities.json")
	viper.SetDefault("reporting.spider_file", "spider_results.json")
	viper.SetDefault("reporting.json_report_file", "report.json")
	viper.SetDefault("reporting.html_report_file", "report.html")
	viper.SetDefault("reporting.xml_report_file", "report.xml")
	viper.SetDefault("reporting.csv_report_file", "report.csv")
	viper.SetDefault("reporting.pdf_report_file", "report.pdf")
	
	// 报告压缩默认值
	viper.SetDefault("reporting.compression.enabled", false)
	viper.SetDefault("reporting.compression.format", "zip")
	viper.SetDefault("reporting.compression.level", 6)
	
	// 自动清理默认值
	viper.SetDefault("reporting.auto_cleanup.enabled", true)
	viper.SetDefault("reporting.auto_cleanup.max_age", "30d")
	viper.SetDefault("reporting.auto_cleanup.max_count", 100)
	
	// Redis默认值
	viper.SetDefault("redis.enabled", false)
	viper.SetDefault("redis.database", 0)
	viper.SetDefault("redis.max_retries", 3)
	viper.SetDefault("redis.pool_size", 10)
	viper.SetDefault("redis.min_idle_conns", 2)
	viper.SetDefault("redis.max_idle_time", "5m")
	viper.SetDefault("redis.conn_max_lifetime", "1h")
	viper.SetDefault("redis.key_prefix", "avs:")
	viper.SetDefault("redis.enable_cluster", false)
	
	// 数据库默认值
	viper.SetDefault("database.type", "sqlite")
	viper.SetDefault("database.dsn", "./autovulnscan.db")
	viper.SetDefault("database.max_open_conns", 25)
	viper.SetDefault("database.max_idle_conns", 5)
	viper.SetDefault("database.conn_max_lifetime", "1h")
	viper.SetDefault("database.enable_migration", true)
	viper.SetDefault("database.log_level", "warn")
	
	// AI模块默认值
	viper.SetDefault("ai_module.enabled", false)
	viper.SetDefault("ai_module.provider", "openai")
	viper.SetDefault("ai_module.max_tokens", 2048)
	viper.SetDefault("ai_module.temperature", 0.7)
	viper.SetDefault("ai_module.timeout", "30s")
	viper.SetDefault("ai_module.max_retries", 3)
	viper.SetDefault("ai_module.enable_cache", true)
	viper.SetDefault("ai_module.cache_expiry", "24h")
	
	// AI功能默认值
	viper.SetDefault("ai_module.features.vuln_analysis", true)
	viper.SetDefault("ai_module.features.payload_generation", false)
	viper.SetDefault("ai_module.features.false_positive_detection", true)
	viper.SetDefault("ai_module.features.report_generation", true)
	viper.SetDefault("ai_module.features.threat_intelligence", false)
	
	// 安全配置默认值
	viper.SetDefault("security.enable_https", false)
	viper.SetDefault("security.tls_config.min_version", "1.2")
	viper.SetDefault("security.tls_config.insecure_skip_verify", false)
	viper.SetDefault("security.authentication.type", "none")
	viper.SetDefault("security.authorization.type", "none")
	viper.SetDefault("security.encryption.algorithm", "aes-256-gcm")
	viper.SetDefault("security.encryption.enable_at_rest", false)
	viper.SetDefault("security.encryption.enable_in_transit", true)
	viper.SetDefault("security.audit_log.enabled", false)
	viper.SetDefault("security.audit_log.max_size", 100)
	viper.SetDefault("security.audit_log.max_age", 90)
	
	// 性能配置默认值
	viper.SetDefault("performance.max_memory", 1024) // 1GB
	viper.SetDefault("performance.max_cpu", 80)
	viper.SetDefault("performance.gc_percent", 100)
	viper.SetDefault("performance.max_goroutines", 1000)
	viper.SetDefault("performance.buffer_size", 4096)
	
	// 缓存默认值
	viper.SetDefault("performance.cache.type", "memory")
	viper.SetDefault("performance.cache.size", 1000)
	viper.SetDefault("performance.cache.ttl", "1h")
	viper.SetDefault("performance.cache.cleanup_interval", "10m")
	viper.SetDefault("performance.cache.enable_compression", false)
	
	// 连接池默认值
	viper.SetDefault("performance.connection_pool.max_idle", 10)
	viper.SetDefault("performance.connection_pool.max_active", 100)
	viper.SetDefault("performance.connection_pool.idle_timeout", "5m")
	viper.SetDefault("performance.connection_pool.connect_timeout", "10s")
	viper.SetDefault("performance.connection_pool.read_timeout", "30s")
	viper.SetDefault("performance.connection_pool.write_timeout", "30s")
	
		// 性能分析默认值
		viper.SetDefault("performance.profiling.enabled", false)
		viper.SetDefault("performance.profiling.port", 6060)
		viper.SetDefault("performance.profiling.cpu_profile", false)
		viper.SetDefault("performance.profiling.mem_profile", false)
		viper.SetDefault("performance.profiling.block_profile", false)
		viper.SetDefault("performance.profiling.mutex_profile", false)
		
		// 通知默认值
		viper.SetDefault("notifications.enabled", false)
		
		// 插件默认值
		viper.SetDefault("plugins.enabled", false)
		viper.SetDefault("plugins.directory", "./plugins")
		viper.SetDefault("plugins.auto_load", true)
	}
	
	// validateConfig 验证配置
	func (cm *ConfigManager) validateConfig(config *Settings) error {
		// 注册自定义验证器
		cm.registerCustomValidators()
		
		if err := cm.validator.Struct(config); err != nil {
			return cm.formatValidationError(err)
		}
		
		// 自定义验证逻辑
		if err := cm.customValidation(config); err != nil {
			return err
		}
		
		return nil
	}
	
	// registerCustomValidators 注册自定义验证器
	func (cm *ConfigManager) registerCustomValidators() {
		// 注册URL验证器
		cm.validator.RegisterValidation("url", func(fl validator.FieldLevel) bool {
			return isValidURL(fl.Field().String())
		})
		
		// 注册邮箱验证器
		cm.validator.RegisterValidation("email", func(fl validator.FieldLevel) bool {
			return isValidEmail(fl.Field().String())
		})
		
		// 注册路径验证器
		cm.validator.RegisterValidation("path", func(fl validator.FieldLevel) bool {
			return isValidPath(fl.Field().String())
		})
	}
	
	// formatValidationError 格式化验证错误
	func (cm *ConfigManager) formatValidationError(err error) error {
		var errors []string
		
		for _, err := range err.(validator.ValidationErrors) {
			switch err.Tag() {
			case "required":
				errors = append(errors, fmt.Sprintf("字段 '%s' 是必需的", err.Field()))
			case "min":
				errors = append(errors, fmt.Sprintf("字段 '%s' 的值必须大于等于 %s", err.Field(), err.Param()))
			case "max":
				errors = append(errors, fmt.Sprintf("字段 '%s' 的值必须小于等于 %s", err.Field(), err.Param()))
			case "url":
				errors = append(errors, fmt.Sprintf("字段 '%s' 必须是有效的URL", err.Field()))
			case "email":
				errors = append(errors, fmt.Sprintf("字段 '%s' 必须是有效的邮箱地址", err.Field()))
			case "oneof":
				errors = append(errors, fmt.Sprintf("字段 '%s' 的值必须是以下之一: %s", err.Field(), err.Param()))
			default:
				errors = append(errors, fmt.Sprintf("字段 '%s' 验证失败: %s", err.Field(), err.Tag()))
			}
		}
		
		return fmt.Errorf("配置验证错误:\n%s", strings.Join(errors, "\n"))
	}
	
	// customValidation 自定义验证逻辑
	func (cm *ConfigManager) customValidation(config *Settings) error {
		// 验证版本兼容性
		if config.Version != ConfigVersion {
			log.Warn().
				Str("config_version", config.Version).
				Str("expected_version", ConfigVersion).
				Msg("配置版本不匹配，可能存在兼容性问题")
		}
		
		// 验证范围配置
		if len(config.Scope) == 0 {
			return fmt.Errorf("必须至少配置一个扫描范围")
		}
		
		// 验证并发配置
		if config.Spider.Concurrency > config.Scanner.Concurrency*2 {
			log.Warn().Msg("爬虫并发数远大于扫描器并发数，可能导致资源浪费")
		}
		
		// 验证Redis配置
		if config.Redis.Enabled && config.Redis.URL == "" {
			return fmt.Errorf("启用Redis时必须提供连接URL")
		}
		
		// 验证AI模块配置
		if config.AIModule.Enabled {
			if config.AIModule.APIKey == "" {
				return fmt.Errorf("启用AI模块时必须提供API密钥")
			}
			if config.AIModule.Model == "" {
				return fmt.Errorf("启用AI模块时必须指定模型")
			}
		}
		
		// 验证通知配置
		if config.Notifications.Enabled {
			if err := cm.validateNotificationConfig(&config.Notifications); err != nil {
				return fmt.Errorf("通知配置验证失败: %w", err)
			}
		}
		
		// 验证报告路径
		if err := cm.ensureDirectoryExists(config.Reporting.Path); err != nil {
			return fmt.Errorf("创建报告目录失败: %w", err)
		}
		
		// 验证日志路径
		if config.Log.FilePath != "" {
			logDir := filepath.Dir(config.Log.FilePath)
			if err := cm.ensureDirectoryExists(logDir); err != nil {
				return fmt.Errorf("创建日志目录失败: %w", err)
			}
		}
		
		return nil
	}
	
	// validateNotificationConfig 验证通知配置
	func (cm *ConfigManager) validateNotificationConfig(config *NotificationConfig) error {
		hasEnabledChannel := false
		
		// 检查是否有启用的通知渠道
		if config.Channels.Email.Enabled {
			hasEnabledChannel = true
		}
		if config.Channels.Slack.Enabled {
			hasEnabledChannel = true
		}
		if config.Channels.Webhook.Enabled {
			hasEnabledChannel = true
		}
		if config.Channels.SMS.Enabled {
			hasEnabledChannel = true
		}
		if config.Channels.DingTalk.Enabled {
			hasEnabledChannel = true
		}
		if config.Channels.WeChat.Enabled {
			hasEnabledChannel = true
		}
		
		if !hasEnabledChannel {
			return fmt.Errorf("启用通知时必须至少配置一个通知渠道")
		}
		
		// 验证通知规则
		for i, rule := range config.Rules {
			if len(rule.Conditions) == 0 {
				return fmt.Errorf("通知规则 '%s' (索引: %d) 必须至少有一个条件", rule.Name, i)
			}
			if len(rule.Channels) == 0 {
				return fmt.Errorf("通知规则 '%s' (索引: %d) 必须至少指定一个通知渠道", rule.Name, i)
			}
		}
		
		return nil
	}
	
	// postProcessConfig 配置后处理
	func (cm *ConfigManager) postProcessConfig(config *Settings) error {
		// 处理相对路径
		if err := cm.processRelativePaths(config); err != nil {
			return err
		}
		
		// 处理环境变量替换
		if err := cm.processEnvironmentVariables(config); err != nil {
			return err
		}
		
		// 处理默认用户代理
		if len(config.Spider.UserAgents) == 0 {
			config.Spider.UserAgents = []string{
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
				"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
				"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			}
		}
		
		// 处理默认漏洞配置
		if len(config.Scanner.Vulnerabilities) == 0 {
			config.Scanner.Vulnerabilities = cm.getDefaultVulnConfigs()
		}
		
		// 处理默认文件扩展名
		if len(config.Spider.FileExtensions) == 0 {
			config.Spider.FileExtensions = []string{
				"html", "htm", "php", "asp", "aspx", "jsp", "js", "json", "xml",
			}
		}
		
		if len(config.Spider.ExcludeExtensions) == 0 {
			config.Spider.ExcludeExtensions = []string{
				"jpg", "jpeg", "png", "gif", "bmp", "ico", "svg",
				"css", "woff", "woff2", "ttf", "eot",
				"mp3", "mp4", "avi", "mov", "wmv", "flv",
				"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
				"zip", "rar", "7z", "tar", "gz",
			}
		}
		
		return nil
	}
	
	// processRelativePaths 处理相对路径
	func (cm *ConfigManager) processRelativePaths(config *Settings) error {
		// 处理报告路径
		if !filepath.IsAbs(config.Reporting.Path) {
			absPath, err := filepath.Abs(config.Reporting.Path)
			if err != nil {
				return fmt.Errorf("处理报告路径失败: %w", err)
			}
			config.Reporting.Path = absPath
		}
		
		// 处理日志路径
		if config.Log.FilePath != "" && !filepath.IsAbs(config.Log.FilePath) {
			absPath, err := filepath.Abs(config.Log.FilePath)
			if err != nil {
				return fmt.Errorf("处理日志路径失败: %w", err)
			}
			config.Log.FilePath = absPath
		}
		
		// 处理插件目录
		if config.Plugins.Enabled && !filepath.IsAbs(config.Plugins.Directory) {
			absPath, err := filepath.Abs(config.Plugins.Directory)
			if err != nil {
				return fmt.Errorf("处理插件目录路径失败: %w", err)
			}
			config.Plugins.Directory = absPath
		}
		
		return nil
	}
	
	// processEnvironmentVariables 处理环境变量替换
	func (cm *ConfigManager) processEnvironmentVariables(config *Settings) error {
		// 使用反射处理所有字符串字段的环境变量替换
		return cm.processEnvVarsRecursive(reflect.ValueOf(config).Elem())
	}
	
	// processEnvVarsRecursive 递归处理环境变量
	func (cm *ConfigManager) processEnvVarsRecursive(v reflect.Value) error {
		switch v.Kind() {
		case reflect.String:
			if v.CanSet() {
				original := v.String()
				expanded := os.ExpandEnv(original)
				if expanded != original {
					v.SetString(expanded)
				}
			}
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if err := cm.processEnvVarsRecursive(v.Field(i)); err != nil {
					return err
				}
			}
		case reflect.Slice:
			for i := 0; i < v.Len(); i++ {
				if err := cm.processEnvVarsRecursive(v.Index(i)); err != nil {
					return err
				}
			}
		case reflect.Map:
			for _, key := range v.MapKeys() {
				mapValue := v.MapIndex(key)
				if mapValue.Kind() == reflect.String {
					original := mapValue.String()
					expanded := os.ExpandEnv(original)
					if expanded != original {
						v.SetMapIndex(key, reflect.ValueOf(expanded))
					}
				}
			}
		case reflect.Ptr:
			if !v.IsNil() {
				return cm.processEnvVarsRecursive(v.Elem())
			}
		}
		return nil
	}
	
	// getDefaultVulnConfigs 获取默认漏洞配置
	func (cm *ConfigManager) getDefaultVulnConfigs() []VulnConfig {
		return []VulnConfig{
			{
				Type:     "xss",
				Enabled:  true,
				Severity: "high",
				Payloads: []Payload{
					{
						Value:       "<script>alert('XSS')</script>",
						Description: "基础XSS测试",
						Type:        "reflected",
						Severity:    "high",
						Tags:        []string{"xss", "script"},
					},
					{
						Value:       "javascript:alert('XSS')",
						Description: "JavaScript协议XSS",
						Type:        "reflected",
						Severity:    "medium",
						Tags:        []string{"xss", "javascript"},
					},
				},
				Timeout:     30 * time.Second,
				MaxAttempts: 3,
			},
			{
				Type:     "sqli",
				Enabled:  true,
				Severity: "critical",
				Payloads: []Payload{
					{
						Value:       "' OR '1'='1",
						Description: "基础SQL注入测试",
						Type:        "boolean",
						Severity:    "critical",
						Tags:        []string{"sqli", "boolean"},
					},
					{
						Value:       "'; DROP TABLE users; --",
						Description: "SQL注入删除表测试",
						Type:        "destructive",
						Severity:    "critical",
						Tags:        []string{"sqli", "destructive"},
					},
				},
				Timeout:     30 * time.Second,
				MaxAttempts: 3,
			},
			{
				Type:     "lfi",
				Enabled:  true,
				Severity: "high",
				Payloads: []Payload{
					{
						Value:       "../../../etc/passwd",
						Description: "Linux本地文件包含",
						Type:        "path_traversal",
						Severity:    "high",
						Tags:        []string{"lfi", "linux"},
					},
					{
						Value:       "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
						Description: "Windows本地文件包含",
						Type:        "path_traversal",
						Severity:    "high",
						Tags:        []string{"lfi", "windows"},
					},
				},
				Timeout:     30 * time.Second,
				MaxAttempts: 3,
			},
			{
				Type:     "rfi",
				Enabled:  false, // 默认禁用，因为可能造成危害
				Severity: "critical",
				Payloads: []Payload{
					{
						Value:       "http://evil.com/shell.txt",
						Description: "远程文件包含测试",
						Type:        "remote_inclusion",
						Severity:    "critical",
						Tags:        []string{"rfi", "remote"},
					},
				},
				Timeout:     30 * time.Second,
				MaxAttempts: 1,
			},
			{
				Type:     "csrf",
				Enabled:  true,
				Severity: "medium",
				Payloads: []Payload{
					{
						Value:       "test_csrf_token",
						Description: "CSRF令牌测试",
						Type:        "token_bypass",
						Severity:    "medium",
						Tags:        []string{"csrf", "token"},
					},
				},
				Timeout:     30 * time.Second,
				MaxAttempts: 2,
			},
		}
	}
	
	// ensureDirectoryExists 确保目录存在
	func (cm *ConfigManager) ensureDirectoryExists(dir string) error {
		if dir == "" {
			return nil
		}
		
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("创建目录失败 %s: %w", dir, err)
			}
			log.Info().Str("directory", dir).Msg("已创建目录")
		}
		
		return nil
	}
	
	// GetConfig 获取当前配置
	func (cm *ConfigManager) GetConfig() *Settings {
		cm.mu.RLock()
		defer cm.mu.RUnlock()
		return cm.config
	}
	
	// UpdateConfig 更新配置
	func (cm *ConfigManager) UpdateConfig(newConfig *Settings) error {
		cm.mu.Lock()
		defer cm.mu.Unlock()
		
		// 验证新配置
		if err := cm.validateConfig(newConfig); err != nil {
			return fmt.Errorf("新配置验证失败: %w", err)
		}
		
		// 后处理新配置
		if err := cm.postProcessConfig(newConfig); err != nil {
			return fmt.Errorf("新配置后处理失败: %w", err)
		}
		
		oldConfig := cm.config
		cm.config = newConfig
		
		// 通知观察者
		cm.notifyWatchers(newConfig)
		
		log.Info().Msg("配置已更新")
		
		// 如果更新失败，可以回滚
		_ = oldConfig
		
		return nil
	}
	
	// WatchConfig 监听配置文件变化
	func (cm *ConfigManager) WatchConfig() error {
		if cm.filePath == "" {
			return fmt.Errorf("无法监听配置文件：未指定文件路径")
		}
		
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			return fmt.Errorf("创建文件监听器失败: %w", err)
		}
		
		go func() {
			defer watcher.Close()
			
			for {
				select {
				case event, ok := <-watcher.Events:
					if !ok {
						return
					}
					
					if event.Op&fsnotify.Write == fsnotify.Write {
						log.Info().Str("file", event.Name).Msg("配置文件已修改，重新加载")
						
						// 重新加载配置
						if newConfig, err := cm.LoadConfig(cm.filePath); err != nil {
							log.Error().Err(err).Msg("重新加载配置失败")
						} else {
							cm.mu.Lock()
							cm.config = newConfig
							cm.mu.Unlock()
							
							// 通知观察者
							cm.notifyWatchers(newConfig)
							
							log.Info().Msg("配置已重新加载")
						}
					}
					
				case err, ok := <-watcher.Errors:
					if !ok {
						return
					}
					log.Error().Err(err).Msg("配置文件监听错误")
				}
			}
		}()
		
		// 监听配置文件
		if err := watcher.Add(cm.filePath); err != nil {
			return fmt.Errorf("添加文件监听失败: %w", err)
		}
		
		log.Info().Str("file", cm.filePath).Msg("开始监听配置文件变化")
		return nil
	}
	
	// AddWatcher 添加配置变化观察者
	func (cm *ConfigManager) AddWatcher(watcher func(*Settings)) {
		cm.mu.Lock()
		defer cm.mu.Unlock()
		cm.watchers = append(cm.watchers, watcher)
	}
	
	// notifyWatchers 通知所有观察者
	func (cm *ConfigManager) notifyWatchers(config *Settings) {
		for _, watcher := range cm.watchers {
			go func(w func(*Settings)) {
				defer func() {
					if r := recover(); r != nil {
						log.Error().Interface("panic", r).Msg("配置观察者执行异常")
					}
				}()
				w(config)
			}(watcher)
		}
	}
	
	// SaveConfig 保存配置到文件
	func (cm *ConfigManager) SaveConfig(config *Settings, path string) error {
		// 验证配置
		if err := cm.validateConfig(config); err != nil {
			return fmt.Errorf("配置验证失败: %w", err)
		}
		
		// 序列化配置
		viper.Set("config", config)
		
		// 写入文件
		if err := viper.WriteConfigAs(path); err != nil {
			return fmt.Errorf("保存配置文件失败: %w", err)
		}
		
		log.Info().Str("file", path).Msg("配置已保存")
		return nil
	}
	
	// ExportConfig 导出配置为指定格式
	func (cm *ConfigManager) ExportConfig(format string) ([]byte, error) {
		cm.mu.RLock()
		defer cm.mu.RUnlock()
		
		if cm.config == nil {
			return nil, fmt.Errorf("配置未初始化")
		}
		
		switch strings.ToLower(format) {
		case "json":
			return json.MarshalIndent(cm.config, "", "  ")
		case "yaml":
			return yaml.Marshal(cm.config)
		case "toml":
			return toml.Marshal(cm.config)
		default:
			return nil, fmt.Errorf("不支持的格式: %s", format)
		}
	}
	
	// ImportConfig 从数据导入配置
	func (cm *ConfigManager) ImportConfig(data []byte, format string) (*Settings, error) {
		var config Settings
		
		switch strings.ToLower(format) {
		case "json":
			if err := json.Unmarshal(data, &config); err != nil {
				return nil, fmt.Errorf("解析JSON配置失败: %w", err)
			}
		case "yaml":
			if err := yaml.Unmarshal(data, &config); err != nil {
				return nil, fmt.Errorf("解析YAML配置失败: %w", err)
			}
		case "toml":
			if err := toml.Unmarshal(data, &config); err != nil {
				return nil, fmt.Errorf("解析TOML配置失败: %w", err)
			}
		default:
			return nil, fmt.Errorf("不支持的格式: %s", format)
		}
		
		// 验证配置
		if err := cm.validateConfig(&config); err != nil {
			return nil, fmt.Errorf("导入的配置验证失败: %w", err)
		}
		
		// 后处理配置
		if err := cm.postProcessConfig(&config); err != nil {
			return nil, fmt.Errorf("导入的配置后处理失败: %w", err)
		}
		
		return &config, nil
	}
	
	// GetConfigSummary 获取配置摘要
	func (cm *ConfigManager) GetConfigSummary() map[string]interface{} {
		cm.mu.RLock()
		defer cm.mu.RUnlock()
		
		if cm.config == nil {
			return map[string]interface{}{"status": "未初始化"}
		}
		
		return map[string]interface{}{
			"version":                cm.config.Version,
			"debug":                  cm.config.Debug,
			"scope_count":            len(cm.config.Scope),
			"blacklist_count":        len(cm.config.Blacklist),
			"spider_concurrency":     cm.config.Spider.Concurrency,
			"scanner_concurrency":    cm.config.Scanner.Concurrency,
			"vulnerabilities_count":  len(cm.config.Scanner.Vulnerabilities),
			"redis_enabled":          cm.config.Redis.Enabled,
			"ai_module_enabled":      cm.config.AIModule.Enabled,
			"notifications_enabled":  cm.config.Notifications.Enabled,
			"plugins_enabled":        cm.config.Plugins.Enabled,
			"dynamic_crawler_enabled": cm.config.Spider.DynamicCrawler.Enabled,
		}
	}
	
	// ValidateConfigFile 验证配置文件
	func ValidateConfigFile(path string) error {
		cm := NewConfigManager()
		_, err := cm.LoadConfig(path)
		return err
	}
	
	// 辅助函数
	
	// isValidURL 验证URL格式
	func isValidURL(str string) bool {
		if str == "" {
			return true // 空字符串在某些情况下是有效的
		}
		
		u, err := url.Parse(str)
		return err == nil && u.Scheme != "" && u.Host != ""
	}
	
	// isValidEmail 验证邮箱格式
	func isValidEmail(email string) bool {
		if email == "" {
			return true
		}
		
		// 简单的邮箱格式验证
		return strings.Contains(email, "@") && strings.Contains(email, ".")
	}
	
	// isValidPath 验证路径格式
	func isValidPath(path string) bool {
		if path == "" {
			return true
		}
		
		// 检查路径是否包含非法字符
		invalidChars := []string{"<", ">", ":", "\"", "|", "?", "*"}
		for _, char := range invalidChars {
			if strings.Contains(path, char) {
				return false
			}
		}
		
		return true
	}
	
	// 便利函数
	
	// LoadConfig 加载配置的便利函数
	func LoadConfig(path string) (*Settings, error) {
		cm := NewConfigManager()
		return cm.LoadConfig(path)
	}
	
	// LoadConfigWithDefaults 使用默认值加载配置
	func LoadConfigWithDefaults() (*Settings, error) {
		cm := NewConfigManager()
		return cm.LoadConfig("")
	}
	
	// MergeConfigs 合并两个配置
	func MergeConfigs(base, override *Settings) *Settings {
		// 使用反射深度合并配置
		// 这里简化实现，实际应该递归合并所有字段
		merged := *base
		
		// 合并基础字段
		if override.Debug {
			merged.Debug = override.Debug
		}
		
		if override.Proxy != "" {
			merged.Proxy = override.Proxy
		}
		
		// 合并数组字段
		if len(override.Scope) > 0 {
			merged.Scope = append(merged.Scope, override.Scope...)
		}
		
		if len(override.Blacklist) > 0 {
			merged.Blacklist = append(merged.Blacklist, override.Blacklist...)
		}
		
		// 合并映射字段
		if len(override.Headers) > 0 {
			if merged.Headers == nil {
				merged.Headers = make(map[string]string)
			}
			for k, v := range override.Headers {
				merged.Headers[k] = v
			}
		}
		
		return &merged
	}
	
	// CreateConfigTemplate 创建配置模板
	func CreateConfigTemplate(path string) error {
		template := `# AutoVulnScan 配置文件模板
	version: "1.0"
	debug: false
	
	# 扫描范围
	scope:
	  - "https://example.com"
	
	# 黑名单
	blacklist:
	  - "*.jpg"
	  - "*.png"
	
	# 自定义HTTP头
	headers:
	  User-Agent: "AutoVulnScan/1.0"
	
	# 日志配置
	log:
	  level: "info"
	  format: "json"
	  file_path: "./logs/autovulnscan.log"
	  max_size: 100
	  max_age: 30
	  max_backups: 10
	  compress: true
	  enable_console: true
	
	# 爬虫配置
	spider:
	  concurrency: 10
	  limit: 1000
	  timeout: 30s
	  max_depth: 3
	  max_page_visit_per_site: 100
	  
	  # 动态爬虫
	  dynamic_crawler:
		enabled: false
		headless: true
		browser_type: "chromium"
	
	# 扫描器配置
	scanner:
	  concurrency: 5
	  limit: 500
	  timeout: 30s
	  position:
		- "get"
		- "post"
		- "cookie"
		- "header"
	
	# 报告配置
	reporting:
	  path: "./reports"
	  json_report_file: "report.json"
	  html_report_file: "report.html"
	
	# Redis配置
	redis:
	  enabled: false
	  url: "redis://localhost:6379"
	
	# AI模块配置
	ai_module:
	  enabled: false
	  provider: "openai"
	  model: "gpt-3.5-turbo"
	  api_key: "${OPENAI_API_KEY}"
	
	# 通知配置
	notifications:
	  enabled: false
	  channels:
		email:
		  enabled: false
		  smtp_host: "smtp.gmail.com"
		  smtp_port: 587
		  username: "your-email@gmail.com"
		  password: "${EMAIL_PASSWORD}"
		  from: "your-email@gmail.com"
		  to:
			- "admin@example.com"
	`
		
	return os.WriteFile(path, []byte(template), 0644)
}

// GetConfigSchema 获取配置结构的JSON Schema
func GetConfigSchema() ([]byte, error) {
	schema := map[string]interface{}{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"title":   "AutoVulnScan Configuration Schema",
		"type":    "object",
		"properties": map[string]interface{}{
			"version": map[string]interface{}{
				"type":        "string",
				"description": "配置文件版本",
				"default":     ConfigVersion,
			},
			"debug": map[string]interface{}{
				"type":        "boolean",
				"description": "是否启用调试模式",
				"default":     false,
			},
			"proxy": map[string]interface{}{
				"type":        "string",
				"description": "代理服务器URL",
				"format":      "uri",
			},
			"scope": map[string]interface{}{
				"type":        "array",
				"description": "扫描范围",
				"items": map[string]interface{}{
					"type": "string",
				},
				"minItems": 1,
			},
			"blacklist": map[string]interface{}{
				"type":        "array",
				"description": "黑名单模式",
				"items": map[string]interface{}{
					"type": "string",
				},
			},
			"headers": map[string]interface{}{
				"type":        "object",
				"description": "自定义HTTP头",
				"additionalProperties": map[string]interface{}{
					"type": "string",
				},
			},
			"log": map[string]interface{}{
				"type":        "object",
				"description": "日志配置",
				"properties": map[string]interface{}{
					"level": map[string]interface{}{
						"type": "string",
						"enum": []string{"debug", "info", "warn", "error", "fatal", "panic"},
					},
					"format": map[string]interface{}{
						"type": "string",
						"enum": []string{"json", "text"},
					},
					"file_path": map[string]interface{}{
						"type": "string",
					},
				},
			},
			"spider": map[string]interface{}{
				"type":        "object",
				"description": "爬虫配置",
				"properties": map[string]interface{}{
					"concurrency": map[string]interface{}{
						"type":    "integer",
						"minimum": 1,
						"maximum": 100,
						"default": 10,
					},
					"limit": map[string]interface{}{
						"type":    "integer",
						"minimum": 1,
						"default": 1000,
					},
					"timeout": map[string]interface{}{
						"type":    "string",
						"pattern": "^[0-9]+(s|m|h)$",
						"default": "30s",
					},
				},
			},
			"scanner": map[string]interface{}{
				"type":        "object",
				"description": "扫描器配置",
				"properties": map[string]interface{}{
					"concurrency": map[string]interface{}{
						"type":    "integer",
						"minimum": 1,
						"maximum": 50,
						"default": 5,
					},
					"vulnerabilities": map[string]interface{}{
						"type": "array",
						"items": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"type": map[string]interface{}{
									"type": "string",
									"enum": []string{"xss", "sqli", "lfi", "rfi", "csrf", "xxe", "ssrf"},
								},
								"enabled": map[string]interface{}{
									"type":    "boolean",
									"default": true,
								},
								"severity": map[string]interface{}{
									"type": "string",
									"enum": []string{"low", "medium", "high", "critical"},
								},
							},
							"required": []string{"type"},
						},
					},
				},
			},
		},
		"required": []string{"version", "scope"},
	}
	
	return json.MarshalIndent(schema, "", "  ")
}

// ConfigDiff 配置差异比较结果
type ConfigDiff struct {
	Added    map[string]interface{} `json:"added"`
	Modified map[string]interface{} `json:"modified"`
	Removed  map[string]interface{} `json:"removed"`
}

// CompareConfigs 比较两个配置的差异
func CompareConfigs(old, new *Settings) (*ConfigDiff, error) {
	// 将配置转换为map进行比较
	oldMap, err := structToMap(old)
	if err != nil {
		return nil, fmt.Errorf("转换旧配置失败: %w", err)
	}
	
	newMap, err := structToMap(new)
	if err != nil {
		return nil, fmt.Errorf("转换新配置失败: %w", err)
	}
	
	diff := &ConfigDiff{
		Added:    make(map[string]interface{}),
		Modified: make(map[string]interface{}),
		Removed:  make(map[string]interface{}),
	}
	
	// 查找新增和修改的字段
	for key, newValue := range newMap {
		if oldValue, exists := oldMap[key]; exists {
			if !reflect.DeepEqual(oldValue, newValue) {
				diff.Modified[key] = map[string]interface{}{
					"old": oldValue,
					"new": newValue,
				}
			}
		} else {
			diff.Added[key] = newValue
		}
	}
	
	// 查找删除的字段
	for key, oldValue := range oldMap {
		if _, exists := newMap[key]; !exists {
			diff.Removed[key] = oldValue
		}
	}
	
	return diff, nil
}

// structToMap 将结构体转换为map
func structToMap(obj interface{}) (map[string]interface{}, error) {
	data, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	
	return result, nil
}

// ConfigBackup 配置备份
type ConfigBackup struct {
	Timestamp time.Time `json:"timestamp"`
	Version   string    `json:"version"`
	Config    *Settings `json:"config"`
	Comment   string    `json:"comment"`
}

// BackupConfig 备份配置
func (cm *ConfigManager) BackupConfig(comment string) (*ConfigBackup, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	if cm.config == nil {
		return nil, fmt.Errorf("配置未初始化")
	}
	
	backup := &ConfigBackup{
		Timestamp: time.Now(),
		Version:   cm.config.Version,
		Config:    cm.config,
		Comment:   comment,
	}
	
	return backup, nil
}

// RestoreConfig 恢复配置
func (cm *ConfigManager) RestoreConfig(backup *ConfigBackup) error {
	if backup == nil || backup.Config == nil {
		return fmt.Errorf("无效的备份数据")
	}
	
	// 验证备份的配置
	if err := cm.validateConfig(backup.Config); err != nil {
		return fmt.Errorf("备份配置验证失败: %w", err)
	}
	
	// 后处理配置
	if err := cm.postProcessConfig(backup.Config); err != nil {
		return fmt.Errorf("备份配置后处理失败: %w", err)
	}
	
	cm.mu.Lock()
	oldConfig := cm.config
	cm.config = backup.Config
	cm.mu.Unlock()
	
	// 通知观察者
	cm.notifyWatchers(backup.Config)
	
	log.Info().
		Time("backup_time", backup.Timestamp).
		Str("comment", backup.Comment).
		Msg("配置已从备份恢复")
	
	// 如果恢复失败，可以回滚
	_ = oldConfig
	
	return nil
}

// SaveBackup 保存备份到文件
func (cm *ConfigManager) SaveBackup(backup *ConfigBackup, path string) error {
	data, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化备份数据失败: %w", err)
	}
	
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("保存备份文件失败: %w", err)
	}
	
	log.Info().Str("file", path).Msg("配置备份已保存")
	return nil
}

// LoadBackup 从文件加载备份
func (cm *ConfigManager) LoadBackup(path string) (*ConfigBackup, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取备份文件失败: %w", err)
	}
	
	var backup ConfigBackup
	if err := json.Unmarshal(data, &backup); err != nil {
		return nil, fmt.Errorf("解析备份数据失败: %w", err)
	}
	
	return &backup, nil
}

// ConfigMigrator 配置迁移器
type ConfigMigrator struct {
	migrations map[string]func(*Settings) error
}

// NewConfigMigrator 创建配置迁移器
func NewConfigMigrator() *ConfigMigrator {
	migrator := &ConfigMigrator{
		migrations: make(map[string]func(*Settings) error),
	}
	
	// 注册迁移函数
	migrator.registerMigrations()
	
	return migrator
}

// registerMigrations 注册迁移函数
func (m *ConfigMigrator) registerMigrations() {
	// 从0.9到1.0的迁移
	m.migrations["0.9->1.0"] = func(config *Settings) error {
		// 添加新字段的默认值
		if len(config.Spider.UserAgents) == 0 {
			config.Spider.UserAgents = []string{
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			}
		}
		
		// 迁移旧的配置结构
		if config.Spider.Timeout == 0 {
			config.Spider.Timeout = 30 * time.Second
		}
		
		return nil
	}
	
	// 可以添加更多迁移函数
}

// Migrate 执行配置迁移
func (m *ConfigMigrator) Migrate(config *Settings, fromVersion, toVersion string) error {
	migrationKey := fmt.Sprintf("%s->%s", fromVersion, toVersion)
	
	migration, exists := m.migrations[migrationKey]
	if !exists {
		return fmt.Errorf("不支持从版本 %s 到 %s 的迁移", fromVersion, toVersion)
	}
	
	if err := migration(config); err != nil {
		return fmt.Errorf("配置迁移失败: %w", err)
	}
	
	// 更新版本号
	config.Version = toVersion
	
	log.Info().
		Str("from_version", fromVersion).
		Str("to_version", toVersion).
		Msg("配置迁移完成")
	
	return nil
}

// ConfigValidator 配置验证器接口
type ConfigValidator interface {
	Validate(config *Settings) error
	GetName() string
	GetDescription() string
}

// SecurityValidator 安全配置验证器
type SecurityValidator struct{}

func (v *SecurityValidator) GetName() string {
	return "security"
}

func (v *SecurityValidator) GetDescription() string {
	return "验证安全相关配置"
}

func (v *SecurityValidator) Validate(config *Settings) error {
	var errors []string
	
	// 检查是否启用了基本的安全措施
	if !config.Security.EnableHTTPS && len(config.Scope) > 0 {
		// 检查scope中是否有HTTPS URL
		hasHTTPS := false
		for _, scope := range config.Scope {
			if strings.HasPrefix(scope, "https://") {
				hasHTTPS = true
				break
			}
		}
		if hasHTTPS {
			errors = append(errors, "检测到HTTPS目标但未启用HTTPS安全配置")
		}
	}
	
	// 检查认证配置
	if config.Security.Authentication.Type != "none" {
		switch config.Security.Authentication.Type {
		case "basic":
			if config.Security.Authentication.BasicAuth.Username == "" ||
				config.Security.Authentication.BasicAuth.Password == "" {
				errors = append(errors, "基础认证配置不完整")
			}
		case "jwt":
			if config.Security.Authentication.JWT.Secret == "" {
				errors = append(errors, "JWT认证缺少密钥")
			}
		}
	}
	
	// 检查加密配置
	if config.Security.Encryption.EnableAtRest {
		if config.Security.Encryption.Key == "" && config.Security.Encryption.KeyFile == "" {
			errors = append(errors, "启用静态加密但未配置密钥")
		}
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("安全配置验证失败:\n%s", strings.Join(errors, "\n"))
	}
	
	return nil
}

// PerformanceValidator 性能配置验证器
type PerformanceValidator struct{}

func (v *PerformanceValidator) GetName() string {
	return "performance"
}

func (v *PerformanceValidator) GetDescription() string {
	return "验证性能相关配置"
}

func (v *PerformanceValidator) Validate(config *Settings) error {
	var warnings []string
	
	// 检查并发配置
	totalConcurrency := config.Spider.Concurrency + config.Scanner.Concurrency
	if totalConcurrency > 50 {
		warnings = append(warnings, fmt.Sprintf("总并发数过高 (%d)，可能影响系统性能", totalConcurrency))
	}
	
	// 检查内存配置
	if config.Performance.MaxMemory < 512 {
		warnings = append(warnings, "最大内存限制过低，可能影响扫描性能")
	}
	
	// 检查超时配置
	if config.Spider.Timeout > 60*time.Second {
		warnings = append(warnings, "爬虫超时时间过长，可能导致扫描效率低下")
	}
	
	if config.Scanner.Timeout > 60*time.Second {
		warnings = append(warnings, "扫描器超时时间过长，可能导致扫描效率低下")
	}
	
	// 输出警告但不阻止配置加载
	if len(warnings) > 0 {
		for _, warning := range warnings {
			log.Warn().Msg(warning)
		}
	}
	
	return nil
}

// RegisterCustomValidators 注册自定义验证器
func (cm *ConfigManager) RegisterCustomValidators(validators ...ConfigValidator) {
	// 这里可以扩展验证器注册逻辑
	for _, validator := range validators {
		log.Info().
			Str("name", validator.GetName()).
			Str("description", validator.GetDescription()).
			Msg("已注册自定义配置验证器")
	}
}

// ValidateWithCustomValidators 使用自定义验证器验证配置
func (cm *ConfigManager) ValidateWithCustomValidators(config *Settings, validators ...ConfigValidator) error {
	for _, validator := range validators {
		if err := validator.Validate(config); err != nil {
			return fmt.Errorf("验证器 '%s' 验证失败: %w", validator.GetName(), err)
		}
	}
	return nil
}

// GetConfigHealth 获取配置健康状态
func (cm *ConfigManager) GetConfigHealth() map[string]interface{} {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	if cm.config == nil {
		return map[string]interface{}{
			"status":  "unhealthy",
			"reason":  "配置未初始化",
			"score":   0,
			"details": map[string]interface{}{},
		}
	}
	
	health := map[string]interface{}{
		"status":  "healthy",
		"score":   100,
		"details": map[string]interface{}{},
	}
	
	score := 100
	details := make(map[string]interface{})
	
	// 检查基础配置
	if len(cm.config.Scope) == 0 {
		score -= 20
		details["scope"] = "未配置扫描范围"
	}
	
	// 检查性能配置
	totalConcurrency := cm.config.Spider.Concurrency + cm.config.Scanner.Concurrency
	if totalConcurrency > 50 {
		score -= 10
		details["concurrency"] = "并发数过高"
	}
	
	// 检查安全配置
	if cm.config.Security.Authentication.Type == "none" && len(cm.config.Scope) > 0 {
		score -= 5
		details["authentication"] = "未启用认证"
	}
	
	// 检查日志配置
	if cm.config.Log.Level == "debug" {
		score -= 5
		details["logging"] = "调试日志可能影响性能"
	}
	
	// 检查存储配置
	if !cm.config.Redis.Enabled && !cm.config.Database.DSN != "" {
		score -= 10
		details["storage"] = "未配置持久化存储"
	}
	
	// 更新健康状态
	health["score"] = score
	health["details"] = details
	
	if score < 70 {
		health["status"] = "warning"
	}
	if score < 50 {
		health["status"] = "unhealthy"
	}
	
	return health
}

// 全局配置管理器实例
var (
	globalConfigManager *ConfigManager
	globalConfigOnce    sync.Once
)

// GetGlobalConfigManager 获取全局配置管理器实例
func GetGlobalConfigManager() *ConfigManager {
	globalConfigOnce.Do(func() {
		globalConfigManager = NewConfigManager()
	})
	return globalConfigManager
}


