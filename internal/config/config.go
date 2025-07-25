// Package config 负责加载和解析应用程序的配置。
package config

import (
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Settings 定义了 AutoVulnScan 应用程序的整体配置结构。
// 它包括调试、代理、HTTP头、爬虫、扫描器、报告、Redis、AI模块和漏洞插件的设置。
type Settings struct {
	// Debug 开启或关闭调试模式，提供更详细的输出。
	Debug bool `mapstructure:"debug"`
	// Proxy 指定用于所有网络请求的代理服务器URL。
	Proxy string `mapstructure:"proxy"`
	// Headers 定义了每个请求中要发送的自定义HTTP头。
	Headers map[string]string `mapstructure:"headers"`
	// Scope 定义了扫描范围内的域。
	Scope []string `mapstructure:"scope"`
	// Blacklist 定义了不应被扫描的URL模式。
	Blacklist []string `mapstructure:"blacklist"`
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
	// AIModule 配置了AI驱动的分析功能。
	AIModule AIModuleConfig `mapstructure:"ai_module"`
}

// LogConfig 定义了日志记录的设置。
type LogConfig struct {
	// FilePath 是日志文件的保存路径。如果为空，则不输出到文件。
	FilePath string `mapstructure:"file_path"`
	// Level 定义了日志级别 (e.g., "debug", "info", "warn", "error")。
	Level string `mapstructure:"level"`
}

// SpiderConfig 保存了所有与爬虫阶段相关的配置。
type SpiderConfig struct {
	// Concurrency 是要运行的并发爬虫的数量。
	Concurrency int `mapstructure:"concurrency"`
	// Limit 是要爬取的最大页面数。
	Limit int `mapstructure:"limit"`
	// Timeout 是每个HTTP请求的超时时间（秒）。
	Timeout int `mapstructure:"timeout"`
	// MaxDepth 是最大爬取深度。
	MaxDepth int `mapstructure:"max_depth"`
	// MaxPageVisitPerSite 是每个站点要访问的最大页面数。
	MaxPageVisitPerSite int `mapstructure:"max_page_visit_per_site"`
	// Cookies 是爬虫要使用的cookie映射。
	Cookies map[string]string `mapstructure:"cookies"`
	// SimilarityPageDom 配置了DOM相似性算法以避免冗余爬取。
	SimilarityPageDom SimilarityPageDomConfig `mapstructure:"similarity_page_dom"`
	// DynamicCrawler 保存了基于无头浏览器的动态爬虫的设置。
	DynamicCrawler DynamicCrawlerConfig `mapstructure:"dynamic_crawler"`
	// Sources 是用于发现URL的来源列表（例如，"robotstxt", "sitemapxml"）。
	Sources []string `mapstructure:"sources"`
}

// SimilarityPageDomConfig 配置了DOM相似性算法。
type SimilarityPageDomConfig struct {
	// Use 启用或禁用DOM相似性检查。
	Use bool `mapstructure:"use"`
	// Threshold 是考虑相似性检查的最小DOM元素数。
	Threshold int `mapstructure:"threshold"`
	// Similarity 是将页面视为重复的相似性阈值（0.0到1.0）。
	Similarity float64 `mapstructure:"similarity"`
	// VectorDim 是用于相似性计算的向量维度。
	VectorDim int `mapstructure:"vector_dim"`
}

// ScannerConfig 定义了漏洞扫描器的设置。
type ScannerConfig struct {
	// Concurrency 是并发扫描任务的数量。
	Concurrency int `mapstructure:"concurrency"`
	// Limit 是要扫描的最大URL数。
	Limit int `mapstructure:"limit"`
	// FilterThreshold 是用于过滤掉相似页面的阈值。
	FilterThreshold int `mapstructure:"filter_threshold"`
	// FoundHiddenParameter 启用或禁用隐藏参数的发现。
	FoundHiddenParameter bool `mapstructure:"found_hidden_parameter"`
	// FoundHiddenParameterFromJS 启用或禁用从JavaScript文件中发现隐藏参数。
	FoundHiddenParameterFromJS bool `mapstructure:"found_hidden_parameter_from_js"`
	// ParameterGroupSize 是在单个测试中分组的参数数量。
	ParameterGroupSize int `mapstructure:"parameter_group_size"`
	// Timeout 是每个扫描请求的超时时间。
	Timeout time.Duration `mapstructure:"timeout"`
	// PluginTimeout 是每个单独插件的超时时间。
	PluginTimeout time.Duration `mapstructure:"plugin_timeout"`
	// Position 是要测试漏洞的位置列表（例如，"get", "post"）。
	Position []string `mapstructure:"position"`
	// Output 配置扫描输出中包含哪些信息。
	Output struct {
		// Response 决定是否在报告中包含完整的HTTP响应。
		Response bool `mapstructure:"response"`
		// ResponseHeader 决定是否在报告中包含响应头。
		ResponseHeader bool `mapstructure:"response_header"`
	} `mapstructure:"output"`
	// HiddenParameters 是要被视为隐藏的参数名称列表。
	HiddenParameters []string `mapstructure:"hidden_parameters"`
	// Vulnerabilities 是扫描器要使用的漏洞配置列表。
	Vulnerabilities []VulnConfig `mapstructure:"vulnerabilities"`
}

// ReportingConfig 定义了生成报告的设置。
type ReportingConfig struct {
	// Path 是将保存报告的目录。
	Path string `mapstructure:"path"`
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
}

// RedisConfig 定义了Redis连接的设置。
type RedisConfig struct {
	// Enabled 决定是否使用Redis进行存储。
	Enabled bool `mapstructure:"enabled"`
	// URL 是Redis服务器的连接字符串。
	URL string `mapstructure:"url"`
}

// DynamicCrawlerConfig 保存了基于无头浏览器的动态爬虫的设置。
type DynamicCrawlerConfig struct {
	// Enabled 决定是否使用动态爬虫。
	Enabled bool `mapstructure:"enabled"`
	// Headless 决定是否以无头模式运行浏览器。
	Headless bool `mapstructure:"headless"`
}

// AIModuleConfig 保存了可选的AI驱动分析模块的设置。
type AIModuleConfig struct {
	// Enabled 决定是否使用AI模块。
	Enabled bool `mapstructure:"enabled"`
	// Model 是要使用的AI模型的名称（例如，"deepseek/deepseek-v3"）。
	Model string `mapstructure:"model"`
	// APIKey 是AI服务的API密钥。
	APIKey string `mapstructure:"api_key"`
}

// VulnConfig 指定要扫描哪些漏洞及其配置。
type VulnConfig struct {
	// Type 是漏洞的类型（例如，"sqli", "xss"）。
	Type string `mapstructure:"type"`
	// Payloads 是该漏洞类型的攻击载荷列表。
	Payloads []Payload `mapstructure:"payloads"`
}

// Payload 定义了单个攻击载荷及其值和描述。
type Payload struct {
	// Value 是实际的载荷字符串。
	Value string `mapstructure:"value"`
	// Description 提供了关于载荷的上下文。
	Description string `mapstructure:"description"`
}

// LoadConfig 从给定路径的文件中读取配置并将其解析到 Settings 结构体中
func LoadConfig(path string) (*Settings, error) {
	var c Settings
	if path != "" {
		viper.SetConfigFile(path)
	} else {
		viper.AddConfigPath(".")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	if err := viper.Unmarshal(&c); err != nil {
		return nil, err
	}
	return &c, nil
}
