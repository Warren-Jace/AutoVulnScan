// Package config 处理应用程序配置的加载和解析
// 负责从配置文件中读取各种设置，包括爬虫、扫描器、报告等模块的配置
package config

import (
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Settings 定义 AutoVulnScan 应用程序的整体配置结构
// 包含调试、代理、头部、爬虫、扫描器、报告、Redis、AI 模块和漏洞的设置
type Settings struct {
	// Debug 启用或禁用调试模式，提供更详细的输出信息
	// 用于开发和故障排除，会输出更多日志信息
	Debug bool `mapstructure:"debug"`

	// Proxy 指定用于所有网络请求的代理服务器 URL
	// 格式：http://host:port 或 https://host:port
	Proxy string `mapstructure:"proxy"`

	// Headers 定义每个请求都要发送的自定义 HTTP 头部
	// 常用于设置 User-Agent、Authorization 等头部信息
	Headers map[string]string `mapstructure:"headers"`

	// Spider 包含与爬取和发现阶段相关的所有配置
	Spider SpiderConfig `mapstructure:"spider"`

	// Scanner 包含与漏洞扫描阶段相关的所有配置
	Scanner ScannerConfig `mapstructure:"scanner"`

	// Reporting 定义生成漏洞报告的设置
	Reporting ReportingConfig `mapstructure:"reporting"`

	// Redis 包含连接到 Redis 服务器进行数据存储的配置
	Redis RedisConfig `mapstructure:"redis"`

	// AIModule 配置 AI 驱动的分析功能
	AIModule AIModuleConfig `mapstructure:"ai_module"`
}

// SpiderConfig 包含与爬取阶段相关的所有配置
// 控制网页爬虫的行为，包括并发数、深度、范围等
type SpiderConfig struct {
	// Concurrency 并发运行的爬虫数量
	// 较高的值可以加快爬取速度，但会增加资源消耗
	Concurrency int `mapstructure:"concurrency"`

	// Limit 要爬取的页面最大数量
	// 用于控制爬取规模，避免无限制爬取
	Limit int `mapstructure:"limit"`

	// Timeout 每个 HTTP 请求的超时时间（秒）
	// 避免单个请求占用过长时间
	Timeout int `mapstructure:"timeout"`

	// MaxDepth 最大爬取深度
	// 控制从起始页面开始的最大目录层级
	MaxDepth int `mapstructure:"max_depth"`

	// MaxPageVisitPerSite 每个站点访问的最大页面数
	// 防止在单个站点上花费过多时间
	MaxPageVisitPerSite int `mapstructure:"max_page_visit_per_site"`

	// Scope 定义爬取范围内的域名
	// 只有这些域名内的 URL 才会被爬取
	Scope []string `mapstructure:"scope"`

	// Blacklist 定义不应被爬取的 URL 模式
	// 用于排除不相关的内容，如社交媒体链接、CDN 资源等
	Blacklist []string `mapstructure:"blacklist"`

	// Cookies 爬虫使用的 cookie 映射
	// 格式：域名 -> cookie字符串，用于身份验证或会话保持
	Cookies map[string]string `mapstructure:"cookies"`

	// SimilarityPageDom 配置 DOM 相似性算法以避免冗余爬取
	// 通过比较页面 DOM 结构来识别重复页面
	SimilarityPageDom SimilarityPageDomConfig `mapstructure:"similarity_page_dom"`

	// UserAgents 爬虫使用的用户代理列表
	// 用于模拟不同的浏览器，避免被反爬虫机制检测
	UserAgents []string `mapstructure:"user_agents"`

	// DynamicCrawler 基于无头浏览器的爬虫设置
	// 用于处理需要 JavaScript 渲染的动态网页
	DynamicCrawler DynamicCrawlerConfig `mapstructure:"dynamic_crawler"`

	// Sources 用于发现 URL 的来源列表
	// 例如："robotstxt"（robots.txt文件）、"sitemapxml"（sitemap.xml文件）
	Sources []string `mapstructure:"sources"`
}

// SimilarityPageDomConfig 配置 DOM 相似性算法
// 用于检测和避免爬取相似或重复的页面
type SimilarityPageDomConfig struct {
	// Use 启用或禁用 DOM 相似性检查
	Use bool `mapstructure:"use"`

	// Threshold 进行相似性检查时考虑的最小 DOM 元素数量
	// 页面元素少于此值时不进行相似性比较
	Threshold int `mapstructure:"threshold"`

	// Similarity 将页面视为重复的相似性阈值（0.0 到 1.0）
	// 值越高表示要求越相似才认为是重复页面
	Similarity float64 `mapstructure:"similarity"`

	// VectorDim 用于相似性计算的向量维度
	// 影响相似性计算的精度和性能
	VectorDim int `mapstructure:"vector_dim"`
}

// ScannerConfig 定义漏洞扫描器的设置
// 控制漏洞扫描的各种参数和行为
type ScannerConfig struct {
	// Concurrency 并发扫描任务的数量
	// 控制同时进行的扫描线程数
	Concurrency int `mapstructure:"concurrency"`

	// Limit 要扫描的 URL 最大数量
	// 控制扫描规模，避免扫描时间过长
	Limit int `mapstructure:"limit"`

	// FilterThreshold 过滤相似页面的阈值
	// 用于避免对相似页面进行冗余扫描
	FilterThreshold int `mapstructure:"filter_threshold"`

	// FoundHiddenParameter 启用或禁用隐藏参数的发现
	// 帮助发现页面中可能存在的隐藏参数
	FoundHiddenParameter bool `mapstructure:"found_hidden_parameter"`

	// FoundHiddenParameterFromJS 启用或禁用从 JavaScript 文件中发现隐藏参数
	// 分析 JS 代码中可能包含的参数信息
	FoundHiddenParameterFromJS bool `mapstructure:"found_hidden_parameter_from_js"`

	// ParameterGroupSize 单个测试中分组的参数数量
	// 批量测试参数，提高扫描效率
	ParameterGroupSize int `mapstructure:"parameter_group_size"`

	// Timeout 每个扫描请求的超时时间
	// 避免单个扫描请求耗时过长
	Timeout time.Duration `mapstructure:"timeout"`

	// PluginTimeout 每个插件的超时时间
	// 控制单个漏洞检测插件的最大执行时间
	PluginTimeout time.Duration `mapstructure:"plugin_timeout"`

	// Position 测试漏洞的位置列表
	// 例如："get"（GET参数）、"post"（POST参数）、"uri"（URI路径）
	Position []string `mapstructure:"position"`

	// Output 配置扫描输出中包含的信息
	Output struct {
		// Response 确定是否在报告中包含完整的 HTTP 响应
		Response bool `mapstructure:"response"`

		// ResponseHeader 确定是否在报告中包含响应头
		ResponseHeader bool `mapstructure:"response_header"`
	} `mapstructure:"output"`

	// HiddenParameters 要被视为隐藏参数的参数名称列表
	// 这些参数会被重点关注和测试
	HiddenParameters []string `mapstructure:"hidden_parameters"`

	// Vulnerabilities 扫描器使用的漏洞配置列表
	// 定义要检测的漏洞类型和相应的测试载荷
	Vulnerabilities []VulnConfig `mapstructure:"vulnerabilities"`
}

// ReportingConfig 定义生成报告的设置
// 控制各种报告文件的生成和存储
type ReportingConfig struct {
	// Path 保存报告的目录路径
	Path string `mapstructure:"path"`

	// VulnReportFile 漏洞报告的文件名
	// 存储发现的所有漏洞信息
	VulnReportFile string `mapstructure:"vuln_report_file"`

	// SpiderFile 爬虫输出文件的文件名
	// 存储所有成功爬取的 URL
	SpiderFile string `mapstructure:"spider_file"`

	// UnscopedSpiderFile 爬虫发现的超出范围 URL 的文件名
	// 存储不在爬取范围内但被发现的 URL
	UnscopedSpiderFile string `mapstructure:"unscoped_spider_file"`

	// SpiderDeDuplicateFile 去重后的爬虫输出文件名
	// 存储去除重复后的所有 URL
	SpiderDeDuplicateFile string `mapstructure:"spider_deduplicate_file"`

	// SpiderParamsFile 爬虫参数输出的文件名
	// 存储包含参数的 URL
	SpiderParamsFile string `mapstructure:"spider_params_file"`
}

// RedisConfig 定义 Redis 连接的设置
// 用于配置 Redis 作为数据存储后端
type RedisConfig struct {
	// Enabled 确定是否使用 Redis 进行存储
	Enabled bool `mapstructure:"enabled"`

	// URL Redis 服务器的连接字符串
	// 格式：redis://host:port/database
	URL string `mapstructure:"url"`
}

// DynamicCrawlerConfig 包含基于无头浏览器的爬虫设置
// 用于处理需要 JavaScript 渲染的动态网页
type DynamicCrawlerConfig struct {
	// Enabled 确定是否使用动态爬虫
	Enabled bool `mapstructure:"enabled"`

	// Headless 确定是否在无头模式下运行浏览器
	// 无头模式不显示浏览器界面，适合服务器环境
	Headless bool `mapstructure:"headless"`
}

// AIModuleConfig 包含可选的 AI 驱动分析模块的设置
// 用于集成 AI 服务进行智能分析
type AIModuleConfig struct {
	// Enabled 确定是否使用 AI 模块
	Enabled bool `mapstructure:"enabled"`

	// Model 要使用的 AI 模型名称
	// 例如："deepseek/deepseek-v3"，支持不同的 AI 服务提供商
	Model string `mapstructure:"model"`

	// APIKey AI 服务的 API 密钥
	// 用于身份验证和访问 AI 服务
	APIKey string `mapstructure:"api_key"`
}

// VulnConfig 指定要扫描的漏洞及其配置
// 定义特定类型漏洞的检测方法和测试载荷
type VulnConfig struct {
	// Type 漏洞类型
	// 例如："sqli"（SQL注入）、"xss"（跨站脚本攻击）
	Type string `mapstructure:"type"`

	// Payloads 该漏洞类型的攻击载荷列表
	// 包含用于测试该类型漏洞的各种载荷
	Payloads []Payload `mapstructure:"payloads"`
}

// Payload 定义单个攻击载荷及其值和描述
// 包含具体的测试载荷和相关说明
type Payload struct {
	// Value 实际的载荷字符串
	// 用于注入到目标参数中进行测试
	Value string `mapstructure:"value"`

	// Description 提供关于载荷的上下文信息
	// 说明载荷的用途和预期效果
	Description string `mapstructure:"description"`
}

// LoadConfig 从给定路径的文件中读取配置并将其解析到 Settings 结构体中
// 使用 Viper 来处理 YAML 文件和环境变量
//
// 参数：
//   - path: 配置文件路径，如果为空则在当前目录查找 config.yaml
//
// 返回值：
//   - config: 解析后的配置结构体
//   - err: 解析过程中的错误信息
func LoadConfig(path string) (config *Settings, err error) {
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
	if err = viper.ReadInConfig(); err != nil {
		return
	}
	err = viper.Unmarshal(&c)
	return &c, err
}
