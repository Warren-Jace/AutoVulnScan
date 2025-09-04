// Package models 定义了漏洞扫描系统中使用的数据结构和模型
package models

import (
	"time"
)

// Request 表示一个HTTP请求
// 用于封装要扫描的HTTP请求信息，包括URL、方法、头部、参数等
type Request struct {
	ID           string            `json:"id"`          // 请求ID
	URL          string            `json:"url"`         // 请求的URL
	Method       string            `json:"method"`      // HTTP方法 (GET, POST, etc.)
	Headers      map[string]string `json:"headers"`     // HTTP请求头
	Params       map[string]string `json:"params"`      // 请求参数
	Body         string            `json:"body"`        // 请求体
	Cookies      map[string]string `json:"cookies"`     // 请求Cookie
	ResponseCode int               `json:"response_code"` // 响应状态码
	ResponseBody string            `json:"response_body"` // 响应体
	Timestamp    string            `json:"timestamp"`    // 请求时间
	FilterRule   string            `json:"filter_rule"`  // 应用的过滤规则
}

// Payload 表示一个测试载荷
// 用于存储漏洞测试中使用的各种输入数据
type Payload struct {
	Value       string `json:"value"`        // 载荷值
	Description string `json:"description"`  // 载荷描述
	Category    string `json:"category"`     // 载荷类别
	Severity    string `json:"severity"`     // 相关漏洞严重程度
}

// Vulnerability 表示一个发现的漏洞
// 用于存储漏洞的详细信息，包括位置、类型、描述、严重程度等
type Vulnerability struct {
	ID          string            `json:"id"`           // 漏洞唯一标识符
	Name        string            `json:"name"`         // 漏洞名称
	Type        string            `json:"type"`         // 漏洞类型 (XSS, SQLi, etc.)
	Description string            `json:"description"`  // 漏洞描述
	Severity    string            `json:"severity"`     // 严重程度 (Low, Medium, High, Critical)
	Location    string            `json:"location"`     // 漏洞位置 (URL)
	Parameter   string            `json:"parameter"`    // 漏洞参数
	Evidence    string            `json:"evidence"`     // 漏洞证据
	Request     *Request          `json:"request"`      // 相关请求
	Response    string            `json:"response"`     // 响应片段
	Solution    string            `json:"solution"`     // 修复建议
	References  []string          `json:"references"`   // 参考链接
	Tags        map[string]string `json:"tags"`        // 附加标签
	Timestamp   string            `json:"timestamp"`    // 发现时间
	Confidence  string            `json:"confidence"`   // 置信度 (Low, Medium, High, Certain)
	Payload     *Payload          `json:"payload"`      // 漏洞载荷
	PayloadJSON string            `json:"payload_json"` // 载荷JSON数据
	RequestJSON string            `json:"request_json"` // 请求JSON数据
	ScanID      string            `json:"scan_id"`      // 关联的扫描ID
	CreatedAt   time.Time         `json:"created_at"`   // 创建时间
	UpdatedAt   time.Time         `json:"updated_at"`   // 更新时间
}

// ScanResult 表示一次扫描的结果
// 用于汇总一次扫描的所有信息，包括目标、配置、发现的漏洞等
type ScanResult struct {
	ID             string            `json:"id"`             // 扫描结果ID
	Target         string            `json:"target"`          // 扫描目标
	StartTime      string            `json:"start_time"`      // 开始时间
	EndTime        string            `json:"end_time"`        // 结束时间
	Duration       string            `json:"duration"`       // 扫描持续时间
	Configuration  ScanConfig       `json:"configuration"`  // 扫描配置
	Vulnerabilities []*Vulnerability  `json:"vulnerabilities"` // 发现的漏洞
	Stats          ScanStats         `json:"stats"`          // 扫描统计
}

// ScanConfig 表示扫描配置
// 用于存储扫描过程中使用的各种配置参数
type ScanConfig struct {
	Modules       []string `json:"modules"`        // 启用的扫描模块
	Concurrency   int      `json:"concurrency"`    // 并发数
	Timeout       int      `json:"timeout"`        // 超时时间(秒)
	FollowRedirects bool   `json:"follow_redirects"` // 是否跟随重定向
	CustomHeaders map[string]string `json:"custom_headers"` // 自定义请求头
}

// ScanStats 表示扫描统计信息
// 用于存储扫描过程中的各种统计数据
type ScanStats struct {
	RequestsSent     int `json:"requests_sent"`     // 发送的请求数
	ResponsesReceived int `json:"responses_received"` // 收到的响应数
	VulnerabilitiesFound int `json:"vulnerabilities_found"` // 发现的漏洞数
	ErrorsEncountered int `json:"errors_encountered"` // 遇到的错误数
}

// CrawlResult 表示爬虫结果
// 用于存储爬虫获取的页面和链接信息
type CrawlResult struct {
	ID            string            `json:"id"`            // 爬取结果ID
	URL           string            `json:"url"`           // 页面URL
	Title         string            `json:"title"`         // 页面标题
	StatusCode    int               `json:"status_code"`    // HTTP状态码
	ContentType   string            `json:"content_type"`   // 内容类型
	Content       string            `json:"content"`        // 页面内容
	ContentLength int64             `json:"content_length"` // 内容长度
	Links         []string          `json:"links"`          // 页面中的链接
	Forms         []Form            `json:"forms"`          // 页面中的表单
	APIEndpoints  []string          `json:"api_endpoints"`  // API端点
	Headers       map[string]string `json:"headers"`         // 响应头
	Timestamp     string            `json:"timestamp"`       // 抓取时间
	FormsJSON     string            `json:"forms_json"`     // 表单JSON数据
	APIEndpointsJSON string         `json:"api_endpoints_json"` // API端点JSON数据
	CreatedAt     time.Time         `json:"created_at"`      // 创建时间
	UpdatedAt     time.Time         `json:"updated_at"`      // 更新时间
}

// Form 表示一个HTML表单
// 用于存储表单的详细信息，包括动作、方法、字段等
type Form struct {
	Action   string            `json:"action"`   // 表单提交URL
	Method   string            `json:"method"`   // 表单提交方法
	Name     string            `json:"name"`     // 表单名称
	ID       string            `json:"id"`       // 表单ID
	Fields   []FormField       `json:"fields"`   // 表单字段
	Enctype  string            `json:"enctype"`  // 编码类型
}

// FormField 表示表单字段
// 用于存储表单字段的详细信息
type FormField struct {
	Name        string `json:"name"`         // 字段名称
	Type        string `json:"type"`         // 字段类型 (text, password, hidden, etc.)
	Value       string `json:"value"`        // 字段值
	Placeholder string `json:"placeholder"`   // 占位符
	Required    bool   `json:"required"`     // 是否必填
	ID          string `json:"id"`           // 字段ID
}

// LLMResponse 表示LLM的响应
// 用于存储LLM生成的漏洞分析和建议
type LLMResponse struct {
	ID           string   `json:"id"`            // 响应ID
	Query        string   `json:"query"`         // 原始查询
	Response     string   `json:"response"`      // LLM响应内容
	Confidence   float64  `json:"confidence"`    // 置信度 (0-1)
	VulnerabilityTypes []string `json:"vulnerability_types"` // 相关漏洞类型
	Recommendations []string `json:"recommendations"`     // 建议措施
	Timestamp    string   `json:"timestamp"`     // 响应时间
	Model        string   `json:"model"`        // 使用的LLM模型
}

// ReportConfig 表示报告生成配置
// 用于存储报告生成的各种配置参数
type ReportConfig struct {
	Format      string   `json:"format"`       // 报告格式 (HTML, PDF, JSON, CSV, Markdown)
	IncludeData []string `json:"include_data"`  // 包含的数据类型
	Template    string   `json:"template"`      // 报告模板
	OutputPath  string   `json:"output_path"`  // 输出路径
	Title       string   `json:"title"`         // 报告标题
	Description string   `json:"description"`   // 报告描述
}

// ProxyConfig 表示代理配置
// 用于存储代理服务器的配置参数
type ProxyConfig struct {
	ListenAddress   string            `json:"listen_address"`   // 监听地址
	Timeout         int               `json:"timeout"`         // 超时时间(秒)
	MaxConnections  int               `json:"max_connections"`  // 最大连接数
	EnableHTTPS     bool              `json:"enable_https"`     // 是否启用HTTPS
	EnableAuth      bool              `json:"enable_auth"`      // 是否启用认证
	AuthUsername    string            `json:"auth_username"`    // 认证用户名
	AuthPassword    string            `json:"auth_password"`    // 认证密码
	EnableLogging   bool              `json:"enable_logging"`   // 是否启用日志
	LogPath         string            `json:"log_path"`         // 日志路径
	FilterRules     []ProxyFilterRule `json:"filter_rules"`     // 过滤规则
}

// ProxyFilterRule 表示代理过滤规则
// 用于定义代理服务器的请求过滤规则
type ProxyFilterRule struct {
	Name        string `json:"name"`         // 规则名称
	Type        string `json:"type"`         // 规则类型 (blacklist, whitelist)
	Pattern     string `json:"pattern"`      // 匹配模式
	Description string `json:"description"`   // 规则描述
	Enabled     bool   `json:"enabled"`      // 是否启用
}

// ProxyStats 表示代理统计信息
// 用于存储代理服务器的运行统计数据
type ProxyStats struct {
	TotalRequests    int64 `json:"total_requests"`    // 总请求数
	BlockedRequests  int64 `json:"blocked_requests"`  // 被阻止的请求数
	AllowedRequests  int64 `json:"allowed_requests"`  // 允许的请求数
	ActiveConnections int  `json:"active_connections"` // 活跃连接数
}

// VulnerabilityStats 表示漏洞统计信息
// 用于存储漏洞分析的各种统计数据
type VulnerabilityStats struct {
	TotalVulnerabilities int               `json:"total_vulnerabilities"` // 漏洞总数
	BySeverity           map[string]int    `json:"by_severity"`          // 按严重程度分类
	ByType               map[string]int    `json:"by_type"`              // 按类型分类
	TopVulnerabilities   []Vulnerability   `json:"top_vulnerabilities"`   // 高危漏洞列表
	LastUpdated          string            `json:"last_updated"`         // 最后更新时间
}

// CrawlStats 表示爬取统计信息
// 用于存储爬虫运行的各种统计数据
type CrawlStats struct {
	TotalPages       int               `json:"total_pages"`        // 总页面数
	UniquePages      int               `json:"unique_pages"`       // 唯一页面数
	TotalLinks       int               `json:"total_links"`        // 总链接数
	UniqueLinks      int               `json:"unique_links"`       // 唯一链接数
	TotalForms       int               `json:"total_forms"`        // 总表单数
	ByStatusCode     map[int]int       `json:"by_status_code"`     // 按状态码分类
	ByContentType    map[string]int    `json:"by_content_type"`    // 按内容类型分类
	TopDomains       map[string]int    `json:"top_domains"`        // 按域名分类
	LastUpdated      string            `json:"last_updated"`       // 最后更新时间
}