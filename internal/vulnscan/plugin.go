// Package vulnscan 提供了核心的漏洞扫描引擎和插件管理机制。
package vulnscan

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"
)

// Plugin 插件接口
// 所有漏洞插件都应实现该接口
type Plugin interface {
	// Info 返回插件元信息
	Info() PluginInfo
	
	// Scan 执行漏洞扫描
	Scan(client *requester.HTTPClient, req *models.Request) ([]*Vulnerability, error)
	
	// Initialize 初始化插件（可选实现）
	Initialize() error
	
	// Cleanup 清理插件资源（可选实现）
	Cleanup() error
}

// AdvancedPlugin 高级插件接口，支持更多功能
type AdvancedPlugin interface {
	Plugin
	
	// ScanWithContext 支持上下文的扫描方法
	ScanWithContext(ctx context.Context, client *requester.HTTPClient, req *models.Request) ([]*Vulnerability, error)
	
	// ValidateTarget 验证目标是否适合此插件扫描
	ValidateTarget(req *models.Request) bool
	
	// GetRequiredHeaders 获取插件所需的HTTP头
	GetRequiredHeaders() map[string]string
	
	// GetScanOptions 获取扫描选项
	GetScanOptions() ScanOptions
}

// ConfigurablePlugin 可配置插件接口
type ConfigurablePlugin interface {
	Plugin
	
	// Configure 配置插件
	Configure(config PluginConfig) error
	
	// GetDefaultConfig 获取默认配置
	GetDefaultConfig() PluginConfig
	
	// ValidateConfig 验证配置
	ValidateConfig(config PluginConfig) error
}

// PayloadPlugin 支持自定义payload的插件接口
type PayloadPlugin interface {
	Plugin
	
	// SetPayloads 设置payloads
	SetPayloads(payloads []models.Payload)
	
	// GetDefaultPayloads 获取默认payloads
	GetDefaultPayloads() []models.Payload
	
	// GeneratePayloads 动态生成payloads
	GeneratePayloads(req *models.Request) []models.Payload
}

// StatefulPlugin 有状态插件接口
type StatefulPlugin interface {
	Plugin
	
	// GetState 获取插件状态
	GetState() PluginState
	
	// SetState 设置插件状态
	SetState(state PluginState) error
	
	// ResetState 重置插件状态
	ResetState() error
}

// PluginInfo 插件元信息
type PluginInfo struct {
	Name         string            `json:"name"`         // 插件名称
	Description  string            `json:"description"`  // 插件描述
	Author       string            `json:"author"`       // 作者
	Version      string            `json:"version"`      // 版本
	Category     string            `json:"category"`     // 分类（如：injection, xss, etc.）
	Severity     SeverityLevel     `json:"severity"`     // 默认严重程度
	Tags         []string          `json:"tags"`         // 标签
	References   []string          `json:"references"`   // 参考链接
	Dependencies []string          `json:"dependencies"` // 依赖的其他插件
	Metadata     map[string]string `json:"metadata"`     // 额外元数据
	CreatedAt    time.Time         `json:"created_at"`   // 创建时间
	UpdatedAt    time.Time         `json:"updated_at"`   // 更新时间
}

// SeverityLevel 严重程度枚举
type SeverityLevel int

const (
	SeverityUnknown SeverityLevel = iota
	SeverityInfo                  // 信息
	SeverityLow                   // 低危
	SeverityMedium                // 中危
	SeverityHigh                  // 高危
	SeverityCritical              // 严重
)

// String 返回严重程度的字符串表示
func (s SeverityLevel) String() string {
	switch s {
	case SeverityInfo:
		return "Info"
	case SeverityLow:
		return "Low"
	case SeverityMedium:
		return "Medium"
	case SeverityHigh:
		return "High"
	case SeverityCritical:
		return "Critical"
	default:
		return "Unknown"
	}
}

// Color 返回严重程度对应的颜色代码
func (s SeverityLevel) Color() string {
	switch s {
	case SeverityInfo:
		return "\033[36m"    // 青色
	case SeverityLow:
		return "\033[32m"    // 绿色
	case SeverityMedium:
		return "\033[33m"    // 黄色
	case SeverityHigh:
		return "\033[31m"    // 红色
	case SeverityCritical:
		return "\033[35m"    // 紫色
	default:
		return "\033[0m"     // 默认
	}
}

// ScanOptions 扫描选项
type ScanOptions struct {
	Timeout          time.Duration `json:"timeout"`           // 超时时间
	MaxRetries       int           `json:"max_retries"`       // 最大重试次数
	RetryDelay       time.Duration `json:"retry_delay"`       // 重试延迟
	RateLimitRPS     int           `json:"rate_limit_rps"`    // 每秒请求数限制
	FollowRedirects  bool          `json:"follow_redirects"`  // 是否跟随重定向
	VerifySSL        bool          `json:"verify_ssl"`        // 是否验证SSL
	UserAgent        string        `json:"user_agent"`        // 用户代理
	MaxPayloads      int           `json:"max_payloads"`      // 最大payload数量
	SkipDuplicates   bool          `json:"skip_duplicates"`   // 跳过重复检测
	EnableDeepScan   bool          `json:"enable_deep_scan"`  // 启用深度扫描
	CustomHeaders    map[string]string `json:"custom_headers"` // 自定义头部
}

// DefaultScanOptions 返回默认扫描选项
func DefaultScanOptions() ScanOptions {
	return ScanOptions{
		Timeout:         30 * time.Second,
		MaxRetries:      3,
		RetryDelay:      time.Second,
		RateLimitRPS:    10,
		FollowRedirects: true,
		VerifySSL:       false,
		UserAgent:       "AutoVulnScan/1.0",
		MaxPayloads:     100,
		SkipDuplicates:  true,
		EnableDeepScan:  false,
		CustomHeaders:   make(map[string]string),
	}
}

// PluginConfig 插件配置
type PluginConfig struct {
	Enabled       bool                   `json:"enabled"`        // 是否启用
	Priority      int                    `json:"priority"`       // 优先级
	ScanOptions   ScanOptions            `json:"scan_options"`   // 扫描选项
	CustomConfig  map[string]interface{} `json:"custom_config"`  // 自定义配置
	PayloadConfig PayloadConfig          `json:"payload_config"` // Payload配置
}

// PayloadConfig Payload配置
type PayloadConfig struct {
	UseBuiltIn     bool     `json:"use_built_in"`     // 使用内置payloads
	UseCustom      bool     `json:"use_custom"`       // 使用自定义payloads
	CustomPayloads []string `json:"custom_payloads"`  // 自定义payload列表
	MaxLength      int      `json:"max_length"`       // 最大payload长度
	Encoding       string   `json:"encoding"`         // 编码方式
}

// PluginState 插件状态
type PluginState struct {
	IsInitialized    bool                   `json:"is_initialized"`
	LastScanTime     time.Time              `json:"last_scan_time"`
	ScanCount        int64                  `json:"scan_count"`
	SuccessCount     int64                  `json:"success_count"`
	ErrorCount       int64                  `json:"error_count"`
	VulnCount        int64                  `json:"vuln_count"`
	AverageTime      time.Duration          `json:"average_time"`
	LastError        string                 `json:"last_error"`
	CustomState      map[string]interface{} `json:"custom_state"`
}

// Vulnerability 漏洞结构体
type Vulnerability struct {
	// 基本信息
	ID            string        `json:"id"`             // 唯一标识
	Type          string        `json:"type"`           // 漏洞类型（如sqli/xss）
	Title         string        `json:"title"`          // 漏洞标题
	Description   string        `json:"description"`    // 详细描述
	Severity      SeverityLevel `json:"severity"`       // 严重程度
	
	// 位置信息
	URL           string        `json:"url"`            // 目标URL
	Method        string        `json:"method"`         // 请求方法
	Param         string        `json:"param"`          // 漏洞参数名
	ParamType     ParamType     `json:"param_type"`     // 参数类型
	
	// 攻击信息
	Payload       string        `json:"payload"`        // 使用的payload
	VulnerableURL string        `json:"vulnerable_url"` // 可复现漏洞的完整URL
	Request       *HTTPRequest  `json:"request"`        // 完整请求信息
	Response      *HTTPResponse `json:"response"`       // 响应信息
	
	// 验证信息
	Evidence      []Evidence    `json:"evidence"`       // 漏洞证据
	Confidence    float64       `json:"confidence"`     // 置信度 (0-1)
	FalsePositive bool          `json:"false_positive"` // 是否为误报
	
	// 元数据
	Plugin        string            `json:"plugin"`         // 发现此漏洞的插件
	Timestamp     time.Time         `json:"timestamp"`      // 检测时间
	Tags          []string          `json:"tags"`           // 标签
	References    []string          `json:"references"`     // 参考链接
	CWE           string            `json:"cwe"`            // CWE编号
	CVSS          *CVSSScore        `json:"cvss,omitempty"` // CVSS评分
	Metadata      map[string]string `json:"metadata"`       // 额外元数据
	
	// 修复建议
	Recommendation string        `json:"recommendation"` // 修复建议
	Solution       string        `json:"solution"`       // 解决方案
}

// ParamType 参数类型枚举
type ParamType int

const (
	ParamTypeUnknown ParamType = iota
	ParamTypeQuery             // URL查询参数
	ParamTypeForm              // 表单参数
	ParamTypeJSON              // JSON参数
	ParamTypeXML               // XML参数
	ParamTypeHeader            // HTTP头参数
	ParamTypeCookie            // Cookie参数
	ParamTypePath              // 路径参数
)

// String 返回参数类型的字符串表示
func (p ParamType) String() string {
	switch p {
	case ParamTypeQuery:
		return "Query"
	case ParamTypeForm:
		return "Form"
	case ParamTypeJSON:
		return "JSON"
	case ParamTypeXML:
		return "XML"
	case ParamTypeHeader:
		return "Header"
	case ParamTypeCookie:
		return "Cookie"
	case ParamTypePath:
		return "Path"
	default:
		return "Unknown"
	}
}

// HTTPRequest 完整的HTTP请求信息
type HTTPRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	Cookies map[string]string `json:"cookies"`
}

// HTTPResponse HTTP响应信息
type HTTPResponse struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	Length     int64             `json:"length"`
	Time       time.Duration     `json:"time"`
}

// Evidence 漏洞证据
type Evidence struct {
	Type        string `json:"type"`        // 证据类型
	Location    string `json:"location"`    // 证据位置
	Value       string `json:"value"`       // 证据值
	Description string `json:"description"` // 描述
}

// CVSSScore CVSS评分
type CVSSScore struct {
	Version string  `json:"version"` // CVSS版本
	Vector  string  `json:"vector"`  // 攻击向量
	Score   float64 `json:"score"`   // 评分
	Rating  string  `json:"rating"`  // 评级
}

// VulnerabilityReport 漏洞报告
type VulnerabilityReport struct {
	Summary      ReportSummary    `json:"summary"`
	Vulnerabilities []*Vulnerability `json:"vulnerabilities"`
	ScanInfo     ScanInfo         `json:"scan_info"`
	Statistics   ReportStatistics `json:"statistics"`
}

// ReportSummary 报告摘要
type ReportSummary struct {
	TotalVulns     int                    `json:"total_vulns"`
	BySeverity     map[SeverityLevel]int  `json:"by_severity"`
	ByType         map[string]int         `json:"by_type"`
	ByPlugin       map[string]int         `json:"by_plugin"`
	HighestSeverity SeverityLevel         `json:"highest_severity"`
}

// ScanInfo 扫描信息
type ScanInfo struct {
	StartTime    time.Time     `json:"start_time"`
	EndTime      time.Time     `json:"end_time"`
	Duration     time.Duration `json:"duration"`
	TargetURL    string        `json:"target_url"`
	PluginsUsed  []string      `json:"plugins_used"`
	ScanOptions  ScanOptions   `json:"scan_options"`
}

// ReportStatistics 报告统计
type ReportStatistics struct {
	RequestsSent     int64         `json:"requests_sent"`
	ResponsesReceived int64        `json:"responses_received"`
	ErrorsEncountered int64        `json:"errors_encountered"`
	AverageResponseTime time.Duration `json:"average_response_time"`
	FalsePositiveRate float64      `json:"false_positive_rate"`
}

// NewVulnerability 创建新的漏洞实例
func NewVulnerability(vulnType, url, payload, param string) *Vulnerability {
	return &Vulnerability{
		ID:        generateVulnID(),
		Type:      vulnType,
		URL:       url,
		Payload:   payload,
		Param:     param,
		Timestamp: time.Now(),
		Confidence: 1.0,
		Evidence:  make([]Evidence, 0),
		Tags:      make([]string, 0),
		References: make([]string, 0),
		Metadata:  make(map[string]string),
	}
}

// AddEvidence 添加漏洞证据
func (v *Vulnerability) AddEvidence(evidenceType, location, value, description string) {
	evidence := Evidence{
		Type:        evidenceType,
		Location:    location,
		Value:       value,
		Description: description,
	}
	v.Evidence = append(v.Evidence, evidence)
}

// SetCVSS 设置CVSS评分
func (v *Vulnerability) SetCVSS(version, vector string, score float64, rating string) {
	v.CVSS = &CVSSScore{
		Version: version,
		Vector:  vector,
		Score:   score,
		Rating:  rating,
	}
}

// ToJSON 将漏洞转换为JSON
func (v *Vulnerability) ToJSON() ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

// FromJSON 从JSON创建漏洞
func FromJSON(data []byte) (*Vulnerability, error) {
	var vuln Vulnerability
	err := json.Unmarshal(data, &vuln)
	return &vuln, err
}

// Validate 验证漏洞数据的完整性
func (v *Vulnerability) Validate() error {
	if v.Type == "" {
		return fmt.Errorf("漏洞类型不能为空")
	}
	if v.URL == "" {
		return fmt.Errorf("目标URL不能为空")
	}
	if v.Confidence < 0 || v.Confidence > 1 {
		return fmt.Errorf("置信度必须在0-1之间")
	}
	return nil
}

// GetSeverityColor 获取严重程度对应的颜色
func (v *Vulnerability) GetSeverityColor() string {
	return v.Severity.Color()
}

// IsHighRisk 判断是否为高风险漏洞
func (v *Vulnerability) IsHighRisk() bool {
	return v.Severity >= SeverityHigh
}

// generateVulnID 生成漏洞唯一ID
func generateVulnID() string {
	return fmt.Sprintf("vuln_%d", time.Now().UnixNano())
}

// BasePlugin 基础插件结构，提供通用实现
type BasePlugin struct {
	info    PluginInfo
	config  PluginConfig
	state   PluginState
	payloads []models.Payload
}

// NewBasePlugin 创建基础插件
func NewBasePlugin(info PluginInfo) *BasePlugin {
	return &BasePlugin{
		info:   info,
		config: PluginConfig{
			Enabled:     true,
			Priority:    0,
			ScanOptions: DefaultScanOptions(),
		},
		state: PluginState{
			CustomState: make(map[string]interface{}),
		},
	}
}

// Info 实现Plugin接口
func (bp *BasePlugin) Info() PluginInfo {
	return bp.info
}

// Initialize 实现Plugin接口
func (bp *BasePlugin) Initialize() error {
	bp.state.IsInitialized = true
	return nil
}

// Cleanup 实现Plugin接口
func (bp *BasePlugin) Cleanup() error {
	return nil
}

// Configure 实现ConfigurablePlugin接口
func (bp *BasePlugin) Configure(config PluginConfig) error {
	bp.config = config
	return nil
}

// GetDefaultConfig 实现ConfigurablePlugin接口
func (bp *BasePlugin) GetDefaultConfig() PluginConfig {
	return PluginConfig{
		Enabled:     true,
		Priority:    0,
		ScanOptions: DefaultScanOptions(),
	}
}

// ValidateConfig 实现ConfigurablePlugin接口
func (bp *BasePlugin) ValidateConfig(config PluginConfig) error {
	// 基础验证逻辑
	return nil
}

// SetPayloads 实现PayloadPlugin接口
func (bp *BasePlugin) SetPayloads(payloads []models.Payload) {
	bp.payloads = payloads
}

// GetDefaultPayloads 实现PayloadPlugin接口
func (bp *BasePlugin) GetDefaultPayloads() []models.Payload {
	return bp.payloads
}

// GeneratePayloads 实现PayloadPlugin接口
func (bp *BasePlugin) GeneratePayloads(req *models.Request) []models.Payload {
	return bp.payloads
}

// GetState 实现StatefulPlugin接口
func (bp *BasePlugin) GetState() PluginState {
	return bp.state
}

// SetState 实现StatefulPlugin接口
func (bp *BasePlugin) SetState(state PluginState) error {
	bp.state = state
	return nil
}

// ResetState 实现StatefulPlugin接口
func (bp *BasePlugin) ResetState() error {
	bp.state = PluginState{
		IsInitialized: bp.state.IsInitialized,
		CustomState:   make(map[string]interface{}),
	}
	return nil
}

// UpdateStats 更新插件统计信息
func (bp *BasePlugin) UpdateStats(success bool, duration time.Duration, vulnCount int) {
	bp.state.ScanCount++
	bp.state.LastScanTime = time.Now()
	
	if success {
		bp.state.SuccessCount++
		bp.state.VulnCount += int64(vulnCount)
	} else {
		bp.state.ErrorCount++
	}
	
	// 更新平均时间
	if bp.state.ScanCount == 1 {
		bp.state.AverageTime = duration
	} else {
		totalTime := bp.state.AverageTime * time.Duration(bp.state.ScanCount-1)
		bp.state.AverageTime = (totalTime + duration) / time.Duration(bp.state.ScanCount)
	}
}
