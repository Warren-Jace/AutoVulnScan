// Package plugins 包含了所有具体的漏洞扫描插件实现。
package plugins

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"
	"autovulnscan/internal/vulnscan"

	"github.com/rs/zerolog/log"
)

// SQLiPlugin 实现了用于检测SQL注入漏洞的插件。
// 支持基于错误、基于布尔、基于时间延迟和基于联合查询的SQL注入检测。
type SQLiPlugin struct {
	vulnscan.BasePlugin
	
	// 核心组件
	httpClient *requester.HTTPClient
	
	// 检测配置
	config SQLiConfig
	
	// 错误模式和检测规则
	errorPatterns    []ErrorPattern
	booleanPatterns  []BooleanPattern
	timePatterns     []TimePattern
	unionPatterns    []UnionPattern
	
	// 缓存和状态
	responseCache sync.Map // URL -> *models.ResponseInfo
	payloadCache  sync.Map // 缓存生成的payloads
	
	// 统计信息
	stats SQLiStats
	
	// 正则表达式（预编译）
	errorRegexes   []*regexp.Regexp
	numericRegex   *regexp.Regexp
	stringRegex    *regexp.Regexp
	
	// 互斥锁
	mu sync.RWMutex
}

// SQLiConfig SQL注入插件配置
type SQLiConfig struct {
	// 基础配置
	MaxPayloads         int           `json:"max_payloads"`          // 最大payload数量
	Timeout             time.Duration `json:"timeout"`               // 请求超时
	TimeBasedDelay      time.Duration `json:"time_based_delay"`      // 时间延迟检测的延迟时间
	
	// 检测类型配置
	EnableErrorBased    bool `json:"enable_error_based"`     // 启用基于错误的检测
	EnableBooleanBased  bool `json:"enable_boolean_based"`   // 启用基于布尔的检测
	EnableTimeBased     bool `json:"enable_time_based"`      // 启用基于时间的检测
	EnableUnionBased    bool `json:"enable_union_based"`     // 启用基于联合查询的检测
	EnableBlindSQLi     bool `json:"enable_blind_sqli"`      // 启用盲注检测
	
	// 响应分析配置
	MinResponseDiff     int     `json:"min_response_diff"`      // 最小响应差异（字节）
	MaxResponseDiffRatio float64 `json:"max_response_diff_ratio"` // 最大响应差异比例
	TimeThreshold       time.Duration `json:"time_threshold"`   // 时间检测阈值
	
	// WAF检测配置
	EnableWAFDetection  bool `json:"enable_waf_detection"`   // 启用WAF检测
	WAFThreshold        int  `json:"waf_threshold"`          // WAF检测阈值
	
	// 误报减少
	EnableFalsePositiveReduction bool `json:"enable_false_positive_reduction"`
	ConfidenceThreshold         float64 `json:"confidence_threshold"`
	
	// 数据库特定检测
	DetectDatabaseType  bool `json:"detect_database_type"`   // 检测数据库类型
	TestNumericFields   bool `json:"test_numeric_fields"`    // 测试数字字段
	TestStringFields    bool `json:"test_string_fields"`     // 测试字符串字段
}

// SQLiStats SQL注入插件统计信息
type SQLiStats struct {
	TotalRequests       int64 `json:"total_requests"`
	SuccessfulTests     int64 `json:"successful_tests"`
	ErrorBasedFound     int64 `json:"error_based_found"`
	BooleanBasedFound   int64 `json:"boolean_based_found"`
	TimeBasedFound      int64 `json:"time_based_found"`
	UnionBasedFound     int64 `json:"union_based_found"`
	BlindSQLiFound      int64 `json:"blind_sqli_found"`
	FalsePositives      int64 `json:"false_positives"`
	WAFDetections       int64 `json:"waf_detections"`
	DatabasesDetected   map[string]int64 `json:"databases_detected"`
	AverageResponseTime time.Duration `json:"average_response_time"`
}

// SQLiType SQL注入类型枚举
type SQLiType int

const (
	SQLiTypeErrorBased SQLiType = iota
	SQLiTypeBooleanBased
	SQLiTypeTimeBased
	SQLiTypeUnionBased
	SQLiTypeBlind
)

// String 返回SQL注入类型字符串
func (t SQLiType) String() string {
	switch t {
	case SQLiTypeErrorBased:
		return "Error-based"
	case SQLiTypeBooleanBased:
		return "Boolean-based"
	case SQLiTypeTimeBased:
		return "Time-based"
	case SQLiTypeUnionBased:
		return "Union-based"
	case SQLiTypeBlind:
		return "Blind"
	default:
		return "Unknown"
	}
}

// DatabaseType 数据库类型
type DatabaseType string

const (
	DatabaseMySQL      DatabaseType = "MySQL"
	DatabasePostgreSQL DatabaseType = "PostgreSQL"
	DatabaseSQLServer  DatabaseType = "SQL Server"
	DatabaseOracle     DatabaseType = "Oracle"
	DatabaseSQLite     DatabaseType = "SQLite"
	DatabaseMongoDB    DatabaseType = "MongoDB"
	DatabaseUnknown    DatabaseType = "Unknown"
)

// ErrorPattern 错误模式定义
type ErrorPattern struct {
	Pattern    string       `json:"pattern"`
	Database   DatabaseType `json:"database"`
	Confidence float64      `json:"confidence"`
	Regex      *regexp.Regexp `json:"-"`
}

// BooleanPattern 布尔模式定义
type BooleanPattern struct {
	TruePayload  string  `json:"true_payload"`
	FalsePayload string  `json:"false_payload"`
	Confidence   float64 `json:"confidence"`
}

// TimePattern 时间延迟模式定义
type TimePattern struct {
	Payload    string       `json:"payload"`
	Database   DatabaseType `json:"database"`
	Delay      time.Duration `json:"delay"`
	Confidence float64      `json:"confidence"`
}

// UnionPattern 联合查询模式定义
type UnionPattern struct {
	Payload    string       `json:"payload"`
	Database   DatabaseType `json:"database"`
	Columns    int          `json:"columns"`
	Confidence float64      `json:"confidence"`
}

// SQLiContext SQL注入检测上下文
type SQLiContext struct {
	OriginalRequest *models.Request
	Parameter       models.Parameter
	Payload         string
	SQLiType        SQLiType
	Context         context.Context
}

// SQLiResult SQL注入检测结果
type SQLiResult struct {
	Vulnerable     bool
	Confidence     float64
	Evidence       []vulnscan.Evidence
	SQLiType       SQLiType
	DatabaseType   DatabaseType
	Payload        string
	Response       *models.ResponseInfo
	ResponseTime   time.Duration
	ErrorPattern   string
	WAFDetected    bool
}

// 默认配置
var defaultSQLiConfig = SQLiConfig{
	MaxPayloads:                     30,
	Timeout:                        30 * time.Second,
	TimeBasedDelay:                 5 * time.Second,
	EnableErrorBased:               true,
	EnableBooleanBased:             true,
	EnableTimeBased:                true,
	EnableUnionBased:               true,
	EnableBlindSQLi:                true,
	MinResponseDiff:                50,
	MaxResponseDiffRatio:           0.1,
	TimeThreshold:                  3 * time.Second,
	EnableWAFDetection:             true,
	WAFThreshold:                   5,
	EnableFalsePositiveReduction:   true,
	ConfidenceThreshold:            0.7,
	DetectDatabaseType:             true,
	TestNumericFields:              true,
	TestStringFields:               true,
}

// init 函数会在包初始化时被调用，用于自动注册插件。
func init() {
	plugin := NewSQLiPlugin()
	vulnscan.RegisterPlugin(plugin)
}

// NewSQLiPlugin 创建新的SQL注入插件实例
func NewSQLiPlugin() *SQLiPlugin {
	info := vulnscan.PluginInfo{
		Name:        "sqli",
		Description: "检测基于错误、布尔、时间延迟和联合查询的SQL注入漏洞",
		Author:      "AutoVulnScan Team",
		Version:     "2.0",
		Category:    "injection",
		Severity:    vulnscan.SeverityCritical,
		Tags:        []string{"sqli", "injection", "database", "web"},
		References: []string{
			"https://owasp.org/www-community/attacks/SQL_Injection",
			"https://portswigger.net/web-security/sql-injection",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	
	plugin := &SQLiPlugin{
		BasePlugin: *vulnscan.NewBasePlugin(info),
		config:     defaultSQLiConfig,
		stats: SQLiStats{
			DatabasesDetected: make(map[string]int64),
		},
	}
	
	// 初始化检测模式
	plugin.initializePatterns()
	plugin.compileRegexes()
	
	return plugin
}

// Initialize 实现Plugin接口
func (p *SQLiPlugin) Initialize() error {
	if err := p.BasePlugin.Initialize(); err != nil {
		return err
	}
	
	// 初始化默认payloads
	if len(p.GetDefaultPayloads()) == 0 {
		p.SetPayloads(p.generateDefaultPayloads())
	}
	
	log.Info().
		Str("plugin", p.Info().Name).
		Int("payloads", len(p.GetDefaultPayloads())).
		Int("error_patterns", len(p.errorPatterns)).
		Msg("SQL注入插件初始化完成")
	
	return nil
}

// initializePatterns 初始化检测模式
func (p *SQLiPlugin) initializePatterns() {
	// 错误模式
	p.errorPatterns = []ErrorPattern{
		// MySQL
		{Pattern: "you have an error in your sql syntax", Database: DatabaseMySQL, Confidence: 0.9},
		{Pattern: "mysql_fetch_array()", Database: DatabaseMySQL, Confidence: 0.8},
		{Pattern: "mysql_num_rows()", Database: DatabaseMySQL, Confidence: 0.8},
		{Pattern: "mysql_query()", Database: DatabaseMySQL, Confidence: 0.8},
		{Pattern: "duplicate entry", Database: DatabaseMySQL, Confidence: 0.7},
		{Pattern: "table doesn't exist", Database: DatabaseMySQL, Confidence: 0.7},
		
		// PostgreSQL
		{Pattern: "postgresql query failed", Database: DatabasePostgreSQL, Confidence: 0.9},
		{Pattern: "pg_query()", Database: DatabasePostgreSQL, Confidence: 0.8},
		{Pattern: "pg_exec()", Database: DatabasePostgreSQL, Confidence: 0.8},
		{Pattern: "syntax error at or near", Database: DatabasePostgreSQL, Confidence: 0.9},
		
		// SQL Server
		{Pattern: "microsoft ole db provider for sql server", Database: DatabaseSQLServer, Confidence: 0.9},
		{Pattern: "unclosed quotation mark after the character string", Database: DatabaseSQLServer, Confidence: 0.8},
		{Pattern: "incorrect syntax near", Database: DatabaseSQLServer, Confidence: 0.8},
		{Pattern: "sqlstate", Database: DatabaseSQLServer, Confidence: 0.7},
		
		// Oracle
		{Pattern: "ora-00936", Database: DatabaseOracle, Confidence: 0.9},
		{Pattern: "ora-00942", Database: DatabaseOracle, Confidence: 0.9},
		{Pattern: "ora-00933", Database: DatabaseOracle, Confidence: 0.9},
		{Pattern: "oracle error", Database: DatabaseOracle, Confidence: 0.8},
		
		// SQLite
		{Pattern: "sqlite_query", Database: DatabaseSQLite, Confidence: 0.8},
		{Pattern: "sqlite error", Database: DatabaseSQLite, Confidence: 0.8},
		{Pattern: "sql error or missing database", Database: DatabaseSQLite, Confidence: 0.8},
		
		// 通用错误
		{Pattern: "sql syntax", Database: DatabaseUnknown, Confidence: 0.6},
		{Pattern: "database error", Database: DatabaseUnknown, Confidence: 0.5},
		{Pattern: "warning: mysql", Database: DatabaseMySQL, Confidence: 0.7},
		{Pattern: "function.mysql", Database: DatabaseMySQL, Confidence: 0.7},
	}
	
	// 布尔模式
	p.booleanPatterns = []BooleanPattern{
		{TruePayload: "' OR '1'='1", FalsePayload: "' OR '1'='2", Confidence: 0.8},
		{TruePayload: "\" OR \"1\"=\"1", FalsePayload: "\" OR \"1\"=\"2", Confidence: 0.8},
		{TruePayload: " OR 1=1", FalsePayload: " OR 1=2", Confidence: 0.7},
		{TruePayload: "' OR 'a'='a", FalsePayload: "' OR 'a'='b", Confidence: 0.8},
		{TruePayload: "1' OR '1'='1' --", FalsePayload: "1' OR '1'='2' --", Confidence: 0.9},
	}
	
	// 时间延迟模式
	p.timePatterns = []TimePattern{
		{Payload: "'; WAITFOR DELAY '00:00:05' --", Database: DatabaseSQLServer, Delay: 5 * time.Second, Confidence: 0.9},
		{Payload: "'; SELECT SLEEP(5) --", Database: DatabaseMySQL, Delay: 5 * time.Second, Confidence: 0.9},
		{Payload: "'; SELECT pg_sleep(5) --", Database: DatabasePostgreSQL, Delay: 5 * time.Second, Confidence: 0.9},
		{Payload: "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --", Database: DatabaseMySQL, Delay: 5 * time.Second, Confidence: 0.8},
		{Payload: "' OR SLEEP(5) --", Database: DatabaseMySQL, Delay: 5 * time.Second, Confidence: 0.8},
	}
	
	// 联合查询模式
	p.unionPatterns = []UnionPattern{
		{Payload: "' UNION SELECT NULL --", Database: DatabaseUnknown, Columns: 1, Confidence: 0.7},
		{Payload: "' UNION SELECT NULL,NULL --", Database: DatabaseUnknown, Columns: 2, Confidence: 0.7},
		{Payload: "' UNION SELECT NULL,NULL,NULL --", Database: DatabaseUnknown, Columns: 3, Confidence: 0.7},
		{Payload: "' UNION SELECT 1,2,3 --", Database: DatabaseUnknown, Columns: 3, Confidence: 0.8},
		{Payload: "' UNION ALL SELECT NULL --", Database: DatabaseUnknown, Columns: 1, Confidence: 0.7},
	}
}

// compileRegexes 预编译正则表达式
func (p *SQLiPlugin) compileRegexes() {
	// 编译错误模式正则
	for i := range p.errorPatterns {
		if regex, err := regexp.Compile("(?i)" + regexp.QuoteMeta(p.errorPatterns[i].Pattern)); err == nil {
			p.errorPatterns[i].Regex = regex
			p.errorRegexes = append(p.errorRegexes, regex)
		} else {
			log.Warn().Err(err).Str("pattern", p.errorPatterns[i].Pattern).Msg("编译错误模式正则失败")
		}
	}
	
	// 编译数字和字符串检测正则
	var err error
	p.numericRegex, err = regexp.Compile(`^\d+$`)
	if err != nil {
		log.Warn().Err(err).Msg("编译数字正则失败")
	}
	
	p.stringRegex, err = regexp.Compile(`^[a-zA-Z0-9\s]+$`)
	if err != nil {
		log.Warn().Err(err).Msg("编译字符串正则失败")
	}
}

// Configure 实现ConfigurablePlugin接口
func (p *SQLiPlugin) Configure(config vulnscan.PluginConfig) error {
	if err := p.BasePlugin.Configure(config); err != nil {
		return err
	}
	
	// 解析SQL注入特定配置
	if sqliConfig, ok := config.CustomConfig["sqli_config"]; ok {
		if cfg, ok := sqliConfig.(SQLiConfig); ok {
			p.config = cfg
		}
	}
	
	return nil
}

// Scan 实现Plugin接口 - 主要扫描入口
func (p *SQLiPlugin) Scan(client *requester.HTTPClient, req *models.Request) ([]*vulnscan.Vulnerability, error) {
	ctx := context.Background()
	return p.ScanWithContext(ctx, client, req)
}

// ScanWithContext 实现AdvancedPlugin接口
func (p *SQLiPlugin) ScanWithContext(ctx context.Context, client *requester.HTTPClient, req *models.Request) ([]*vulnscan.Vulnerability, error) {
	startTime := time.Now()
	defer func() {
		p.UpdateStats(true, time.Since(startTime), 0)
	}()
	
	p.httpClient = client
	var vulnerabilities []*vulnscan.Vulnerability
	
	// 并发扫描参数
	paramChan := make(chan models.Parameter, len(req.Params))
	resultChan := make(chan []*vulnscan.Vulnerability, len(req.Params))
	
	// 启动工作协程
	const maxWorkers = 3 // SQL注入检测比较耗时，减少并发数
	workers := len(req.Params)
	if workers > maxWorkers {
		workers = maxWorkers
	}
	
	for i := 0; i < workers; i++ {
		go p.parameterWorker(ctx, req, paramChan, resultChan)
	}
	
	// 发送参数到通道
	for _, param := range req.Params {
		paramChan <- param
	}
	close(paramChan)
	
	// 收集结果
	for i := 0; i < len(req.Params); i++ {
		select {
		case vulns := <-resultChan:
			vulnerabilities = append(vulnerabilities, vulns...)
		case <-ctx.Done():
			return vulnerabilities, ctx.Err()
		}
	}
	
	// 去重和排序
	vulnerabilities = p.deduplicateVulnerabilities(vulnerabilities)
	
	log.Info().
		Str("plugin", "sqli").
		Str("url", req.URL).
		Int("vulnerabilities", len(vulnerabilities)).
		Dur("duration", time.Since(startTime)).
		Msg("SQL注入扫描完成")
	
	return vulnerabilities, nil
}

// parameterWorker 参数扫描工作协程
func (p *SQLiPlugin) parameterWorker(ctx context.Context, req *models.Request, paramChan <-chan models.Parameter, resultChan chan<- []*vulnscan.Vulnerability) {
	for param := range paramChan {
		vulns, err := p.scanParameter(ctx, req, param)
		if err != nil {
			log.Warn().
				Err(err).
				Str("url", req.URL).
				Str("param", param.Name).
				Msg("参数扫描失败")
			resultChan <- []*vulnscan.Vulnerability{}
			continue
		}
		resultChan <- vulns
	}
}

// scanParameter 扫描单个参数
func (p *SQLiPlugin) scanParameter(ctx context.Context, req *models.Request, param models.Parameter) ([]*vulnscan.Vulnerability, error) {
	var vulnerabilities []*vulnscan.Vulnerability
	var payloadResponses []string
	
	// 根据参数类型选择测试策略
	testStrategies := p.selectTestStrategies(param)
	
	for _, strategy := range testStrategies {
		select {
		case <-ctx.Done():
			return vulnerabilities, ctx.Err()
		default:
		}
		
		payloads := p.selectPayloadsForStrategy(strategy, param)
		
		for _, payload := range payloads {
			sqliCtx := &SQLiContext{
				OriginalRequest: req,
				Parameter:       param,
				Payload:         payload.Value,
				SQLiType:        strategy,
				Context:         ctx,
			}
			
			result, err := p.testSQLiPayload(sqliCtx)
			if err != nil {
				log.Debug().
					Err(err).
					Str("param", param.Name).
					Str("payload", payload.Value).
					Msg("SQL注入payload测试失败")
				continue
			}
			
			if result.Response != nil {
				payloadResponses = append(payloadResponses, result.Response.Hash)
			}
			
			if result.Vulnerable && result.Confidence >= p.config.ConfidenceThreshold {
				vuln := p.createVulnerabilityFromResult(sqliCtx, result)
				vulnerabilities = append(vulnerabilities, vuln)
				
				// 更新统计信息
				p.updateTypeStats(result.SQLiType)
				if result.DatabaseType != DatabaseUnknown {
					p.mu.Lock()
					p.stats.DatabasesDetected[string(result.DatabaseType)]++
					p.mu.Unlock()
				}
			}
		}
	}
	
	// WAF检测
	if p.config.EnableWAFDetection {
		p.detectWAF(req.URL, param.Name, payloadResponses)
	}
	
	return vulnerabilities, nil
}

// selectTestStrategies 选择测试策略
func (p *SQLiPlugin) selectTestStrategies(param models.Parameter) []SQLiType {
	var strategies []SQLiType
	
	if p.config.EnableErrorBased {
		strategies = append(strategies, SQLiTypeErrorBased)
	}
	
	if p.config.EnableBooleanBased {
		strategies = append(strategies, SQLiTypeBooleanBased)
	}
	
	if p.config.EnableTimeBased {
		strategies = append(strategies, SQLiTypeTimeBased)
	}
	
	if p.config.EnableUnionBased {
		strategies = append(strategies, SQLiTypeUnionBased)
	}
	
	return strategies
}

// selectPayloadsForStrategy 为策略选择payloads
func (p *SQLiPlugin) selectPayloadsForStrategy(strategy SQLiType, param models.Parameter) []models.Payload {
	var payloads []models.Payload
	
	switch strategy {
	case SQLiTypeErrorBased:
		payloads = p.generateErrorBasedPayloads(param)
	case SQLiTypeBooleanBased:
		payloads = p.generateBooleanBasedPayloads(param)
	case SQLiTypeTimeBased:
		payloads = p.generateTimeBasedPayloads(param)
	case SQLiTypeUnionBased:
		payloads = p.generateUnionBasedPayloads(param)
	}
	
	// 限制payload数量
	maxPayloads := p.config.MaxPayloads / 4 // 平均分配给每种类型
	if len(payloads) > maxPayloads {
		payloads = payloads[:maxPayloads]
	}
	
	return payloads
}

// generateErrorBasedPayloads 生成基于错误的payloads
func (p *SQLiPlugin) generateErrorBasedPayloads(param models.Parameter) []models.Payload {
	basePayloads := []string{
		"'",
		"\"",
		"')",
		"\")",
		"';",
		"\";",
		"' OR '1'='1",
		"\" OR \"1\"=\"1",
		"' AND '1'='2",
		"\" AND \"1\"=\"2",
		"' UNION SELECT NULL --",
		"\" UNION SELECT NULL --",
		"' OR 1=1 --",
		"\" OR 1=1 --",
		"' AND 1=2 --",
		"\" AND 1=2 --",
		"admin'--",
		"admin\"--",
		"' OR 'x'='x",
		"\" OR \"x\"=\"x",
	}
	
	var payloads []models.Payload
	for i, payload := range basePayloads {
		payloads = append(payloads, models.Payload{
			ID:          fmt.Sprintf("sqli_error_%d", i+1),
			Value:       payload,
			Type:        "sqli_error",
			Description: fmt.Sprintf("Error-based SQLi payload #%d", i+1),
			Severity:    models.SeverityHigh,
		})
	}
	
	return payloads
}

// generateBooleanBasedPayloads 生成基于布尔的payloads
func (p *SQLiPlugin) generateBooleanBasedPayloads(param models.Parameter) []models.Payload {
	var payloads []models.Payload
	
	for i, pattern := range p.booleanPatterns {
		// True payload
		payloads = append(payloads, models.Payload{
			ID:          fmt.Sprintf("sqli_bool_true_%d", i+1),
			Value:       pattern.TruePayload,
			Type:        "sqli_boolean_true",
			Description: fmt.Sprintf("Boolean-based SQLi true payload #%d", i+1),
			Severity:    models.SeverityHigh,
		})
		
		// False payload
		payloads = append(payloads, models.Payload{
			ID:          fmt.Sprintf("sqli_bool_false_%d", i+1),
			Value:       pattern.FalsePayload,
			Type:        "sqli_boolean_false",
			Description: fmt.Sprintf("Boolean-based SQLi false payload #%d", i+1),
			Severity:    models.SeverityHigh,
		})
	}
	
	return payloads
}

// generateTimeBasedPayloads 生成基于时间的payloads
func (p *SQLiPlugin) generateTimeBasedPayloads(param models.Parameter) []models.Payload {
	var payloads []models.Payload
	
	for i, pattern := range p.timePatterns {
		payloads = append(payloads, models.Payload{
			ID:          fmt.Sprintf("sqli_time_%d", i+1),
			Value:       pattern.Payload,
			Type:        "sqli_time",
			Description: fmt.Sprintf("Time-based SQLi payload #%d (%s)", i+1, pattern.Database),
			Severity:    models.SeverityHigh,
		})
	}
	
	return payloads
}

// generateUnionBasedPayloads 生成基于联合查询的payloads
func (p *SQLiPlugin) generateUnionBasedPayloads(param models.Parameter) []models.Payload {
	var payloads []models.Payload
	
	for i, pattern := range p.unionPatterns {
		payloads = append(payloads, models.Payload{
			ID:          fmt.Sprintf("sqli_union_%d", i+1),
			Value:       pattern.Payload,
			Type:        "sqli_union",
			Description: fmt.Sprintf("Union-based SQLi payload #%d (%d columns)", i+1, pattern.Columns),
			Severity:    models.SeverityHigh,
		})
	}
	
	return payloads
}

// testSQLiPayload 测试SQL注入payload
func (p *SQLiPlugin) testSQLiPayload(sqliCtx *SQLiContext) (*SQLiResult, error) {
	result := &SQLiResult{
		Payload:  sqliCtx.Payload,
		SQLiType: sqliCtx.SQLiType,
	}
	
	startTime := time.Now()
	
	// 1. 获取基线响应
	baselineResp, err := p.getBaselineResponse(sqliCtx)
	if err != nil {
		return result, fmt.Errorf("获取基线响应失败: %w", err)
	}
	
	// 2. 发送payload请求
	testResp, err := p.sendPayloadRequest(sqliCtx)
	if err != nil {
		return result, fmt.Errorf("发送payload请求失败: %w", err)
	}
	
	result.Response = testResp
	result.ResponseTime = time.Since(startTime)
	
	// 3. 根据SQL注入类型
	// 3. 根据SQL注入类型进行分析
	switch sqliCtx.SQLiType {
	case SQLiTypeErrorBased:
		err = p.analyzeErrorBasedResponse(sqliCtx, baselineResp, testResp, result)
	case SQLiTypeBooleanBased:
		err = p.analyzeBooleanBasedResponse(sqliCtx, baselineResp, testResp, result)
	case SQLiTypeTimeBased:
		err = p.analyzeTimeBasedResponse(sqliCtx, baselineResp, testResp, result)
	case SQLiTypeUnionBased:
		err = p.analyzeUnionBasedResponse(sqliCtx, baselineResp, testResp, result)
	default:
		err = fmt.Errorf("未知的SQL注入类型: %v", sqliCtx.SQLiType)
	}
	
	if err != nil {
		return result, fmt.Errorf("分析响应失败: %w", err)
	}
	
	return result, nil
}

// analyzeErrorBasedResponse 分析基于错误的响应
func (p *SQLiPlugin) analyzeErrorBasedResponse(sqliCtx *SQLiContext, baseline, test *models.ResponseInfo, result *SQLiResult) error {
	confidence := 0.0
	var evidence []vulnscan.Evidence
	
	// 检查SQL错误模式
	if errorPattern, dbType := p.checkErrorPatterns(test.Body); errorPattern != "" {
		confidence = 0.9
		result.DatabaseType = dbType
		result.ErrorPattern = errorPattern
		
		evidence = append(evidence, vulnscan.Evidence{
			Type:        "sql_error",
			Location:    "response_body",
			Value:       errorPattern,
			Description: fmt.Sprintf("检测到%s数据库错误信息", dbType),
		})
		
		log.Info().
			Str("plugin", "sqli").
			Str("url", sqliCtx.OriginalRequest.URL).
			Str("param", sqliCtx.Parameter.Name).
			Str("payload", sqliCtx.Payload).
			Str("pattern", errorPattern).
			Str("database", string(dbType)).
			Msg("检测到SQL错误模式")
	}
	
	// 检查响应差异
	if p.hasSignificantDifference(baseline, test) {
		confidence += 0.3
		evidence = append(evidence, vulnscan.Evidence{
			Type:        "response_diff",
			Location:    "response",
			Value:       fmt.Sprintf("基线长度: %d, 测试长度: %d", len(baseline.Body), len(test.Body)),
			Description: "响应存在显著差异",
		})
	}
	
	// 检查状态码变化
	if baseline.StatusCode != test.StatusCode {
		confidence += 0.2
		evidence = append(evidence, vulnscan.Evidence{
			Type:        "status_change",
			Location:    "response_status",
			Value:       fmt.Sprintf("%d -> %d", baseline.StatusCode, test.StatusCode),
			Description: "HTTP状态码发生变化",
		})
	}
	
	result.Vulnerable = confidence >= p.config.ConfidenceThreshold
	result.Confidence = confidence
	result.Evidence = evidence
	
	return nil
}

// analyzeBooleanBasedResponse 分析基于布尔的响应
func (p *SQLiPlugin) analyzeBooleanBasedResponse(sqliCtx *SQLiContext, baseline, test *models.ResponseInfo, result *SQLiResult) error {
	// 布尔型SQL注入需要成对测试true/false payload
	// 这里简化处理，实际应该存储true/false响应进行比较
	confidence := 0.0
	var evidence []vulnscan.Evidence
	
	// 检查响应差异
	if p.hasSignificantDifference(baseline, test) {
		confidence = 0.6
		evidence = append(evidence, vulnscan.Evidence{
			Type:        "response_diff",
			Location:    "response",
			Value:       fmt.Sprintf("基线Hash: %s, 测试Hash: %s", baseline.Hash, test.Hash),
			Description: "布尔型SQL注入响应差异",
		})
	}
	
	// 检查内容长度变化模式
	lenDiff := len(test.Body) - len(baseline.Body)
	if lenDiff != 0 {
		confidence += 0.3
		evidence = append(evidence, vulnscan.Evidence{
			Type:        "length_diff",
			Location:    "response_body",
			Value:       fmt.Sprintf("长度差异: %d", lenDiff),
			Description: "响应长度发生变化",
		})
	}
	
	result.Vulnerable = confidence >= p.config.ConfidenceThreshold
	result.Confidence = confidence
	result.Evidence = evidence
	
	return nil
}

// analyzeTimeBasedResponse 分析基于时间的响应
func (p *SQLiPlugin) analyzeTimeBasedResponse(sqliCtx *SQLiContext, baseline, test *models.ResponseInfo, result *SQLiResult) error {
	confidence := 0.0
	var evidence []vulnscan.Evidence
	
	// 检查响应时间延迟
	if result.ResponseTime >= p.config.TimeThreshold {
		confidence = 0.8
		evidence = append(evidence, vulnscan.Evidence{
			Type:        "time_delay",
			Location:    "response_time",
			Value:       result.ResponseTime.String(),
			Description: fmt.Sprintf("响应时间延迟 %v，超过阈值 %v", result.ResponseTime, p.config.TimeThreshold),
		})
		
		log.Info().
			Str("plugin", "sqli").
			Str("url", sqliCtx.OriginalRequest.URL).
			Str("param", sqliCtx.Parameter.Name).
			Str("payload", sqliCtx.Payload).
			Dur("response_time", result.ResponseTime).
			Dur("threshold", p.config.TimeThreshold).
			Msg("检测到时间延迟SQL注入")
	}
	
	// 检查响应内容是否正常（排除网络问题）
	if test.StatusCode == baseline.StatusCode && len(test.Body) > 0 {
		confidence += 0.1
		evidence = append(evidence, vulnscan.Evidence{
			Type:        "normal_response",
			Location:    "response",
			Value:       fmt.Sprintf("状态码: %d, 响应长度: %d", test.StatusCode, len(test.Body)),
			Description: "响应内容正常，排除网络延迟",
		})
	}
	
	result.Vulnerable = confidence >= p.config.ConfidenceThreshold
	result.Confidence = confidence
	result.Evidence = evidence
	
	return nil
}

// analyzeUnionBasedResponse 分析基于联合查询的响应
func (p *SQLiPlugin) analyzeUnionBasedResponse(sqliCtx *SQLiContext, baseline, test *models.ResponseInfo, result *SQLiResult) error {
	confidence := 0.0
	var evidence []vulnscan.Evidence
	
	// 检查UNION查询特征
	bodyStr := strings.ToLower(string(test.Body))
	
	// 检查是否出现了额外的数据行
	if p.hasAdditionalData(baseline, test) {
		confidence = 0.7
		evidence = append(evidence, vulnscan.Evidence{
			Type:        "additional_data",
			Location:    "response_body",
			Value:       fmt.Sprintf("响应长度增加: %d", len(test.Body)-len(baseline.Body)),
			Description: "检测到UNION查询返回的额外数据",
		})
	}
	
	// 检查UNION查询错误
	unionErrors := []string{
		"the used select statements have a different number of columns",
		"all queries combined using a union",
		"conversion failed when converting",
		"union query with wrong number of columns",
	}
	
	for _, errPattern := range unionErrors {
		if strings.Contains(bodyStr, errPattern) {
			confidence += 0.4
			evidence = append(evidence, vulnscan.Evidence{
				Type:        "union_error",
				Location:    "response_body",
				Value:       errPattern,
				Description: "检测到UNION查询相关错误",
			})
			break
		}
	}
	
	result.Vulnerable = confidence >= p.config.ConfidenceThreshold
	result.Confidence = confidence
	result.Evidence = evidence
	
	return nil
}

// checkErrorPatterns 检查响应中是否包含SQL错误模式
func (p *SQLiPlugin) checkErrorPatterns(body []byte) (string, DatabaseType) {
	bodyLower := strings.ToLower(string(body))
	
	for _, pattern := range p.errorPatterns {
		if pattern.Regex != nil && pattern.Regex.MatchString(bodyLower) {
			return pattern.Pattern, pattern.Database
		} else if strings.Contains(bodyLower, pattern.Pattern) {
			return pattern.Pattern, pattern.Database
		}
	}
	
	return "", DatabaseUnknown
}

// hasAdditionalData 检查是否有额外数据
func (p *SQLiPlugin) hasAdditionalData(baseline, test *models.ResponseInfo) bool {
	if len(test.Body) <= len(baseline.Body) {
		return false
	}
	
	// 检查长度增加是否显著
	increase := len(test.Body) - len(baseline.Body)
	return increase > 50 && float64(increase)/float64(len(baseline.Body)) > 0.1
}

// getBaselineResponse 获取基线响应
func (p *SQLiPlugin) getBaselineResponse(sqliCtx *SQLiContext) (*models.ResponseInfo, error) {
	cacheKey := p.generateCacheKey(sqliCtx.OriginalRequest, sqliCtx.Parameter.Name, sqliCtx.Parameter.Value)
	
	// 检查缓存
	if cached, ok := p.responseCache.Load(cacheKey); ok {
		return cached.(*models.ResponseInfo), nil
	}
	
	// 构建基线请求
	req, err := p.buildHTTPRequest(sqliCtx.OriginalRequest, sqliCtx.Parameter.Name, sqliCtx.Parameter.Value)
	if err != nil {
		return nil, err
	}
	
	// 发送请求
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	
	respInfo, err := p.getResponseInfo(resp)
	if err != nil {
		return nil, err
	}
	
	// 缓存响应
	p.responseCache.Store(cacheKey, respInfo)
	
	return respInfo, nil
}

// sendPayloadRequest 发送payload请求
func (p *SQLiPlugin) sendPayloadRequest(sqliCtx *SQLiContext) (*models.ResponseInfo, error) {
	req, err := p.buildHTTPRequest(sqliCtx.OriginalRequest, sqliCtx.Parameter.Name, sqliCtx.Payload)
	if err != nil {
		return nil, err
	}
	
	p.logRequestDebug(req, sqliCtx.Payload)
	
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	
	respInfo, err := p.getResponseInfo(resp)
	if err != nil {
		return nil, err
	}
	
	p.logResponseDebug(resp, respInfo)
	
	return respInfo, nil
}

// createVulnerabilityFromResult 从检测结果创建漏洞对象
func (p *SQLiPlugin) createVulnerabilityFromResult(sqliCtx *SQLiContext, result *SQLiResult) *vulnscan.Vulnerability {
	severity := vulnscan.SeverityHigh
	if result.Confidence >= 0.9 {
		severity = vulnscan.SeverityCritical
	} else if result.Confidence < 0.7 {
		severity = vulnscan.SeverityMedium
	}
	
	description := fmt.Sprintf("检测到%s SQL注入漏洞，置信度: %.2f", result.SQLiType.String(), result.Confidence)
	if result.DatabaseType != DatabaseUnknown {
		description += fmt.Sprintf("，数据库类型: %s", result.DatabaseType)
	}
	if result.ErrorPattern != "" {
		description += fmt.Sprintf("，错误模式: %s", result.ErrorPattern)
	}
	
	testURL := p.buildVulnerableURL(sqliCtx.OriginalRequest, sqliCtx.Parameter.Name, sqliCtx.Payload)
	
	vuln := &vulnscan.Vulnerability{
		Type:          p.Info().Name,
		URL:           sqliCtx.OriginalRequest.URL,
		Payload:       sqliCtx.Payload,
		Param:         sqliCtx.Parameter.Name,
		Method:        sqliCtx.OriginalRequest.Method,
		VulnerableURL: testURL,
		Timestamp:     time.Now(),
		Severity:      severity,
		Confidence:    result.Confidence,
		Description:   description,
		Evidence:      result.Evidence,
		Metadata: map[string]interface{}{
			"sqli_type":      result.SQLiType.String(),
			"database_type":  string(result.DatabaseType),
			"error_pattern":  result.ErrorPattern,
			"response_time":  result.ResponseTime.String(),
			"waf_detected":   result.WAFDetected,
			"response_size":  len(result.Response.Body),
			"status_code":    result.Response.StatusCode,
		},
	}
	
	// 添加修复建议
	vuln.Remediation = p.generateRemediation(result.SQLiType, result.DatabaseType)
	
	return vuln
}

// generateRemediation 生成修复建议
func (p *SQLiPlugin) generateRemediation(sqliType SQLiType, dbType DatabaseType) string {
	baseRemediation := `修复建议：
1. 使用参数化查询/预编译语句
2. 对用户输入进行严格验证和过滤
3. 使用最小权限原则配置数据库账户
4. 启用数据库审计和监控
5. 定期更新数据库软件和补丁`
	
	switch sqliType {
	case SQLiTypeErrorBased:
		return baseRemediation + `
6. 禁用详细错误信息的显示
7. 实施自定义错误页面`
		
	case SQLiTypeTimeBased:
		return baseRemediation + `
6. 设置查询超时限制
7. 监控异常的响应时间`
		
	case SQLiTypeUnionBased:
		return baseRemediation + `
6. 限制UNION查询的使用
7. 验证查询结果的数据结构`
		
	case SQLiTypeBooleanBased:
		return baseRemediation + `
6. 避免基于查询结果的条件分支
7. 使用一致的响应格式`
	}
	
	if dbType != DatabaseUnknown {
		return baseRemediation + fmt.Sprintf(`
6. 针对%s数据库的特定安全配置
7. 使用%s的安全特性和函数`, dbType, dbType)
	}
	
	return baseRemediation
}

// generateDefaultPayloads 生成默认payloads
func (p *SQLiPlugin) generateDefaultPayloads() []models.Payload {
	var allPayloads []models.Payload
	
	// 合并不同类型的payloads
	dummyParam := models.Parameter{Name: "test", Value: "test"}
	
	errorPayloads := p.generateErrorBasedPayloads(dummyParam)
	booleanPayloads := p.generateBooleanBasedPayloads(dummyParam)
	timePayloads := p.generateTimeBasedPayloads(dummyParam)
	unionPayloads := p.generateUnionBasedPayloads(dummyParam)
	
	allPayloads = append(allPayloads, errorPayloads...)
	allPayloads = append(allPayloads, booleanPayloads...)
	allPayloads = append(allPayloads, timePayloads...)
	allPayloads = append(allPayloads, unionPayloads...)
	
	return allPayloads
}

// detectWAF 检测WAF
func (p *SQLiPlugin) detectWAF(url, paramName string, responses []string) {
	if len(responses) < p.config.WAFThreshold {
		return
	}
	
	// 检查所有响应是否相同
	uniqueResponses := make(map[string]bool)
	for _, resp := range responses {
		uniqueResponses[resp] = true
	}
	
	if len(uniqueResponses) == 1 {
		log.Warn().
			Str("url", url).
			Str("param", paramName).
			Int("total_payloads", len(responses)).
			Msg("检测到可能的WAF/过滤器，所有SQL注入payload响应一致")
		
		p.mu.Lock()
		p.stats.WAFDetections++
		p.mu.Unlock()
	}
}

// updateTypeStats 更新类型统计
func (p *SQLiPlugin) updateTypeStats(sqliType SQLiType) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	switch sqliType {
	case SQLiTypeErrorBased:
		p.stats.ErrorBasedFound++
	case SQLiTypeBooleanBased:
		p.stats.BooleanBasedFound++
	case SQLiTypeTimeBased:
		p.stats.TimeBasedFound++
	case SQLiTypeUnionBased:
		p.stats.UnionBasedFound++
	case SQLiTypeBlind:
		p.stats.BlindSQLiFound++
	}
}

// deduplicateVulnerabilities 去重漏洞
func (p *SQLiPlugin) deduplicateVulnerabilities(vulns []*vulnscan.Vulnerability) []*vulnscan.Vulnerability {
	seen := make(map[string]bool)
	var result []*vulnscan.Vulnerability
	
	for _, vuln := range vulns {
		key := fmt.Sprintf("%s_%s_%s", vuln.URL, vuln.Param, vuln.Method)
		if !seen[key] {
			seen[key] = true
			result = append(result, vuln)
		}
	}
	
	return result
}

// hasSignificantDifference 检查两个响应是否有显著差异
func (p *SQLiPlugin) hasSignificantDifference(base, test *models.ResponseInfo) bool {
	if base == nil || test == nil {
		return false
	}
	
	// 状态码不同
	if base.StatusCode != test.StatusCode {
		return true
	}
	
	// 内容hash不同
	if base.Hash != test.Hash {
		return true
	}
	
	// 响应长度差异检查
	lenDiff := len(test.Body) - len(base.Body)
	if lenDiff < 0 {
		lenDiff = -lenDiff
	}
	
	// 检查绝对差异和相对差异
	if lenDiff > p.config.MinResponseDiff {
		if len(base.Body) > 0 {
			relativeRatio := float64(lenDiff) / float64(len(base.Body))
			return relativeRatio > p.config.MaxResponseDiffRatio
		}
		return true
	}
	
	return false
}

// buildVulnerableURL 构建包含漏洞的URL
func (p *SQLiPlugin) buildVulnerableURL(req *models.Request, paramName, payload string) string {
	if req.Method == "POST" {
		return req.URL // POST请求返回原始URL
	}
	
	// GET请求构建包含payload的URL
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return req.URL
	}
	
	query := parsedURL.Query()
	for _, param := range req.Params {
		if param.Name == paramName {
			query.Set(param.Name, payload)
		} else {
			query.Set(param.Name, param.Value)
		}
	}
	
	parsedURL.RawQuery = query.Encode()
	return parsedURL.String()
}

// getResponseInfo 获取响应信息并计算hash
func (p *SQLiPlugin) getResponseInfo(resp *http.Response) (*models.ResponseInfo, error) {
	if resp == nil {
		return nil, fmt.Errorf("http响应为空")
	}
	
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %w", err)
	}
	
	hash := sha256.Sum256(body)
	shortHash := hex.EncodeToString(hash[:4])
	
	return &models.ResponseInfo{
		Body:       body,
		StatusCode: resp.StatusCode,
		Hash:       shortHash,
		Headers:    resp.Header,
		Size:       len(body),
	}, nil
}

// buildHTTPRequest 构建HTTP请求
func (p *SQLiPlugin) buildHTTPRequest(originalReq *models.Request, paramName, paramValue string) (*http.Request, error) {
	var req *http.Request
	var err error
	
	if originalReq.Method == "POST" {
		req, err = p.buildPOSTRequest(originalReq, paramName, paramValue)
	} else {
		req, err = p.buildGETRequest(originalReq, paramName, paramValue)
	}
	
	if err != nil {
		return nil, fmt.Errorf("创建HTTP请求失败: %w", err)
	}
	
	// 复制原始请求头
	if originalReq.Headers != nil {
		req.Header = originalReq.Headers.Clone()
	}
	
	// 设置超时
	ctx, cancel := context.WithTimeout(context.Background(), p.config.Timeout)
	req = req.WithContext(ctx)
	
	// 注意：这里不能直接调用cancel()，因为请求可能还在使用
	_ = cancel
	
	return req, nil
}

// buildPOSTRequest 构建POST请求
func (p *SQLiPlugin) buildPOSTRequest(originalReq *models.Request, paramName, paramValue string) (*http.Request, error) {
	form := make(url.Values)
	for _, param := range originalReq.Params {
		if param.Name == paramName {
			form.Set(param.Name, paramValue)
		} else {
			form.Set(param.Name, param.Value)
		}
	}
	
	req, err := http.NewRequest("POST", originalReq.URL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

// buildGETRequest 构建GET请求
func (p *SQLiPlugin) buildGETRequest(originalReq *models.Request, paramName, paramValue string) (*http.Request, error) {
	parsedURL, err := url.Parse(originalReq.URL)
	if err != nil {
		return nil, err
	}
	
	query := parsedURL.Query()
	for _, param := range originalReq.Params {
		if param.Name == paramName {
			query.Set(param.Name, paramValue)
		} else {
			query.Set(param.Name, param.Value)
		}
	}
	
	parsedURL.RawQuery = query.Encode()
	return http.NewRequest("GET", parsedURL.String(), nil)
}

// generateCacheKey 生成缓存键
func (p *SQLiPlugin) generateCacheKey(req *models.Request, paramName, paramValue string) string {
	return fmt.Sprintf("%s_%s_%s_%s", req.Method, req.URL, paramName, paramValue)
}

// logRequestDebug 记录请求调试信息
func (p *SQLiPlugin) logRequestDebug(req *http.Request, payload string) {
	if log.Debug().Enabled() {
		if dump, err := httputil.DumpRequestOut(req, true); err == nil {
			log.Debug().Str("plugin", "sqli").Msgf("Raw SQLi Request:\n%s", string(dump))
		}
		
		log.Debug().
			Str("plugin", "sqli").
			Str("method", req.Method).
			Str("url", req.URL.String()).
			Str("payload", payload).
			Msg("Sending SQLi test request")
	}
}

// logResponseDebug 记录响应调试信息
func (p *SQLiPlugin) logResponseDebug(resp *http.Response, info *models.ResponseInfo) {
	if !log.Debug().Enabled() || info == nil {
		return
	}
	
	const previewLen = 200
	preview := string(info.Body)
	if len(preview) > previewLen {
		preview = preview[:previewLen] + "..."
	}
	
	log.Debug().
		Str("plugin", "sqli").
		Int("status", info.StatusCode).
		Int("bodyLen", len(info.Body)).
		Str("bodyPreview", preview).
		Str("respHash", info.Hash).
		Msg("HTTP response received")
}

// UpdateStats 更新统计信息
func (p *SQLiPlugin) UpdateStats(success bool, responseTime time.Duration, vulnCount int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	p.stats.TotalRequests++
	if success {
		p.stats.SuccessfulTests++
	}
	
	// 更新平均响应时间
	if p.stats.TotalRequests == 1 {
		p.stats.AverageResponseTime = responseTime
	} else {
		p.stats.AverageResponseTime = (p.stats.AverageResponseTime*time.Duration(p.stats.TotalRequests-1) + responseTime) / time.Duration(p.stats.TotalRequests)
	}
}

// GetStats 获取统计信息
func (p *SQLiPlugin) GetStats() SQLiStats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.stats
}

// ResetStats 重置统计信息
func (p *SQLiPlugin) ResetStats() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stats = SQLiStats{
		DatabasesDetected: make(map[string]int64),
	}
}

// Cleanup 清理资源
func (p *SQLiPlugin) Cleanup() error {
	// 清理缓存
	p.responseCache.Range(func(key, value interface{}) bool {
		p.responseCache.Delete(key)
		return true
	})
	
	p.payloadCache.Range(func(key, value interface{}) bool {
		p.payloadCache.Delete(key)
		return true
	})
	
	log.Info().Str("plugin", "sqli").Msg("SQL注入插件清理完成")
	return nil
}

// Validate 实现Plugin接口的验证方法
func (p *SQLiPlugin) Validate() error {
	if len(p.errorPatterns) == 0 {
		return fmt.Errorf("SQL注入插件没有配置错误模式")
	}
	
	if p.config.MaxPayloads <= 0 {
		return fmt.Errorf("MaxPayloads必须大于0")
	}
	
	if p.config.Timeout <= 0 {
		return fmt.Errorf("Timeout必须大于0")
	}
	
	if p.config.TimeThreshold <= 0 {
		return fmt.Errorf("TimeThreshold必须大于0")
	}
	
	return nil
}

// SetPayloads 设置插件的攻击载荷（保持兼容性）
func (p *SQLiPlugin) SetPayloads(payloads []models.Payload) {
	p.BasePlugin.SetPayloads(payloads)
}

// GetDefaultPayloads 获取默认payloads（保持兼容性）
func (p *SQLiPlugin) GetDefaultPayloads() []models.Payload {
	if len(p.BasePlugin.GetDefaultPayloads()) == 0 {
		return p.generateDefaultPayloads()
	}
	return p.BasePlugin.GetDefaultPayloads()
}
