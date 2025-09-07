// Package vulnscan 提供了核心的漏洞扫描引擎和插件管理机制。
package vulnscan

import (
	"fmt"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
)

// WAFDetector WAF检测器接口
type WAFDetector interface {
	// DetectWAF 检测WAF
	DetectWAF(url, paramName string, responses []string) bool
	// GetWAFType 获取检测到的WAF类型
	GetWAFType() string
	// GetWAFEvidence 获取WAF证据
	GetWAFEvidence() []string
	// Reset 重置检测器状态
	Reset()
}

// WAFType WAF类型
type WAFType string

const (
	WAFTypeUnknown    WAFType = "unknown"
	WAFTypeModSecurity WAFType = "modsecurity"
	WAFTypeCloudflare  WAFType = "cloudflare"
	WAFTypeAWSWAF      WAFType = "awswaf"
	WAFTypeImperva     WAFType = "imperva"
	WAFTypeF5          WAFType = "f5"
	WAFTypeBarracuda   WAFType = "barracuda"
	WAFTypeSucuri      WAFType = "sucuri"
	WAFTypeWordfence   WAFType = "wordfence"
)

// WAFSignature WAF签名
type WAFSignature struct {
	Name        string   `json:"name"`
	Type        WAFType  `json:"type"`
	Patterns    []string `json:"patterns"`
	Headers     []string `json:"headers"`
	StatusCodes []int    `json:"status_codes"`
	Description string   `json:"description"`
}

// DefaultWAFDetector 默认WAF检测器
type DefaultWAFDetector struct {
	mu        sync.RWMutex
	detected  bool
	wafType   WAFType
	evidence  []string
	signatures []WAFSignature
}

// NewDefaultWAFDetector 创建默认WAF检测器
func NewDefaultWAFDetector() *DefaultWAFDetector {
	detector := &DefaultWAFDetector{
		evidence: make([]string, 0),
	}
	detector.initializeSignatures()
	return detector
}

// initializeSignatures 初始化WAF签名
func (d *DefaultWAFDetector) initializeSignatures() {
	d.signatures = []WAFSignature{
		// ModSecurity
		{
			Name:        "ModSecurity",
			Type:        WAFTypeModSecurity,
			Patterns:    []string{"mod_security", "modsecurity", "mod security"},
			Headers:     []string{"server: modsecurity", "x-modsecurity-crs"},
			StatusCodes: []int{403, 406},
			Description: "ModSecurity Web应用防火墙",
		},
		// Cloudflare
		{
			Name:        "Cloudflare",
			Type:        WAFTypeCloudflare,
			Patterns:    []string{"cloudflare", "cf-ray", "__cfduid"},
			Headers:     []string{"server: cloudflare", "cf-ray"},
			StatusCodes: []int{403, 503},
			Description: "Cloudflare Web应用防火墙",
		},
		// AWS WAF
		{
			Name:        "AWS WAF",
			Type:        WAFTypeAWSWAF,
			Patterns:    []string{"aws waf", "amazon waf"},
			Headers:     []string{"x-amz-waf"},
			StatusCodes: []int{403, 405},
			Description: "AWS Web应用防火墙",
		},
		// Imperva
		{
			Name:        "Imperva",
			Type:        WAFTypeImperva,
			Patterns:    []string{"imperva", "incapsula", "securecdn"},
			Headers:     []string{"x-cdn: incapsula", "x-iinfo"},
			StatusCodes: []int{403, 406},
			Description: "Imperva SecureSphere",
		},
		// F5
		{
			Name:        "F5",
			Type:        WAFTypeF5,
			Patterns:    []string{"f5", "big-ip", "asm"},
			Headers:     []string{"server: big-ip", "x-wa-info"},
			StatusCodes: []int{403, 406},
			Description: "F5 BIG-IP ASM",
		},
		// Barracuda
		{
			Name:        "Barracuda",
			Type:        WAFTypeBarracuda,
			Patterns:    []string{"barracuda", "barra"},
			Headers:     []string{"server: barracuda", "x-barracuda"},
			StatusCodes: []int{403, 406},
			Description: "Barracuda Web应用防火墙",
		},
		// Sucuri
		{
			Name:        "Sucuri",
			Type:        WAFTypeSucuri,
			Patterns:    []string{"sucuri", "sucuri firewall"},
			Headers:     []string{"x-sucuri-cache", "x-sucuri-id"},
			StatusCodes: []int{403, 406},
			Description: "Sucuri Web应用防火墙",
		},
		// Wordfence
		{
			Name:        "Wordfence",
			Type:        WAFTypeWordfence,
			Patterns:    []string{"wordfence", "wordfence security"},
			Headers:     []string{},
			StatusCodes: []int{403, 503},
			Description: "Wordfence WordPress安全插件",
		},
	}
}

// DetectWAF 检测WAF
func (d *DefaultWAFDetector) DetectWAF(url, paramName string, responses []string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	// 重置状态
	d.detected = false
	d.wafType = WAFTypeUnknown
	d.evidence = make([]string, 0)

	// 如果响应数量不足，无法检测
	if len(responses) < 3 {
		return false
	}

	// 检查所有响应是否相同
	uniqueResponses := make(map[string]bool)
	for _, resp := range responses {
		uniqueResponses[resp] = true
	}

	// 如果所有响应都相同，可能是WAF拦截
	if len(uniqueResponses) == 1 {
		d.detected = true
		d.wafType = WAFTypeUnknown
		evidence := fmt.Sprintf("所有%d个payload响应相同，可能是WAF拦截", len(responses))
		d.evidence = append(d.evidence, evidence)

		log.Warn().
			Str("url", url).
			Str("param", paramName).
			Int("total_payloads", len(responses)).
			Msg("检测到可能的WAF/过滤器，所有payload响应一致")

		return true
	}

	// 检查特定WAF签名
	for _, resp := range responses {
		for _, sig := range d.signatures {
			// 检查响应内容中的模式
			for _, pattern := range sig.Patterns {
				if strings.Contains(strings.ToLower(resp), strings.ToLower(pattern)) {
					d.detected = true
					d.wafType = sig.Type
					evidence := fmt.Sprintf("在响应中检测到%s模式: %s", sig.Name, pattern)
					d.evidence = append(d.evidence, evidence)
					return true
				}
			}
		}
	}

	return false
}

// GetWAFType 获取检测到的WAF类型
func (d *DefaultWAFDetector) GetWAFType() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return string(d.wafType)
}

// GetWAFEvidence 获取WAF证据
func (d *DefaultWAFDetector) GetWAFEvidence() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// 返回证据的副本
	evidence := make([]string, len(d.evidence))
	copy(evidence, d.evidence)
	return evidence
}

// Reset 重置检测器状态
func (d *DefaultWAFDetector) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.detected = false
	d.wafType = WAFTypeUnknown
	d.evidence = make([]string, 0)
}

// GetWAFDetector 获取WAF检测器
func GetWAFDetector() WAFDetector {
	return NewDefaultWAFDetector()
}