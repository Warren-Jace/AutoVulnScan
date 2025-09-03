// Package vulnscan 提供了核心的漏洞扫描引擎和插件管理机制。
package vulnscan

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// ReportGenerator 报告生成器接口
type ReportGenerator interface {
	// GenerateVulnerabilityReport 生成漏洞报告
	GenerateVulnerabilityReport(vulns []*Vulnerability) *VulnerabilityReport
	// GenerateSummary 生成摘要
	GenerateSummary(vulns []*Vulnerability) ReportSummary
	// FormatReport 格式化报告
	FormatReport(report *VulnerabilityReport, format string) (string, error)
	// AddCustomField 添加自定义字段
	AddCustomField(name string, value interface{})
}

// DefaultReportGenerator 默认报告生成器
type DefaultReportGenerator struct {
	customFields map[string]interface{}
}

// NewDefaultReportGenerator 创建默认报告生成器
func NewDefaultReportGenerator() *DefaultReportGenerator {
	return &DefaultReportGenerator{
		customFields: make(map[string]interface{}),
	}
}

// GenerateVulnerabilityReport 生成漏洞报告
func (rg *DefaultReportGenerator) GenerateVulnerabilityReport(vulns []*Vulnerability) *VulnerabilityReport {
	report := &VulnerabilityReport{
		Summary:      rg.GenerateSummary(vulns),
		Vulnerabilities: vulns,
		ScanInfo: ScanInfo{
			StartTime:   time.Now(),
			PluginsUsed: []string{},
		},
		Statistics: rg.generateStatistics(vulns),
	}

	// 添加自定义字段
	if len(rg.customFields) > 0 {
		for _, vuln := range vulns {
			if vuln.Metadata == nil {
				vuln.Metadata = make(map[string]string)
			}
			for k, v := range rg.customFields {
				vuln.Metadata[k] = fmt.Sprintf("%v", v)
			}
		}
	}

	// 收集使用的插件
	plugins := make(map[string]bool)
	for _, vuln := range vulns {
		if vuln.Plugin != "" {
			plugins[vuln.Plugin] = true
		}
	}
	for plugin := range plugins {
		report.ScanInfo.PluginsUsed = append(report.ScanInfo.PluginsUsed, plugin)
	}
	sort.Strings(report.ScanInfo.PluginsUsed)

	return report
}

// GenerateSummary 生成摘要
func (rg *DefaultReportGenerator) GenerateSummary(vulns []*Vulnerability) ReportSummary {
	summary := ReportSummary{
		TotalVulns:     len(vulns),
		BySeverity:     make(map[SeverityLevel]int),
		ByType:         make(map[string]int),
		ByPlugin:       make(map[string]int),
		HighestSeverity: SeverityUnknown,
	}

	for _, vuln := range vulns {
		// 按严重程度统计
		summary.BySeverity[vuln.Severity]++
		
		// 按类型统计
		summary.ByType[vuln.Type]++
		
		// 按插件统计
		if vuln.Plugin != "" {
			summary.ByPlugin[vuln.Plugin]++
		}
		
		// 更新最高严重程度
		if vuln.Severity > summary.HighestSeverity {
			summary.HighestSeverity = vuln.Severity
		}
	}

	return summary
}

// generateStatistics 生成统计信息
func (rg *DefaultReportGenerator) generateStatistics(vulns []*Vulnerability) ReportStatistics {
	stats := ReportStatistics{
		FalsePositiveRate: 0.0,
	}

	var totalConfidence float64
	var highConfidenceCount int
	var falsePositiveCount int

	for _, vuln := range vulns {
		totalConfidence += vuln.Confidence
		if vuln.Confidence >= 0.8 {
			highConfidenceCount++
		}
		if vuln.FalsePositive {
			falsePositiveCount++
		}
	}

	if len(vulns) > 0 {
		stats.FalsePositiveRate = float64(falsePositiveCount) / float64(len(vulns))
	}

	// 计算平均置信度
	if len(vulns) > 0 {
		avgConfidence := totalConfidence / float64(len(vulns))
		stats.AverageResponseTime = time.Duration(avgConfidence * float64(time.Second))
	}

	return stats
}

// FormatReport 格式化报告
func (rg *DefaultReportGenerator) FormatReport(report *VulnerabilityReport, format string) (string, error) {
	switch strings.ToLower(format) {
	case "text", "txt":
		return rg.formatTextReport(report), nil
	case "json":
		return rg.formatJSONReport(report)
	case "html":
		return rg.formatHTMLReport(report), nil
	default:
		return rg.formatTextReport(report), nil
	}
}

// formatTextReport 格式化文本报告
func (rg *DefaultReportGenerator) formatTextReport(report *VulnerabilityReport) string {
	var builder strings.Builder

	// 报告头部
	builder.WriteString("=" + strings.Repeat("=", 60) + "\n")
	builder.WriteString("漏洞扫描报告\n")
	builder.WriteString("=" + strings.Repeat("=", 60) + "\n\n")

	// 扫描信息
	builder.WriteString("扫描信息:\n")
	builder.WriteString("-" + strings.Repeat("-", 40) + "\n")
	builder.WriteString(fmt.Sprintf("开始时间: %s\n", report.ScanInfo.StartTime.Format("2006-01-02 15:04:05")))
	builder.WriteString(fmt.Sprintf("结束时间: %s\n", report.ScanInfo.EndTime.Format("2006-01-02 15:04:05")))
	builder.WriteString(fmt.Sprintf("扫描时长: %s\n", report.ScanInfo.Duration))
	builder.WriteString(fmt.Sprintf("目标URL: %s\n", report.ScanInfo.TargetURL))
	builder.WriteString(fmt.Sprintf("使用插件: %s\n", strings.Join(report.ScanInfo.PluginsUsed, ", ")))\n	builder.WriteString("\n")

	// 摘要信息
	builder.WriteString("漏洞摘要:\n")
	builder.WriteString("-" + strings.Repeat("-", 40) + "\n")
	builder.WriteString(fmt.Sprintf("漏洞总数: %d\n", report.Summary.TotalVulns))
	builder.WriteString(fmt.Sprintf("最高严重程度: %s\n", report.Summary.HighestSeverity.String()))
	builder.WriteString("\n按严重程度分布:\n")
	for severity, count := range report.Summary.BySeverity {
		builder.WriteString(fmt.Sprintf("  - %s: %d\n", severity.String(), count))
	}
	builder.WriteString("\n按类型分布:\n")
	for vulnType, count := range report.Summary.ByType {
		builder.WriteString(fmt.Sprintf("  - %s: %d\n", vulnType, count))
	}
	builder.WriteString("\n")

	// 漏洞详情
	builder.WriteString("漏洞详情:\n")
	builder.WriteString("-" + strings.Repeat("-", 40) + "\n")
	for i, vuln := range report.Vulnerabilities {
		builder.WriteString(fmt.Sprintf("[%d] %s\n", i+1, vuln.Title))
		builder.WriteString(fmt.Sprintf("类型: %s\n", vuln.Type))
		builder.WriteString(fmt.Sprintf("严重程度: %s\n", vuln.Severity.String()))
		builder.WriteString(fmt.Sprintf("URL: %s\n", vuln.URL))
		if vuln.Param != "" {
			builder.WriteString(fmt.Sprintf("参数: %s\n", vuln.Param))
		}
		if vuln.Payload != "" {
			builder.WriteString(fmt.Sprintf("Payload: %s\n", vuln.Payload))
		}
		builder.WriteString(fmt.Sprintf("置信度: %.2f\n", vuln.Confidence))
		builder.WriteString(fmt.Sprintf("描述: %s\n", vuln.Description))
		if len(vuln.Evidence) > 0 {
			builder.WriteString("证据:\n")
			for _, evidence := range vuln.Evidence {
				builder.WriteString(fmt.Sprintf("  - %s: %s\n", evidence.Type, evidence.Value))
			}
		}
		if vuln.Recommendation != "" {
			builder.WriteString(fmt.Sprintf("修复建议: %s\n", vuln.Recommendation))
		}
		builder.WriteString("\n")
	}

	// 统计信息
	builder.WriteString("统计信息:\n")
	builder.WriteString("-" + strings.Repeat("-", 40) + "\n")
	builder.WriteString(fmt.Sprintf("误报率: %.2f%%\n", report.Statistics.FalsePositiveRate*100))
	builder.WriteString(fmt.Sprintf("平均响应时间: %s\n", report.Statistics.AverageResponseTime))
	builder.WriteString("\n")

	return builder.String()
}

// formatJSONReport 格式化JSON报告
func (rg *DefaultReportGenerator) formatJSONReport(report *VulnerabilityReport) (string, error) {
	// 这里简化处理，实际应该使用json.Marshal
	return "{\"status\":\"JSON format not implemented yet\"}", nil
}

// formatHTMLReport 格式化HTML报告
func (rg *DefaultReportGenerator) formatHTMLReport(report *VulnerabilityReport) string {
	// 这里简化处理，返回基本的HTML结构
	return "<!DOCTYPE html><html><head><title>漏洞扫描报告</title></head><body><h1>漏洞扫描报告</h1><p>HTML格式报告尚未完全实现</p></body></html>"
}

// AddCustomField 添加自定义字段
func (rg *DefaultReportGenerator) AddCustomField(name string, value interface{}) {
	rg.customFields[name] = value
}

// StandardRemediationGenerator 标准修复建议生成器
type StandardRemediationGenerator struct {
	remediationTemplates map[string]string
}

// NewStandardRemediationGenerator 创建标准修复建议生成器
func NewStandardRemediationGenerator() *StandardRemediationGenerator {
	generator := &StandardRemediationGenerator{
		remediationTemplates: make(map[string]string),
	}
	generator.initializeTemplates()
	return generator
}

// initializeTemplates 初始化修复建议模板
func (rg *StandardRemediationGenerator) initializeTemplates() {
	rg.remediationTemplates["xss"] = `XSS漏洞修复建议:
1. 对所有用户输入进行严格的验证和过滤
2. 实施输出编码，根据上下文使用HTML、URL、JS或CSS编码
3. 使用内容安全策略(CSP)限制脚本执行
4. 设置HttpOnly和Secure标志的Cookie
5. 使用现代Web框架提供的自动XSS防护功能`

	rg.remediationTemplates["sqli"] = `SQL注入漏洞修复建议:
1. 使用参数化查询/预编译语句
2. 对用户输入进行严格验证和过滤
3. 使用最小权限原则配置数据库账户
4. 启用数据库审计和监控
5. 定期更新数据库软件和补丁`

	rg.remediationTemplates["base"] = `通用安全建议:
1. 实施输入验证和输出编码
2. 使用最小权限原则
3. 启用安全日志和监控
4. 定期进行安全评估和渗透测试
5. 及时应用安全补丁`
}

// GenerateRemediation 生成修复建议
func (rg *StandardRemediationGenerator) GenerateRemediation(vulnType string, additionalInfo map[string]string) string {
	template, exists := rg.remediationTemplates[vulnType]
	if !exists {
		template = rg.remediationTemplates["base"]
	}

	// 如果有额外信息，可以添加到建议中
	if additionalInfo != nil {
		for key, value := range additionalInfo {
			template += fmt.Sprintf("\n%d. %s: %s", len(strings.Split(template, "\n"))+1, key, value)
		}
	}

	return template
}