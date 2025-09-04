// Package report 提供了生成漏洞扫描报告的功能
// 支持多种格式，包括HTML、PDF、JSON、CSV和Markdown
package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"autovulnscan/internal/llm"
	"autovulnscan/internal/models"

	"github.com/rs/zerolog/log"
)

// Generator 表示报告生成器
type Generator struct {
	llmClient *llm.Client
	templates map[string]*template.Template
}

// NewGenerator 创建一个新的报告生成器
func NewGenerator(llmClient *llm.Client) (*Generator, error) {
	g := &Generator{
		llmClient: llmClient,
		templates: make(map[string]*template.Template),
	}

	// 加载内置模板
	if err := g.loadBuiltInTemplates(); err != nil {
		return nil, fmt.Errorf("failed to load built-in templates: %w", err)
	}

	return g, nil
}

// Generate 生成报告
func (g *Generator) Generate(scanResult *models.ScanResult, config models.ReportConfig) error {
	// 验证配置
	if scanResult == nil {
		return fmt.Errorf("scan result cannot be nil")
	}

	if config.Format == "" {
		config.Format = "HTML"
	}

	if config.OutputPath == "" {
		timestamp := time.Now().Format("20060102-150405")
		config.OutputPath = fmt.Sprintf("vulnerability_report_%s.%s", timestamp, strings.ToLower(config.Format))
	}

	// 确保输出目录存在
	dir := filepath.Dir(config.OutputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// 根据格式生成报告
	switch strings.ToLower(config.Format) {
	case "html":
		return g.generateHTMLReport(scanResult, config)
	case "pdf":
		return g.generatePDFReport(scanResult, config)
	case "json":
		return g.generateJSONReport(scanResult, config)
	case "csv":
		return g.generateCSVReport(scanResult, config)
	case "markdown", "md":
		return g.generateMarkdownReport(scanResult, config)
	default:
		return fmt.Errorf("unsupported report format: %s", config.Format)
	}
}

// generateHTMLReport 生成HTML报告
func (g *Generator) generateHTMLReport(scanResult *models.ScanResult, config models.ReportConfig) error {
	// 准备模板数据
	data := g.prepareTemplateData(scanResult, config)

	// 获取模板
	tmpl, ok := g.templates["html"]
	if !ok {
		return fmt.Errorf("HTML template not found")
	}

	// 执行模板
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to execute HTML template: %w", err)
	}

	// 写入文件
	if err := os.WriteFile(config.OutputPath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write HTML report: %w", err)
	}

	log.Info().Str("path", config.OutputPath).Msg("HTML report generated successfully")
	return nil
}

// generatePDFReport 生成PDF报告
func (g *Generator) generatePDFReport(scanResult *models.ScanResult, config models.ReportConfig) error {
	// 首先生成HTML报告
	htmlPath := strings.TrimSuffix(config.OutputPath, filepath.Ext(config.OutputPath)) + ".html"
	htmlConfig := config
	htmlConfig.OutputPath = htmlPath
	htmlConfig.Format = "HTML"

	if err := g.generateHTMLReport(scanResult, htmlConfig); err != nil {
		return fmt.Errorf("failed to generate intermediate HTML report: %w", err)
	}

	// 使用外部工具将HTML转换为PDF
	// 这里可以使用wkhtmltopdf或pandoc等工具
	// 由于Go标准库中没有PDF生成功能，这里只是一个示例实现
	log.Warn().Msg("PDF generation requires external tools like wkhtmltopdf or pandoc")
	log.Info().Str("html_path", htmlPath).Msg("Generated HTML file that can be converted to PDF")

	return fmt.Errorf("PDF generation not implemented, HTML file generated at: %s", htmlPath)
}

// generateJSONReport 生成JSON报告
func (g *Generator) generateJSONReport(scanResult *models.ScanResult, config models.ReportConfig) error {
	// 序列化扫描结果
	data, err := json.MarshalIndent(scanResult, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal scan result: %w", err)
	}

	// 写入文件
	if err := os.WriteFile(config.OutputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write JSON report: %w", err)
	}

	log.Info().Str("path", config.OutputPath).Msg("JSON report generated successfully")
	return nil
}

// generateCSVReport 生成CSV报告
func (g *Generator) generateCSVReport(scanResult *models.ScanResult, config models.ReportConfig) error {
	// 创建CSV文件
	file, err := os.Create(config.OutputPath)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()

	// 创建CSV写入器
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入标题行
	header := []string{"ID", "Name", "Type", "Severity", "Location", "Parameter", "Description", "Solution", "Timestamp"}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	// 写入漏洞数据
	for _, vuln := range scanResult.Vulnerabilities {
		record := []string{
			vuln.ID,
			vuln.Name,
			vuln.Type,
			vuln.Severity,
			vuln.Location,
			vuln.Parameter,
			vuln.Description,
			vuln.Solution,
			vuln.Timestamp,
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("failed to write CSV record: %w", err)
		}
	}

	log.Info().Str("path", config.OutputPath).Msg("CSV report generated successfully")
	return nil
}

// generateMarkdownReport 生成Markdown报告
func (g *Generator) generateMarkdownReport(scanResult *models.ScanResult, config models.ReportConfig) error {
	// 准备模板数据
	data := g.prepareTemplateData(scanResult, config)

	// 获取模板
	tmpl, ok := g.templates["markdown"]
	if !ok {
		return fmt.Errorf("Markdown template not found")
	}

	// 执行模板
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to execute Markdown template: %w", err)
	}

	// 写入文件
	if err := os.WriteFile(config.OutputPath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write Markdown report: %w", err)
	}

	log.Info().Str("path", config.OutputPath).Msg("Markdown report generated successfully")
	return nil
}

// generateLLMReport 使用LLM生成报告
func (g *Generator) generateLLMReport(scanResult *models.ScanResult, config models.ReportConfig) error {
	if g.llmClient == nil {
		return fmt.Errorf("LLM client not available")
	}

	// 使用LLM生成报告内容
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
	defer cancel()

	reportContent, err := g.llmClient.GenerateReport(ctx, scanResult, config.Format)
	if err != nil {
		return fmt.Errorf("failed to generate report with LLM: %w", err)
	}

	// 写入文件
	if err := os.WriteFile(config.OutputPath, []byte(reportContent), 0644); err != nil {
		return fmt.Errorf("failed to write LLM report: %w", err)
	}

	log.Info().Str("path", config.OutputPath).Msg("LLM report generated successfully")
	return nil
}

// prepareTemplateData 准备模板数据
func (g *Generator) prepareTemplateData(scanResult *models.ScanResult, config models.ReportConfig) map[string]interface{} {
	// 按严重程度排序漏洞
	sortedVulns := make([]models.Vulnerability, len(scanResult.Vulnerabilities))
	copy(sortedVulns, scanResult.Vulnerabilities)

	sort.Slice(sortedVulns, func(i, j int) bool {
		severityOrder := map[string]int{"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
		return severityOrder[sortedVulns[i].Severity] > severityOrder[sortedVulns[j].Severity]
	})

	// 按严重程度分组漏洞
	vulnsBySeverity := make(map[string][]models.Vulnerability)
	for _, vuln := range sortedVulns {
		vulnsBySeverity[vuln.Severity] = append(vulnsBySeverity[vuln.Severity], vuln)
	}

	// 按类型分组漏洞
	vulnsByType := make(map[string][]models.Vulnerability)
	for _, vuln := range sortedVulns {
		vulnsByType[vuln.Type] = append(vulnsByType[vuln.Type], vuln)
	}

	// 计算统计信息
	stats := struct {
		Total          int
		Critical       int
		High           int
		Medium         int
		Low            int
		Info           int
		Types          map[string]int
		TopVulnerable  []models.Vulnerability
	}{
		Types: make(map[string]int),
	}

	for _, vuln := range scanResult.Vulnerabilities {
		stats.Total++
		switch vuln.Severity {
		case "Critical":
			stats.Critical++
		case "High":
			stats.High++
		case "Medium":
			stats.Medium++
		case "Low":
			stats.Low++
		case "Info":
			stats.Info++
		}
		stats.Types[vuln.Type]++
	}

	// 获取前5个最严重的漏洞
	if len(sortedVulns) > 5 {
		stats.TopVulnerable = sortedVulns[:5]
	} else {
		stats.TopVulnerable = sortedVulns
	}

	// 准备模板数据
	data := map[string]interface{}{
		"Report": map[string]interface{}{
			"Title":       config.Title,
			"Description": config.Description,
			"Format":      config.Format,
			"GeneratedAt": time.Now().Format(time.RFC3339),
		},
		"ScanResult":      scanResult,
		"Vulnerabilities": sortedVulns,
		"VulnsBySeverity": vulnsBySeverity,
		"VulnsByType":     vulnsByType,
		"Stats":           stats,
	}

	return data
}

// loadBuiltInTemplates 加载内置模板
func (g *Generator) loadBuiltInTemplates() error {
	// HTML模板
	htmlTemplate := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Report.Title}}</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .header h1 {
            margin: 0;
            font-size: 28px;
        }
        .header p {
            margin: 5px 0 0 0;
            font-size: 16px;
            opacity: 0.8;
        }
        .summary {
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .summary h2 {
            margin-top: 0;
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        .stats {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            margin-bottom: 20px;
        }
        .stat-card {
            flex: 1;
            min-width: 150px;
            background-color: white;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-card h3 {
            margin: 0 0 10px 0;
            font-size: 32px;
        }
        .stat-card p {
            margin: 0;
            color: #7f8c8d;
        }
        .critical { color: #e74c3c; }
        .high { color: #e67e22; }
        .medium { color: #f1c40f; }
        .low { color: #3498db; }
        .info { color: #2ecc71; }
        .vulnerabilities {
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .vulnerabilities h2 {
            margin-top: 0;
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        .vulnerability {
            border-bottom: 1px solid #ecf0f1;
            padding: 15px 0;
        }
        .vulnerability:last-child {
            border-bottom: none;
        }
        .vulnerability h3 {
            margin: 0 0 5px 0;
            color: #2c3e50;
        }
        .vulnerability .meta {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-bottom: 10px;
        }
        .vulnerability .meta span {
            background-color: #ecf0f1;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 12px;
        }
        .vulnerability .description {
            margin-bottom: 10px;
        }
        .vulnerability .solution {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 3px;
            border-left: 3px solid #3498db;
        }
        .footer {
            text-align: center;
            margin-top: 20px;
            padding: 10px;
            color: #7f8c8d;
            font-size: 14px;
        }
        .severity-badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            color: white;
            font-weight: bold;
            font-size: 12px;
        }
        .severity-critical { background-color: #e74c3c; }
        .severity-high { background-color: #e67e22; }
        .severity-medium { background-color: #f1c40f; color: #333; }
        .severity-low { background-color: #3498db; }
        .severity-info { background-color: #2ecc71; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{.Report.Title}}</h1>
        <p>{{.Report.Description}}</p>
        <p>Generated on {{.Report.GeneratedAt}}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>This report summarizes the security vulnerabilities found during the scan of <strong>{{.ScanResult.Target}}</strong> performed on {{.ScanResult.StartTime}}.</p>
        
        <div class="stats">
            <div class="stat-card">
                <h3>{{.Stats.Total}}</h3>
                <p>Total Vulnerabilities</p>
            </div>
            <div class="stat-card">
                <h3 class="critical">{{.Stats.Critical}}</h3>
                <p>Critical</p>
            </div>
            <div class="stat-card">
                <h3 class="high">{{.Stats.High}}</h3>
                <p>High</p>
            </div>
            <div class="stat-card">
                <h3 class="medium">{{.Stats.Medium}}</h3>
                <p>Medium</p>
            </div>
            <div class="stat-card">
                <h3 class="low">{{.Stats.Low}}</h3>
                <p>Low</p>
            </div>
        </div>
    </div>
    
    <div class="vulnerabilities">
        <h2>Vulnerability Details</h2>
        
        {{range .Vulnerabilities}}
        <div class="vulnerability">
            <h3>{{.Name}}</h3>
            <div class="meta">
                <span class="severity-badge severity-{{.Severity | toLower}}">{{.Severity}}</span>
                <span>{{.Type}}</span>
                <span>{{.Location}}</span>
                <span>{{.Timestamp}}</span>
            </div>
            <div class="description">
                <p>{{.Description}}</p>
            </div>
            <div class="solution">
                <strong>Remediation:</strong> {{.Solution}}
            </div>
        </div>
        {{end}}
    </div>
    
    <div class="footer">
        <p>Generated by AutoVulnScan</p>
    </div>
</body>
</html>`

	// 解析HTML模板
	tmpl, err := template.New("html").Funcs(template.FuncMap{
		"toLower": strings.ToLower,
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse HTML template: %w", err)
	}
	g.templates["html"] = tmpl

	// Markdown模板
	markdownTemplate := `# {{.Report.Title}}

{{.Report.Description}}

**Generated on:** {{.Report.GeneratedAt}}  
**Target:** {{.ScanResult.Target}}  
**Scan Duration:** {{.ScanResult.Duration}}

## Executive Summary

This report summarizes the security vulnerabilities found during the scan of **{{.ScanResult.Target}}** performed on {{.ScanResult.StartTime}}.

### Vulnerability Summary

| Severity | Count |
|----------|-------|
| Critical | {{.Stats.Critical}} |
| High     | {{.Stats.High}} |
| Medium   | {{.Stats.Medium}} |
| Low      | {{.Stats.Low}} |
| Info     | {{.Stats.Info}} |
| **Total** | **{{.Stats.Total}}** |

## Vulnerability Details

{{range .Vulnerabilities}}
### {{.Name}}

- **Severity:** {{.Severity}}
- **Type:** {{.Type}}
- **Location:** {{.Location}}
- **Parameter:** {{.Parameter}}
- **Discovered:** {{.Timestamp}}

#### Description

{{.Description}}

#### Evidence

\\`\\`\\`
{{.Evidence}}
\\`\\`\\`

#### Remediation

{{.Solution}}

---
{{end}}

## Recommendations

1. **Critical vulnerabilities should be addressed immediately** as they pose the highest risk to your application.
2. **High severity vulnerabilities** should be prioritized in your next development cycle.
3. **Medium and Low severity vulnerabilities** should be addressed as part of your regular security maintenance.
4. **Implement a secure development lifecycle** to prevent introducing new vulnerabilities.
5. **Consider regular security scans** to continuously monitor your application for new vulnerabilities.

---

*Generated by AutoVulnScan*
`

	// 解析Markdown模板
	tmpl, err = template.New("markdown").Parse(markdownTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse Markdown template: %w", err)
	}
	g.templates["markdown"] = tmpl

	return nil
}