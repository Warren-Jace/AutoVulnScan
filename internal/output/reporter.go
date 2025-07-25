// Package output 处理扫描结果的报告生成和日志记录。
// 它负责将爬虫发现的URL、识别出的参数和检测到的漏洞以多种格式（如TXT, JSON, HTML）保存到文件中。
package output

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"text/template"
	"time"

	"autovulnscan/internal/config"
	"autovulnscan/internal/models"
	"autovulnscan/internal/vulnscan"

	"github.com/rs/zerolog/log"
)

// 预定义常量
const (
	utf8BOM    = "\xEF\xBB\xBF"
	fileMode   = 0644
	dirMode    = 0755
	bufferSize = 4096
)

// HTML模板常量
const htmlTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>AutoVulnScan Report</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 20px; 
            background-color: #f5f5f5; 
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white; 
            padding: 20px; 
            border-radius: 8px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1); 
        }
        h1 { color: #333; border-bottom: 3px solid #007acc; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .summary { 
            background: #f8f9fa; 
            padding: 15px; 
            border-radius: 5px; 
            margin: 20px 0; 
        }
        table { 
            border-collapse: collapse; 
            width: 100%; 
            margin-top: 20px; 
        }
        th, td { 
            border: 1px solid #ddd; 
            padding: 12px; 
            text-align: left; 
        }
        th { 
            background-color: #007acc; 
            color: white; 
            font-weight: bold; 
        }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f5f5f5; }
        .vuln-type { 
            padding: 4px 8px; 
            border-radius: 4px; 
            font-weight: bold; 
            color: white; 
            background-color: #dc3545; 
        }
        .method-get { color: #28a745; font-weight: bold; }
        .method-post { color: #dc3545; font-weight: bold; }
        .no-vulns { 
            text-align: center; 
            color: #28a745; 
            font-size: 18px; 
            padding: 40px; 
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 AutoVulnScan Security Report</h1>
        
        <div class="summary">
            <p><strong>📅 Start Time:</strong> {{.StartTime.Format "2006-01-02 15:04:05"}}</p>
            <p><strong>🏁 End Time:</strong> {{.EndTime.Format "2006-01-02 15:04:05"}}</p>
            <p><strong>⏱️ Duration:</strong> {{.Duration}}</p>
            <p><strong>🎯 Target:</strong> {{.Target}}</p>
            <p><strong>🚨 Vulnerabilities Found:</strong> <span style="color: {{if gt .VulnerabilitiesFound 0}}#dc3545{{else}}#28a745{{end}}; font-weight: bold;">{{.VulnerabilitiesFound}}</span></p>
        </div>

        <h2>🔓 Vulnerability Details</h2>
        {{if eq .VulnerabilitiesFound 0}}
            <div class="no-vulns">
                ✅ No vulnerabilities found. Your application appears to be secure!
            </div>
        {{else}}
            <table>
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>URL</th>
                        <th>Method</th>
                        <th>Parameter</th>
                        <th>Payload</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Vulnerabilities}}
                    <tr>
                        <td><span class="vuln-type">{{.Type}}</span></td>
                        <td style="word-break: break-all;">{{.URL}}</td>
                        <td class="method-{{.Method | lower}}">{{.Method}}</td>
                        <td>{{.Param}}</td>
                        <td style="word-break: break-all; font-family: monospace;">{{.Payload}}</td>
                        <td>{{.Timestamp.Format "15:04:05"}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        {{end}}
    </div>
</body>
</html>`

// Reporter 处理各种格式的扫描结果输出。
// 它管理多个文件句柄，并使用缓冲写入和并发处理来提高性能。
type Reporter struct {
	mu                    sync.RWMutex
	wg                    sync.WaitGroup
	spiderFile            *bufio.Writer
	unscopedSpiderFile    *bufio.Writer             
	spiderDeDuplicateFile *bufio.Writer             
	spiderParamsFile      *bufio.Writer             
	vulnFile              *bufio.Writer             
	
	// 文件句柄
	spiderFileHandle            *os.File
	unscopedSpiderFileHandle    *os.File
	spiderDeDuplicateFileHandle *os.File
	spiderParamsFileHandle      *os.File
	vulnFileHandle              *os.File
	
	vulnerabilities []*vulnscan.Vulnerability
	vulnCounts      map[string]int
	reportedVulns   map[string]struct{}
	config          config.ReportingConfig
	startTime       time.Time
	targetURL       string

	textBuffer *bytes.Buffer
	jsonBuffer *bytes.Buffer
}

// NewReporter 创建一个新的Reporter实例。
// 它会创建配置中指定的输出目录和所有报告文件。
func NewReporter(cfg config.ReportingConfig, targetURL string) (*Reporter, error) {
	if err := os.MkdirAll(cfg.Path, dirMode); err != nil {
		return nil, fmt.Errorf("failed to create report directory: %w", err)
	}

	r := &Reporter{
		vulnerabilities: make([]*vulnscan.Vulnerability, 0, 100),
		vulnCounts:      make(map[string]int),
		reportedVulns:   make(map[string]struct{}),
		startTime:       time.Now(),
		config:          cfg,
		targetURL:       targetURL,
		textBuffer:      bytes.NewBuffer(make([]byte, 0, bufferSize)),
		jsonBuffer:      bytes.NewBuffer(make([]byte, 0, bufferSize)),
	}

	var err error
	r.spiderFileHandle, r.spiderFile, err = createBufferedFile(filepath.Join(cfg.Path, cfg.SpiderFile))
		if err != nil {
			return nil, err
		}
	r.unscopedSpiderFileHandle, r.unscopedSpiderFile, err = createBufferedFile(filepath.Join(cfg.Path, cfg.UnscopedSpiderFile))
	if err != nil {
		return nil, err
	}
	r.spiderDeDuplicateFileHandle, r.spiderDeDuplicateFile, err = createBufferedFile(filepath.Join(cfg.Path, cfg.SpiderDeDuplicateFile))
	if err != nil {
		return nil, err
	}
	r.spiderParamsFileHandle, r.spiderParamsFile, err = createBufferedFile(filepath.Join(cfg.Path, cfg.SpiderParamsFile))
	if err != nil {
		return nil, err
	}
	r.vulnFileHandle, r.vulnFile, err = createBufferedFile(filepath.Join(cfg.Path, cfg.VulnReportFile))
	if err != nil {
		return nil, err
	}

	return r, nil
}

func createBufferedFile(filePath string) (*os.File, *bufio.Writer, error) {
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, fileMode)
	if err != nil {
		return nil, nil, err
	}
	return file, bufio.NewWriterSize(file, bufferSize), nil
}

// AddSpiderResult 添加一个由爬虫发现的URL到 'spider_results.txt'。
func (r *Reporter) AddSpiderResult(result models.Request) {
	r.logToFile(r.spiderFile, result.URL)
}

// AddUnscopedSpiderResult 添加一个超出扫描范围的URL到 'unscoped_spider_results.txt'。
func (r *Reporter) AddUnscopedSpiderResult(result models.Request) {
	r.logToFile(r.unscopedSpiderFile, result.URL)
}

// AddDeDuplicateSpiderResult 添加一个经过内容去重后的URL到 'spider_deduplicate_results.txt'。
func (r *Reporter) AddDeDuplicateSpiderResult(result string) {
	r.logToFile(r.spiderDeDuplicateFile, result)
}

// AddParamsResult 添加一个带有参数的URL到 'spider_params_results.txt'。
func (r *Reporter) AddParamsResult(result string) {
	r.logToFile(r.spiderParamsFile, result)
}

// AddVulnerability 记录一个新发现的漏洞。
// 此函数是线程安全的，并且会进行漏洞去重。
// 它会将详细的漏洞信息（包括请求和响应）异步写入 'vuln_report.txt'。
func (r *Reporter) AddVulnerability(v *vulnscan.Vulnerability) {
	r.mu.Lock()
	defer r.mu.Unlock()

	vulnSignature := fmt.Sprintf("%s|%s|%s|%s", v.Type, v.URL, v.Method, v.Param)
	if _, exists := r.reportedVulns[vulnSignature]; exists {
		return
	}

	r.vulnerabilities = append(r.vulnerabilities, v)
	r.reportedVulns[vulnSignature] = struct{}{}
	r.vulnCounts[v.Type]++

	vulnDetails := fmt.Sprintf(
		"漏洞类型: %s\nURL: %s\n方法: %s\n参数: %s\nPayload: %s\n发现时间: %s\n\n--- Request ---\n%s\n\n--- Response ---\n%s\n",
		v.Type, v.URL, v.Method, v.Param, v.Payload, v.Timestamp.Format(time.RFC3339), v.RequestDump, v.ResponseDump,
	)

	r.logToFile(r.vulnFile, vulnDetails+"\n"+strings.Repeat("-", 80))

	log.Warn().
		Str("type", v.Type).
		Str("url", v.URL).
		Str("param", v.Param).
		Msg("Vulnerability Found!")
}

// Close 等待所有异步文件写入完成，关闭所有文件句柄，并生成最终的JSON和HTML报告。
func (r *Reporter) Close() {
	r.wg.Wait() // 等待所有异步写入完成

	r.mu.Lock()
	defer r.mu.Unlock()

	// 刷新并关闭所有文件
	if r.spiderFile != nil {
		r.spiderFile.Flush()
		r.spiderFileHandle.Close()
	}
	if r.unscopedSpiderFile != nil {
		r.unscopedSpiderFile.Flush()
		r.unscopedSpiderFileHandle.Close()
	}
	if r.spiderDeDuplicateFile != nil {
		r.spiderDeDuplicateFile.Flush()
		r.spiderDeDuplicateFileHandle.Close()
	}
	if r.spiderParamsFile != nil {
		r.spiderParamsFile.Flush()
		r.spiderParamsFileHandle.Close()
	}
	if r.vulnFile != nil {
		r.vulnFile.Flush()
		r.vulnFileHandle.Close()
	}

	if err := r.generateFinalReports(); err != nil {
		log.Error().Err(err).Msg("Failed to generate final reports")
	}
}

// generateFinalReports 生成最终的报告文件（JSON和HTML）。
func (r *Reporter) generateFinalReports() error {
	report := r.createFinalReport()

	if err := r.generateJSONReport(report); err != nil {
		log.Error().Err(err).Msg("Failed to generate JSON report")
	}

	if err := r.generateHTMLReport(report); err != nil {
		log.Error().Err(err).Msg("Failed to generate HTML report")
	}
	return nil
}

// createFinalReport 创建用于生成报告的最终数据结构。
func (r *Reporter) createFinalReport() Report {
	endTime := time.Now()
	return Report{
		Target:               r.targetURL,
		StartTime:            r.startTime,
		EndTime:              endTime,
		Duration:             endTime.Sub(r.startTime).String(),
		VulnerabilitiesFound: len(r.vulnerabilities),
		Vulnerabilities:      r.vulnerabilities,
	}
}

// generateJSONReport 将报告数据序列化为JSON并写入文件。
func (r *Reporter) generateJSONReport(report Report) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal json report: %w", err)
	}
	reportPath := filepath.Join(r.config.Path, r.config.JSONReportFile)
	return os.WriteFile(reportPath, data, 0644)
}

// generateHTMLReport 使用模板生成HTML格式的报告。
func (r *Reporter) generateHTMLReport(report Report) error {
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse HTML template: %w", err)
	}

	reportPath := filepath.Join(r.config.Path, r.config.HTMLReportFile)
	file, err := os.Create(reportPath)
	if err != nil {
		return fmt.Errorf("failed to create HTML file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	return tmpl.Execute(writer, report)
}

// logToFile 异步地将一行数据写入指定的缓冲写入器。
func (r *Reporter) logToFile(writer *bufio.Writer, data string) {
	if writer == nil {
		return
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.mu.Lock()
		defer r.mu.Unlock()
		if _, err := writer.WriteString(data + "\n"); err != nil {
			log.Warn().Err(err).Msg("Failed to write to log file")
		}
	}()
}

// Report 定义了最终报告（JSON和HTML）的结构。
type Report struct {
	Target               string                    `json:"target"`
	StartTime            time.Time                 `json:"start_time"`
	EndTime              time.Time                 `json:"end_time"`
	Duration             string                    `json:"duration"`
	VulnerabilitiesFound int                       `json:"vulnerabilities_found"`
	Vulnerabilities      []*vulnscan.Vulnerability `json:"vulnerabilities"`
}

// ScanSummary 定义了扫描摘要的数据结构，当前未在代码中使用，但可用于未来的扩展。
// ScanSummary defines the data structure for a scan summary.
type ScanSummary struct {
	ScanStartTime        time.Time `json:"scan_start_time"`
	ScanEndTime          time.Time `json:"scan_end_time"`
	TotalDuration        string    `json:"total_duration"`
	VulnerabilitiesFound int       `json:"vulnerabilities_found"`
}

// SanitizeFilename 从给定的URL创建一个在文件系统中有效的文件名。
// 例如，它会替换 "://" 以避免路径问题。
// 这个函数当前未被使用，但可用于需要基于URL创建文件的场景。
// SanitizeFilename creates a valid filename from a given URL.
func SanitizeFilename(urlStr string) string {
	// 更安全的文件名清理
	replacer := strings.NewReplacer(
		"://", "_",
		"/", "_",
		"\\", "_",
		":", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
	)
	return replacer.Replace(urlStr) + ".log"
}
