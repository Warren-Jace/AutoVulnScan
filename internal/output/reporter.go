// Package output 处理扫描结果的报告生成和日志记录
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
	utf8BOM = "\xEF\xBB\xBF"
	fileMode = 0644
	dirMode  = 0755
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

// Reporter 处理各种格式的扫描结果输出
type Reporter struct {
	mu                    sync.RWMutex              // 读写互斥锁，提高并发性能
	wg                    sync.WaitGroup            // 等待组，用于等待所有goroutine完成
	spiderFile            *bufio.Writer             // 使用缓冲写入提高性能
	unscopedSpiderFile    *bufio.Writer             
	spiderDeDuplicateFile *bufio.Writer             
	spiderParamsFile      *bufio.Writer             
	vulnFile              *bufio.Writer             
	
	// 文件句柄，用于关闭和同步
	spiderFileHandle            *os.File
	unscopedSpiderFileHandle    *os.File
	spiderDeDuplicateFileHandle *os.File
	spiderParamsFileHandle      *os.File
	vulnFileHandle              *os.File
	
	vulnerabilities       []*vulnscan.Vulnerability // 存储所有发现的漏洞
	vulnCounts            map[string]int            // 各类型漏洞的计数
	reportedVulns         map[string]struct{}       // 使用空结构体节省内存
	config                config.ReportingConfig    // 报告配置
	startTime             time.Time                 // 扫描开始时间
	
	// 性能优化：预分配缓冲区
	textBuffer            *bytes.Buffer
	jsonBuffer            *bytes.Buffer
}

// fileManager 文件管理器，简化文件操作
type fileManager struct {
	path   string
	handle *os.File
	writer *bufio.Writer
}

// NewReporter 创建一个新的Reporter实例
func NewReporter(cfg config.ReportingConfig) (*Reporter, error) {
	// 创建输出目录，如果不存在的话
	if err := os.MkdirAll(cfg.Path, dirMode); err != nil {
		return nil, fmt.Errorf("failed to create report directory: %w", err)
	}

	// 文件配置
	fileConfigs := []struct {
		name     string
		manager  **fileManager
		writer   **bufio.Writer
		handle   **os.File
	}{
		{cfg.SpiderFile, nil, nil, nil},
		{cfg.UnscopedSpiderFile, nil, nil, nil},
		{cfg.SpiderDeDuplicateFile, nil, nil, nil},
		{cfg.SpiderParamsFile, nil, nil, nil},
		{cfg.VulnReportFile, nil, nil, nil},
	}

	var fileHandles []*os.File
	var writers []*bufio.Writer

	// 创建所有文件
	for _, fc := range fileConfigs {
		handle, writer, err := createBufferedFile(filepath.Join(cfg.Path, fc.name))
		if err != nil {
			// 清理已创建的文件
			for _, h := range fileHandles {
				h.Close()
			}
			return nil, fmt.Errorf("failed to create file %s: %w", fc.name, err)
		}
		fileHandles = append(fileHandles, handle)
		writers = append(writers, writer)
	}

	return &Reporter{
		spiderFile:            writers[0],
		unscopedSpiderFile:    writers[1],
		spiderDeDuplicateFile: writers[2],
		spiderParamsFile:      writers[3],
		vulnFile:              writers[4],
		
		spiderFileHandle:            fileHandles[0],
		unscopedSpiderFileHandle:    fileHandles[1],
		spiderDeDuplicateFileHandle: fileHandles[2],
		spiderParamsFileHandle:      fileHandles[3],
		vulnFileHandle:              fileHandles[4],
		
		vulnerabilities:       make([]*vulnscan.Vulnerability, 0, 100), // 预分配容量
		vulnCounts:            make(map[string]int),
		reportedVulns:         make(map[string]struct{}),
		startTime:             time.Now(),
		config:                cfg,
		textBuffer:            bytes.NewBuffer(make([]byte, 0, bufferSize)),
		jsonBuffer:            bytes.NewBuffer(make([]byte, 0, bufferSize)),
	}, nil
}

// createBufferedFile 创建带缓冲的文件
func createBufferedFile(filePath string) (*os.File, *bufio.Writer, error) {
	// 检查文件是否存在以及文件大小
	fileInfo, err := os.Stat(filePath)
	fileExists := err == nil
	isEmpty := fileExists && fileInfo.Size() == 0

	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, fileMode)
	if err != nil {
		return nil, nil, err
	}

	writer := bufio.NewWriterSize(file, bufferSize)

	// 只有当文件不存在或为空时才写入 BOM 头
	if !fileExists || isEmpty {
		if _, err := writer.WriteString(utf8BOM); err != nil {
			file.Close()
			return nil, nil, err
		}
	}

	return file, writer, nil
}

// Close 关闭所有报告文件并生成最终的汇总报告
func (r *Reporter) Close() {
	// 等待所有goroutine完成
	r.wg.Wait()

	r.mu.Lock()
	defer r.mu.Unlock()

	// 刷新并关闭所有缓冲写入器
	writers := []*bufio.Writer{
		r.spiderFile,
		r.unscopedSpiderFile,
		r.spiderDeDuplicateFile,
		r.spiderParamsFile,
	}

	handles := []*os.File{
		r.spiderFileHandle,
		r.unscopedSpiderFileHandle,
		r.spiderDeDuplicateFileHandle,
		r.spiderParamsFileHandle,
	}

	// 刷新缓冲区并关闭文件
	for i, writer := range writers {
		if err := writer.Flush(); err != nil {
			log.Warn().Err(err).Msg("Failed to flush writer")
		}
		handles[i].Close()
	}

	// 写入文本格式的漏洞汇总（同步写入）
	r.writeTextSummary()

	// 刷新并关闭漏洞文件
	if err := r.vulnFile.Flush(); err != nil {
		log.Warn().Err(err).Msg("Failed to flush vulnerability file")
	}
	r.vulnFileHandle.Close()

	// 并发生成报告
	var reportWg sync.WaitGroup
	reportWg.Add(2)

	go func() {
		defer reportWg.Done()
		if err := r.generateJSONReport(); err != nil {
			log.Error().Err(err).Msg("Failed to generate JSON report")
		}
	}()

	go func() {
		defer reportWg.Done()
		if err := r.generateHTMLReport(); err != nil {
			log.Error().Err(err).Msg("Failed to generate HTML report")
		}
	}()

	reportWg.Wait()
}

// writeTextSummary 写入文本格式的漏洞汇总信息
func (r *Reporter) writeTextSummary() {
	if len(r.vulnerabilities) == 0 {
		return
	}

	r.textBuffer.Reset()
	r.textBuffer.WriteString("Vulnerability Summary:\n\n")
	r.textBuffer.WriteString("--------------------------------------------------\n\n")

	// 使用更高效的字符串构建
	for i, vuln := range r.vulnerabilities {
		vulnerableURL := vuln.VulnerableURL
		if vuln.Method == "POST" {
			vulnerableURL = fmt.Sprintf("%s [POST params] %s=%s", vuln.URL, vuln.Param, vuln.Payload)
		}

		fmt.Fprintf(r.textBuffer, "序号:           %d\n", i+1)
		fmt.Fprintf(r.textBuffer, "检测时间:       %s\n", vuln.Timestamp.Format(time.RFC3339))
		fmt.Fprintf(r.textBuffer, "漏洞名称:       %s\n", vuln.Type)
		fmt.Fprintf(r.textBuffer, "url地址:        %s\n", vuln.URL)
		fmt.Fprintf(r.textBuffer, "Payload:        %s\n", vuln.Payload)
		fmt.Fprintf(r.textBuffer, "请求方式:       %s\n", vuln.Method)
		fmt.Fprintf(r.textBuffer, "漏洞参数:       %s\n", vuln.Param)
		fmt.Fprintf(r.textBuffer, "漏洞地址:       %s\n\n", vulnerableURL)
	}

	// 添加漏洞类型统计信息
	r.textBuffer.WriteString("Vulnerability Summary:\n")
	for name, count := range r.vulnCounts {
		fmt.Fprintf(r.textBuffer, "- %s: %d\n", name, count)
	}
	r.textBuffer.WriteString("\n--------------------------------------------------\n")

	// 写入文件
	if _, err := r.vulnFile.WriteString(r.textBuffer.String()); err != nil {
		log.Warn().Err(err).Msg("Failed to write vulnerability summary")
	}
}

// LogURL 记录爬取到的URL
func (r *Reporter) LogURL(url string) {
	r.logToFile(r.spiderFile, url)
}

// LogUnscopedURL 记录未在范围内的URL
func (r *Reporter) LogUnscopedURL(url string) {
	r.logToFile(r.unscopedSpiderFile, url)
}

// LogDeDuplicateURL 记录去重后的URL
func (r *Reporter) LogDeDuplicateURL(url string) {
	r.logToFile(r.spiderDeDuplicateFile, url)
}

// LogParamURL 记录带参数的URL
func (r *Reporter) LogParamURL(req *models.Request) {
	r.logToFile(r.spiderParamsFile, req.URLWithParams())
}

// LogVulnerability 记录发现的漏洞，检查重复后再记录
func (r *Reporter) LogVulnerability(vuln *vulnscan.Vulnerability) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// 生成漏洞签名用于去重
	signature := r.getVulnerabilitySignature(vuln)
	if _, exists := r.reportedVulns[signature]; exists {
		log.Debug().Str("signature", signature).Msg("Duplicate vulnerability found, skipping.")
		return
	}

	// 添加到漏洞列表
	r.vulnerabilities = append(r.vulnerabilities, vuln)
	r.vulnCounts[vuln.Type]++
	r.reportedVulns[signature] = struct{}{}

	// 记录日志
	log.Info().
		Str("param", vuln.Param).
		Str("type", vuln.Type).
		Str("url", vuln.URL).
		Msg("Vulnerability Found!")
}

// getVulnerabilitySignature 生成漏洞的唯一签名，用于去重
func (r *Reporter) getVulnerabilitySignature(vuln *vulnscan.Vulnerability) string {
	// 使用更高效的字符串拼接
	var builder strings.Builder
	builder.Grow(len(vuln.Type) + len(vuln.URL) + len(vuln.Param) + len(vuln.Method) + 3)
	builder.WriteString(vuln.Type)
	builder.WriteByte('|')
	builder.WriteString(vuln.URL)
	builder.WriteByte('|')
	builder.WriteString(vuln.Param)
	builder.WriteByte('|')
	builder.WriteString(vuln.Method)
	return builder.String()
}

// generateJSONReport 生成JSON格式的扫描报告
func (r *Reporter) generateJSONReport() error {
	r.mu.RLock()
	report := r.createFinalReport()
	r.mu.RUnlock()

	r.jsonBuffer.Reset()
	encoder := json.NewEncoder(r.jsonBuffer)
	encoder.SetIndent("", "  ")
	
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("failed to encode json report: %w", err)
	}

	// 写入文件
	return os.WriteFile(filepath.Join(r.config.Path, "report.json"), r.jsonBuffer.Bytes(), fileMode)
}

// generateHTMLReport 生成HTML格式的扫描报告
func (r *Reporter) generateHTMLReport() error {
	r.mu.RLock()
	report := r.createFinalReport()
	r.mu.RUnlock()

	// 创建模板函数
	funcMap := template.FuncMap{
		"lower": strings.ToLower,
	}

	// 解析模板
	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse HTML template: %w", err)
	}

	// 创建HTML文件
	file, err := os.Create(filepath.Join(r.config.Path, "report.html"))
	if err != nil {
		return fmt.Errorf("failed to create HTML file: %w", err)
	}
	defer file.Close()

	// 使用缓冲写入器提高性能
	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// 执行模板并写入文件
	return tmpl.Execute(writer, report)
}

// createFinalReport 创建最终报告数据结构
func (r *Reporter) createFinalReport() Report {
	return Report{
		StartTime:            r.startTime,
		EndTime:              time.Now(),
		Duration:             time.Since(r.startTime).String(),
		Target:               r.config.Path, // 这里应该是目标URL
		VulnerabilitiesFound: len(r.vulnerabilities),
		Vulnerabilities:      r.vulnerabilities,
	}
}

// logToFile 异步写入数据到指定文件
func (r *Reporter) logToFile(writer *bufio.Writer, data string) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		
		r.mu.RLock()
		defer r.mu.RUnlock()
		
		if _, err := writer.WriteString(data + "\n"); err != nil {
			log.Warn().Err(err).Msg("Failed to write to log file")
		}
	}()
}

// Report 扫描报告的数据结构
type Report struct {
	StartTime            time.Time                 `json:"start_time"`            // 扫描开始时间
	EndTime              time.Time                 `json:"end_time"`              // 扫描结束时间
	Duration             string                    `json:"duration"`              // 扫描持续时间
	Target               string                    `json:"target"`                // 扫描目标
	VulnerabilitiesFound int                       `json:"vulnerabilities_found"` // 发现的漏洞数量
	Vulnerabilities      []*vulnscan.Vulnerability `json:"vulnerabilities"`       // 漏洞详细信息列表
}

// ScanSummary 扫描汇总信息的数据结构
type ScanSummary struct {
	ScanStartTime        time.Time `json:"scan_start_time"`       // 扫描开始时间
	ScanEndTime          time.Time `json:"scan_end_time"`         // 扫描结束时间
	TotalDuration        string    `json:"total_duration"`        // 总持续时间
	VulnerabilitiesFound int       `json:"vulnerabilities_found"` // 发现的漏洞数量
}

// SanitizeFilename 从URL创建有效的文件名
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
