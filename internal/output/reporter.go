// Package output 处理扫描结果的报告生成和日志记录
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"autovulnscan/internal/config"
	"autovulnscan/internal/models"
	"autovulnscan/internal/vulnscan"

	"github.com/rs/zerolog/log"
	"text/template"
)

// Reporter 处理各种格式的扫描结果输出
type Reporter struct {
	mu                    sync.Mutex                 // 互斥锁，保护并发访问
	wg                    sync.WaitGroup             // 等待组，用于等待所有goroutine完成
	spiderFile            *os.File                   // 爬虫URL文件句柄
	spiderDeDuplicateFile *os.File                   // 去重后的爬虫URL文件句柄
	spiderParamsFile      *os.File                   // 带参数的爬虫URL文件句柄
	vulnFile              *os.File                   // 漏洞报告文件句柄
	vulnerabilities       []*vulnscan.Vulnerability // 存储所有发现的漏洞
	vulnCounts            map[string]int             // 各类型漏洞的计数
	reportedVulns         map[string]bool            // 用于去重的已报告漏洞映射
	config                config.ReportingConfig    // 报告配置
	startTime             time.Time                  // 扫描开始时间
}

// NewReporter 创建一个新的Reporter实例
func NewReporter(outputDir string) (*Reporter, error) {
	// 创建输出目录，如果不存在的话
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create report directory: %w", err)
	}

	// 辅助函数：创建文件并写入UTF-8 BOM头
	createFileWithBOM := func(name string) (*os.File, error) {
		filePath := filepath.Join(outputDir, name)
		 // 检查文件是否存在以及文件大小
		 fileInfo, err := os.Stat(filePath)
		 fileExists := err == nil
		 isEmpty := fileExists && fileInfo.Size() == 0

		file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}

		// 只有当文件不存在或为空时才写入 BOM 头
        if !fileExists || isEmpty {
			// 写入UTF-8 BOM头（字节序标记）
            if _, err := file.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
                file.Close()
                return nil, err
            }
        }
		return file, nil
	}

	// 创建爬虫URL记录文件
	sf, err := createFileWithBOM("urls-spider.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to open spider file: %w", err)
	}

	// 创建去重后的爬虫URL记录文件
	sddf, err := createFileWithBOM("urls-spider_de-duplicate_all.txt")
	if err != nil {
		sf.Close()
		return nil, fmt.Errorf("failed to open spider de-duplicate file: %w", err)
	}

	// 创建带参数的爬虫URL记录文件
	spf, err := createFileWithBOM("urls-spider_params.txt")
	if err != nil {
		sf.Close()
		sddf.Close()
		return nil, fmt.Errorf("failed to open spider params file: %w", err)
	}

	// 创建漏洞报告文件
	vf, err := createFileWithBOM("urls-Vulns.txt")
	if err != nil {
		sf.Close()
		sddf.Close()
		spf.Close()
		return nil, fmt.Errorf("failed to open vulnerability report file: %w", err)
	}

	return &Reporter{
		spiderFile:            sf,
		spiderDeDuplicateFile: sddf,
		spiderParamsFile:      spf,
		vulnFile:              vf,
		vulnerabilities:       make([]*vulnscan.Vulnerability, 0),
		vulnCounts:            make(map[string]int),
		reportedVulns:         make(map[string]bool),
		startTime:             time.Now(),
		config:                config.ReportingConfig{Path: outputDir},
	}, nil
}

// Close 关闭所有报告文件并生成最终的汇总报告
func (r *Reporter) Close() {
	// 等待所有goroutine完成
	r.wg.Wait()

	r.mu.Lock()
	defer r.mu.Unlock()

	// 关闭其他文件句柄
	r.spiderFile.Close()
	r.spiderDeDuplicateFile.Close()
	r.spiderParamsFile.Close()

	// 写入文本格式的漏洞汇总（同步写入）
	r.writeTextSummary()
	
	// 关闭漏洞文件
	r.vulnFile.Close()

	// 生成JSON格式报告
	if err := r.generateJSONReport(); err != nil {
		log.Error().Err(err).Msg("Failed to generate JSON report")
	}
	// 生成HTML格式报告
	if err := r.generateHTMLReport(); err != nil {
		log.Error().Err(err).Msg("Failed to generate HTML report")
	}
}

// writeTextSummary 写入文本格式的漏洞汇总信息（修复为同步写入）
func (r *Reporter) writeTextSummary() {
	if len(r.vulnerabilities) == 0 {
		return
	}

	var builder strings.Builder
	builder.WriteString("Vulnerability Summary:\n\n")
	builder.WriteString("--------------------------------------------------\n\n")

	// 遍历所有漏洞，生成详细信息
	for i, vuln := range r.vulnerabilities {
		vulnerableURL := vuln.VulnerableURL
		// 如果是POST请求，格式化显示参数和载荷
		if vuln.Method == "POST" {
			vulnerableURL = fmt.Sprintf("%s [POST aams] %s=%s", vuln.URL, vuln.Param, vuln.Payload)
		}

		builder.WriteString(fmt.Sprintf("序号:           %d\n", i+1))
		builder.WriteString(fmt.Sprintf("检测时间:       %s\n", vuln.Timestamp.Format(time.RFC3339)))
		builder.WriteString(fmt.Sprintf("漏洞名称:       %s\n", vuln.Type))
		builder.WriteString(fmt.Sprintf("url地址:        %s\n", vuln.URL))
		builder.WriteString(fmt.Sprintf("Payload:        %s\n", vuln.Payload))
		builder.WriteString(fmt.Sprintf("请求方式:       %s\n", vuln.Method))
		builder.WriteString(fmt.Sprintf("漏洞参数:       %s\n", vuln.Param))
		builder.WriteString(fmt.Sprintf("漏洞地址:       %s\n\n", vulnerableURL))
	}

	// 添加漏洞类型统计信息
	builder.WriteString("Vulnerability Summary:\n")
	for name, count := range r.vulnCounts {
		builder.WriteString(fmt.Sprintf("- %s: %d\n", name, count))
	}
	builder.WriteString("\n--------------------------------------------------\n")

	// 同步写入，确保数据被写入
	if _, err := r.vulnFile.WriteString(builder.String()); err != nil {
		log.Warn().Err(err).Msg("Failed to write vulnerability summary")
	}
	
	// 强制刷新缓冲区，确保数据写入磁盘
	if err := r.vulnFile.Sync(); err != nil {
		log.Warn().Err(err).Msg("Failed to sync vulnerability file")
	}
}

// LogURL 记录爬取到的URL
func (r *Reporter) LogURL(url string) {
	r.logToFile(r.spiderFile, url)
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
	r.reportedVulns[signature] = true

	// 记录日志
	log.Info().
		Str("param", vuln.Param).
		Str("type", vuln.Type).
		Str("url", vuln.URL).
		Msg("Vulnerability Found!")
}

// getVulnerabilitySignature 生成漏洞的唯一签名，用于去重
func (r *Reporter) getVulnerabilitySignature(vuln *vulnscan.Vulnerability) string {
	return fmt.Sprintf("%s|%s|%s|%s", vuln.Type, vuln.URL, vuln.Param, vuln.Method)
}

// generateJSONReport 生成JSON格式的扫描报告
func (r *Reporter) generateJSONReport() error {
	report := Report{
		StartTime:            r.startTime,
		EndTime:              time.Now(),
		Duration:             time.Since(r.startTime).String(),
		Target:               r.config.Path, // 这里应该是目标URL
		VulnerabilitiesFound: len(r.vulnerabilities),
		Vulnerabilities:      r.vulnerabilities,
	}

	// 序列化为JSON格式
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal json report: %w", err)
	}

	// 写入文件
	return os.WriteFile(filepath.Join(r.config.Path, "report.json"), data, 0644)
}

// generateHTMLReport 生成HTML格式的扫描报告
func (r *Reporter) generateHTMLReport() error {
	report := r.createFinalReport()
	// HTML模板定义
	htmlTemplate := `
<!DOCTYPE html>
<html>
<head>
    <title>AutoVulnScan Report</title>
    <style>
        body { font-family: sans-serif; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>AutoVulnScan Report</h1>
    <p><strong>Start Time:</strong> {{.StartTime}}</p>
    <p><strong>End Time:</strong> {{.EndTime}}</p>
    <p><strong>Duration:</strong> {{.Duration}}</p>
    <p><strong>Target:</strong> {{.Target}}</p>
    <p><strong>Vulnerabilities Found:</strong> {{.VulnerabilitiesFound}}</p>
    <h2>Vulnerabilities</h2>
    <table>
        <tr>
            <th>Type</th>
            <th>URL</th>
            <th>Method</th>
            <th>Param</th>
            <th>Payload</th>
        </tr>
        {{range .Vulnerabilities}}
        <tr>
            <td>{{.Type}}</td>
            <td>{{.URL}}</td>
            <td>{{.Method}}</td>
            <td>{{.Param}}</td>
            <td>{{.Payload}}</td>
        </tr>
        {{end}}
    </table>
</body>
</html>`
	// 解析模板
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return err
	}

	// 创建HTML文件
	file, err := os.Create(filepath.Join(r.config.Path, "report.html"))
	if err != nil {
		return err
	}
	defer file.Close()
	// 执行模板并写入文件
	return tmpl.Execute(file, report)
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
func (r *Reporter) logToFile(file *os.File, data string) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		if _, err := file.WriteString(data + "\n"); err != nil {
			log.Warn().Err(err).Msg("Failed to write to log file")
		}
	}()
}

// Report 扫描报告的数据结构
type Report struct {
	StartTime            time.Time                  `json:"start_time"`            // 扫描开始时间
	EndTime              time.Time                  `json:"end_time"`              // 扫描结束时间
	Duration             string                     `json:"duration"`              // 扫描持续时间
	Target               string                     `json:"target"`                // 扫描目标
	VulnerabilitiesFound int                        `json:"vulnerabilities_found"` // 发现的漏洞数量
	Vulnerabilities      []*vulnscan.Vulnerability `json:"vulnerabilities"`       // 漏洞详细信息列表
}

// ScanSummary 扫描汇总信息的数据结构
type ScanSummary struct {
	ScanStartTime        time.Time `json:"scan_start_time"`        // 扫描开始时间
	ScanEndTime          time.Time `json:"scan_end_time"`          // 扫描结束时间
	TotalDuration        string    `json:"total_duration"`         // 总持续时间
	VulnerabilitiesFound int       `json:"vulnerabilities_found"`  // 发现的漏洞数量
}

// SanitizeFilename 从URL创建有效的文件名
func SanitizeFilename(urlStr string) string {
	// 这个函数在提供的代码中没有被使用，但它是new_code的一部分
	// 保持原样，但如果使用的话可能需要实际的实现
	return strings.ReplaceAll(urlStr, "://", "_") + ".log"
}
