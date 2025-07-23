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

	"text/template"

	"github.com/rs/zerolog/log"
)

// Reporter 负责处理和输出扫描结果。
// Reporter is responsible for handling and outputting scan results.
type Reporter struct {
	mu                    sync.Mutex                // mu 是一个互斥锁，用于保护对共享资源的并发访问。
	wg                    sync.WaitGroup            // wg 是一个等待组，用于等待所有异步日志写入操作完成。
	spiderFile            *os.File                  // spiderFile 是记录所有爬取到的有效URL的文件。
	unscopedSpiderFile    *os.File                  // unscopedSpiderFile 是记录所有超出扫描范围的URL的文件。
	spiderDeDuplicateFile *os.File                  // spiderDeDuplicateFile 是记录去重后的URL的文件。
	spiderParamsFile      *os.File                  // spiderParamsFile 是记录所有带有参数的URL的文件。
	vulnFile              *os.File                  // vulnFile 是记录详细漏洞信息的文本文件。
	vulnerabilities       []*vulnscan.Vulnerability // vulnerabilities 是一个切片，存储所有发现的漏洞。
	vulnCounts            map[string]int            // vulnCounts 统计每种类型漏洞的数量。
	reportedVulns         map[string]bool           // reportedVulns 用于存储已报告漏洞的签名，以实现去重。
	config                config.ReportingConfig    // config 存储报告相关的配置。
	startTime             time.Time                 // startTime 记录了扫描任务的开始时间。
	targetURL             string                    // targetURL 是本次扫描的目标URL。
}

// NewReporter 创建并初始化一个新的 Reporter 实例。
// 它会根据配置创建输出目录和所有必要的日志文件。
// NewReporter creates and initializes a new Reporter instance.
func NewReporter(cfg config.ReportingConfig, targetURL string) (*Reporter, error) {
	// 如果输出目录不存在，则创建它。
	if err := os.MkdirAll(cfg.Path, 0755); err != nil {
		return nil, fmt.Errorf("创建报告目录失败 (failed to create report directory): %w", err)
	}

	// createFileWithBOM 是一个辅助函数，用于创建文件并写入UTF-8 BOM头。
	// 这有助于确保文件在各种文本编辑器中（尤其是Windows上）正确显示中文字符。
	createFileWithBOM := func(name string) (*os.File, error) {
		filePath := filepath.Join(cfg.Path, name)
		file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}

		// 检查文件是否为空，如果为空，则写入BOM。
		stat, err := file.Stat()
		if err != nil {
			file.Close()
			return nil, err
		}
		if stat.Size() == 0 {
			// 写入UTF-8 BOM (EF BB BF)。
			if _, err := file.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
				file.Close()
				return nil, err
			}
		}
		return file, nil
	}

	// 依次创建所有报告文件。
	spiderFile, err := createFileWithBOM(cfg.SpiderFile)
	if err != nil {
		return nil, fmt.Errorf("打开爬虫URL文件失败 (failed to open spider file): %w", err)
	}

	usf, err := createFileWithBOM(cfg.UnscopedSpiderFile)
	if err != nil {
		spiderFile.Close()
		return nil, fmt.Errorf("打开范围外URL文件失败 (failed to open unscoped spider file): %w", err)
	}

	sddf, err := createFileWithBOM(cfg.SpiderDeDuplicateFile)
	if err != nil {
		spiderFile.Close()
		usf.Close()
		return nil, fmt.Errorf("打开去重URL文件失败 (failed to open spider de-duplicate file): %w", err)
	}

	spf, err := createFileWithBOM(cfg.SpiderParamsFile)
	if err != nil {
		spiderFile.Close()
		usf.Close()
		sddf.Close()
		return nil, fmt.Errorf("打开带参数URL文件失败 (failed to open spider params file): %w", err)
	}

	vf, err := createFileWithBOM(cfg.VulnReportFile)
	if err != nil {
		spiderFile.Close()
		usf.Close()
		sddf.Close()
		spf.Close()
		return nil, fmt.Errorf("打开漏洞报告文件失败 (failed to open vulnerability report file): %w", err)
	}

	// 返回初始化完成的 Reporter 实例。
	return &Reporter{
		mu:                    sync.Mutex{},
		wg:                    sync.WaitGroup{},
		spiderFile:            spiderFile,
		unscopedSpiderFile:    usf,
		spiderDeDuplicateFile: sddf,
		spiderParamsFile:      spf,
		vulnFile:              vf,
		vulnerabilities:       make([]*vulnscan.Vulnerability, 0),
		vulnCounts:            make(map[string]int),
		reportedVulns:         make(map[string]bool),
		startTime:             time.Now(),
		config:                cfg,
		targetURL:             targetURL, // 保存目标URL
	}, nil
}

// Close 等待所有异步任务完成，关闭所有文件句柄，并生成最终的报告。
// Close waits for all async tasks to complete, closes all file handles, and generates final reports.
func (r *Reporter) Close() {
	// 等待所有异步文件写入完成。
	r.wg.Wait()

	r.mu.Lock()
	defer r.mu.Unlock()

	// 确保所有文件句柄都被安全关闭。
	if r.spiderFile != nil {
		r.spiderFile.Close()
	}
	if r.unscopedSpiderFile != nil {
		r.unscopedSpiderFile.Close()
	}
	if r.spiderDeDuplicateFile != nil {
		r.spiderDeDuplicateFile.Close()
	}
	if r.spiderParamsFile != nil {
		r.spiderParamsFile.Close()
	}

	// 在关闭漏洞文件之前，写入文本格式的漏洞摘要。
	if r.vulnFile != nil {
		r.writeTextSummary()
		r.vulnFile.Close()
	}

	// 生成JSON和HTML格式的最终报告。
	if err := r.generateFinalReports(); err != nil {
		log.Error().Err(err).Msg("生成最终报告失败 (Failed to generate final reports)")
	}
}

// writeTextSummary 将详细的漏洞信息和统计摘要写入文本文件。
// 这是一个同步操作，以确保在程序退出前所有数据都被写入。
// writeTextSummary writes detailed vulnerability information and a statistical summary to a text file.
func (r *Reporter) writeTextSummary() {
	if len(r.vulnerabilities) == 0 {
		return // 如果没有发现漏洞，则不执行任何操作。
	}

	var builder strings.Builder
	builder.WriteString("\n==================================================\n")
	builder.WriteString("              漏洞详细报告 (Vulnerability Detailed Report)\n")
	builder.WriteString("==================================================\n\n")

	// 遍历所有发现的漏洞，并格式化输出。
	for i, vuln := range r.vulnerabilities {
		var vulnerableURL string
		// 对POST请求进行特殊格式化，以清晰地显示参数和载荷。
		if vuln.Method == "POST" {
			vulnerableURL = fmt.Sprintf("%s [POST Data] %s=%s", vuln.URL, vuln.Param, vuln.Payload)
		} else {
			vulnerableURL = vuln.VulnerableURL
		}

		builder.WriteString(fmt.Sprintf("序号 (Index):         %d\n", i+1))
		builder.WriteString(fmt.Sprintf("检测时间 (Timestamp): %s\n", vuln.Timestamp.Format(time.RFC3339)))
		builder.WriteString(fmt.Sprintf("漏洞名称 (Type):      %s\n", vuln.Type))
		builder.WriteString(fmt.Sprintf("URL 地址 (URL):       %s\n", vuln.URL))
		builder.WriteString(fmt.Sprintf("利用载荷 (Payload):   %s\n", vuln.Payload))
		builder.WriteString(fmt.Sprintf("请求方法 (Method):    %s\n", vuln.Method))
		builder.WriteString(fmt.Sprintf("漏洞参数 (Parameter): %s\n", vuln.Param))
		builder.WriteString(fmt.Sprintf("漏洞链接 (Vulnerable URL): %s\n\n", vulnerableURL))
	}

	builder.WriteString("--------------------------------------------------\n")
	builder.WriteString("              漏洞统计摘要 (Vulnerability Summary)\n")
	builder.WriteString("--------------------------------------------------\n")
	// 添加漏洞类型统计。
	if len(r.vulnCounts) > 0 {
		for name, count := range r.vulnCounts {
			builder.WriteString(fmt.Sprintf("- %-20s: %d\n", name, count))
		}
	} else {
		builder.WriteString("未发现漏洞 (No vulnerabilities found).\n")
	}
	builder.WriteString("--------------------------------------------------\n")

	// 将构建好的字符串写入文件。
	if _, err := r.vulnFile.WriteString(builder.String()); err != nil {
		log.Warn().Err(err).Msg("写入漏洞摘要失败 (Failed to write vulnerability summary)")
	}

	// 强制将文件缓冲区的内容刷入磁盘，确保数据持久化。
	if err := r.vulnFile.Sync(); err != nil {
		log.Warn().Err(err).Msg("同步漏洞文件到磁盘失败 (Failed to sync vulnerability file)")
	}
}

// LogURL 异步记录一个在扫描范围内的URL。
// LogURL asynchronously logs a URL that is within the scan scope.
func (r *Reporter) LogURL(url string) {
	r.logToFile(r.spiderFile, url)
}

// LogUnscopedURL 异步记录一个不在扫描范围内的URL。
// LogUnscopedURL asynchronously logs a URL that is out of the scan scope.
func (r *Reporter) LogUnscopedURL(url string) {
	r.logToFile(r.unscopedSpiderFile, url)
}

// LogDeDuplicateURL 异步记录一个经过主去重逻辑的URL。
// LogDeDuplicateURL asynchronously logs a URL that has passed the main de-duplication logic.
func (r *Reporter) LogDeDuplicateURL(url string) {
	r.logToFile(r.spiderDeDuplicateFile, url)
}

// LogParamURL 异步记录一个包含参数的请求的完整URL。
// LogParamURL asynchronously logs the full URL of a request that includes parameters.
func (r *Reporter) LogParamURL(req *models.Request) {
	r.logToFile(r.spiderParamsFile, req.URLWithParams())
}

// LogVulnerability 记录一个新发现的漏洞。
// 此函数是线程安全的，并且会进行漏洞去重。
// LogVulnerability logs a newly discovered vulnerability. This function is thread-safe and performs de-duplication.
func (r *Reporter) LogVulnerability(vuln *vulnscan.Vulnerability) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// 使用漏洞的唯一签名来检查是否已经报告过。
	signature := r.getVulnerabilitySignature(vuln)
	if r.reportedVulns[signature] {
		log.Debug().Str("signature", signature).Msg("发现重复漏洞，已跳过。(Duplicate vulnerability found, skipping.)")
		return
	}

	// 如果是新漏洞，则添加到列表中，并更新统计。
	r.vulnerabilities = append(r.vulnerabilities, vuln)
	r.vulnCounts[vuln.Type]++
	r.reportedVulns[signature] = true

	// 在控制台输出日志，通知用户发现了新漏洞。
	log.Info().
		Str("type", vuln.Type).
		Str("url", vuln.URL).
		Str("param", vuln.Param).
		Msg("发现新漏洞！(New Vulnerability Found!)")
}

// getVulnerabilitySignature 为漏洞生成一个唯一的字符串签名。
// 签名基于漏洞类型、URL、参数和请求方法，用于去重。
// getVulnerabilitySignature generates a unique string signature for a vulnerability for de-duplication.
func (r *Reporter) getVulnerabilitySignature(vuln *vulnscan.Vulnerability) string {
	return fmt.Sprintf("%s|%s|%s|%s", vuln.Type, vuln.URL, vuln.Method, vuln.Param)
}

// generateFinalReports 生成JSON和HTML格式的最终报告。
// generateFinalReports generates the final reports in JSON and HTML format.
func (r *Reporter) generateFinalReports() error {
	report := r.createFinalReport()

	// 生成JSON报告
	if err := r.generateJSONReport(report); err != nil {
		log.Error().Err(err).Msg("生成JSON报告失败 (Failed to generate JSON report)")
	}

	// 生成HTML报告
	if err := r.generateHTMLReport(report); err != nil {
		log.Error().Err(err).Msg("生成HTML报告失败 (Failed to generate HTML report)")
	}
	return nil
}

// generateJSONReport 将报告数据序列化为JSON并写入文件。
// generateJSONReport serializes the report data to JSON and writes it to a file.
func (r *Reporter) generateJSONReport(report Report) error {
	// 将报告结构体序列化为格式化的JSON。
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("JSON序列化失败 (failed to marshal json report): %w", err)
	}

	// 将JSON数据写入文件。
	reportPath := filepath.Join(r.config.Path, r.config.JSONReportFile)
	return os.WriteFile(reportPath, data, 0644)
}

// generateHTMLReport 使用模板生成HTML格式的报告。
// generateHTMLReport generates an HTML-formatted report using a template.
func (r *Reporter) generateHTMLReport(report Report) error {
	// 定义HTML报告的模板。
	htmlTemplate := `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>AutoVulnScan 扫描报告 (Scan Report)</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 40px; background-color: #f7f9fc; color: #333; }
        .container { max-width: 1200px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
        h1, h2 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        h1 { text-align: center; }
        .summary p { font-size: 1.1em; line-height: 1.6; }
        .summary strong { color: #3498db; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #3498db; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        tr:hover { background-color: #eaf5ff; }
    </style>
</head>
<body>
    <div class="container">
        <h1>AutoVulnScan 扫描报告 (Scan Report)</h1>
        <div class="summary">
            <p><strong>目标 (Target):</strong> {{.Target}}</p>
            <p><strong>开始时间 (Start Time):</strong> {{.StartTime.Format "2006-01-02 15:04:05"}}</p>
            <p><strong>结束时间 (End Time):</strong> {{.EndTime.Format "2006-01-02 15:04:05"}}</p>
            <p><strong>总耗时 (Duration):</strong> {{.Duration}}</p>
            <p><strong>发现漏洞数 (Vulnerabilities Found):</strong> <strong style="color: #e74c3c;">{{.VulnerabilitiesFound}}</strong></p>
        </div>
        
        <h2>漏洞详情 (Vulnerability Details)</h2>
        <table>
            <thead>
                <tr>
                    <th>漏洞类型 (Type)</th>
                    <th>URL</th>
                    <th>请求方法 (Method)</th>
                    <th>参数 (Parameter)</th>
                    <th>载荷 (Payload)</th>
                </tr>
            </thead>
            <tbody>
                {{range .Vulnerabilities}}
                <tr>
                    <td>{{.Type}}</td>
                    <td>{{.URL}}</td>
                    <td>{{.Method}}</td>
                    <td>{{.Param}}</td>
                    <td>{{.Payload}}</td>
                </tr>
                {{else}}
                <tr>
                    <td colspan="5" style="text-align: center;">未发现任何漏洞 (No vulnerabilities found)</td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>
</body>
</html>`

	// 解析HTML模板。
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"Format": time.Time.Format,
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("解析HTML模板失败 (failed to parse html template): %w", err)
	}

	// 创建HTML报告文件。
	reportPath := filepath.Join(r.config.Path, r.config.HTMLReportFile)
	file, err := os.Create(reportPath)
	if err != nil {
		return fmt.Errorf("创建HTML报告文件失败 (failed to create html report file): %w", err)
	}
	defer file.Close()

	// 将报告数据渲染到模板并写入文件。
	return tmpl.Execute(file, report)
}

// createFinalReport 创建用于生成报告的最终数据结构。
// createFinalReport creates the final data structure used for generating reports.
func (r *Reporter) createFinalReport() Report {
	return Report{
		StartTime:            r.startTime,
		EndTime:              time.Now(),
		Duration:             time.Since(r.startTime).String(),
		Target:               r.targetURL, // 使用保存的目标URL
		VulnerabilitiesFound: len(r.vulnerabilities),
		Vulnerabilities:      r.vulnerabilities,
	}
}

// logToFile 异步地将一行数据写入指定的文件。
// 它使用 sync.WaitGroup 来跟踪正在进行的写入操作。
// logToFile asynchronously writes a line of data to the specified file.
func (r *Reporter) logToFile(file *os.File, data string) {
	if file == nil {
		log.Warn().Msg("尝试写入的日志文件句柄为nil (Log file handle is nil)")
		return
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()

		r.mu.Lock()
		defer r.mu.Unlock()
		if _, err := file.WriteString(data + "\n"); err != nil {
			log.Warn().Err(err).Str("file", file.Name()).Msg("写入日志文件失败 (Failed to write to log file)")
		}
	}()
}

// Report 定义了最终报告（JSON和HTML）的结构。
// Report defines the structure for the final reports (JSON and HTML).
type Report struct {
	StartTime            time.Time                 `json:"start_time"`            // 扫描开始时间
	EndTime              time.Time                 `json:"end_time"`              // 扫描结束时间
	Duration             string                    `json:"duration"`              // 扫描持续时间
	Target               string                    `json:"target"`                // 扫描目标URL
	VulnerabilitiesFound int                       `json:"vulnerabilities_found"` // 发现的漏洞总数
	Vulnerabilities      []*vulnscan.Vulnerability `json:"vulnerabilities"`       // 包含所有漏洞详情的列表
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
	// 替换协议分隔符
	sanitized := strings.ReplaceAll(urlStr, "://", "_")
	// 替换其他无效字符
	sanitized = strings.ReplaceAll(sanitized, "/", "_")
	sanitized = strings.ReplaceAll(sanitized, ":", "_")
	sanitized = strings.ReplaceAll(sanitized, "?", "_")
	sanitized = strings.ReplaceAll(sanitized, "&", "_")
	return sanitized + ".log"
}
