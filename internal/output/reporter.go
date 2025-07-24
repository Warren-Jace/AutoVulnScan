// Package output 处理扫描结果的报告生成和日志记录
package output

import (
	"bufio"
	"context"
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
	mu                    sync.RWMutex              // 改为读写锁，提高并发性能
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

	// 新增字段用于优化
	fileBuffers  map[*os.File]*bufio.Writer // 文件缓冲区，提高写入性能
	ctx          context.Context            // 用于优雅关闭
	cancel       context.CancelFunc         // 取消函数
	closed       bool                       // 标记是否已关闭
	htmlTemplate *template.Template         // 缓存HTML模板
}

// fileInfo 结构体用于简化文件创建逻辑
type fileInfo struct {
	name string
	file **os.File
}

// NewReporter 创建并初始化一个新的 Reporter 实例。
// 它会根据配置创建输出目录和所有必要的日志文件。
// NewReporter creates and initializes a new Reporter instance.
func NewReporter(cfg config.ReportingConfig, targetURL string) (*Reporter, error) {
	// 验证输入参数
	if cfg.Path == "" {
		return nil, fmt.Errorf("报告路径不能为空")
	}

	if targetURL == "" {
		log.Warn().Msg("目标URL为空")
	}

	// 创建上下文用于优雅关闭
	ctx, cancel := context.WithCancel(context.Background())

	// 创建Reporter实例
	reporter := &Reporter{
		config:      cfg,
		startTime:   time.Now(),
		targetURL:   targetURL,
		ctx:         ctx,
		cancel:      cancel,
		fileBuffers: make(map[*os.File]*bufio.Writer, 5),
		closed:      false,
	}

	// 初始化数据结构，预分配容量
	const initialCapacity = 1000
	reporter.vulnerabilities = make([]*vulnscan.Vulnerability, 0, initialCapacity)
	reporter.vulnCounts = make(map[string]int, 20)
	reporter.reportedVulns = make(map[string]bool, initialCapacity)

	// 初始化HTML模板
	if err := reporter.initHTMLTemplate(); err != nil {
		cancel()
		return nil, fmt.Errorf("初始化HTML模板失败: %w", err)
	}

	// 创建输出目录
	if err := reporter.createOutputDirectory(); err != nil {
		cancel()
		return nil, err
	}

	// 批量创建文件
	if err := reporter.createAllFiles(); err != nil {
		reporter.cleanup()
		cancel()
		return nil, err
	}

	log.Info().
		Str("reportPath", cfg.Path).
		Str("targetURL", targetURL).
		Msg("Reporter初始化完成")

	return reporter, nil
}

// createOutputDirectory 创建输出目录
func (r *Reporter) createOutputDirectory() error {
	const maxRetries = 3
	var lastErr error

	for i := 0; i < maxRetries; i++ {
		if err := os.MkdirAll(r.config.Path, 0755); err != nil {
			lastErr = err
			if i < maxRetries-1 {
				time.Sleep(time.Duration(i+1) * 100 * time.Millisecond)
				continue
			}
		} else {
			return nil
		}
	}
	return fmt.Errorf("创建报告目录失败 (failed to create report directory): %w", lastErr)
}

// initHTMLTemplate 初始化并缓存HTML模板
func (r *Reporter) initHTMLTemplate() error {
	htmlTemplate := `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AutoVulnScan 扫描报告 (Scan Report)</title>
  <style>
      body { 
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; 
          margin: 40px; 
          background-color: #f7f9fc; 
          color: #333; 
          line-height: 1.6;
      }
      .container { 
          max-width: 1200px; 
          margin: auto; 
          background: #fff; 
          padding: 30px; 
          border-radius: 12px; 
          box-shadow: 0 4px 20px rgba(0,0,0,0.1); 
      }
      h1, h2 { 
          color: #2c3e50; 
          border-bottom: 3px solid #3498db; 
          padding-bottom: 15px; 
          margin-bottom: 25px;
      }
      h1 { 
          text-align: center; 
          font-size: 2.5em;
          margin-bottom: 40px;
      }
      .summary { 
          background: #f8f9fa; 
          padding: 25px; 
          border-radius: 8px; 
          margin-bottom: 30px;
          border-left: 5px solid #3498db;
      }
      .summary p { 
          font-size: 1.1em; 
          margin: 10px 0;
      }
      .summary strong { 
          color: #3498db; 
      }
      .vuln-count {
          color: #e74c3c;
          font-size: 1.3em;
          font-weight: bold;
      }
      table { 
          border-collapse: collapse; 
          width: 100%; 
          margin-top: 20px; 
          background: white;
          border-radius: 8px;
          overflow: hidden;
          box-shadow: 0 2px 10px rgba(0,0,0,0.1);
      }
      th, td { 
          border: 1px solid #e1e8ed; 
          padding: 15px 12px; 
          text-align: left; 
          word-break: break-all;
      }
      th { 
          background: linear-gradient(135deg, #3498db, #2980b9); 
          color: white; 
          font-weight: 600;
          text-transform: uppercase;
          font-size: 0.9em;
          letter-spacing: 0.5px;
      }
      tr:nth-child(even) { 
          background-color: #f8f9fa; 
      }
      tr:hover { 
          background-color: #e3f2fd; 
          transition: background-color 0.3s ease;
      }
      .no-vulns {
          text-align: center;
          color: #27ae60;
          font-weight: bold;
          font-size: 1.1em;
          padding: 30px;
      }
      .footer {
          margin-top: 40px;
          text-align: center;
          color: #7f8c8d;
          font-size: 0.9em;
      }
  </style>
</head>
<body>
  <div class="container">
      <h1>🛡️ AutoVulnScan 扫描报告</h1>
      <div class="summary">
          <p><strong>🎯 扫描目标:</strong> {{.Target}}</p>
          <p><strong>⏰ 开始时间:</strong> {{.StartTime.Format "2006-01-02 15:04:05"}}</p>
          <p><strong>⏱️ 结束时间:</strong> {{.EndTime.Format "2006-01-02 15:04:05"}}</p>
          <p><strong>⏳ 总耗时:</strong> {{.Duration}}</p>
          <p><strong>🚨 发现漏洞数:</strong> <span class="vuln-count">{{.VulnerabilitiesFound}}</span></p>
      </div>
      
      <h2>🔍 漏洞详情 (Vulnerability Details)</h2>
      <table>
          <thead>
              <tr>
                  <th>漏洞类型</th>
                  <th>URL地址</th>
                  <th>请求方法</th>
                  <th>参数名称</th>
                  <th>攻击载荷</th>
                  <th>发现时间</th>
              </tr>
          </thead>
          <tbody>
              {{range .Vulnerabilities}}
              <tr>
                  <td><strong>{{.Type}}</strong></td>
                  <td><code>{{.URL}}</code></td>
                  <td><span style="background: #3498db; color: white; padding: 3px 8px; border-radius: 4px; font-size: 0.8em;">{{.Method}}</span></td>
                  <td>{{.Param}}</td>
                  <td><code style="background: #f1c40f; padding: 2px 6px; border-radius: 3px;">{{.Payload}}</code></td>
                  <td>{{.Timestamp.Format "01-02 15:04:05"}}</td>
              </tr>
              {{else}}
              <tr>
                  <td colspan="6" class="no-vulns">
                      🎉 未发现任何漏洞 (No vulnerabilities found)
                  </td>
              </tr>
              {{end}}
          </tbody>
      </table>
      
      <div class="footer">
          <p>Generated by AutoVulnScan at {{.EndTime.Format "2006-01-02 15:04:05"}}</p>
      </div>
  </div>
</body>
</html>`

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"Format": time.Time.Format,
	}).Parse(htmlTemplate)

	if err != nil {
		return err
	}

	r.htmlTemplate = tmpl
	return nil
}

// createAllFiles 批量创建所有需要的文件
func (r *Reporter) createAllFiles() error {
	// 定义需要创建的文件列表
	fileList := []fileInfo{
		{r.config.SpiderFile, &r.spiderFile},
		{r.config.UnscopedSpiderFile, &r.unscopedSpiderFile},
		{r.config.SpiderDeDuplicateFile, &r.spiderDeDuplicateFile},
		{r.config.SpiderParamsFile, &r.spiderParamsFile},
	}

	// 批量创建带BOM的文件
	for _, info := range fileList {
		file, err := r.createFileWithBOM(info.name)
		if err != nil {
			return fmt.Errorf("创建文件 %s 失败: %w", info.name, err)
		}
		*info.file = file
		r.fileBuffers[file] = bufio.NewWriterSize(file, 8192)
	}

	// 单独处理漏洞文件（截断模式）
	vulnFilePath := filepath.Join(r.config.Path, r.config.VulnReportFile)
	vf, err := os.Create(vulnFilePath)
	if err != nil {
		return fmt.Errorf("打开漏洞报告文件失败 (failed to open vulnerability report file): %w", err)
	}
	r.vulnFile = vf
	r.fileBuffers[vf] = bufio.NewWriterSize(vf, 8192)

	return nil
}

// createFileWithBOM 创建带BOM的文件
func (r *Reporter) createFileWithBOM(filename string) (*os.File, error) {
	filePath := filepath.Join(r.config.Path, filename)

	// 检查文件是否存在且非空
	fileExists := false
	if stat, err := os.Stat(filePath); err == nil && stat.Size() > 0 {
		fileExists = true
	}

	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %w", err)
	}

	// 如果文件不存在或为空，写入BOM
	if !fileExists {
		if _, err := file.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
			file.Close()
			return nil, fmt.Errorf("写入BOM失败: %w", err)
		}
	}

	return file, nil
}

// logToFileOptimized 优化的异步文件写入
func (r *Reporter) logToFileOptimized(file *os.File, content string) {
	if file == nil || content == "" {
		return
	}

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()

		// 检查是否已关闭
		select {
		case <-r.ctx.Done():
			return
		default:
		}

		r.mu.RLock()
		buffer, exists := r.fileBuffers[file]
		closed := r.closed
		r.mu.RUnlock()

		if closed || !exists {
			return
		}

		// 使用读锁进行写入操作
		r.mu.RLock()
		defer r.mu.RUnlock()

		if _, err := buffer.WriteString(content + "\n"); err != nil {
			log.Error().Err(err).Str("file", file.Name()).Msg("写入文件失败")
		}
	}()
}

// cleanup 清理资源
func (r *Reporter) cleanup() {
	// 刷新所有缓冲区
	for file, buffer := range r.fileBuffers {
		if buffer != nil {
			if err := buffer.Flush(); err != nil {
				log.Warn().Err(err).Str("file", file.Name()).Msg("刷新文件缓冲区失败")
			}
		}
	}

	// 关闭所有文件
	files := []*os.File{
		r.spiderFile,
		r.unscopedSpiderFile,
		r.spiderDeDuplicateFile,
		r.spiderParamsFile,
		r.vulnFile,
	}

	for _, file := range files {
		if file != nil {
			if err := file.Close(); err != nil {
				log.Warn().Err(err).Str("file", file.Name()).Msg("关闭文件失败")
			}
		}
	}
}

// Close 等待所有异步任务完成，关闭所有文件句柄，并生成最终的报告。
// Close waits for all async tasks to complete, closes all file handles, and generates final reports.
func (r *Reporter) Close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	r.mu.Unlock()

	// 取消上下文，通知所有goroutine停止
	r.cancel()

	// 等待所有异步文件写入完成，设置超时
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Debug().Msg("所有异步任务已完成")
	case <-time.After(10 * time.Second):
		log.Warn().Msg("等待异步任务完成超时")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// 在关闭漏洞文件之前，写入文本格式的漏洞摘要。
	if r.vulnFile != nil {
		r.writeTextSummary()
	}

	// 清理资源
	r.cleanup()

	// 生成JSON和HTML格式的最终报告。
	if err := r.generateFinalReports(); err != nil {
		log.Error().Err(err).Msg("生成最终报告失败 (Failed to generate final reports)")
	}

	log.Info().
		Int("vulnerabilities", len(r.vulnerabilities)).
		Dur("duration", time.Since(r.startTime)).
		Msg("Reporter关闭完成")
}

// writeTextSummary 写入文本摘要
func (r *Reporter) writeTextSummary() {
	if len(r.vulnerabilities) == 0 {
		log.Info().Msg("未发现任何漏洞。(No vulnerabilities found.)")
		return
	}

	// 使用strings.Builder提高字符串拼接性能
	var reportBuilder strings.Builder
	const estimatedSize = len(r.vulnerabilities) * 500 // 估算每个漏洞500字符
	reportBuilder.Grow(estimatedSize)

	// 写入BOM头
	reportBuilder.Write([]byte{0xEF, 0xBB, 0xBF})

	// 1. 写入漏洞摘要
	r.writeSummarySection(&reportBuilder)

	// 2. 写入漏洞详情
	r.writeDetailsSection(&reportBuilder)

	// 3. 一次性写入文件
	buffer := r.fileBuffers[r.vulnFile]
	if buffer != nil {
		if _, err := buffer.WriteString(reportBuilder.String()); err != nil {
			log.Error().Err(err).Msg("写入漏洞报告失败 (Failed to write vulnerability report)")
		}
		if err := buffer.Flush(); err != nil {
			log.Error().Err(err).Msg("刷新漏洞报告缓冲区失败")
		}
	}
}

// writeSummarySection 写入摘要部分
func (r *Reporter) writeSummarySection(builder *strings.Builder) {
	builder.WriteString("==================================================\n")
	builder.WriteString("              漏洞统计摘要 (Vulnerability Summary)\n")
	builder.WriteString("==================================================\n")
	builder.WriteString(fmt.Sprintf("总计发现 %d 个漏洞，分布在 %d 个类别中。\n",
		len(r.vulnerabilities), len(r.vulnCounts)))
	builder.WriteString("--------------------------------------------------\n")

	for name, count := range r.vulnCounts {
		builder.WriteString(fmt.Sprintf("- %-20s: %d\n", name, count))
	}
	builder.WriteString("==================================================\n\n")
}

// writeDetailsSection 写入详情部分
func (r *Reporter) writeDetailsSection(builder *strings.Builder) {
	for i, vuln := range r.vulnerabilities {
		if vuln == nil {
			log.Warn().Int("index", i).Msg("发现空漏洞对象")
			continue
		}

		var vulnerableURL string
		// 根据请求方法构建可复现的漏洞地址
		if vuln.Method == "POST" {
			vulnerableURL = fmt.Sprintf("%s  [POST参数] %s=%s", vuln.URL, vuln.Param, vuln.Payload)
		} else { // 默认为GET请求
			vulnerableURL = vuln.VulnerableURL
		}

		// 使用更高效的字符串格式化
		builder.WriteString(fmt.Sprintf(
			"序号:           %d\n"+
				"检测时间:       %s\n"+
				"漏洞名称:       %s\n"+
				"url地址:        %s\n"+
				"Payload:        %s\n"+
				"请求方式:       %s\n"+
				"漏洞参数:       %s\n"+
				"漏洞地址:       %s\n\n",
			i+1,
			vuln.Timestamp.Format("2006-01-02T15:04:05+08:00"),
			vuln.Type,
			vuln.URL,
			vuln.Payload,
			vuln.Method,
			vuln.Param,
			vulnerableURL,
		))
	}
}

// LogURL 异步记录一个在扫描范围内的URL。
// LogURL asynchronously logs a URL that is within the scan scope.
func (r *Reporter) LogURL(url string) {
	r.logToFileOptimized(r.spiderFile, url)
}

// LogUnscopedURL 异步记录一个不在扫描范围内的URL。
// LogUnscopedURL asynchronously logs a URL that is out of the scan scope.
func (r *Reporter) LogUnscopedURL(url string) {
	r.logToFileOptimized(r.unscopedSpiderFile, url)
}

// LogDeDuplicateURL 异步记录一个经过主去重逻辑的URL。
// LogDeDuplicateURL asynchronously logs a URL that has passed the main de-duplication logic.
func (r *Reporter) LogDeDuplicateURL(url string) {
	r.logToFileOptimized(r.spiderDeDuplicateFile, url)
}

// LogParamURL 异步记录一个包含参数的请求的完整URL。
// LogParamURL asynchronously logs the full URL of a request that includes parameters.
func (r *Reporter) LogParamURL(req *models.Request) {
	if req == nil {
		log.Warn().Msg("请求对象为空，跳过记录")
		return
	}
	r.logToFileOptimized(r.spiderParamsFile, req.URLWithParams())
}

// LogVulnerability 记录一个新发现的漏洞。
// 此函数是线程安全的，并且会进行漏洞去重。
// LogVulnerability logs a newly discovered vulnerability. This function is thread-safe and performs de-duplication.
func (r *Reporter) LogVulnerability(vuln *vulnscan.Vulnerability) {
	if vuln == nil {
		log.Warn().Msg("漏洞对象为空，跳过记录")
		return
	}

	// 生成漏洞签名
	signature := r.getVulnerabilitySignature(vuln)

	// 先用读锁检查是否已存在
	r.mu.RLock()
	if r.closed {
		r.mu.RUnlock()
		log.Debug().Msg("Reporter已关闭，跳过漏洞记录")
		return
	}

	if r.reportedVulns[signature] {
		r.mu.RUnlock()
		log.Debug().Str("signature", signature).Msg("发现重复漏洞，已跳过。(Duplicate vulnerability found, skipping.)")
		return
	}
	r.mu.RUnlock()

	// 使用写锁进行实际的添加操作
	r.mu.Lock()
	defer r.mu.Unlock()

	// 双重检查，防止并发情况下的重复添加
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
		Str("method", vuln.Method).
		Time("timestamp", vuln.Timestamp).
		Msg("发现新漏洞！(New Vulnerability Found!)")
}

// getVulnerabilitySignature 为漏洞生成一个唯一的字符串签名。
// 签名基于漏洞类型、URL、参数和请求方法，用于去重。
// getVulnerabilitySignature generates a unique string signature for a vulnerability for de-duplication.
func (r *Reporter) getVulnerabilitySignature(vuln *vulnscan.Vulnerability) string {
	// 使用更高效的字符串拼接
	var builder strings.Builder
	builder.Grow(len(vuln.Type) + len(vuln.URL) + len(vuln.Method) + len(vuln.Param) + 4)
	builder.WriteString(vuln.Type)
	builder.WriteByte('|')
	builder.WriteString(vuln.URL)
	builder.WriteByte('|')
	builder.WriteString(vuln.Method)
	builder.WriteByte('|')
	builder.WriteString(vuln.Param)
	return builder.String()
}

// generateFinalReports 生成JSON和HTML格式的最终报告。
// generateFinalReports generates the final reports in JSON and HTML format.
func (r *Reporter) generateFinalReports() error {
	report := r.createFinalReport()

	// 使用并发生成报告
	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	wg.Add(2)

	// 并发生成JSON报告
	go func() {
		defer wg.Done()
		if err := r.generateJSONReport(report); err != nil {
			errChan <- fmt.Errorf("生成JSON报告失败: %w", err)
		}
	}()

	// 并发生成HTML报告
	go func() {
		defer wg.Done()
		if err := r.generateHTMLReport(report); err != nil {
			errChan <- fmt.Errorf("生成HTML报告失败: %w", err)
		}
	}()

	wg.Wait()
	close(errChan)

	// 收集错误
	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}

	// 返回第一个错误
	if len(errors) > 0 {
		for _, err := range errors {
			log.Error().Err(err).Msg("报告生成错误")
		}
		return errors[0]
	}

	return nil
}

// generateJSONReport 生成JSON报告
func (r *Reporter) generateJSONReport(report Report) error {
	reportPath := filepath.Join(r.config.Path, r.config.JSONReportFile)

	// 创建文件
	file, err := os.Create(reportPath)
	if err != nil {
		return fmt.Errorf("创建JSON报告文件失败: %w", err)
	}
	defer file.Close()

	// 使用缓冲写入
	writer := bufio.NewWriterSize(file, 16384) // 16KB缓冲区
	defer writer.Flush()

	// 创建JSON编码器，直接写入文件
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false) // 避免HTML转义

	return encoder.Encode(report)
}

// generateHTMLReport 生成HTML报告
// generateHTMLReport 生成HTML报告
func (r *Reporter) generateHTMLReport(report Report) error {
	// 创建HTML报告文件
	reportPath := filepath.Join(r.config.Path, r.config.HTMLReportFile)
	file, err := os.Create(reportPath)
	if err != nil {
		return fmt.Errorf("创建HTML报告文件失败 (failed to create html report file): %w", err)
	}
	defer file.Close()

	// 使用缓冲写入
	writer := bufio.NewWriterSize(file, 16384) // 16KB缓冲区
	defer writer.Flush()

	// 将报告数据渲染到模板并写入文件
	return r.htmlTemplate.Execute(writer, report)
}

// createFinalReport 创建用于生成报告的最终数据结构。
// createFinalReport creates the final data structure used for generating reports.
func (r *Reporter) createFinalReport() Report {
	endTime := time.Now()
	duration := endTime.Sub(r.startTime)

	return Report{
		Target:               r.targetURL,
		StartTime:            r.startTime,
		EndTime:              endTime,
		Duration:             duration.String(),
		VulnerabilitiesFound: len(r.vulnerabilities),
		Vulnerabilities:      r.vulnerabilities,
		VulnCounts:           r.vulnCounts,
	}
}

// Report 表示最终的扫描报告数据结构
type Report struct {
	Target               string                    `json:"target"`
	StartTime            time.Time                 `json:"start_time"`
	EndTime              time.Time                 `json:"end_time"`
	Duration             string                    `json:"duration"`
	VulnerabilitiesFound int                       `json:"vulnerabilities_found"`
	Vulnerabilities      []*vulnscan.Vulnerability `json:"vulnerabilities"`
	VulnCounts           map[string]int            `json:"vuln_counts"`
}
