// Package output 处理扫描结果的报告生成和日志记录
package output

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"autovulnscan/internal/config"
	"autovulnscan/internal/models"

	"github.com/rs/zerolog/log"
)

// ReportFormat 报告格式枚举
type ReportFormat string

const (
	FormatJSON ReportFormat = "json"
	FormatHTML ReportFormat = "html"
	FormatXML  ReportFormat = "xml"
	FormatCSV  ReportFormat = "csv"
	FormatText ReportFormat = "text"
)

// ReportType 报告类型枚举
type ReportType string

const (
	TypeSummary ReportType = "summary"
	TypeDetail  ReportType = "detail"
	TypeFull    ReportType = "full"
)

// FileType 文件类型枚举
type FileType string

const (
	FileTypeSpider            FileType = "spider"
	FileTypeUnscopedSpider    FileType = "unscoped_spider"
	FileTypeSpiderDeDuplicate FileType = "spider_deduplicate"
	FileTypeSpiderParams      FileType = "spider_params"
	FileTypeVulnerability     FileType = "vulnerability"
	FileTypeReport            FileType = "report"
)

// ReportConfig 报告配置
type ReportConfig struct {
	Path              string                 `json:"path"`                // 输出路径
	Format            ReportFormat           `json:"format"`              // 报告格式
	Type              ReportType             `json:"type"`                // 报告类型
	IncludeFalsePositives bool               `json:"include_false_positives"` // 是否包含误报
	MinSeverity       models.Severity        `json:"min_severity"`        // 最小严重程度
	Template          string                 `json:"template,omitempty"`  // 自定义模板路径
	CustomFields      []string               `json:"custom_fields,omitempty"` // 自定义字段
	MaxFileSize       int64                  `json:"max_file_size"`       // 最大文件大小(MB)
	BufferSize        int                    `json:"buffer_size"`         // 缓冲区大小
	EnableCompression bool                   `json:"enable_compression"`  // 是否启用压缩
	Metadata          map[string]interface{} `json:"metadata,omitempty"`  // 元数据
}

// DefaultReportConfig 返回默认报告配置
func DefaultReportConfig() ReportConfig {
	return ReportConfig{
		Path:                  "./reports",
		Format:                FormatJSON,
		Type:                  TypeFull,
		IncludeFalsePositives: false,
		MinSeverity:           models.SeverityLow,
		MaxFileSize:           100, // 100MB
		BufferSize:            64 * 1024, // 64KB
		EnableCompression:     false,
		Metadata:              make(map[string]interface{}),
	}
}

// FileManager 文件管理器
type FileManager struct {
	mu          sync.RWMutex
	files       map[FileType]*os.File
	buffers     map[FileType]*bufio.Writer
	config      ReportConfig
	basePath    string
	closed      bool
	writeCount  map[FileType]int64
	lastFlush   map[FileType]time.Time
	flushTicker *time.Ticker
}

// NewFileManager 创建文件管理器
func NewFileManager(config ReportConfig, basePath string) (*FileManager, error) {
	fm := &FileManager{
		files:       make(map[FileType]*os.File),
		buffers:     make(map[FileType]*bufio.Writer),
		config:      config,
		basePath:    basePath,
		writeCount:  make(map[FileType]int64),
		lastFlush:   make(map[FileType]time.Time),
		flushTicker: time.NewTicker(5 * time.Second), // 每5秒刷新一次缓冲区
	}

	// 创建输出目录
	if err := fm.createOutputDirectory(); err != nil {
		return nil, err
	}

	// 启动定期刷新
	go fm.periodicFlush()

	return fm, nil
}

// createOutputDirectory 创建输出目录
func (fm *FileManager) createOutputDirectory() error {
	const maxRetries = 3
	var lastErr error

	for i := 0; i < maxRetries; i++ {
		if err := os.MkdirAll(fm.basePath, 0755); err != nil {
			lastErr = err
			if i < maxRetries-1 {
				time.Sleep(time.Duration(i+1) * 100 * time.Millisecond)
				continue
			}
		} else {
			return nil
		}
	}
	return fmt.Errorf("创建报告目录失败: %w", lastErr)
}

// CreateFile 创建指定类型的文件
func (fm *FileManager) CreateFile(fileType FileType, filename string) error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	if fm.closed {
		return fmt.Errorf("文件管理器已关闭")
	}

	// 检查文件是否已存在
	if _, exists := fm.files[fileType]; exists {
		return fmt.Errorf("文件类型 %s 已存在", fileType)
	}

	fullPath := filepath.Join(fm.basePath, filename)
	
	// 创建文件
	file, err := os.OpenFile(fullPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("创建文件 %s 失败: %w", fullPath, err)
	}

	// 创建缓冲写入器
	buffer := bufio.NewWriterSize(file, fm.config.BufferSize)

	fm.files[fileType] = file
	fm.buffers[fileType] = buffer
	fm.writeCount[fileType] = 0
	fm.lastFlush[fileType] = time.Now()

	log.Debug().
		Str("fileType", string(fileType)).
		Str("path", fullPath).
		Msg("文件创建成功")

	return nil
}

// WriteToFile 写入数据到指定类型的文件
func (fm *FileManager) WriteToFile(fileType FileType, data []byte) error {
	fm.mu.RLock()
	buffer, exists := fm.buffers[fileType]
	fm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("文件类型 %s 不存在", fileType)
	}

	if fm.closed {
		return fmt.Errorf("文件管理器已关闭")
	}

	// 检查文件大小限制
	fm.mu.Lock()
	if fm.writeCount[fileType] > fm.config.MaxFileSize*1024*1024 {
		fm.mu.Unlock()
		return fmt.Errorf("文件 %s 超过大小限制", fileType)
	}
	fm.writeCount[fileType] += int64(len(data))
	fm.mu.Unlock()

	// 写入数据
	if _, err := buffer.Write(data); err != nil {
		return fmt.Errorf("写入文件 %s 失败: %w", fileType, err)
	}

	// 如果缓冲区接近满或距离上次刷新时间过长，则立即刷新
	if buffer.Buffered() > fm.config.BufferSize/2 || 
	   time.Since(fm.lastFlush[fileType]) > 10*time.Second {
		return fm.FlushFile(fileType)
	}

	return nil
}

// WriteLineToFile 写入一行数据到指定类型的文件
func (fm *FileManager) WriteLineToFile(fileType FileType, line string) error {
	if !strings.HasSuffix(line, "\n") {
		line += "\n"
	}
	return fm.WriteToFile(fileType, []byte(line))
}

// FlushFile 刷新指定文件的缓冲区
func (fm *FileManager) FlushFile(fileType FileType) error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	buffer, exists := fm.buffers[fileType]
	if !exists {
		return fmt.Errorf("文件类型 %s 不存在", fileType)
	}

	if err := buffer.Flush(); err != nil {
		return fmt.Errorf("刷新文件 %s 缓冲区失败: %w", fileType, err)
	}

	fm.lastFlush[fileType] = time.Now()
	return nil
}

// FlushAll 刷新所有文件的缓冲区
func (fm *FileManager) FlushAll() error {
	fm.mu.RLock()
	fileTypes := make([]FileType, 0, len(fm.buffers))
	for fileType := range fm.buffers {
		fileTypes = append(fileTypes, fileType)
	}
	fm.mu.RUnlock()

	var errors []string
	for _, fileType := range fileTypes {
		if err := fm.FlushFile(fileType); err != nil {
			errors = append(errors, err.Error())
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("刷新文件失败: %s", strings.Join(errors, "; "))
	}

	return nil
}

// periodicFlush 定期刷新缓冲区
func (fm *FileManager) periodicFlush() {
	for range fm.flushTicker.C {
		if fm.closed {
			return
		}
		
		if err := fm.FlushAll(); err != nil {
			log.Error().Err(err).Msg("定期刷新缓冲区失败")
		}
	}
}

// Close 关闭文件管理器
func (fm *FileManager) Close() error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	if fm.closed {
		return nil
	}

	fm.closed = true
	fm.flushTicker.Stop()

	var errors []string

	// 刷新并关闭所有文件
	for fileType, buffer := range fm.buffers {
		if err := buffer.Flush(); err != nil {
			errors = append(errors, fmt.Sprintf("刷新 %s: %v", fileType, err))
		}
	}

	for fileType, file := range fm.files {
		if err := file.Close(); err != nil {
			errors = append(errors, fmt.Sprintf("关闭 %s: %v", fileType, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("关闭文件管理器时出现错误: %s", strings.Join(errors, "; "))
	}

	log.Info().Msg("文件管理器已关闭")
	return nil
}

// Reporter 负责处理和输出扫描结果
type Reporter struct {
	mu                sync.RWMutex
	wg                sync.WaitGroup
	config            ReportConfig
	fileManager       *FileManager
	vulnerabilities   []*models.Vulnerability
	scanResults       []*models.ScanResult
	crawlResults      []*models.CrawlResult
	vulnCounts        map[models.VulnerabilityType]int
	severityCounts    map[models.Severity]int
	reportedVulns     map[string]bool
	startTime         time.Time
	endTime           time.Time
	targetURL         string
	ctx               context.Context
	cancel            context.CancelFunc
	closed            bool
	htmlTemplate      *template.Template
	statistics        *ReportStatistics
}

// ReportStatistics 报告统计信息
type ReportStatistics struct {
	TotalVulnerabilities int                                    `json:"total_vulnerabilities"`
	VulnCountBySeverity  map[models.Severity]int               `json:"vuln_count_by_severity"`
	VulnCountByType      map[models.VulnerabilityType]int      `json:"vuln_count_by_type"`
	TotalURLs            int                                    `json:"total_urls"`
	TotalRequests        int                                    `json:"total_requests"`
	ScanDuration         time.Duration                          `json:"scan_duration"`
	StartTime            time.Time                              `json:"start_time"`
	EndTime              time.Time                              `json:"end_time"`
	TargetURL            string                                 `json:"target_url"`
	ScannerVersion       string                                 `json:"scanner_version"`
	ConfigHash           string                                 `json:"config_hash"`
	Metadata             map[string]interface{}                 `json:"metadata,omitempty"`
}

// NewReporter 创建并初始化一个新的 Reporter 实例
func NewReporter(config ReportConfig, targetURL string) (*Reporter, error) {
	// 验证输入参数
	if config.Path == "" {
		return nil, fmt.Errorf("报告路径不能为空")
	}

	if targetURL == "" {
		log.Warn().Msg("目标URL为空")
	}

	// 创建上下文用于优雅关闭
	ctx, cancel := context.WithCancel(context.Background())

	// 创建文件管理器
	fileManager, err := NewFileManager(config, config.Path)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("创建文件管理器失败: %w", err)
	}

	// 创建Reporter实例
	reporter := &Reporter{
		config:            config,
		fileManager:       fileManager,
		startTime:         time.Now(),
		targetURL:         targetURL,
		ctx:               ctx,
		cancel:            cancel,
		closed:            false,
		vulnerabilities:   make([]*models.Vulnerability, 0, 1000),
		scanResults:       make([]*models.ScanResult, 0, 100),
		crawlResults:      make([]*models.CrawlResult, 0, 100),
		vulnCounts:        make(map[models.VulnerabilityType]int),
		severityCounts:    make(map[models.Severity]int),
		reportedVulns:     make(map[string]bool, 1000),
		statistics:        &ReportStatistics{
			VulnCountBySeverity: make(map[models.Severity]int),
			VulnCountByType:     make(map[models.VulnerabilityType]int),
			StartTime:           time.Now(),
			TargetURL:           targetURL,
			ScannerVersion:      "1.0.0",
			Metadata:            make(map[string]interface{}),
		},
	}

	// 初始化HTML模板
	if err := reporter.initHTMLTemplate(); err != nil {
		fileManager.Close()
		cancel()
		return nil, fmt.Errorf("初始化HTML模板失败: %w", err)
	}

	// 创建必要的文件
	if err := reporter.createAllFiles(); err != nil {
		fileManager.Close()
		cancel()
		return nil, fmt.Errorf("创建文件失败: %w", err)
	}

	log.Info().
		Str("reportPath", config.Path).
		Str("targetURL", targetURL).
		Str("format", string(config.Format)).
		Msg("Reporter初始化完成")

	return reporter, nil
}

// createAllFiles 创建所有必要的文件
func (r *Reporter) createAllFiles() error {
	timestamp := time.Now().Format("20060102_150405")
	
	files := map[FileType]string{
		FileTypeSpider:            fmt.Sprintf("spider_%s.txt", timestamp),
		FileTypeUnscopedSpider:    fmt.Sprintf("unscoped_spider_%s.txt", timestamp),
		FileTypeSpiderDeDuplicate: fmt.Sprintf("spider_deduplicate_%s.txt", timestamp),
		FileTypeSpiderParams:      fmt.Sprintf("spider_params_%s.txt", timestamp),
		FileTypeVulnerability:     fmt.Sprintf("vulnerabilities_%s.txt", timestamp),
	}

	for fileType, filename := range files {
		if err := r.fileManager.CreateFile(fileType, filename); err != nil {
			return fmt.Errorf("创建文件 %s 失败: %w", filename, err)
		}
	}

	return nil
}

// initHTMLTemplate 初始化并缓存HTML模板
func (r *Reporter) initHTMLTemplate() error {
	htmlTemplateContent := r.getHTMLTemplate()
	
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"formatTime": func(t time.Time) string {
			return t.Format("2006-01-02 15:04:05")
		},
		"formatDuration": func(d time.Duration) string {
			return d.String()
		},
		"severityClass": func(severity models.Severity) string {
			switch severity {
			case models.SeverityCritical:
				return "critical"
			case models.SeverityHigh:
				return "high"
			case models.SeverityMedium:
				return "medium"
			case models.SeverityLow:
				return "low"
			default:
				return "info"
			}
		},
		"add": func(a, b int) int {
			return a + b
		},
	}).Parse(htmlTemplateContent)
	
	if err != nil {
		return fmt.Errorf("解析HTML模板失败: %w", err)
	}
	
	r.htmlTemplate = tmpl
	return nil
}

// LogSpiderURL 记录爬虫发现的URL
func (r *Reporter) LogSpiderURL(url string) error {
	if r.closed {
		return fmt.Errorf("Reporter已关闭")
	}

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		
		if err := r.fileManager.WriteLineToFile(FileTypeSpider, url); err != nil {
			log.Error().Err(err).Str("url", url).Msg("记录爬虫URL失败")
		}
	}()

	return nil
}

// LogUnscopedSpiderURL 记录超出范围的URL
func (r *Reporter) LogUnscopedSpiderURL(url string) error {
	if r.closed {
		return fmt.Errorf("Reporter已关闭")
	}

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		
		if err := r.fileManager.WriteLineToFile(FileTypeUnscopedSpider, url); err != nil {
			log.Error().Err(err).Str("url", url).Msg("记录超出范围URL失败")
		}
	}()

	return nil
}

// LogSpiderDeDuplicateURL 记录去重后的URL
func (r *Reporter) LogSpiderDeDuplicateURL(url string) error {
	if r.closed {
		return fmt.Errorf("Reporter已关闭")
	}

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		
		if err := r.fileManager.WriteLineToFile(FileTypeSpiderDeDuplicate, url); err != nil {
			log.Error().Err(err).Str("url", url).Msg("记录去重URL失败")
		}
	}()

	return nil
}

// LogSpiderParamsURL 记录带参数的URL
func (r *Reporter) LogSpiderParamsURL(url string) error {
	if r.closed {
		return fmt.Errorf("Reporter已关闭")
	}

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		
		if err := r.fileManager.WriteLineToFile(FileTypeSpiderParams, url); err != nil {
			log.Error().Err(err).Str("url", url).Msg("记录参数URL失败")
		}
	}()

	return nil
}

// AddVulnerability 添加漏洞到报告中
func (r *Reporter) AddVulnerability(vuln *models.Vulnerability) error {
	if r.closed {
		return fmt.Errorf("Reporter已关闭")
	}

	if vuln == nil {
		return fmt.Errorf("漏洞信息不能为空")
	}

	// 检查严重程度过滤
	if r.shouldSkipVulnerability(vuln) {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// 生成漏洞签名用于去重
	signature := r.generateVulnSignature(vuln)
	if r.reportedVulns[signature] {
		log.Debug().
			Str("signature", signature).
			Str("type", string(vuln.Type)).
			Msg("漏洞已存在，跳过")
		return nil
	}

	// 添加漏洞
	r.vulnerabilities = append(r.vulnerabilities, vuln)
	r.reportedVulns[signature] = true
	
	// 更新统计信息
	r.vulnCounts[vuln.Type]++
	r.severityCounts[vuln.Severity]++
	r.statistics.VulnCountByType[vuln.Type]++
	r.statistics.VulnCountBySeverity[vuln.Severity]++
	r.statistics.TotalVulnerabilities++

	// 异步记录到文件
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.logVulnerabilityToFile(vuln)
	}()

	log.Info().
		Str("type", string(vuln.Type)).
		Str("severity", string(vuln.Severity)).
		Str("url", vuln.URL).
		Msg("发现新漏洞")

	return nil
}

// shouldSkipVulnerability 检查是否应该跳过该漏洞
func (r *Reporter) shouldSkipVulnerability(vuln *models.Vulnerability) bool {
	// 检查严重程度过滤
	if vuln.GetSeverityScore() < r.getSeverityScore(r.config.MinSeverity) {
		return true
	}

	// 检查是否包含误报
	if !r.config.IncludeFalsePositives && vuln.Status == "false_positive" {
		return true
	}

	return false
}

// getSeverityScore 获取严重程度分数
func (r *Reporter) getSeverityScore(severity models.Severity) int {
	switch severity {
	case models.SeverityInfo:
		return 1
	case models.SeverityLow:
		return 2
	case models.SeverityMedium:
		return 3
	case models.SeverityHigh:
		return 4
	case models.SeverityCritical:
		return 5
	default:
		return 0
	}
}

// generateVulnSignature 生成漏洞签名用于去重
func (r *Reporter) generateVulnSignature(vuln *models.Vulnerability) string {
	return fmt.Sprintf("%s|%s|%s|%s", 
		vuln.Type, 
		vuln.URL, 
		vuln.Parameter, 
		vuln.Payload)
}

// logVulnerabilityToFile 将漏洞信息记录到文件
func (r *Reporter) logVulnerabilityToFile(vuln *models.Vulnerability) {
	vulnText := fmt.Sprintf("[%s] %s - %s\n  URL: %s\n  Parameter: %s\n  Payload: %s\n  Description: %s\n  Evidence: %s\n  Time: %s\n\n",
		vuln.Severity,
		vuln.Type,
		vuln.Title,
		vuln.URL,
		vuln.Parameter,
		vuln.Payload,
		vuln.Description,
		vuln.Evidence,
		vuln.FoundAt.Format("2006-01-02 15:04:05"))

	if err := r.fileManager.WriteToFile(FileTypeVulnerability, []byte(vulnText)); err != nil {
		log.Error().Err(err).Msg("记录漏洞到文件失败")
	}
}

// AddScanResult 添加扫描结果
func (r *Reporter) AddScanResult(result *models.ScanResult) error {
	if r.closed {
		return fmt.Errorf("Reporter已关闭")
	}

	if result == nil {
		return fmt.Errorf("扫描结果不能为空")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.scanResults = append(r.scanResults, result)
	r.statistics.TotalRequests += result.TotalRequests

	// 添加扫描结果中的漏洞
	for _, vuln := range result.Vulnerabilities {
		// 这里不使用锁，因为AddVulnerability内部已经有锁
		r.mu.Unlock()
		r.AddVulnerability(vuln)
		r.mu.Lock()
	}

	return nil
}

// AddCrawlResult 添加爬取结果
func (r *Reporter) AddCrawlResult(result *models.CrawlResult) error {
	if r.closed {
		return fmt.Errorf("Reporter已关闭")
	}

	if result == nil {
		return fmt.Errorf("爬取结果不能为空")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.crawlResults = append(r.crawlResults, result)
	r.statistics.TotalURLs += result.GetURLCount()

	return nil
}

// GenerateReport 生成最终报告
func (r *Reporter) GenerateReport() error {
	if r.closed {
		return fmt.Errorf("Reporter已关闭")
	}

	r.mu.Lock()
	r.endTime = time.Now()
	r.statistics.EndTime = r.endTime
	r.statistics.ScanDuration = r.endTime.Sub(r.startTime)
	r.mu.Unlock()

	// 等待所有异步操作完成
	r.wg.Wait()

	// 刷新所有文件缓冲区
	if err := r.fileManager.FlushAll(); err != nil {
		log.Error().Err(err).Msg("刷新文件缓冲区失败")
	}

	// 生成不同格式的报告
	timestamp := time.Now().Format("20060102_150405")
	
	switch r.config.Format {
	case FormatJSON:
		return r.generateJSONReport(timestamp)
	case FormatHTML:
		return r.generateHTMLReport(timestamp)
	case FormatXML:
		return r.generateXMLReport(timestamp)
	case FormatCSV:
		return r.generateCSVReport(timestamp)
	case FormatText:
		return r.generateTextReport(timestamp)
	default:
		return fmt.Errorf("不支持的报告格式: %s", r.config.Format)
	}
}

// generateJSONReport 生成JSON格式报告
func (r *Reporter) generateJSONReport(timestamp string) error {
	filename := fmt.Sprintf("report_%s.json", timestamp)
	filepath := filepath.Join(r.config.Path, filename)

	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("创建JSON报告文件失败: %w", err)
	}
	defer file.Close()

	report := r.buildReportData()
	
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("编码JSON报告失败: %w", err)
	}

	log.Info().Str("file", filepath).Msg("JSON报告生成完成")
	return nil
}

// generateHTMLReport 生成HTML格式报告
func (r *Reporter) generateHTMLReport(timestamp string) error {
	filename := fmt.Sprintf("report_%s.html", timestamp)
	filepath := filepath.Join(r.config.Path, filename)

	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("创建HTML报告文件失败: %w", err)
	}
	defer file.Close()

	report := r.buildReportData()
	
	if err := r.htmlTemplate.Execute(file, report); err != nil {
		return fmt.Errorf("生成HTML报告失败: %w", err)
	}

	log.Info().Str("file", filepath).Msg("HTML报告生成完成")
	return nil
}

// generateXMLReport 生成XML格式报告
func (r *Reporter) generateXMLReport(timestamp string) error {
	filename := fmt.Sprintf("report_%s.xml", timestamp)
	filepath := filepath.Join(r.config.Path, filename)

	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("创建XML报告文件失败: %w", err)
	}
	defer file.Close()

	report := r.buildReportData()
	
	encoder := xml.NewEncoder(file)
	encoder.Indent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("编码XML报告失败: %w", err)
	}

	log.Info().Str("file", filepath).Msg("XML报告生成完成")
	return nil
}

// generateCSVReport 生成CSV格式报告
func (r *Reporter) generateCSVReport(timestamp string) error {
	filename := fmt.Sprintf("report_%s.csv", timestamp)
	filepath := filepath.Join(r.config.Path, filename)

	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("创建CSV报告文件失败: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入CSV头部
	header := []string{
		"ID", "Type", "Severity", "Title", "Description", "URL", 
		"Parameter", "Payload", "Evidence", "Status", "Confidence", 
		"Found At", "CWE", "OWASP",
	}
	
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("写入CSV头部失败: %w", err)
	}

	// 写入漏洞数据
	r.mu.RLock()
	vulnerabilities := make([]*models.Vulnerability, len(r.vulnerabilities))
	copy(vulnerabilities, r.vulnerabilities)
	r.mu.RUnlock()

	for _, vuln := range vulnerabilities {
		record := []string{
			vuln.ID,
			string(vuln.Type),
			string(vuln.Severity),
			vuln.Title,
			vuln.Description,
			vuln.URL,
			vuln.Parameter,
			vuln.Payload,
			vuln.Evidence,
			vuln.Status,
			fmt.Sprintf("%.2f", vuln.Confidence),
			vuln.FoundAt.Format("2006-01-02 15:04:05"),
			vuln.CWE,
			vuln.OWASP,
		}
		
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("写入CSV记录失败: %w", err)
		}
	}

	log.Info().Str("file", filepath).Msg("CSV报告生成完成")
	return nil
}

// generateTextReport 生成文本格式报告
func (r *Reporter) generateTextReport(timestamp string) error {
	filename := fmt.Sprintf("report_%s.txt", timestamp)
	filepath := filepath.Join(r.config.Path, filename)

	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("创建文本报告文件失败: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	report := r.buildReportData()

	// 写入报告头部
	fmt.Fprintf(writer, "AutoVulnScan 扫描报告\n")
	fmt.Fprintf(writer, "======================\n\n")
	fmt.Fprintf(writer, "目标URL: %s\n", report.Statistics.TargetURL)
	fmt.Fprintf(writer, "扫描开始时间: %s\n", report.Statistics.StartTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(writer, "扫描结束时间: %s\n", report.Statistics.EndTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(writer, "扫描耗时: %s\n", report.Statistics.ScanDuration.String())
	fmt.Fprintf(writer, "发现漏洞数量: %d\n", report.Statistics.TotalVulnerabilities)
	fmt.Fprintf(writer, "扫描URL数量: %d\n", report.Statistics.TotalURLs)
	fmt.Fprintf(writer, "总请求数量: %d\n\n", report.Statistics.TotalRequests)

	// 按严重程度统计
	fmt.Fprintf(writer, "漏洞严重程度统计:\n")
	fmt.Fprintf(writer, "----------------\n")
	for severity, count := range report.Statistics.VulnCountBySeverity {
		fmt.Fprintf(writer, "%s: %d\n", severity, count)
	}
	fmt.Fprintf(writer, "\n")

	// 按类型统计
	fmt.Fprintf(writer, "漏洞类型统计:\n")
	fmt.Fprintf(writer, "------------\n")
	for vulnType, count := range report.Statistics.VulnCountByType {
		fmt.Fprintf(writer, "%s: %d\n", vulnType, count)
	}
	fmt.Fprintf(writer, "\n")

	// 详细漏洞信息
	if len(report.Vulnerabilities) > 0 {
		fmt.Fprintf(writer, "详细漏洞信息:\n")
		fmt.Fprintf(writer, "============\n\n")
		
		for i, vuln := range report.Vulnerabilities {
			fmt.Fprintf(writer, "%d. %s [%s]\n", i+1, vuln.Title, vuln.Severity)
			fmt.Fprintf(writer, "   类型: %s\n", vuln.Type)
			fmt.Fprintf(writer, "   URL: %s\n", vuln.URL)
			if vuln.Parameter != "" {
				fmt.Fprintf(writer, "   参数: %s\n", vuln.Parameter)
			}
			if vuln.Payload != "" {
				fmt.Fprintf(writer, "   载荷: %s\n", vuln.Payload)
			}
			fmt.Fprintf(writer, "   描述: %s\n", vuln.Description)
			if vuln.Evidence != "" {
				fmt.Fprintf(writer, "   证据: %s\n", vuln.Evidence)
			}
			fmt.Fprintf(writer, "   发现时间: %s\n", vuln.FoundAt.Format("2006-01-02 15:04:05"))
			fmt.Fprintf(writer, "   置信度: %.2f\n", vuln.Confidence)
			fmt.Fprintf(writer, "\n")
		}
	}

	log.Info().Str("file", filepath).Msg("文本报告生成完成")
	return nil
}

// ReportData 报告数据结构
type ReportData struct {
	Statistics      *ReportStatistics        `json:"statistics" xml:"statistics"`
	Vulnerabilities []*models.Vulnerability  `json:"vulnerabilities" xml:"vulnerabilities>vulnerability"`
	ScanResults     []*models.ScanResult     `json:"scan_results,omitempty" xml:"scan_results>scan_result,omitempty"`
	CrawlResults    []*models.CrawlResult    `json:"crawl_results,omitempty" xml:"crawl_results>crawl_result,omitempty"`
	Config          ReportConfig             `json:"config" xml:"config"`
	GeneratedAt     time.Time                `json:"generated_at" xml:"generated_at"`
}

// buildReportData 构建报告数据
func (r *Reporter) buildReportData() *ReportData {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// 深拷贝漏洞数据以避免并发问题
	vulnerabilities := make([]*models.Vulnerability, len(r.vulnerabilities))
	for i, vuln := range r.vulnerabilities {
		vulnerabilities[i] = vuln.Clone()
	}

	// 按严重程度排序漏洞
	sort.Slice(vulnerabilities, func(i, j int) bool {
		return vulnerabilities[i].GetSeverityScore() > vulnerabilities[j].GetSeverityScore()
	})

	return &ReportData{
		Statistics:      r.statistics,
		Vulnerabilities: vulnerabilities,
		ScanResults:     r.scanResults,
		CrawlResults:    r.crawlResults,
		Config:          r.config,
		GeneratedAt:     time.Now(),
	}
}

// GetStatistics 获取统计信息
func (r *Reporter) GetStatistics() *ReportStatistics {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// 返回统计信息的副本
	stats := &ReportStatistics{
		TotalVulnerabilities: r.statistics.TotalVulnerabilities,
		VulnCountBySeverity:  make(map[models.Severity]int),
		VulnCountByType:      make(map[models.VulnerabilityType]int),
		TotalURLs:            r.statistics.TotalURLs,
		TotalRequests:        r.statistics.TotalRequests,
		ScanDuration:         r.statistics.ScanDuration,
		StartTime:            r.statistics.StartTime,
		EndTime:              r.statistics.EndTime,
		TargetURL:            r.statistics.TargetURL,
		ScannerVersion:       r.statistics.ScannerVersion,
		ConfigHash:           r.statistics.ConfigHash,
		Metadata:             make(map[string]interface{}),
	}

	// 深拷贝映射
	for k, v := range r.statistics.VulnCountBySeverity {
		stats.VulnCountBySeverity[k] = v
	}
	for k, v := range r.statistics.VulnCountByType {
		stats.VulnCountByType[k] = v
	}
	for k, v := range r.statistics.Metadata {
		stats.Metadata[k] = v
	}

	return stats
}

// GetVulnerabilities 获取所有漏洞
func (r *Reporter) GetVulnerabilities() []*models.Vulnerability {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// 返回漏洞的副本
	vulnerabilities := make([]*models.Vulnerability, len(r.vulnerabilities))
	for i, vuln := range r.vulnerabilities {
		vulnerabilities[i] = vuln.Clone()
	}

	return vulnerabilities
}

// GetVulnerabilityCount 获取漏洞总数
func (r *Reporter) GetVulnerabilityCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.vulnerabilities)
}

// GetHighSeverityCount 获取高危及以上漏洞数量
func (r *Reporter) GetHighSeverityCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	count := 0
	for _, vuln := range r.vulnerabilities {
		if vuln.Severity == models.SeverityHigh || vuln.Severity == models.SeverityCritical {
			count++
		}
	}
	return count
}

// UpdateMetadata 更新元数据
func (r *Reporter) UpdateMetadata(key string, value interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	if r.statistics.Metadata == nil {
		r.statistics.Metadata = make(map[string]interface{})
	}
	r.statistics.Metadata[key] = value
}

// SetScannerVersion 设置扫描器版本
func (r *Reporter) SetScannerVersion(version string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.statistics.ScannerVersion = version
}

// SetConfigHash 设置配置哈希
func (r *Reporter) SetConfigHash(hash string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.statistics.ConfigHash = hash
}

// ExportToFile 导出数据到指定文件
func (r *Reporter) ExportToFile(filename string, format ReportFormat) error {
	if r.closed {
		return fmt.Errorf("Reporter已关闭")
	}

	filepath := filepath.Join(r.config.Path, filename)
	
	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("创建导出文件失败: %w", err)
	}
	defer file.Close()

	report := r.buildReportData()

	switch format {
	case FormatJSON:
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	case FormatXML:
		encoder := xml.NewEncoder(file)
		encoder.Indent("", "  ")
		return encoder.Encode(report)
	default:
		return fmt.Errorf("不支持的导出格式: %s", format)
	}
}

// Close 关闭Reporter并清理资源
func (r *Reporter) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	r.mu.Unlock()

	// 取消上下文
	if r.cancel != nil {
		r.cancel()
	}

	// 等待所有异步操作完成
	r.wg.Wait()

	// 关闭文件管理器
	var closeErr error
	if r.fileManager != nil {
		closeErr = r.fileManager.Close()
	}

	log.Info().
		Int("vulnerabilities", len(r.vulnerabilities)).
		Str("duration", time.Since(r.startTime).String()).
		Msg("Reporter已关闭")

	return closeErr
}

// getHTMLTemplate 获取HTML模板内容
func (r *Reporter) getHTMLTemplate() string {
	return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AutoVulnScan 扫描报告</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 300;
        }
        
        .header .subtitle {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .content {
            padding: 40px;
        }
        
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        
        .summary-card {
            background: #f8f9fa;
            padding: 25px;
            border-radius: 10px;
            border-left: 4px solid #667eea;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .summary-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
        }
        
        .summary-card h3 {
            color: #667eea;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }
        
        .summary-card .value {
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }
        
        .severity-stats, .type-stats {
            margin: 40px 0;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        
        .stat-item {
            background: white;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #e1e8ed;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: all 0.3s ease;
        }
        
        .stat-item:hover {
            border-color: #667eea;
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.1);
        }
        
        .stat-label {
            font-weight: 500;
        }
        
        .stat-value {
            font-size: 1.2em;
            font-weight: bold;
            padding: 5px 12px;
            border-radius: 20px;
            color: white;
        }
        
        .severity-critical { background: #dc3545; }
        .severity-high { background: #fd7e14; }
        .severity-medium { background: #ffc107; color: #333 !important; }
        .severity-low { background: #28a745; }
        .severity-info { background: #17a2b8; }
        
        .vulnerabilities {
            margin-top: 40px;
        }
        
        .vuln-item {
            background: white;
            border: 1px solid #e1e8ed;
            border-radius: 10px;
            margin-bottom: 20px;
            overflow: hidden;
            transition: all 0.3s ease;
        }
        
        .vuln-item:hover {
            box-shadow: 0 8px 25px rgba(0,0,0,0.1);
            border-color: #667eea;
        }
        
        .vuln-header {
            padding: 20px;
            background: #f8f9fa;
            border-bottom: 1px solid #e1e8ed;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .vuln-title {
            font-size: 1.1em;
            font-weight: 600;
            color: #333;
        }
        
        .vuln-severity {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
            color: white;
        }
        
        .vuln-body {
            padding: 20px;
        }
        
        .vuln-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        
        .detail-group {
            margin-bottom: 15px;
        }
        
        .detail-label {
            font-weight: 600;
            color: #667eea;
            margin-bottom: 5px;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .detail-value {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            border-left: 3px solid #667eea;
            word-break: break-all;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }
        
        .no-vulnerabilities {
            text-align: center;
            padding: 60px 20px;
            color: #28a745;
        }
        
        .no-vulnerabilities .icon {
            font-size: 4em;
            margin-bottom: 20px;
        }
        
        .no-vulnerabilities h3 {
            font-size: 1.5em;
            margin-bottom: 10px;
        }
        
        .footer {
            background: #f8f9fa;
            padding: 30px;
            text-align: center;
            color: #6c757d;
            border-top: 1px solid #e1e8ed;
        }
        
        .section-title {
            font-size: 1.8em;
            color: #333;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
            display: flex;
            align-items: center;
        }
        
        .section-title::before {
            content: '';
            width: 4px;
            height: 30px;
            background: #667eea;
            margin-right: 15px;
            border-radius: 2px;
        }
        
        @media (max-width: 768px) {
            .container {
                margin: 10px;
                border-radius: 10px;
            }
            
            .header {
                padding: 30px 20px;
            }
            
            .header h1 {
                font-size: 2em;
            }
            
            .content {
                padding: 20px;
            }
            
            .summary {
                grid-template-columns: 1fr;
            }
            
            .vuln-details {
                grid-template-columns: 1fr;
            }
        }
        
        .progress-bar {
            background: #e9ecef;
            border-radius: 10px;
            overflow: hidden;
            height: 8px;
            margin-top: 10px;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea, #764ba2);
            transition: width 0.3s ease;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ AutoVulnScan</h1>
            <div class="subtitle">安全漏洞扫描报告</div>
        </div>
        
        <div class="content">
            <div class="summary">
                <div class="summary-card">
                    <h3>目标URL</h3>
                    <div class="value" style="font-size: 1em; word-break: break-all;">{{.Statistics.TargetURL}}</div>
                </div>
                <div class="summary-card">
                    <h3>发现漏洞</h3>
                    <div class="value">{{.Statistics.TotalVulnerabilities}}</div>
                </div>
                <div class="summary-card">
                    <h3>扫描URL</h3>
                    <div class="value">{{.Statistics.TotalURLs}}</div>
                </div>
                <div class="summary-card">
                    <h3>总请求数</h3>
                    <div class="value">{{.Statistics.TotalRequests}}</div>
                </div>
                <div class="summary-card">
                    <h3>扫描耗时</h3>
                    <div class="value" style="font-size: 1.2em;">{{formatDuration .Statistics.ScanDuration}}</div>
                </div>
                <div class="summary-card">
                    <h3>扫描时间</h3>
                    <div class="value" style="font-size: 0.9em;">{{formatTime .Statistics.StartTime}}</div>
                </div>
            </div>
            
            {{if .Statistics.VulnCountBySeverity}}
            <div class="severity-stats">
                <h2 class="section-title">漏洞严重程度统计</h2>
                <div class="stats-grid">
                    {{range $severity, $count := .Statistics.VulnCountBySeverity}}
                    {{if gt $count 0}}
                    <div class="stat-item">
                        <span class="stat-label">{{$severity}}</span>
                        <span class="stat-value {{severityClass $severity}}">{{$count}}</span>
                    </div>
                    {{end}}
                    {{end}}
                </div>
            </div>
            {{end}}
            
            {{if .Statistics.VulnCountByType}}
            <div class="type-stats">
                <h2 class="section-title">漏洞类型统计</h2>
                <div class="stats-grid">
                    {{range $type, $count := .Statistics.VulnCountByType}}
                    {{if gt $count 0}}
                    <div class="stat-item">
                        <span class="stat-label">{{$type}}</span>
                        <span class="stat-value" style="background: #667eea;">{{$count}}</span>
                    </div>
                    {{end}}
                    {{end}}
                </div>
            </div>
            {{end}}
            
            <div class="vulnerabilities">
                <h2 class="section-title">详细漏洞信息</h2>
                {{if .Vulnerabilities}}
                    {{range $index, $vuln := .Vulnerabilities}}
                    <div class="vuln-item">
                        <div class="vuln-header">
                            <div class="vuln-title">{{add $index 1}}. {{$vuln.Title}}</div>
                            <div class="vuln-severity {{severityClass $vuln.Severity}}">{{$vuln.Severity}}</div>
                        </div>
                        <div class="vuln-body">
                            <div class="vuln-details">
                                <div>
                                    <div class="detail-group">
                                        <div class="detail-label">漏洞类型</div>
                                        <div class="detail-value">{{$vuln.Type}}</div>
                                    </div>
                                    <div class="detail-group">
                                        <div class="detail-label">URL</div>
                                        <div class="detail-value">{{$vuln.URL}}</div>
                                    </div>
                                    {{if $vuln.Parameter}}
                                    <div class="detail-group">
                                        <div class="detail-label">参数</div>
                                        <div class="detail-value">{{$vuln.Parameter}}</div>
                                    </div>
                                    {{end}}
                                </div>
                                <div>
                                    {{if $vuln.Payload}}
                                    <div class="detail-group">
                                        <div class="detail-label">攻击载荷</div>
                                        <div class="detail-value">{{$vuln.Payload}}</div>
                                    </div>
                                    {{end}}
                                    <div class="detail-group">
                                        <div class="detail-label">描述</div>
                                        <div class="detail-value">{{$vuln.Description}}</div>
                                    </div>
                                    {{if $vuln.Evidence}}
                                    <div class="detail-group">
                                        <div class="detail-label">证据</div>
                                        <div class="detail-value">{{$vuln.Evidence}}</div>
                                    </div>
                                    {{end}}
                                </div>
                            </div>
                            <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #e1e8ed; font-size: 0.9em; color: #6c757d;">
                                <strong>发现时间:</strong> {{formatTime $vuln.FoundAt}} | 
                                <strong>置信度:</strong> {{printf "%.0f%%" (mul $vuln.Confidence 100)}}
                                {{if $vuln.CWE}} | <strong>CWE:</strong> {{$vuln.CWE}}{{end}}
                                {{if $vuln.OWASP}} | <strong>OWASP:</strong> {{$vuln.OWASP}}{{end}}
                            </div>
                        </div>
                    </div>
                    {{end}}
                {{else}}
                    <div class="no-vulnerabilities">
                        <div class="icon">🎉</div>
                        <h3>未发现安全漏洞</h3>
                        <p>恭喜！本次扫描未发现任何安全漏洞。</p>
                    </div>
                {{end}}
            </div>
        </div>
        
        <div class="footer">
            <p>报告生成时间: {{formatTime .GeneratedAt}}</p>
            <p>AutoVulnScan v{{.Statistics.ScannerVersion}} - 自动化漏洞扫描工具</p>
        </div>
    </div>
</body>
</html>`
}

// ReportManager 报告管理器，用于管理多个Reporter实例
type ReportManager struct {
	mu        sync.RWMutex
	reporters map[string]*Reporter
	config    ReportConfig
}

// NewReportManager 创建报告管理器
func NewReportManager(config ReportConfig) *ReportManager {
	return &ReportManager{
		reporters: make(map[string]*Reporter),
		config:    config,
	}
}

// CreateReporter 创建新的Reporter
func (rm *ReportManager) CreateReporter(id, targetURL string) (*Reporter, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if _, exists := rm.reporters[id]; exists {
		return nil, fmt.Errorf("Reporter ID %s 已存在", id)
	}

	reporter, err := NewReporter(rm.config, targetURL)
	if err != nil {
		return nil, fmt.Errorf("创建Reporter失败: %w", err)
	}

	rm.reporters[id] = reporter
	return reporter, nil
}

// GetReporter 获取指定ID的Reporter
func (rm *ReportManager) GetReporter(id string) (*Reporter, bool) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	reporter, exists := rm.reporters[id]
	return reporter, exists
}

// RemoveReporter 移除并关闭指定ID的Reporter
func (rm *ReportManager) RemoveReporter(id string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	reporter, exists := rm.reporters[id]
	if !exists {
		return fmt.Errorf("Reporter ID %s 不存在", id)
	}

	if err := reporter.Close(); err != nil {
		log.Error().Err(err).Str("id", id).Msg("关闭Reporter失败")
	}

	delete(rm.reporters, id)
	return nil
}

// ListReporters 列出所有Reporter ID
func (rm *ReportManager) ListReporters() []string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	ids := make([]string, 0, len(rm.reporters))
	for id := range rm.reporters {
		ids = append(ids, id)
	}
	return ids
}

// CloseAll 关闭所有Reporter
func (rm *ReportManager) CloseAll() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	var errors []string
	for id, reporter := range rm.reporters {
		if err := reporter.Close(); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", id, err))
		}
	}

	rm.reporters = make(map[string]*Reporter)

	if len(errors) > 0 {
		return fmt.Errorf("关闭Reporter时出现错误: %s", strings.Join(errors, "; "))
	}

	return nil
}

// GetAllStatistics 获取所有Reporter的统计信息
func (rm *ReportManager) GetAllStatistics() map[string]*ReportStatistics {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	stats := make(map[string]*ReportStatistics)
	for id, reporter := range rm.reporters {
		stats[id] = reporter.GetStatistics()
	}
	return stats
}

// ReportExporter 报告导出器
type ReportExporter struct {
	config ReportConfig
}

// NewReportExporter 创建报告导出器
func NewReportExporter(config ReportConfig) *ReportExporter {
	return &ReportExporter{
		config: config,
	}
}

// ExportVulnerabilities 导出漏洞数据
func (re *ReportExporter) ExportVulnerabilities(vulns []*models.Vulnerability, format ReportFormat, outputPath string) error {
	switch format {
	case FormatJSON:
		return re.exportVulnerabilitiesJSON(vulns, outputPath)
	case FormatCSV:
		return re.exportVulnerabilitiesCSV(vulns, outputPath)
	case FormatXML:
		return re.exportVulnerabilitiesXML(vulns, outputPath)
	default:
		return fmt.Errorf("不支持的导出格式: %s", format)
	}
}

// exportVulnerabilitiesJSON 导出JSON格式漏洞数据
func (re *ReportExporter) exportVulnerabilitiesJSON(vulns []*models.Vulnerability, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建JSON文件失败: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	
	exportData := struct {
		Vulnerabilities []*models.Vulnerability `json:"vulnerabilities"`
		ExportedAt      time.Time               `json:"exported_at"`
		Count           int                     `json:"count"`
	}{
		Vulnerabilities: vulns,
		ExportedAt:      time.Now(),
		Count:           len(vulns),
	}

	return encoder.Encode(exportData)
}

// exportVulnerabilitiesCSV 导出CSV格式漏洞数据
func (re *ReportExporter) exportVulnerabilitiesCSV(vulns []*models.Vulnerability, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建CSV文件失败: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入头部
	header := []string{
		"ID", "Type", "Severity", "Title", "Description", "URL", 
		"Parameter", "Payload", "Evidence", "Status", "Confidence", 
		"Found At", "CWE", "OWASP", "Solution",
	}
	
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("写入CSV头部失败: %w", err)
	}

	// 写入数据
	for _, vuln := range vulns {
		record := []string{
			vuln.ID,
			string(vuln.Type),
			string(vuln.Severity),
			vuln.Title,
			vuln.Description,
			vuln.URL,
			vuln.Parameter,
			vuln.Payload,
			vuln.Evidence,
			vuln.Status,
			fmt.Sprintf("%.2f", vuln.Confidence),
			vuln.FoundAt.Format("2006-01-02 15:04:05"),
			vuln.CWE,
			vuln.OWASP,
			vuln.Solution,
		}
		
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("写入CSV记录失败: %w", err)
		}
	}

	return nil
}

// exportVulnerabilitiesXML 导出XML格式漏洞数据
func (re *ReportExporter) exportVulnerabilitiesXML(vulns []*models.Vulnerability, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建XML文件失败: %w", err)
	}
	defer file.Close()

	encoder := xml.NewEncoder(file)
	encoder.Indent("", "  ")

	// 写入XML头部
	if _, err := file.WriteString(xml.Header); err != nil {
		return fmt.Errorf("写入XML头部失败: %w", err)
	}

	exportData := struct {
		XMLName         xml.Name                `xml:"vulnerabilities"`
		Vulnerabilities []*models.Vulnerability `xml:"vulnerability"`
		ExportedAt      time.Time               `xml:"exported_at,attr"`
		Count           int                     `xml:"count,attr"`
	}{
		Vulnerabilities: vulns,
		ExportedAt:      time.Now(),
		Count:           len(vulns),
	}

	return encoder.Encode(exportData)
}

// ReportFilter 报告过滤器
type ReportFilter struct {
	MinSeverity           models.Severity              `json:"min_severity"`
	MaxSeverity           models.Severity              `json:"max_severity"`
	VulnerabilityTypes    []models.VulnerabilityType   `json:"vulnerability_types"`
	ExcludeTypes          []models.VulnerabilityType   `json:"exclude_types"`
	IncludeFalsePositives bool                         `json:"include_false_positives"`
	MinConfidence         float64                      `json:"min_confidence"`
	MaxConfidence         float64                      `json:"max_confidence"`
	URLPattern            string                       `json:"url_pattern"`
	ParameterPattern      string                       `json:"parameter_pattern"`
	StartTime             *time.Time                   `json:"start_time,omitempty"`
	EndTime               *time.Time                   `json:"end_time,omitempty"`
	Tags                  []string                     `json:"tags,omitempty"`
	ExcludeTags           []string                     `json:"exclude_tags,omitempty"`
	Status                []string                     `json:"status,omitempty"`
	Limit                 int                          `json:"limit,omitempty"`
	Offset                int                          `json:"offset,omitempty"`
}

// DefaultReportFilter 返回默认过滤器
func DefaultReportFilter() *ReportFilter {
	return &ReportFilter{
		MinSeverity:           models.SeverityInfo,
		MaxSeverity:           models.SeverityCritical,
		IncludeFalsePositives: false,
		MinConfidence:         0.0,
		MaxConfidence:         1.0,
		Limit:                 1000,
		Offset:                0,
	}
}

// ApplyFilter 应用过滤器到漏洞列表
func (rf *ReportFilter) ApplyFilter(vulns []*models.Vulnerability) []*models.Vulnerability {
	if len(vulns) == 0 {
		return vulns
	}

	var filtered []*models.Vulnerability

	for _, vuln := range vulns {
		if rf.shouldIncludeVulnerability(vuln) {
			filtered = append(filtered, vuln)
		}
	}

	// 应用分页
	if rf.Offset > 0 || rf.Limit > 0 {
		start := rf.Offset
		if start > len(filtered) {
			return []*models.Vulnerability{}
		}

		end := len(filtered)
		if rf.Limit > 0 && start+rf.Limit < end {
			end = start + rf.Limit
		}

		filtered = filtered[start:end]
	}

	return filtered
}

// shouldIncludeVulnerability 检查是否应该包含该漏洞
func (rf *ReportFilter) shouldIncludeVulnerability(vuln *models.Vulnerability) bool {
	// 检查严重程度
	if vuln.GetSeverityScore() < rf.getSeverityScore(rf.MinSeverity) ||
		vuln.GetSeverityScore() > rf.getSeverityScore(rf.MaxSeverity) {
		return false
	}

	// 检查漏洞类型
	if len(rf.VulnerabilityTypes) > 0 {
		found := false
		for _, vType := range rf.VulnerabilityTypes {
			if vuln.Type == vType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// 检查排除类型
	for _, excludeType := range rf.ExcludeTypes {
		if vuln.Type == excludeType {
			return false
		}
	}

	// 检查误报
	if !rf.IncludeFalsePositives && vuln.Status == "false_positive" {
		return false
	}

	// 检查置信度
	if vuln.Confidence < rf.MinConfidence || vuln.Confidence > rf.MaxConfidence {
		return false
	}

	// 检查URL模式
	if rf.URLPattern != "" {
		matched, err := filepath.Match(rf.URLPattern, vuln.URL)
		if err != nil || !matched {
			return false
		}
	}

	// 检查参数模式
	if rf.ParameterPattern != "" && vuln.Parameter != "" {
		matched, err := filepath.Match(rf.ParameterPattern, vuln.Parameter)
		if err != nil || !matched {
			return false
		}
	}

	// 检查时间范围
	if rf.StartTime != nil && vuln.FoundAt.Before(*rf.StartTime) {
		return false
	}
	if rf.EndTime != nil && vuln.FoundAt.After(*rf.EndTime) {
		return false
	}

	// 检查标签
	if len(rf.Tags) > 0 {
		hasRequiredTag := false
		for _, tag := range rf.Tags {
			if vuln.HasTag(tag) {
				hasRequiredTag = true
				break
			}
		}
		if !hasRequiredTag {
			return false
		}
	}

	// 检查排除标签
	for _, excludeTag := range rf.ExcludeTags {
		if vuln.HasTag(excludeTag) {
			return false
		}
	}

	// 检查状态
	if len(rf.Status) > 0 {
		statusMatch := false
		for _, status := range rf.Status {
			if vuln.Status == status {
				statusMatch = true
				break
			}
		}
		if !statusMatch {
			return false
		}
	}

	return true
}

// getSeverityScore 获取严重程度分数
func (rf *ReportFilter) getSeverityScore(severity models.Severity) int {
	switch severity {
	case models.SeverityInfo:
		return 1
	case models.SeverityLow:
		return 2
	case models.SeverityMedium:
		return 3
	case models.SeverityHigh:
		return 4
	case models.SeverityCritical:
		return 5
	default:
		return 0
	}
}

// ReportScheduler 报告调度器，用于定时生成报告
type ReportScheduler struct {
	mu        sync.RWMutex
	reporters map[string]*Reporter
	config    ReportConfig
	ticker    *time.Ticker
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

// NewReportScheduler 创建报告调度器
func NewReportScheduler(config ReportConfig, interval time.Duration) *ReportScheduler {
	ctx, cancel := context.WithCancel(context.Background())
	
	rs := &ReportScheduler{
		reporters: make(map[string]*Reporter),
		config:    config,
		ticker:    time.NewTicker(interval),
		ctx:       ctx,
		cancel:    cancel,
	}

	// 启动调度器
	rs.wg.Add(1)
	go rs.run()

	return rs
}

// AddReporter 添加Reporter到调度器
func (rs *ReportScheduler) AddReporter(id string, reporter *Reporter) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.reporters[id] = reporter
}

// RemoveReporter 从调度器移除Reporter
func (rs *ReportScheduler) RemoveReporter(id string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	delete(rs.reporters, id)
}

// run 运行调度器
func (rs *ReportScheduler) run() {
	defer rs.wg.Done()
	
	for {
		select {
		case <-rs.ctx.Done():
			return
		case <-rs.ticker.C:
			rs.generateScheduledReports()
		}
	}
}

// generateScheduledReports 生成定时报告
func (rs *ReportScheduler) generateScheduledReports() {
	rs.mu.RLock()
	reporters := make(map[string]*Reporter)
	for id, reporter := range rs.reporters {
		reporters[id] = reporter
	}
	rs.mu.RUnlock()

	for id, reporter := range reporters {
		go func(reporterID string, r *Reporter) {
			if err := r.GenerateReport(); err != nil {
				log.Error().
					Err(err).
					Str("reporter_id", reporterID).
					Msg("定时生成报告失败")
			} else {
				log.Info().
					Str("reporter_id", reporterID).
					Msg("定时报告生成完成")
			}
		}(id, reporter)
	}
}

// Stop 停止调度器
func (rs *ReportScheduler) Stop() {
	rs.cancel()
	rs.ticker.Stop()
	rs.wg.Wait()
	
	log.Info().Msg("报告调度器已停止")
}

// ReportCompressor 报告压缩器
type ReportCompressor struct {
	config ReportConfig
}

// NewReportCompressor 创建报告压缩器
func NewReportCompressor(config ReportConfig) *ReportCompressor {
	return &ReportCompressor{
		config: config,
	}
}

// CompressReports 压缩报告文件
func (rc *ReportCompressor) CompressReports(inputPaths []string, outputPath string) error {
	// 这里可以实现ZIP或其他格式的压缩
	// 为了简化，这里只是示例实现
	log.Info().
		Strs("input_paths", inputPaths).
		Str("output_path", outputPath).
		Msg("压缩报告文件")
	
	// TODO: 实现实际的压缩逻辑
	return nil
}

// ReportValidator 报告验证器
type ReportValidator struct{}

// NewReportValidator 创建报告验证器
func NewReportValidator() *ReportValidator {
	return &ReportValidator{}
}

// ValidateReport 验证报告数据
func (rv *ReportValidator) ValidateReport(report *ReportData) error {
	if report == nil {
		return fmt.Errorf("报告数据不能为空")
	}

	if report.Statistics == nil {
		return fmt.Errorf("报告统计信息不能为空")
	}

	// 验证漏洞数据
	for i, vuln := range report.Vulnerabilities {
		if err := rv.validateVulnerability(vuln); err != nil {
			return fmt.Errorf("漏洞 %d 验证失败: %w", i, err)
		}
	}

	// 验证统计数据一致性
	if len(report.Vulnerabilities) != report.Statistics.TotalVulnerabilities {
		return fmt.Errorf("漏洞数量不一致: 实际 %d, 统计 %d", 
			len(report.Vulnerabilities), report.Statistics.TotalVulnerabilities)
	}

	return nil
}

// validateVulnerability 验证单个漏洞数据
func (rv *ReportValidator) validateVulnerability(vuln *models.Vulnerability) error {
	if vuln == nil {
		return fmt.Errorf("漏洞数据不能为空")
	}

	if vuln.ID == "" {
		return fmt.Errorf("漏洞ID不能为空")
	}

	if vuln.Title == "" {
		return fmt.Errorf("漏洞标题不能为空")
	}

	if vuln.URL == "" {
		return fmt.Errorf("漏洞URL不能为空")
	}

	if vuln.Confidence < 0 || vuln.Confidence > 1 {
		return fmt.Errorf("漏洞置信度必须在0-1之间")
	}

	return nil
}

// 工具函数

// MergeReports 合并多个报告
func MergeReports(reports ...*ReportData) (*ReportData, error) {
	if len(reports) == 0 {
		return nil, fmt.Errorf("没有报告可合并")
	}

	merged := &ReportData{
		Statistics: &ReportStatistics{
			VulnCountBySeverity: make(map[models.Severity]int),
			VulnCountByType:     make(map[models.VulnerabilityType]int),
			Metadata:            make(map[string]interface{}),
		},
		Vulnerabilities: make([]*models.Vulnerability, 0),
		ScanResults:     make([]*models.ScanResult, 0),
		CrawlResults:    make([]*models.CrawlResult, 0),
		GeneratedAt:     time.Now(),
	}

	// 合并数据
	for _, report := range reports {
		if report == nil {
			continue
		}

		// 合并漏洞
		merged.Vulnerabilities = append(merged.Vulnerabilities, report.Vulnerabilities...)
		
		// 合并扫描结果
		merged.ScanResults = append(merged.ScanResults, report.ScanResults...)
		
		// 合并爬取结果
		merged.CrawlResults = append(merged.CrawlResults, report.CrawlResults...)

		// 合并统计信息
		if report.Statistics != nil {
			merged.Statistics.TotalURLs += report.Statistics.TotalURLs
			merged.Statistics.TotalRequests += report.Statistics.TotalRequests
			
			for severity, count := range report.Statistics.VulnCountBySeverity {
				merged.Statistics.VulnCountBySeverity[severity] += count
			}
			
			for vulnType, count := range report.Statistics.VulnCountByType {
				merged.Statistics.VulnCountByType[vulnType] += count
			}
		}
	}

	// 更新总漏洞数
	merged.Statistics.TotalVulnerabilities = len(merged.Vulnerabilities)

	// 设置时间范围
	if len(reports) > 0 && reports[0].Statistics != nil {
		merged.Statistics.StartTime = reports[0].Statistics.StartTime
		merged.Statistics.EndTime = reports[0].Statistics.EndTime
		
		for _, report := range reports[1:] {
			if report.Statistics == nil {
				continue
			}
			
			if report.Statistics.StartTime.Before(merged.Statistics.StartTime) {
				merged.Statistics.StartTime = report.Statistics.StartTime
			}
			
			if report.Statistics.EndTime.After(merged.Statistics.EndTime) {
				merged.Statistics.EndTime = report.Statistics.EndTime
			}
		}
		
		merged.Statistics.ScanDuration = merged.Statistics.EndTime.Sub(merged.Statistics.StartTime)
	}

	return merged, nil
}

// SortVulnerabilities 按指定条件排序漏洞
func SortVulnerabilities(vulns []*models.Vulnerability, sortBy string, ascending bool) {
	sort.Slice(vulns, func(i, j int) bool {
		var result bool
		
		switch sortBy {
		case "severity":
			result = vulns[i].GetSeverityScore() < vulns[j].GetSeverityScore()
		case "type":
			result = string(vulns[i].Type) < string(vulns[j].Type)
		case "url":
			result = vulns[i].URL < vulns[j].URL
		case "confidence":
			result = vulns[i].Confidence < vulns[j].Confidence
		case "found_at":
			result = vulns[i].FoundAt.Before(vulns[j].FoundAt)
		default:
			result = vulns[i].Title < vulns[j].Title
		}
		
		if !ascending {
			result = !result
		}
		
		return result
	})
}

// GroupVulnerabilitiesByType 按类型分组漏洞
func GroupVulnerabilitiesByType(vulns []*models.Vulnerability) map[models.VulnerabilityType][]*models.Vulnerability {
	groups := make(map[models.VulnerabilityType][]*models.Vulnerability)
	
	for _, vuln := range vulns {
		groups[vuln.Type] = append(groups[vuln.Type], vuln)
	}
	
	return groups
}

// GroupVulnerabilitiesBySeverity 按严重程度分组漏洞
func GroupVulnerabilitiesBySeverity(vulns []*models.Vulnerability) map[models.Severity][]*models.Vulnerability {
	groups := make(map[models.Severity][]*models.Vulnerability)
	
	for _, vuln := range vulns {
		groups[vuln.Severity] = append(groups[vuln.Severity], vuln)
	}
	
	return groups
}

// CalculateRiskScore 计算风险分数
func CalculateRiskScore(vulns []*models.Vulnerability) float64 {
	if len(vulns) == 0 {
		return 0.0
	}

	var totalScore float64
	for _, vuln := range vulns {
		severityScore := float64(vuln.GetSeverityScore())
		confidenceScore := vuln.Confidence
		totalScore += severityScore * confidenceScore
	}

	return totalScore / float64(len(vulns))
}


