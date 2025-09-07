// Package vulnscan 提供了核心的漏洞扫描引擎和插件管理机制。
package vulnscan

import (
	"sync"
	"time"
)

// StatsType 统计类型
type StatsType string

const (
	// StatsTypeScan 扫描统计
	StatsTypeScan StatsType = "scan"
	// StatsTypeVulnerability 漏洞统计
	StatsTypeVulnerability StatsType = "vulnerability"
	// StatsTypePerformance 性能统计
	StatsTypePerformance StatsType = "performance"
	// StatsTypeReport 报告统计
	StatsTypeReport StatsType = "report"
	// StatsTypePlugin 插件统计
	StatsTypePlugin StatsType = "plugin"
)

// ScanStats 扫描统计
type ScanStats struct {
	TotalRequests      int64         `json:"total_requests"`
	SuccessfulRequests int64         `json:"successful_requests"`
	FailedRequests     int64         `json:"failed_requests"`
	TotalScans         int64         `json:"total_scans"`
	SuccessfulScans    int64         `json:"successful_scans"`
	FailedScans        int64         `json:"failed_scans"`
	TotalTargets       int64         `json:"total_targets"`
	ScannedTargets     int64         `json:"scanned_targets"`
	ScanStartTime      time.Time     `json:"scan_start_time"`
	ScanEndTime        time.Time     `json:"scan_end_time"`
	TotalScanTime      time.Duration `json:"total_scan_time"`
	AverageScanTime    time.Duration `json:"average_scan_time"`
	LastScanTime       time.Time     `json:"last_scan_time"`
}

// VulnerabilityStats 漏洞统计
type VulnerabilityStats struct {
	TotalVulnerabilities     int64                       `json:"total_vulnerabilities"`
	VulnerabilitiesByType    map[string]int64            `json:"vulnerabilities_by_type"`
	VulnerabilitiesBySeverity map[SeverityLevel]int64    `json:"vulnerabilities_by_severity"`
	VulnerabilitiesByPlugin map[string]int64            `json:"vulnerabilities_by_plugin"`
	ConfirmedVulnerabilities int64                      `json:"confirmed_vulnerabilities"`
	FalsePositives          int64                       `json:"false_positives"`
	AverageConfidence       float64                     `json:"average_confidence"`
	VulnerabilityTrend      []VulnerabilityTrendPoint   `json:"vulnerability_trend"`
}

// VulnerabilityTrendPoint 漏洞趋势点
type VulnerabilityTrendPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Count     int64     `json:"count"`
	Type      string    `json:"type"`
	Severity  string    `json:"severity"`
}

// PerformanceStats 性能统计
type PerformanceStats struct {
	AverageResponseTime    time.Duration `json:"average_response_time"`
	MinResponseTime       time.Duration `json:"min_response_time"`
	MaxResponseTime       time.Duration `json:"max_response_time"`
	TotalProcessingTime   time.Duration `json:"total_processing_time"`
	RequestsPerSecond     float64       `json:"requests_per_second"`
	MemoryUsage           int64         `json:"memory_usage"`
	CPUUsage              float64       `json:"cpu_usage"`
	NetworkUsage          int64         `json:"network_usage"`
	CacheHitRate          float64       `json:"cache_hit_rate"`
	ErrorRate             float64       `json:"error_rate"`
	RetryRate             float64       `json:"retry_rate"`
	TimeoutRate           float64       `json:"timeout_rate"`
}

// ReportStats 报告统计
type ReportStats struct {
	TotalReports          int64            `json:"total_reports"`
	ReportsByFormat      map[string]int64 `json:"reports_by_format"`
	ReportsByType        map[string]int64 `json:"reports_by_type"`
	AverageReportSize     int64            `json:"average_report_size"`
	LastReportTime       time.Time        `json:"last_report_time"`
	ReportGenerationTime time.Duration    `json:"report_generation_time"`
}

// PluginStats 插件统计
type PluginStats struct {
	TotalPlugins         int64                     `json:"total_plugins"`
	ActivePlugins        int64                     `json:"active_plugins"`
	PluginsByType        map[string]int64          `json:"plugins_by_type"`
	PluginExecutionTime  map[string]time.Duration `json:"plugin_execution_time"`
	PluginSuccessRate    map[string]float64       `json:"plugin_success_rate"`
	PluginErrorCount     map[string]int64         `json:"plugin_error_count"`
	LastPluginExecution  map[string]time.Time     `json:"last_plugin_execution"`
}

// StatsManager 统计管理器接口
type StatsManager interface {
	// UpdateScanStats 更新扫描统计
	UpdateScanStats(stats ScanStats)
	// UpdateVulnerabilityStats 更新漏洞统计
	UpdateVulnerabilityStats(stats VulnerabilityStats)
	// UpdatePerformanceStats 更新性能统计
	UpdatePerformanceStats(stats PerformanceStats)
	// UpdateReportStats 更新报告统计
	UpdateReportStats(stats ReportStats)
	// UpdatePluginStats 更新插件统计
	UpdatePluginStats(stats PluginStats)
	// IncrementRequestCount 增加请求计数
	IncrementRequestCount(success bool)
	// IncrementScanCount 增加扫描计数
	IncrementScanCount(success bool)
	// IncrementVulnerabilityCount 增加漏洞计数
	IncrementVulnerabilityCount(vulnType string, severity SeverityLevel, pluginName string)
	// AddVulnerabilityTrendPoint 添加漏洞趋势点
	AddVulnerabilityTrendPoint(point VulnerabilityTrendPoint)
	// UpdateResponseTime 更新响应时间
	UpdateResponseTime(responseTime time.Duration)
	// UpdateMemoryUsage 更新内存使用
	UpdateMemoryUsage(memoryUsage int64)
	// UpdateCPUUsage 更新CPU使用
	UpdateCPUUsage(cpuUsage float64)
	// UpdateNetworkUsage 更新网络使用
	UpdateNetworkUsage(networkUsage int64)
	// UpdateCacheStats 更新缓存统计
	UpdateCacheStats(hits, misses int64)
	// UpdateErrorStats 更新错误统计
	UpdateErrorStats(errors, retries, timeouts int64)
	// UpdatePluginExecutionTime 更新插件执行时间
	UpdatePluginExecutionTime(pluginName string, executionTime time.Duration)
	// UpdatePluginSuccessRate 更新插件成功率
	UpdatePluginSuccessRate(pluginName string, success bool)
	// UpdatePluginErrorCount 更新插件错误计数
	UpdatePluginErrorCount(pluginName string)
	// GetScanStats 获取扫描统计
	GetScanStats() ScanStats
	// GetVulnerabilityStats 获取漏洞统计
	GetVulnerabilityStats() VulnerabilityStats
	// GetPerformanceStats 获取性能统计
	GetPerformanceStats() PerformanceStats
	// GetReportStats 获取报告统计
	GetReportStats() ReportStats
	// GetPluginStats 获取插件统计
	GetPluginStats() PluginStats
	// GetAllStats 获取所有统计
	GetAllStats() map[string]interface{}
	// ResetStats 重置统计
	ResetStats()
	// StartScan 开始扫描
	StartScan()
	// EndScan 结束扫描
	EndScan()
	// ExportStats 导出统计
	ExportStats() ([]byte, error)
	// ImportStats 导入统计
	ImportStats(data []byte) error
}

// DefaultStatsManager 默认统计管理器
type DefaultStatsManager struct {
	mu                sync.RWMutex
	scanStats         ScanStats
	vulnerabilityStats VulnerabilityStats
	performanceStats  PerformanceStats
	reportStats       ReportStats
	pluginStats       PluginStats
	scanStartTime     time.Time
	scanInProgress    bool
}

// NewDefaultStatsManager 创建默认统计管理器
func NewDefaultStatsManager() *DefaultStatsManager {
	return &DefaultStatsManager{
		scanStats: ScanStats{},
		vulnerabilityStats: VulnerabilityStats{
			VulnerabilitiesByType:     make(map[string]int64),
			VulnerabilitiesBySeverity: make(map[SeverityLevel]int64),
			VulnerabilitiesByPlugin:   make(map[string]int64),
			VulnerabilityTrend:        make([]VulnerabilityTrendPoint, 0),
		},
		performanceStats: PerformanceStats{},
		reportStats: ReportStats{
			ReportsByFormat: make(map[string]int64),
			ReportsByType:   make(map[string]int64),
		},
		pluginStats: PluginStats{
			PluginsByType:       make(map[string]int64),
			PluginExecutionTime: make(map[string]time.Duration),
			PluginSuccessRate:   make(map[string]float64),
			PluginErrorCount:    make(map[string]int64),
			LastPluginExecution: make(map[string]time.Time),
		},
	}
}

// UpdateScanStats 更新扫描统计
func (sm *DefaultStatsManager) UpdateScanStats(stats ScanStats) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.scanStats = stats
}

// UpdateVulnerabilityStats 更新漏洞统计
func (sm *DefaultStatsManager) UpdateVulnerabilityStats(stats VulnerabilityStats) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.vulnerabilityStats = stats
}

// UpdatePerformanceStats 更新性能统计
func (sm *DefaultStatsManager) UpdatePerformanceStats(stats PerformanceStats) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.performanceStats = stats
}

// UpdateReportStats 更新报告统计
func (sm *DefaultStatsManager) UpdateReportStats(stats ReportStats) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.reportStats = stats
}

// UpdatePluginStats 更新插件统计
func (sm *DefaultStatsManager) UpdatePluginStats(stats PluginStats) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.pluginStats = stats
}

// IncrementRequestCount 增加请求计数
func (sm *DefaultStatsManager) IncrementRequestCount(success bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.scanStats.TotalRequests++
	if success {
		sm.scanStats.SuccessfulRequests++
	} else {
		sm.scanStats.FailedRequests++
	}

	// 更新性能统计
	if sm.scanStats.TotalRequests > 0 {
		sm.performanceStats.ErrorRate = float64(sm.scanStats.FailedRequests) / float64(sm.scanStats.TotalRequests)
	}
}

// IncrementScanCount 增加扫描计数
func (sm *DefaultStatsManager) IncrementScanCount(success bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.scanStats.TotalScans++
	if success {
		sm.scanStats.SuccessfulScans++
	} else {
		sm.scanStats.FailedScans++
	}

	// 更新最后扫描时间
	sm.scanStats.LastScanTime = time.Now()

	// 如果扫描正在进行，更新扫描时间
	if sm.scanInProgress && !sm.scanStartTime.IsZero() {
		scanDuration := time.Since(sm.scanStartTime)
		sm.scanStats.TotalScanTime += scanDuration
		if sm.scanStats.SuccessfulScans > 0 {
			sm.scanStats.AverageScanTime = sm.scanStats.TotalScanTime / time.Duration(sm.scanStats.SuccessfulScans)
		}
	}
}

// IncrementVulnerabilityCount 增加漏洞计数
func (sm *DefaultStatsManager) IncrementVulnerabilityCount(vulnType string, severity SeverityLevel, pluginName string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.vulnerabilityStats.TotalVulnerabilities++

	// 按类型统计
	if vulnType != "" {
		sm.vulnerabilityStats.VulnerabilitiesByType[vulnType]++
	}

	// 按严重程度统计
	if severity != SeverityUnknown {
		sm.vulnerabilityStats.VulnerabilitiesBySeverity[severity]++
	}

	// 按插件统计
	if pluginName != "" {
		sm.vulnerabilityStats.VulnerabilitiesByPlugin[pluginName]++
	}

	// 添加趋势点
	sm.vulnerabilityStats.VulnerabilityTrend = append(sm.vulnerabilityStats.VulnerabilityTrend, VulnerabilityTrendPoint{
		Timestamp: time.Now(),
		Count:     1,
		Type:      vulnType,
		Severity:  severity.String(),
	})

	// 限制趋势点数量
	if len(sm.vulnerabilityStats.VulnerabilityTrend) > 1000 {
		sm.vulnerabilityStats.VulnerabilityTrend = sm.vulnerabilityStats.VulnerabilityTrend[1:]
	}
}

// AddVulnerabilityTrendPoint 添加漏洞趋势点
func (sm *DefaultStatsManager) AddVulnerabilityTrendPoint(point VulnerabilityTrendPoint) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.vulnerabilityStats.VulnerabilityTrend = append(sm.vulnerabilityStats.VulnerabilityTrend, point)

	// 限制趋势点数量
	if len(sm.vulnerabilityStats.VulnerabilityTrend) > 1000 {
		sm.vulnerabilityStats.VulnerabilityTrend = sm.vulnerabilityStats.VulnerabilityTrend[1:]
	}
}

// UpdateResponseTime 更新响应时间
func (sm *DefaultStatsManager) UpdateResponseTime(responseTime time.Duration) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// 初始化最小响应时间
	if sm.performanceStats.MinResponseTime == 0 {
		sm.performanceStats.MinResponseTime = responseTime
	}

	// 更新最小响应时间
	if responseTime < sm.performanceStats.MinResponseTime {
		sm.performanceStats.MinResponseTime = responseTime
	}

	// 更新最大响应时间
	if responseTime > sm.performanceStats.MaxResponseTime {
		sm.performanceStats.MaxResponseTime = responseTime
	}

	// 更新总处理时间
	sm.performanceStats.TotalProcessingTime += responseTime

	// 计算平均响应时间
	if sm.scanStats.SuccessfulRequests > 0 {
		sm.performanceStats.AverageResponseTime = sm.performanceStats.TotalProcessingTime / time.Duration(sm.scanStats.SuccessfulRequests)
	}

	// 计算每秒请求数
	if sm.scanStats.TotalScanTime > 0 {
		sm.performanceStats.RequestsPerSecond = float64(sm.scanStats.SuccessfulRequests) / sm.scanStats.TotalScanTime.Seconds()
	}
}

// UpdateMemoryUsage 更新内存使用
func (sm *DefaultStatsManager) UpdateMemoryUsage(memoryUsage int64) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.performanceStats.MemoryUsage = memoryUsage
}

// UpdateCPUUsage 更新CPU使用
func (sm *DefaultStatsManager) UpdateCPUUsage(cpuUsage float64) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.performanceStats.CPUUsage = cpuUsage
}

// UpdateNetworkUsage 更新网络使用
func (sm *DefaultStatsManager) UpdateNetworkUsage(networkUsage int64) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.performanceStats.NetworkUsage = networkUsage
}

// UpdateCacheStats 更新缓存统计
func (sm *DefaultStatsManager) UpdateCacheStats(hits, misses int64) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	total := hits + misses
	if total > 0 {
		sm.performanceStats.CacheHitRate = float64(hits) / float64(total)
	} else {
		sm.performanceStats.CacheHitRate = 0.0
	}
}

// UpdateErrorStats 更新错误统计
func (sm *DefaultStatsManager) UpdateErrorStats(errors, retries, timeouts int64) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// 更新错误率
	if sm.scanStats.TotalRequests > 0 {
		sm.performanceStats.ErrorRate = float64(errors) / float64(sm.scanStats.TotalRequests)
	}

	// 更新重试率
	if sm.scanStats.TotalRequests > 0 {
		sm.performanceStats.RetryRate = float64(retries) / float64(sm.scanStats.TotalRequests)
	}

	// 更新超时率
	if sm.scanStats.TotalRequests > 0 {
		sm.performanceStats.TimeoutRate = float64(timeouts) / float64(sm.scanStats.TotalRequests)
	}
}

// UpdatePluginExecutionTime 更新插件执行时间
func (sm *DefaultStatsManager) UpdatePluginExecutionTime(pluginName string, executionTime time.Duration) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if pluginName == "" {
		return
	}

	// 更新插件执行时间
	if _, exists := sm.pluginStats.PluginExecutionTime[pluginName]; exists {
		sm.pluginStats.PluginExecutionTime[pluginName] += executionTime
	} else {
		sm.pluginStats.PluginExecutionTime[pluginName] = executionTime
	}

	// 更新最后执行时间
	sm.pluginStats.LastPluginExecution[pluginName] = time.Now()
}

// UpdatePluginSuccessRate 更新插件成功率
func (sm *DefaultStatsManager) UpdatePluginSuccessRate(pluginName string, success bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if pluginName == "" {
		return
	}

	// 获取当前执行次数和成功次数
	currentRate, exists := sm.pluginStats.PluginSuccessRate[pluginName]
	if !exists {
		currentRate = 0.0
	}

	// 计算新的成功率
	// 这里简化处理，实际应该记录执行次数和成功次数
	if success {
		sm.pluginStats.PluginSuccessRate[pluginName] = (currentRate*99 + 100) / 100
	} else {
		sm.pluginStats.PluginSuccessRate[pluginName] = (currentRate * 99) / 100
	}
}

// UpdatePluginErrorCount 更新插件错误计数
func (sm *DefaultStatsManager) UpdatePluginErrorCount(pluginName string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if pluginName == "" {
		return
	}

	sm.pluginStats.PluginErrorCount[pluginName]++
}

// GetScanStats 获取扫描统计
func (sm *DefaultStatsManager) GetScanStats() ScanStats {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	return sm.scanStats
}

// GetVulnerabilityStats 获取漏洞统计
func (sm *DefaultStatsManager) GetVulnerabilityStats() VulnerabilityStats {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	return sm.vulnerabilityStats
}

// GetPerformanceStats 获取性能统计
func (sm *DefaultStatsManager) GetPerformanceStats() PerformanceStats {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	return sm.performanceStats
}

// GetReportStats 获取报告统计
func (sm *DefaultStatsManager) GetReportStats() ReportStats {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	return sm.reportStats
}

// GetPluginStats 获取插件统计
func (sm *DefaultStatsManager) GetPluginStats() PluginStats {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	return sm.pluginStats
}

// GetAllStats 获取所有统计
func (sm *DefaultStatsManager) GetAllStats() map[string]interface{} {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["scan"] = sm.scanStats
	stats["vulnerability"] = sm.vulnerabilityStats
	stats["performance"] = sm.performanceStats
	stats["report"] = sm.reportStats
	stats["plugin"] = sm.pluginStats

	return stats
}

// ResetStats 重置统计
func (sm *DefaultStatsManager) ResetStats() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.scanStats = ScanStats{}

	sm.vulnerabilityStats = VulnerabilityStats{
		VulnerabilitiesByType:     make(map[string]int64),
		VulnerabilitiesBySeverity: make(map[SeverityLevel]int64),
		VulnerabilitiesByPlugin:   make(map[string]int64),
		VulnerabilityTrend:        make([]VulnerabilityTrendPoint, 0),
	}

	sm.performanceStats = PerformanceStats{}

	sm.reportStats = ReportStats{
		ReportsByFormat: make(map[string]int64),
		ReportsByType:   make(map[string]int64),
	}

	sm.pluginStats = PluginStats{
		PluginsByType:       make(map[string]int64),
		PluginExecutionTime: make(map[string]time.Duration),
		PluginSuccessRate:   make(map[string]float64),
		PluginErrorCount:    make(map[string]int64),
		LastPluginExecution: make(map[string]time.Time),
	}

	sm.scanStartTime = time.Time{}
	sm.scanInProgress = false
}

// StartScan 开始扫描
func (sm *DefaultStatsManager) StartScan() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.scanStartTime = time.Now()
	sm.scanInProgress = true
	sm.scanStats.ScanStartTime = sm.scanStartTime
}

// EndScan 结束扫描
func (sm *DefaultStatsManager) EndScan() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.scanInProgress && !sm.scanStartTime.IsZero() {
		scanDuration := time.Since(sm.scanStartTime)
		sm.scanStats.TotalScanTime += scanDuration
		sm.scanStats.ScanEndTime = time.Now()

		if sm.scanStats.SuccessfulScans > 0 {
			sm.scanStats.AverageScanTime = sm.scanStats.TotalScanTime / time.Duration(sm.scanStats.SuccessfulScans)
		}
	}

	sm.scanInProgress = false
}

// ExportStats 导出统计
func (sm *DefaultStatsManager) ExportStats() ([]byte, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// 这里应该实现JSON序列化
	// 简化实现，返回空字节切片
	return []byte{}, nil
}

// ImportStats 导入统计
func (sm *DefaultStatsManager) ImportStats(data []byte) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// 这里应该实现JSON序列化
	// 简化实现，直接返回
	return nil
}

// GetStatsManager 获取统计管理器
func GetStatsManager() StatsManager {
	return NewDefaultStatsManager()
}