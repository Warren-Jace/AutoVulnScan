// Package api 提供了RESTful API接口
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"

	"autovulnscan/internal/config"
	"autovulnscan/internal/models"
	"autovulnscan/internal/plugin"
)

// Server API服务器
type Server struct {
	server      *http.Server
	router      *mux.Router
	config      *config.GlobalConfig
	pluginMgr   *plugin.PluginManager
	stats       *models.ScanStats
	vulnStorage VulnStorage
	crawlStorage CrawlStorage
}

// VulnStorage 漏洞存储接口
type VulnStorage interface {
	// GetVulnerabilities 获取漏洞列表
	GetVulnerabilities(filter map[string]interface{}) ([]*models.Vulnerability, error)
	// GetVulnerability 获取漏洞详情
	GetVulnerability(id string) (*models.Vulnerability, error)
	// AddVulnerability 添加漏洞
	AddVulnerability(vuln *models.Vulnerability) error
	// UpdateVulnerability 更新漏洞
	UpdateVulnerability(vuln *models.Vulnerability) error
	// DeleteVulnerability 删除漏洞
	DeleteVulnerability(id string) error
	// GetVulnerabilityStats 获取漏洞统计信息
	GetVulnerabilityStats() (*models.VulnerabilityStats, error)
}

// CrawlStorage 爬取存储接口
type CrawlStorage interface {
	// GetCrawlResults 获取爬取结果列表
	GetCrawlResults(filter map[string]interface{}) ([]*models.CrawlResult, error)
	// GetCrawlResult 获取爬取结果详情
	GetCrawlResult(id string) (*models.CrawlResult, error)
	// AddCrawlResult 添加爬取结果
	AddCrawlResult(result *models.CrawlResult) error
	// UpdateCrawlResult 更新爬取结果
	UpdateCrawlResult(result *models.CrawlResult) error
	// DeleteCrawlResult 删除爬取结果
	DeleteCrawlResult(id string) error
	// GetCrawlStats 获取爬取统计信息
	GetCrawlStats() (*models.CrawlStats, error)
}

// APIResponse API响应结构
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// NewServer 创建新的API服务器
func NewServer(cfg *config.GlobalConfig, pluginMgr *plugin.PluginManager, vulnStorage VulnStorage, crawlStorage CrawlStorage) *Server {
	s := &Server{
		router:      mux.NewRouter(),
		config:      cfg,
		pluginMgr:   pluginMgr,
		stats:       &models.ScanStats{},
		vulnStorage: vulnStorage,
		crawlStorage: crawlStorage,
	}

	// 配置路由
	s.setupRoutes()

	// 创建HTTP服务器
	s.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.API.Port),
		Handler: s.router,
	}

	return s
}

// setupRoutes 设置路由
func (s *Server) setupRoutes() {
	// 添加CORS中间件
	s.router.Use(s.corsMiddleware)

	// 添加日志中间件
	s.router.Use(s.loggingMiddleware)

	// 添加认证中间件
	if s.config.API.Auth {
		s.router.Use(s.authMiddleware)
	}

	// API版本
	v1 := s.router.PathPrefix("/api/v1").Subrouter()

	// 系统信息
	v1.HandleFunc("/info", s.handleInfo).Methods("GET")

	// 配置管理
	v1.HandleFunc("/config", s.handleGetConfig).Methods("GET")
	v1.HandleFunc("/config", s.handleUpdateConfig).Methods("PUT")

	// 插件管理
	v1.HandleFunc("/plugins", s.handleListPlugins).Methods("GET")
	v1.HandleFunc("/plugins/{name}", s.handleGetPlugin).Methods("GET")
	v1.HandleFunc("/plugins/{name}/enable", s.handleEnablePlugin).Methods("POST")
	v1.HandleFunc("/plugins/{name}/disable", s.handleDisablePlugin).Methods("POST")
	v1.HandleFunc("/plugins/{name}/reload", s.handleReloadPlugin).Methods("POST")

	// 扫描任务
	v1.HandleFunc("/scans", s.handleListScans).Methods("GET")
	v1.HandleFunc("/scans", s.handleStartScan).Methods("POST")
	v1.HandleFunc("/scans/{id}", s.handleGetScan).Methods("GET")
	v1.HandleFunc("/scans/{id}/stop", s.handleStopScan).Methods("POST")

	// 漏洞管理
	v1.HandleFunc("/vulnerabilities", s.handleListVulnerabilities).Methods("GET")
	v1.HandleFunc("/vulnerabilities/{id}", s.handleGetVulnerability).Methods("GET")
	v1.HandleFunc("/vulnerabilities/{id}", s.handleUpdateVulnerability).Methods("PUT")
	v1.HandleFunc("/vulnerabilities/{id}", s.handleDeleteVulnerability).Methods("DELETE")
	v1.HandleFunc("/vulnerabilities/stats", s.handleVulnerabilityStats).Methods("GET")

	// 爬取结果
	v1.HandleFunc("/crawl/results", s.handleListCrawlResults).Methods("GET")
	v1.HandleFunc("/crawl/results/{id}", s.handleGetCrawlResult).Methods("GET")
	v1.HandleFunc("/crawl/results/{id}", s.handleUpdateCrawlResult).Methods("PUT")
	v1.HandleFunc("/crawl/results/{id}", s.handleDeleteCrawlResult).Methods("DELETE")
	v1.HandleFunc("/crawl/stats", s.handleCrawlStats).Methods("GET")

	// 报告生成
	v1.HandleFunc("/reports", s.handleGenerateReport).Methods("POST")

	// 统计信息
	v1.HandleFunc("/stats", s.handleStats).Methods("GET")

	// 健康检查
	v1.HandleFunc("/health", s.handleHealth).Methods("GET")
}

// Start 启动API服务器
func (s *Server) Start() error {
	log.Info().Int("port", s.config.API.Port).Msg("Starting API server")

	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("Failed to start API server")
		}
	}()

	return nil
}

// Stop 停止API服务器
func (s *Server) Stop() error {
	log.Info().Msg("Stopping API server")

	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.server.Shutdown(ctx); err != nil {
			log.Error().Err(err).Msg("Failed to shutdown API server")
			return err
		}
	}

	log.Info().Msg("API server stopped")

	return nil
}

// corsMiddleware CORS中间件
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 设置CORS头
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// 处理预检请求
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware 日志中间件
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// 包装ResponseWriter以捕获状态码
		wrapped := wrapResponseWriter(w)

		// 处理请求
		next.ServeHTTP(wrapped, r)

		// 记录请求日志
		log.Info().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Str("query", r.URL.RawQuery).
			Str("ip", r.RemoteAddr).
			Str("user-agent", r.UserAgent()).
			Int("status", wrapped.status).
			Dur("duration", time.Since(start)).
			Msg("API request")
	})
}

// authMiddleware 认证中间件
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 获取Authorization头
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			s.sendErrorResponse(w, http.StatusUnauthorized, "Authorization header is required")
			return
		}

		// 解析Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			s.sendErrorResponse(w, http.StatusUnauthorized, "Invalid authorization format")
			return
		}

		token := parts[1]

		// 验证token
		if token != s.config.API.Password {
			s.sendErrorResponse(w, http.StatusUnauthorized, "Invalid token")
			return
		}

		// 认证成功，继续处理请求
		next.ServeHTTP(w, r)
	})
}

// handleInfo 处理系统信息请求
func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	info := map[string]interface{}{
		"name":    "AutoVulnScan",
		"version": "1.0.0",
		"status":  "running",
	}

	s.sendSuccessResponse(w, "System information retrieved successfully", info)
}

// handleGetConfig 处理获取配置请求
func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	// 返回配置的副本，避免敏感信息泄露
	configCopy := *s.config
	configCopy.Database.Password = "***"
	configCopy.Proxy.AuthPassword = "***"

	s.sendSuccessResponse(w, "Configuration retrieved successfully", configCopy)
}

// handleUpdateConfig 处理更新配置请求
func (s *Server) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	var newConfig config.GlobalConfig
	if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
		s.sendErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("Failed to decode request body: %v", err))
		return
	}

	// 更新配置
	*s.config = newConfig

	s.sendSuccessResponse(w, "Configuration updated successfully", nil)
}

// handleListPlugins 处理列出插件请求
func (s *Server) handleListPlugins(w http.ResponseWriter, r *http.Request) {
	// 获取查询参数
	pluginType := r.URL.Query().Get("type")

	var plugins []*plugin.PluginInfo
	if pluginType != "" {
		// 根据类型获取插件
		plugins = s.pluginMgr.ListPluginsByType(plugin.PluginType(pluginType))
	} else {
		// 获取所有插件
		plugins = s.pluginMgr.ListPlugins()
	}

	s.sendSuccessResponse(w, "Plugins retrieved successfully", plugins)
}

// handleGetPlugin 处理获取插件详情请求
func (s *Server) handleGetPlugin(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	// 获取插件
	pluginInstance, err := s.pluginMgr.GetPlugin(name)
	if err != nil {
		s.sendErrorResponse(w, http.StatusNotFound, fmt.Sprintf("Plugin not found: %v", err))
		return
	}

	// 获取插件信息
	info := pluginInstance.GetInfo()

	s.sendSuccessResponse(w, "Plugin retrieved successfully", info)
}

// handleEnablePlugin 处理启用插件请求
func (s *Server) handleEnablePlugin(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	// 启用插件
	if err := s.pluginMgr.EnablePlugin(name); err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to enable plugin: %v", err))
		return
	}

	s.sendSuccessResponse(w, "Plugin enabled successfully", nil)
}

// handleDisablePlugin 处理禁用插件请求
func (s *Server) handleDisablePlugin(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	// 禁用插件
	if err := s.pluginMgr.DisablePlugin(name); err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to disable plugin: %v", err))
		return
	}

	s.sendSuccessResponse(w, "Plugin disabled successfully", nil)
}

// handleReloadPlugin 处理重新加载插件请求
func (s *Server) handleReloadPlugin(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	// 重新加载插件
	_, err := s.pluginMgr.ReloadPlugin(name)
	if err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to reload plugin: %v", err))
		return
	}

	s.sendSuccessResponse(w, "Plugin reloaded successfully", nil)
}

// handleListScans 处理列出扫描任务请求
func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	// 获取查询参数
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	status := r.URL.Query().Get("status")

	// 解析分页参数
	limit := 10
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	offset := 0
	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	// 构建过滤器
	filter := map[string]interface{}{
		"limit":  limit,
		"offset": offset,
	}

	if status != "" {
		filter["status"] = status
	}

	// 获取扫描任务列表
	// 这里应该从存储中获取扫描任务列表
	// 简化实现，返回空列表
	scans := []map[string]interface{}{}

	s.sendSuccessResponse(w, "Scans retrieved successfully", scans)
}

// handleStartScan 处理启动扫描任务请求
func (s *Server) handleStartScan(w http.ResponseWriter, r *http.Request) {
	var scanConfig map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&scanConfig); err != nil {
		s.sendErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("Failed to decode request body: %v", err))
		return
	}

	// 启动扫描任务
	// 这里应该调用扫描引擎启动扫描任务
	// 简化实现，返回任务ID
	taskId := generateTaskID()

	result := map[string]interface{}{
		"task_id": taskId,
		"status":  "running",
	}

	s.sendSuccessResponse(w, "Scan started successfully", result)
}

// handleGetScan 处理获取扫描任务详情请求
func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	// 获取扫描任务详情
	// 这里应该从存储中获取扫描任务详情
	// 简化实现，返回模拟数据
	scan := map[string]interface{}{
		"id":     id,
		"status": "running",
		"progress": map[string]interface{}{
			"percent": 50,
			"current": "scanning",
		},
	}

	s.sendSuccessResponse(w, "Scan retrieved successfully", scan)
}

// handleStopScan 处理停止扫描任务请求
func (s *Server) handleStopScan(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	_ = vars["id"]

	// 停止扫描任务
	// 这里应该调用扫描引擎停止扫描任务
	// 简化实现，直接返回成功

	s.sendSuccessResponse(w, "Scan stopped successfully", nil)
}

// handleListVulnerabilities 处理列出漏洞请求
func (s *Server) handleListVulnerabilities(w http.ResponseWriter, r *http.Request) {
	// 获取查询参数
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	severity := r.URL.Query().Get("severity")
	type_ := r.URL.Query().Get("type")
	target := r.URL.Query().Get("target")

	// 解析分页参数
	limit := 10
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	offset := 0
	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	// 构建过滤器
	filter := map[string]interface{}{
		"limit":  limit,
		"offset": offset,
	}

	if severity != "" {
		filter["severity"] = severity
	}

	if type_ != "" {
		filter["type"] = type_
	}

	if target != "" {
		filter["target"] = target
	}

	// 获取漏洞列表
	vulns, err := s.vulnStorage.GetVulnerabilities(filter)
	if err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get vulnerabilities: %v", err))
		return
	}

	s.sendSuccessResponse(w, "Vulnerabilities retrieved successfully", vulns)
}

// handleGetVulnerability 处理获取漏洞详情请求
func (s *Server) handleGetVulnerability(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	// 获取漏洞详情
	vuln, err := s.vulnStorage.GetVulnerability(id)
	if err != nil {
		s.sendErrorResponse(w, http.StatusNotFound, fmt.Sprintf("Vulnerability not found: %v", err))
		return
	}

	s.sendSuccessResponse(w, "Vulnerability retrieved successfully", vuln)
}

// handleUpdateVulnerability 处理更新漏洞请求
func (s *Server) handleUpdateVulnerability(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var vuln models.Vulnerability
	if err := json.NewDecoder(r.Body).Decode(&vuln); err != nil {
		s.sendErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("Failed to decode request body: %v", err))
		return
	}

	// 设置ID
	vuln.ID = id

	// 更新漏洞
	if err := s.vulnStorage.UpdateVulnerability(&vuln); err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to update vulnerability: %v", err))
		return
	}

	s.sendSuccessResponse(w, "Vulnerability updated successfully", vuln)
}

// handleDeleteVulnerability 处理删除漏洞请求
func (s *Server) handleDeleteVulnerability(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	// 删除漏洞
	if err := s.vulnStorage.DeleteVulnerability(id); err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to delete vulnerability: %v", err))
		return
	}

	s.sendSuccessResponse(w, "Vulnerability deleted successfully", nil)
}

// handleVulnerabilityStats 处理漏洞统计请求
func (s *Server) handleVulnerabilityStats(w http.ResponseWriter, r *http.Request) {
	// 获取漏洞统计信息
	stats, err := s.vulnStorage.GetVulnerabilityStats()
	if err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get vulnerability stats: %v", err))
		return
	}

	s.sendSuccessResponse(w, "Vulnerability stats retrieved successfully", stats)
}

// handleListCrawlResults 处理列出爬取结果请求
func (s *Server) handleListCrawlResults(w http.ResponseWriter, r *http.Request) {
	// 获取查询参数
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	target := r.URL.Query().Get("target")

	// 解析分页参数
	limit := 10
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	offset := 0
	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	// 构建过滤器
	filter := map[string]interface{}{
		"limit":  limit,
		"offset": offset,
	}

	if target != "" {
		filter["target"] = target
	}

	// 获取爬取结果列表
	results, err := s.crawlStorage.GetCrawlResults(filter)
	if err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get crawl results: %v", err))
		return
	}

	s.sendSuccessResponse(w, "Crawl results retrieved successfully", results)
}

// handleGetCrawlResult 处理获取爬取结果详情请求
func (s *Server) handleGetCrawlResult(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	// 获取爬取结果详情
	result, err := s.crawlStorage.GetCrawlResult(id)
	if err != nil {
		s.sendErrorResponse(w, http.StatusNotFound, fmt.Sprintf("Crawl result not found: %v", err))
		return
	}

	s.sendSuccessResponse(w, "Crawl result retrieved successfully", result)
}

// handleUpdateCrawlResult 处理更新爬取结果请求
func (s *Server) handleUpdateCrawlResult(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var result models.CrawlResult
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		s.sendErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("Failed to decode request body: %v", err))
		return
	}

	// 设置URL
	result.URL = id

	// 更新爬取结果
	if err := s.crawlStorage.UpdateCrawlResult(&result); err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to update crawl result: %v", err))
		return
	}

	s.sendSuccessResponse(w, "Crawl result updated successfully", result)
}

// handleDeleteCrawlResult 处理删除爬取结果请求
func (s *Server) handleDeleteCrawlResult(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	// 删除爬取结果
	if err := s.crawlStorage.DeleteCrawlResult(id); err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to delete crawl result: %v", err))
		return
	}

	s.sendSuccessResponse(w, "Crawl result deleted successfully", nil)
}

// handleCrawlStats 处理爬取统计请求
func (s *Server) handleCrawlStats(w http.ResponseWriter, r *http.Request) {
	// 获取爬取统计信息
	stats, err := s.crawlStorage.GetCrawlStats()
	if err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get crawl stats: %v", err))
		return
	}

	s.sendSuccessResponse(w, "Crawl stats retrieved successfully", stats)
}

// handleGenerateReport 处理生成报告请求
func (s *Server) handleGenerateReport(w http.ResponseWriter, r *http.Request) {
	var reportConfig models.ReportConfig
	if err := json.NewDecoder(r.Body).Decode(&reportConfig); err != nil {
		s.sendErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("Failed to decode request body: %v", err))
		return
	}

	// 生成报告
	// 这里应该调用报告生成器生成报告
	// 简化实现，返回报告ID
	reportId := generateReportID()

	result := map[string]interface{}{
		"report_id": reportId,
		"status":    "generating",
	}

	s.sendSuccessResponse(w, "Report generation started successfully", result)
}

// handleStats 处理统计信息请求
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	// 获取统计信息
	// 这里应该从各个组件获取统计信息
	// 简化实现，返回模拟数据
	stats := map[string]interface{}{
		"scans": map[string]interface{}{
			"total":    10,
			"running":  2,
			"completed": 8,
		},
		"vulnerabilities": map[string]interface{}{
			"total":     50,
			"critical":  5,
			"high":      15,
			"medium":    20,
			"low":       10,
		},
		"crawl": map[string]interface{}{
			"total_pages":   100,
			"total_forms":   50,
			"total_apis":    30,
			"total_domains": 5,
		},
	}

	s.sendSuccessResponse(w, "Stats retrieved successfully", stats)
}

// handleHealth 处理健康检查请求
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// 检查系统健康状态
	// 这里应该检查各个组件的健康状态
	// 简化实现，直接返回健康状态
	health := map[string]interface{}{
		"status": "healthy",
		"components": map[string]interface{}{
			"database": "healthy",
			"scanner":  "healthy",
			"crawler":  "healthy",
			"proxy":    "healthy",
		},
	}

	s.sendSuccessResponse(w, "Health check passed", health)
}

// sendSuccessResponse 发送成功响应
func (s *Server) sendSuccessResponse(w http.ResponseWriter, message string, data interface{}) {
	response := APIResponse{
		Success: true,
		Message: message,
		Data:    data,
	}

	s.sendResponse(w, http.StatusOK, response)
}

// sendErrorResponse 发送错误响应
func (s *Server) sendErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	response := APIResponse{
		Success: false,
		Message: message,
		Error:   message,
	}

	s.sendResponse(w, statusCode, response)
}

// sendResponse 发送响应
func (s *Server) sendResponse(w http.ResponseWriter, statusCode int, response APIResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error().Err(err).Msg("Failed to encode response")
	}
}

// generateTaskID 生成任务ID
func generateTaskID() string {
	return fmt.Sprintf("task_%d", time.Now().UnixNano())
}

// generateReportID 生成报告ID
func generateReportID() string {
	return fmt.Sprintf("report_%d", time.Now().UnixNano())
}

// responseWriter 包装http.ResponseWriter以捕获状态码
type responseWriter struct {
	http.ResponseWriter
	status int
}

// WriteHeader 写入状态码
func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// wrapResponseWriter 包装http.ResponseWriter
func wrapResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{ResponseWriter: w, status: http.StatusOK}
}