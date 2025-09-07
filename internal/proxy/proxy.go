// Package proxy 提供了HTTP代理功能
package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/rs/zerolog/log"

	"autovulnscan/internal/config"
	"autovulnscan/internal/models"
)

// Proxy 代理服务器
type Proxy struct {
	proxy         *goproxy.ProxyHttpServer
	server        *http.Server
	config        *config.ProxyConfig
	stats         *models.ProxyStats
	filterRules   []*ProxyFilterRule
	requestChan   chan *models.Request
	responseChan  chan *models.Request
	mutex         sync.RWMutex
	certStorage   *CertStorage
	interceptors  map[string]RequestInterceptor
	ctx           context.Context
	cancel        context.CancelFunc
}

// RequestInterceptor 请求拦截器接口
type RequestInterceptor interface {
	// InterceptRequest 拦截请求
	InterceptRequest(req *http.Request, ctx *ProxyContext) (*http.Request, error)
	// InterceptResponse 拦截响应
	InterceptResponse(resp *http.Response, ctx *ProxyContext) (*http.Response, error)
	// Name 拦截器名称
	Name() string
}

// ProxyContext 代理上下文
type ProxyContext struct {
	// 请求ID
	RequestID string
	// 配置
	Config *config.ProxyConfig
	// 统计信息
	Stats *models.ProxyStats
	// 自定义数据
	Data map[string]interface{}
}

// ProxyFilterRule 代理过滤规则
type ProxyFilterRule struct {
	// 规则名称
	Name string `json:"name"`
	// 规则描述
	Description string `json:"description"`
	// 是否启用
	Enabled bool `json:"enabled"`
	// URL模式（正则表达式）
	URLPattern string `json:"url_pattern"`
	// 请求方法
	Method string `json:"method"`
	// 请求头过滤
	HeaderFilters map[string]string `json:"header_filters"`
	// 响应码过滤
	ResponseCodes []int `json:"response_codes"`
	// 内容类型过滤
	ContentTypes []string `json:"content_types"`
	// 动作（block/modify/record）
	Action string `json:"action"`
	// 优先级
	Priority int `json:"priority"`
	// 编译后的URL模式
	compiledPattern *regexp.Regexp
}

// CertStorage 证书存储
type CertStorage struct {
	mutex    sync.RWMutex
	certs    map[string]*tls.Certificate
	certDir  string
	caCert   *tls.Certificate
	caKey    []byte
}

// NewCertStorage 创建新的证书存储
func NewCertStorage(certDir string) (*CertStorage, error) {
	storage := &CertStorage{
		certs:   make(map[string]*tls.Certificate),
		certDir: certDir,
	}

	// 生成或加载CA证书
	if err := storage.initCA(); err != nil {
		return nil, fmt.Errorf("failed to initialize CA: %w", err)
	}

	return storage, nil
}

// initCA 初始化CA证书
func (cs *CertStorage) initCA() error {
	// 这里应该实现CA证书的生成或加载
	// 简化实现，实际应用中应该使用更完整的证书管理
	return nil
}

// GetCert 获取证书
func (cs *CertStorage) GetCert(host string) (*tls.Certificate, error) {
	cs.mutex.RLock()
	cert, exists := cs.certs[host]
	cs.mutex.RUnlock()

	if exists {
		return cert, nil
	}

	// 生成新证书
	newCert, err := cs.generateCert(host)
	if err != nil {
		return nil, err
	}

	cs.mutex.Lock()
	cs.certs[host] = newCert
	cs.mutex.Unlock()

	return newCert, nil
}

// generateCert 生成证书
func (cs *CertStorage) generateCert(host string) (*tls.Certificate, error) {
	// 这里应该实现证书生成逻辑
	// 简化实现，实际应用中应该使用更完整的证书生成
	return nil, fmt.Errorf("not implemented")
}

// NewProxy 创建新的代理服务器
func NewProxy(cfg *config.ProxyConfig) (*Proxy, error) {
	ctx, cancel := context.WithCancel(context.Background())

	p := &Proxy{
		proxy:        goproxy.NewProxyHttpServer(),
		config:       cfg,
		stats:        &models.ProxyStats{},
		requestChan:  make(chan *models.Request, 100),
		responseChan: make(chan *models.Request, 100),
		interceptors: make(map[string]RequestInterceptor),
		ctx:          ctx,
		cancel:       cancel,
	}

	// 初始化证书存储
	certStorage, err := NewCertStorage("certs") // 使用默认证书目录
	if err != nil {
		return nil, fmt.Errorf("failed to initialize certificate storage: %w", err)
	}
	p.certStorage = certStorage

	// 配置代理
	p.configureProxy()

	// 加载过滤规则
	if err := p.loadFilterRules(); err != nil {
		return nil, fmt.Errorf("failed to load filter rules: %w", err)
	}

	// 初始化拦截器
	p.initInterceptors()

	return p, nil
}

// configureProxy 配置代理
func (p *Proxy) configureProxy() {
	// 配置代理行为
	// 注意: goproxy.Verbose 和 goproxy.Logger 的配置需要特殊处理
	// 由于类型不匹配，我们暂时不设置这些属性

	// 配置HTTPS
	if p.config.EnableHTTPS {
		p.proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
		p.proxy.OnRequest().HandleConnectFunc(p.handleConnect)
	}

	// 配置认证
if p.config.EnableAuth && p.config.AuthUsername != "" && p.config.AuthPassword != "" {
	p.proxy.OnRequest().DoFunc(p.handleAuth)
}

	// 配置请求处理
	p.proxy.OnRequest().DoFunc(p.handleRequest)

	// 配置响应处理
	p.proxy.OnResponse().DoFunc(p.handleResponse)
}

// handleConnect 处理HTTPS连接
func (p *Proxy) handleConnect(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	// 获取或生成证书
	cert, err := p.certStorage.GetCert(host)
	if err != nil {
		log.Error().Err(err).Str("host", host).Msg("Failed to get certificate")
		return goproxy.RejectConnect, host
	}

	// 配置TLS
// 注意：goproxy库的版本可能有不同的TLS配置方式
// 这里使用通用的证书配置方式
ctx.UserData = cert

	return goproxy.MitmConnect, host
}

// handleAuth 处理认证
func (p *Proxy) handleAuth(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	// 检查代理认证头
	auth := req.Header.Get("Proxy-Authorization")
	if auth == "" {
		// 返回407需要代理认证
		resp := goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusProxyAuthRequired, "Proxy authentication required")
		resp.Header.Set("Proxy-Authenticate", "Basic realm=\"Proxy\"")
		return req, resp
	}

	// 解析认证信息
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || parts[0] != "Basic" {
		resp := goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusProxyAuthRequired, "Invalid authentication method")
		return req, resp
	}

	// 解码Base64
	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		resp := goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusProxyAuthRequired, "Invalid authentication")
		return req, resp
	}

	// 检查用户名和密码
	credentials := strings.SplitN(string(decoded), ":", 2)// 检查用户名和密码
if len(credentials) != 2 || credentials[0] != p.config.AuthUsername || credentials[1] != p.config.AuthPassword {
		resp := goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusProxyAuthRequired, "Invalid credentials")
		return req, resp
	}

	// 认证成功，继续处理请求
	return req, nil
}

// handleRequest 处理请求
func (p *Proxy) handleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	// 更新统计信息
p.mutex.Lock()
p.stats.TotalRequests++
p.mutex.Unlock()

	// 创建请求记录
	// 将http.Header转换为map[string]string
	headers := make(map[string]string)
	for key, values := range req.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}
	request := &models.Request{
		ID:        generateRequestID(),
		URL:       req.URL.String(),
		Method:    req.Method,
		Headers:   headers,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// 创建代理上下文
	proxyCtx := &ProxyContext{
		RequestID: request.ID,
		Config:    p.config,
		Stats:     p.stats,
		Data:      make(map[string]interface{}),
	}

	// 应用过滤规则
	if rule, action := p.applyFilterRules(req, proxyCtx); rule != nil {
		switch action {
		case "block":
			// 阻止请求
			resp := goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Request blocked by filter rule")
			return req, resp
		case "modify":
			// 修改请求
			// 这里可以根据规则修改请求
		case "record":
			// 记录请求
			request.FilterRule = rule.Name
		}
	}

	// 应用拦截器
	for name, interceptor := range p.interceptors {
		log.Debug().Str("interceptor", name).Str("url", req.URL.String()).Msg("Applying request interceptor")

		var err error
		req, err = interceptor.InterceptRequest(req, proxyCtx)
		if err != nil {
			log.Error().Err(err).Str("interceptor", name).Str("url", req.URL.String()).Msg("Failed to intercept request")
			resp := goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusInternalServerError, "Failed to intercept request")
			return req, resp
		}
	}

	// 发送请求到通道
	select {
	case p.requestChan <- request:
	default:
		log.Warn().Msg("Request channel is full, dropping request")
	}

	// 继续处理请求
	return req, nil
}

// handleResponse 处理响应
func (p *Proxy) handleResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	// 更新统计信息
p.mutex.Lock()
p.stats.AllowedRequests++
p.mutex.Unlock()

	// 获取请求记录
	requestID := generateRequestID()
	if ctx.Req != nil {
		requestID = ctx.Req.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}
	}

	// 创建代理上下文
	proxyCtx := &ProxyContext{
		RequestID: requestID,
		Config:    p.config,
		Stats:     p.stats,
		Data:      make(map[string]interface{}),
	}

	// 应用拦截器
	for name, interceptor := range p.interceptors {
		log.Debug().Str("interceptor", name).Str("url", resp.Request.URL.String()).Msg("Applying response interceptor")

		var err error
		resp, err = interceptor.InterceptResponse(resp, proxyCtx)
		if err != nil {
			log.Error().Err(err).Str("interceptor", name).Str("url", resp.Request.URL.String()).Msg("Failed to intercept response")
			return resp
		}
	}

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Str("url", resp.Request.URL.String()).Msg("Failed to read response body")
		return resp
	}

	// 恢复响应体
	resp.Body = io.NopCloser(bytes.NewBuffer(body))

	// 创建请求记录
	// 将http.Header转换为map[string]string
	headers := make(map[string]string)
	for key, values := range resp.Request.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}
	request := &models.Request{
		ID:           requestID,
		URL:          resp.Request.URL.String(),
		Method:       resp.Request.Method,
		Headers:      headers,
		ResponseCode: resp.StatusCode,
		ResponseBody: string(body),
		Timestamp:    time.Now().Format(time.RFC3339),
	}

	// 发送响应到通道
	select {
	case p.responseChan <- request:
	default:
		log.Warn().Msg("Response channel is full, dropping response")
	}

	// 继续处理响应
	return resp
}

// loadFilterRules 加载过滤规则
func (p *Proxy) loadFilterRules() error {
	// 从配置加载过滤规则
	for _, ruleConfig := range p.config.FilterRules {
		rule := &ProxyFilterRule{
			Name:          ruleConfig.Name,
			Description:   ruleConfig.Description,
			Enabled:       ruleConfig.Enabled,
			URLPattern:    ruleConfig.Pattern,
		Method:        "GET",
			HeaderFilters: ruleConfig.HeaderFilters,
			ResponseCodes: ruleConfig.ResponseCodes,
			ContentTypes:  ruleConfig.ContentTypes,
			Action:        ruleConfig.Action,
			Priority:      ruleConfig.Priority,
		}

		// 编译URL模式
		if rule.URLPattern != "" {
			compiled, err := regexp.Compile(rule.URLPattern)
			if err != nil {
				log.Error().Err(err).Str("name", rule.Name).Msg("Failed to compile URL pattern")
				continue
			}
			rule.compiledPattern = compiled
		}

		p.filterRules = append(p.filterRules, rule)
	}

	return nil
}

// applyFilterRules 应用过滤规则
func (p *Proxy) applyFilterRules(req *http.Request, ctx *ProxyContext) (*ProxyFilterRule, string) {
	// 按优先级排序规则
	rules := make([]*ProxyFilterRule, len(p.filterRules))
	copy(rules, p.filterRules)

	// 按优先级排序（降序）
	for i := 0; i < len(rules)-1; i++ {
		for j := i + 1; j < len(rules); j++ {
			if rules[i].Priority < rules[j].Priority {
				rules[i], rules[j] = rules[j], rules[i]
			}
		}
	}

	// 应用规则
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		// 检查URL模式
		if rule.compiledPattern != nil && !rule.compiledPattern.MatchString(req.URL.String()) {
			continue
		}

		// 检查请求方法
		if rule.Method != "" && rule.Method != req.Method {
			continue
		}

		// 检查请求头
		if len(rule.HeaderFilters) > 0 {
			match := true
			for key, value := range rule.HeaderFilters {
				if req.Header.Get(key) != value {
					match = false
					break
				}
			}
			if !match {
				continue
			}
		}

		// 规则匹配
		return rule, rule.Action
	}

	return nil, ""
}

// initInterceptors 初始化拦截器
func (p *Proxy) initInterceptors() {
	// 添加默认拦截器
	p.AddInterceptor(&HeaderInterceptor{})
	p.AddInterceptor(&CookieInterceptor{})
	p.AddInterceptor(&ContentTypeInterceptor{})
}

// AddInterceptor 添加拦截器
func (p *Proxy) AddInterceptor(interceptor RequestInterceptor) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.interceptors[interceptor.Name()] = interceptor
	log.Info().Str("name", interceptor.Name()).Msg("Added interceptor")
}

// RemoveInterceptor 移除拦截器
func (p *Proxy) RemoveInterceptor(name string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if _, exists := p.interceptors[name]; exists {
		delete(p.interceptors, name)
		log.Info().Str("name", name).Msg("Removed interceptor")
	}
}

// Start 启动代理服务器
func (p *Proxy) Start() error {
	// 创建HTTP服务器
	p.server = &http.Server{
		Addr:    p.config.ListenAddress,
		Handler: p.proxy,
	}

	// 启动服务器
	log.Info().Str("address", p.config.ListenAddress).Msg("Starting proxy server")

	go func() {
		if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("Failed to start proxy server")
		}
	}()

	return nil
}

// Stop 停止代理服务器
func (p *Proxy) Stop() error {
	log.Info().Msg("Stopping proxy server")

	// 取消上下文
	p.cancel()

	// 关闭服务器
	if p.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := p.server.Shutdown(ctx); err != nil {
			log.Error().Err(err).Msg("Failed to shutdown proxy server")
			return err
		}
	}

	// 关闭通道
	close(p.requestChan)
	close(p.responseChan)

	log.Info().Msg("Proxy server stopped")

	return nil
}

// GetStats 获取统计信息
func (p *Proxy) GetStats() *models.ProxyStats {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	// 返回统计信息的副本
	stats := *p.stats
	return &stats
}

// GetRequests 获取请求通道
func (p *Proxy) GetRequests() <-chan *models.Request {
	return p.requestChan
}

// GetResponses 获取响应通道
func (p *Proxy) GetResponses() <-chan *models.Request {
	return p.responseChan
}

// AddFilterRule 添加过滤规则
func (p *Proxy) AddFilterRule(rule *ProxyFilterRule) error {
	// 编译URL模式
	if rule.URLPattern != "" {
		compiled, err := regexp.Compile(rule.URLPattern)
		if err != nil {
			return fmt.Errorf("failed to compile URL pattern: %w", err)
		}
		rule.compiledPattern = compiled
	}

	p.mutex.Lock()
	p.filterRules = append(p.filterRules, rule)
	p.mutex.Unlock()

	log.Info().Str("name", rule.Name).Msg("Added filter rule")

	return nil
}

// RemoveFilterRule 移除过滤规则
func (p *Proxy) RemoveFilterRule(name string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for i, rule := range p.filterRules {
		if rule.Name == name {
			p.filterRules = append(p.filterRules[:i], p.filterRules[i+1:]...)
			log.Info().Str("name", name).Msg("Removed filter rule")
			return nil
		}
	}

	return fmt.Errorf("filter rule not found: %s", name)
}

// UpdateFilterRule 更新过滤规则
func (p *Proxy) UpdateFilterRule(name string, updatedRule *ProxyFilterRule) error {
	// 编译URL模式
	if updatedRule.URLPattern != "" {
		compiled, err := regexp.Compile(updatedRule.URLPattern)
		if err != nil {
			return fmt.Errorf("failed to compile URL pattern: %w", err)
		}
		updatedRule.compiledPattern = compiled
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	for i, rule := range p.filterRules {
		if rule.Name == name {
			p.filterRules[i] = updatedRule
			log.Info().Str("name", name).Msg("Updated filter rule")
			return nil
		}
	}

	return fmt.Errorf("filter rule not found: %s", name)
}

// GetFilterRules 获取过滤规则
func (p *Proxy) GetFilterRules() []*ProxyFilterRule {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	// 返回规则的副本
	rules := make([]*ProxyFilterRule, len(p.filterRules))
	copy(rules, p.filterRules)

	return rules
}

// EnableFilterRule 启用过滤规则
func (p *Proxy) EnableFilterRule(name string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for _, rule := range p.filterRules {
		if rule.Name == name {
			rule.Enabled = true
			log.Info().Str("name", name).Msg("Enabled filter rule")
			return nil
		}
	}

	return fmt.Errorf("filter rule not found: %s", name)
}

// DisableFilterRule 禁用过滤规则
func (p *Proxy) DisableFilterRule(name string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for _, rule := range p.filterRules {
		if rule.Name == name {
			rule.Enabled = false
			log.Info().Str("name", name).Msg("Disabled filter rule")
			return nil
		}
	}

	return fmt.Errorf("filter rule not found: %s", name)
}

// ClearStats 清除统计信息
func (p *Proxy) ClearStats() {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.stats = &models.ProxyStats{}

	log.Info().Msg("Cleared proxy stats")
}

// generateRequestID 生成请求ID
func generateRequestID() string {
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}

// HeaderInterceptor 请求头拦截器
type HeaderInterceptor struct{}

// InterceptRequest 拦截请求
func (i *HeaderInterceptor) InterceptRequest(req *http.Request, ctx *ProxyContext) (*http.Request, error) {
	// 添加请求ID
	if req.Header.Get("X-Request-ID") == "" {
		req.Header.Set("X-Request-ID", ctx.RequestID)
	}

	// 记录请求头
	log.Debug().Str("url", req.URL.String()).Str("method", req.Method).Msg("Intercepting request headers")

	return req, nil
}

// InterceptResponse 拦截响应
func (i *HeaderInterceptor) InterceptResponse(resp *http.Response, ctx *ProxyContext) (*http.Response, error) {
	// 记录响应头
	log.Debug().Str("url", resp.Request.URL.String()).Int("status", resp.StatusCode).Msg("Intercepting response headers")

	return resp, nil
}

// Name 拦截器名称
func (i *HeaderInterceptor) Name() string {
	return "header"
}

// CookieInterceptor Cookie拦截器
type CookieInterceptor struct{}

// InterceptRequest 拦截请求
func (i *CookieInterceptor) InterceptRequest(req *http.Request, ctx *ProxyContext) (*http.Request, error) {
	// 记录Cookie
	cookies := req.Cookies()
	if len(cookies) > 0 {
		log.Debug().Str("url", req.URL.String()).Int("count", len(cookies)).Msg("Intercepting request cookies")
	}

	return req, nil
}

// InterceptResponse 拦截响应
func (i *CookieInterceptor) InterceptResponse(resp *http.Response, ctx *ProxyContext) (*http.Response, error) {
	// 记录Set-Cookie头
	cookies := resp.Cookies()
	if len(cookies) > 0 {
		log.Debug().Str("url", resp.Request.URL.String()).Int("count", len(cookies)).Msg("Intercepting response cookies")
	}

	return resp, nil
}

// Name 拦截器名称
func (i *CookieInterceptor) Name() string {
	return "cookie"
}

// ContentTypeInterceptor 内容类型拦截器
type ContentTypeInterceptor struct{}

// InterceptRequest 拦截请求
func (i *ContentTypeInterceptor) InterceptRequest(req *http.Request, ctx *ProxyContext) (*http.Request, error) {
	// 记录Content-Type
	contentType := req.Header.Get("Content-Type")
	if contentType != "" {
		log.Debug().Str("url", req.URL.String()).Str("content_type", contentType).Msg("Intercepting request content type")
	}

	return req, nil
}

// InterceptResponse 拦截响应
func (i *ContentTypeInterceptor) InterceptResponse(resp *http.Response, ctx *ProxyContext) (*http.Response, error) {
	// 记录Content-Type
	contentType := resp.Header.Get("Content-Type")
	if contentType != "" {
		log.Debug().Str("url", resp.Request.URL.String()).Str("content_type", contentType).Msg("Intercepting response content type")
	}

	return resp, nil
}

// Name 拦截器名称
func (i *ContentTypeInterceptor) Name() string {
	return "content_type"
}