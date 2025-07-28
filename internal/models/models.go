// Package models 包含了 AutoVulnScan 应用程序中使用到的核心数据结构。
// 这些结构体用于在不同模块之间传递数据，例如从爬虫到扫描器，或从扫描器到报告器。
package models

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TaskType 任务类型枚举
type TaskType string

const (
	TaskTypeCrawl TaskType = "crawl" // 爬取任务
	TaskTypeScan  TaskType = "scan"  // 扫描任务
)

// TaskStatus 任务状态枚举
type TaskStatus string

const (
	TaskStatusPending    TaskStatus = "pending"    // 等待中
	TaskStatusRunning    TaskStatus = "running"    // 运行中
	TaskStatusCompleted  TaskStatus = "completed"  // 已完成
	TaskStatusFailed     TaskStatus = "failed"     // 失败
	TaskStatusCancelled  TaskStatus = "cancelled"  // 已取消
	TaskStatusTimeout    TaskStatus = "timeout"    // 超时
)

// Priority 优先级枚举
type Priority int

const (
	PriorityLow    Priority = 1 // 低优先级
	PriorityNormal Priority = 5 // 普通优先级
	PriorityHigh   Priority = 8 // 高优先级
	PriorityCritical Priority = 10 // 关键优先级
)

// VulnerabilityType 漏洞类型枚举
type VulnerabilityType string

const (
	VulnTypeSQLInjection VulnerabilityType = "sql_injection"
	VulnTypeXSS          VulnerabilityType = "xss"
	VulnTypeCSRF         VulnerabilityType = "csrf"
	VulnTypeRCE          VulnerabilityType = "rce"
	VulnTypeLFI          VulnerabilityType = "lfi"
	VulnTypeRFI          VulnerabilityType = "rfi"
	VulnTypeXXE          VulnerabilityType = "xxe"
	VulnTypeSSRF         VulnerabilityType = "ssrf"
	VulnTypeOpenRedirect VulnerabilityType = "open_redirect"
	VulnTypePathTraversal VulnerabilityType = "path_traversal"
)

// Severity 漏洞严重程度枚举
type Severity string

const (
	SeverityInfo     Severity = "info"     // 信息
	SeverityLow      Severity = "low"      // 低危
	SeverityMedium   Severity = "medium"   // 中危
	SeverityHigh     Severity = "high"     // 高危
	SeverityCritical Severity = "critical" // 严重
)

// Parameter 代表一个独立的HTTP参数，例如来自查询字符串或POST表单体。
type Parameter struct {
	Name        string `json:"name"`                   // 参数名
	Value       string `json:"value"`                  // 参数值
	Type        string `json:"type,omitempty"`         // 参数类型 (query, form, header, cookie)
	Required    bool   `json:"required,omitempty"`     // 是否必需
	Description string `json:"description,omitempty"`  // 参数描述
	Example     string `json:"example,omitempty"`      // 示例值
}

// NewParameter 创建新的参数
func NewParameter(name, value, paramType string) Parameter {
	return Parameter{
		Name:  name,
		Value: value,
		Type:  paramType,
	}
}

// Clone 克隆参数
func (p Parameter) Clone() Parameter {
	return Parameter{
		Name:        p.Name,
		Value:       p.Value,
		Type:        p.Type,
		Required:    p.Required,
		Description: p.Description,
		Example:     p.Example,
	}
}

// IsEmpty 检查参数是否为空
func (p Parameter) IsEmpty() bool {
	return p.Name == "" && p.Value == ""
}

// Request 代表一个被发现的、可用于扫描的HTTP请求。
// 它是一个包含了方法、URL、头部、主体和参数的综合数据容器。
type Request struct {
	ID          string            `json:"id"`                     // 请求唯一标识
	URL         string            `json:"url"`                    // 请求URL
	Method      string            `json:"method"`                 // HTTP方法
	Headers     http.Header       `json:"headers"`                // HTTP头部
	Body        string            `json:"body"`                   // 请求体
	Params      []Parameter       `json:"params"`                 // 参数列表
	Cookies     []*http.Cookie    `json:"cookies,omitempty"`      // Cookie
	UserAgent   string            `json:"user_agent,omitempty"`   // User-Agent
	Referer     string            `json:"referer,omitempty"`      // Referer
	ContentType string            `json:"content_type,omitempty"` // Content-Type
	Timestamp   time.Time         `json:"timestamp"`              // 创建时间
	Source      string            `json:"source,omitempty"`       // 来源 (crawler, manual, etc.)
	Metadata    map[string]string `json:"metadata,omitempty"`     // 元数据
}

// NewRequest 创建新的请求
func NewRequest(method, urlStr string) *Request {
	return &Request{
		ID:        generateID(method + urlStr),
		URL:       urlStr,
		Method:    strings.ToUpper(method),
		Headers:   make(http.Header),
		Params:    make([]Parameter, 0),
		Timestamp: time.Now(),
		Metadata:  make(map[string]string),
	}
}

// Clone 克隆请求
func (r *Request) Clone() *Request {
	clone := &Request{
		ID:          r.ID,
		URL:         r.URL,
		Method:      r.Method,
		Headers:     make(http.Header),
		Body:        r.Body,
		Params:      make([]Parameter, len(r.Params)),
		UserAgent:   r.UserAgent,
		Referer:     r.Referer,
		ContentType: r.ContentType,
		Timestamp:   r.Timestamp,
		Source:      r.Source,
		Metadata:    make(map[string]string),
	}
	
	// 深拷贝Headers
	for key, values := range r.Headers {
		clone.Headers[key] = make([]string, len(values))
		copy(clone.Headers[key], values)
	}
	
	// 深拷贝Params
	for i, param := range r.Params {
		clone.Params[i] = param.Clone()
	}
	
	// 深拷贝Cookies
	if r.Cookies != nil {
		clone.Cookies = make([]*http.Cookie, len(r.Cookies))
		for i, cookie := range r.Cookies {
			clone.Cookies[i] = &http.Cookie{}
			*clone.Cookies[i] = *cookie
		}
	}
	
	// 深拷贝Metadata
	for key, value := range r.Metadata {
		clone.Metadata[key] = value
	}
	
	return clone
}

// URLWithParams 返回带有查询参数的完整URL字符串。
func (r *Request) URLWithParams() string {
	if r.Method == "GET" && len(r.Params) > 0 {
		baseURL, err := url.Parse(r.URL)
		if err != nil {
			return r.URL // 如果URL解析失败，则返回原始URL
		}
		
		values := url.Values{}
		for _, p := range r.Params {
			if p.Type == "query" || p.Type == "" {
				values.Add(p.Name, p.Value)
			}
		}
		
		if len(values) > 0 {
			baseURL.RawQuery = values.Encode()
		}
		
		return baseURL.String()
	}
	return r.URL
}

// GetQueryParams 获取查询参数
func (r *Request) GetQueryParams() []Parameter {
	var queryParams []Parameter
	for _, param := range r.Params {
		if param.Type == "query" || param.Type == "" {
			queryParams = append(queryParams, param)
		}
	}
	return queryParams
}

// GetFormParams 获取表单参数
func (r *Request) GetFormParams() []Parameter {
	var formParams []Parameter
	for _, param := range r.Params {
		if param.Type == "form" {
			formParams = append(formParams, param)
		}
	}
	return formParams
}

// AddParam 添加参数
func (r *Request) AddParam(param Parameter) {
	r.Params = append(r.Params, param)
}

// SetParam 设置参数值
func (r *Request) SetParam(name, value string) {
	for i, param := range r.Params {
		if param.Name == name {
			r.Params[i].Value = value
			return
		}
	}
	// 如果参数不存在，则添加新参数
	r.AddParam(Parameter{Name: name, Value: value})
}

// GetParam 获取参数值
func (r *Request) GetParam(name string) (string, bool) {
	for _, param := range r.Params {
		if param.Name == name {
			return param.Value, true
		}
	}
	return "", false
}

// RemoveParam 移除参数
func (r *Request) RemoveParam(name string) {
	for i, param := range r.Params {
		if param.Name == name {
			r.Params = append(r.Params[:i], r.Params[i+1:]...)
			return
		}
	}
}

// ToHTTPRequest 转换为标准的http.Request
func (r *Request) ToHTTPRequest(ctx context.Context) (*http.Request, error) {
	var body strings.Reader
	if r.Body != "" {
		body = *strings.NewReader(r.Body)
	}
	
	req, err := http.NewRequestWithContext(ctx, r.Method, r.URLWithParams(), &body)
	if err != nil {
		return nil, fmt.Errorf("创建HTTP请求失败: %w", err)
	}
	
	// 设置头部
	for key, values := range r.Headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	
	// 设置Cookie
	for _, cookie := range r.Cookies {
		req.AddCookie(cookie)
	}
	
	// 设置User-Agent
	if r.UserAgent != "" {
		req.Header.Set("User-Agent", r.UserAgent)
	}
	
	// 设置Referer
	if r.Referer != "" {
		req.Header.Set("Referer", r.Referer)
	}
	
	// 设置Content-Type
	if r.ContentType != "" {
		req.Header.Set("Content-Type", r.ContentType)
	}
	
	return req, nil
}

// Validate 验证请求的有效性
func (r *Request) Validate() error {
	if r.URL == "" {
		return fmt.Errorf("URL不能为空")
	}
	
	if _, err := url.Parse(r.URL); err != nil {
		return fmt.Errorf("无效的URL: %w", err)
	}
	
	if r.Method == "" {
		return fmt.Errorf("HTTP方法不能为空")
	}
	
	validMethods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}
	methodValid := false
	for _, method := range validMethods {
		if r.Method == method {
			methodValid = true
			break
		}
	}
	
	if !methodValid {
		return fmt.Errorf("无效的HTTP方法: %s", r.Method)
	}
	
	return nil
}

// Hash 计算请求的哈希值
func (r *Request) Hash() string {
	data := fmt.Sprintf("%s|%s|%s", r.Method, r.URL, r.Body)
	return fmt.Sprintf("%x", md5.Sum([]byte(data)))
}

// ParameterizedURL 代表一个URL及其识别出的参数。
type ParameterizedURL struct {
	URL         string      `json:"url"`                   // URL
	Params      []Parameter `json:"params"`                // 参数列表
	BaseURL     string      `json:"base_url,omitempty"`    // 基础URL（不含参数）
	QueryString string      `json:"query_string,omitempty"` // 查询字符串
	Fragment    string      `json:"fragment,omitempty"`    // URL片段
	Timestamp   time.Time   `json:"timestamp"`             // 创建时间
}

// NewParameterizedURL 创建一个新的 ParameterizedURL 实例。
func NewParameterizedURL(urlStr string, params []Parameter) *ParameterizedURL {
	parsedURL, _ := url.Parse(urlStr)
	baseURL := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path)
	
	return &ParameterizedURL{
		URL:         urlStr,
		Params:      params,
		BaseURL:     baseURL,
		QueryString: parsedURL.RawQuery,
		Fragment:    parsedURL.Fragment,
		Timestamp:   time.Now(),
	}
}

// ToRequest 转换为Request对象
func (pu *ParameterizedURL) ToRequest(method string) *Request {
	req := NewRequest(method, pu.BaseURL)
	req.Params = make([]Parameter, len(pu.Params))
	copy(req.Params, pu.Params)
	return req
}

// Payload 代表一个用于漏洞测试的攻击载荷。
type Payload struct {
	ID          string            `json:"id"`                     // 载荷唯一标识
	Value       string            `json:"value"`                  // 载荷值
	Description string            `json:"description"`            // 载荷描述
	Type        VulnerabilityType `json:"type"`                   // 漏洞类型
	Category    string            `json:"category,omitempty"`     // 载荷分类
	Severity    Severity          `json:"severity"`               // 严重程度
	Tags        []string          `json:"tags,omitempty"`         // 标签
	References  []string          `json:"references,omitempty"`   // 参考链接
	Author      string            `json:"author,omitempty"`       // 作者
	CreatedAt   time.Time         `json:"created_at"`             // 创建时间
	UpdatedAt   time.Time         `json:"updated_at,omitempty"`   // 更新时间
	Metadata    map[string]string `json:"metadata,omitempty"`     // 元数据
}

// NewPayload 创建新的载荷
func NewPayload(value, description string, vulnType VulnerabilityType) *Payload {
	return &Payload{
		ID:          generateID(value),
		Value:       value,
		Description: description,
		Type:        vulnType,
		Severity:    SeverityMedium,
		Tags:        make([]string, 0),
		References:  make([]string, 0),
		CreatedAt:   time.Now(),
		Metadata:    make(map[string]string),
	}
}

// Clone 克隆载荷
func (p *Payload) Clone() *Payload {
	clone := &Payload{
		ID:          p.ID,
		Value:       p.Value,
		Description: p.Description,
		Type:        p.Type,
		Category:    p.Category,
		Severity:    p.Severity,
		Tags:        make([]string, len(p.Tags)),
		References:  make([]string, len(p.References)),
		Author:      p.Author,
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
		Metadata:    make(map[string]string),
	}
	
	copy(clone.Tags, p.Tags)
	copy(clone.References, p.References)
	
	for key, value := range p.Metadata {
		clone.Metadata[key] = value
	}
	
	return clone
}

// AddTag 添加标签
func (p *Payload) AddTag(tag string) {
	for _, existingTag := range p.Tags {
		if existingTag == tag {
			return // 标签已存在
		}
	}
	p.Tags = append(p.Tags, tag)
}

// RemoveTag 移除标签
func (p *Payload) RemoveTag(tag string) {
	for i, existingTag := range p.Tags {
		if existingTag == tag {
			p.Tags = append(p.Tags[:i], p.Tags[i+1:]...)
			return
		}
	}
}

// HasTag 检查是否包含标签
func (p *Payload) HasTag(tag string) bool {
	for _, existingTag := range p.Tags {
		if existingTag == tag {
			return true
		}
	}
	return false
}

// Task 代表一个交给编排器(Orchestrator)处理的工作单元。
type Task struct {
	ID          string                 `json:"id"`                     // 任务唯一标识
	Type        TaskType               `json:"type"`                   // 任务类型
	Status      TaskStatus             `json:"status"`                 // 任务状态
	Priority    Priority               `json:"priority"`               // 优先级
	URL         string                 `json:"url"`                    // 要处理的URL
	Depth       int                    `json:"depth"`                  // 当前的爬取深度
	MaxDepth    int                    `json:"max_depth,omitempty"`    // 最大爬取深度
	Request     *Request               `json:"request,omitempty"`      // 扫描请求
	Payloads    []*Payload             `json:"payloads,omitempty"`     // 载荷列表
	Config      map[string]interface{} `json:"config,omitempty"`       // 任务配置
	Context     context.Context        `json:"-"`                      // 上下文
	Cancel      context.CancelFunc     `json:"-"`                      // 取消函数
	CreatedAt   time.Time              `json:"created_at"`             // 创建时间
	StartedAt   *time.Time             `json:"started_at,omitempty"`   // 开始时间
	CompletedAt *time.Time             `json:"completed_at,omitempty"` // 完成时间
	Error       string                 `json:"error,omitempty"`        // 错误信息
	Result      interface{}            `json:"result,omitempty"`       // 任务结果
	Metadata    map[string]string      `json:"metadata,omitempty"`     // 元数据
	Retries     int                    `json:"retries"`                // 重试次数
	MaxRetries  int                    `json:"max_retries"`            // 最大重试次数
}

// NewCrawlTask 创建爬取任务
func NewCrawlTask(url string, depth int) *Task {
	ctx, cancel := context.WithCancel(context.Background())
	return &Task{
		ID:         generateID(fmt.Sprintf("crawl_%s_%d", url, depth)),
		Type:       TaskTypeCrawl,
		Status:     TaskStatusPending,
		Priority:   PriorityNormal,
		URL:        url,
		Depth:      depth,
		MaxDepth:   10,
		Config:     make(map[string]interface{}),
		Context:    ctx,
		Cancel:     cancel,
		CreatedAt:  time.Now(),
		Metadata:   make(map[string]string),
		MaxRetries: 3,
	}
}

// NewScanTask 创建扫描任务
func NewScanTask(request *Request, payloads []*Payload) *Task {
	ctx, cancel := context.WithCancel(context.Background())
	return &Task{
		ID:         generateID(fmt.Sprintf("scan_%s", request.ID)),
		Type:       TaskTypeScan,
		Status:     TaskStatusPending,
		Priority:   PriorityNormal,
		URL:        request.URL,
		Request:    request,
		Payloads:   payloads,
		Config:     make(map[string]interface{}),
		Context:    ctx,
		Cancel:     cancel,
		CreatedAt:  time.Now(),
		Metadata:   make(map[string]string),
		MaxRetries: 3,
	}
}

// Start 开始任务
func (t *Task) Start() {
	t.Status = TaskStatusRunning
	now := time.Now()
	t.StartedAt = &now
}

// Complete 完成任务
func (t *Task) Complete(result interface{}) {
	t.Status = TaskStatusCompleted
	t.Result = result
	now := time.Now()
	t.CompletedAt = &now
}

// Fail 任务失败
func (t *Task) Fail(err error) {
	t.Status = TaskStatusFailed
	if err != nil {
		t.Error = err.Error()
	}
	now := time.Now()
	t.CompletedAt = &now
}

// Cancel 取消任务
func (t *Task) Cancel() {
	t.Status = TaskStatusCancelled
	if t.Cancel != nil {
		t.Cancel()
	}
	now := time.Now()
	t.CompletedAt = &now
}

// Timeout 任务超时
func (t *Task) Timeout() {
	t.Status = TaskStatusTimeout
	now := time.Now()
	t.CompletedAt = &now
}

// ShouldRetry 是否应该重试
func (t *Task) ShouldRetry() bool {
	return t.Retries < t.MaxRetries && (t.Status == TaskStatusFailed || t.Status == TaskStatusTimeout)
}

// Retry 重试任务
func (t *Task) Retry() {
	if t.ShouldRetry() {
		t.Retries++
		t.Status = TaskStatusPending
		t.Error = ""
		t.StartedAt = nil
		t.CompletedAt = nil
	}
}

// Duration 获取任务执行时长
func (t *Task) Duration() time.Duration {
	if t.StartedAt == nil {
		return 0
	}
	
	endTime := time.Now()
	if t.CompletedAt != nil {
		endTime = *t.CompletedAt
	}
	
	return endTime.Sub(*t.StartedAt)
}

// IsCompleted 检查任务是否已完成
func (t *Task) IsCompleted() bool {
	return t.Status == TaskStatusCompleted ||
		t.Status == TaskStatusFailed ||
		t.Status == TaskStatusCancelled ||
		t.Status == TaskStatusTimeout
}

// Clone 克隆任务
func (t *Task) Clone() *Task {
	ctx, cancel := context.WithCancel(context.Background())
	
	clone := &Task{
		ID:         generateID(t.ID + "_clone"),
		Type:       t.Type,
		Status:     TaskStatusPending,
		Priority:   t.Priority,
		URL:        t.URL,
		Depth:      t.Depth,
		MaxDepth:   t.MaxDepth,
		Config:     make(map[string]interface{}),
		Context:    ctx,
		Cancel:     cancel,
		CreatedAt:  time.Now(),
		Metadata:   make(map[string]string),
		MaxRetries: t.MaxRetries,
	}
	
	// 深拷贝Request
	if t.Request != nil {
		clone.Request = t.Request.Clone()
	}
	
	// 深拷贝Payloads
	if t.Payloads != nil {
		clone.Payloads = make([]*Payload, len(t.Payloads))
		for i, payload := range t.Payloads {
			clone.Payloads[i] = payload.Clone()
		}
	}
	
	// 深拷贝Config
	for key, value := range t.Config {
		clone.Config[key] = value
	}
	
	// 深拷贝Metadata
	for key, value := range t.Metadata {
		clone.Metadata[key] = value
	}
	
	return clone
}

// ResponseInfo 封装响应信息
type ResponseInfo struct {
	StatusCode    int                    `json:"status_code"`              // HTTP状态码
	Headers       http.Header            `json:"headers"`                  // 响应头
	Body          []byte                 `json:"body"`                     // 响应体
	ContentType   string                 `json:"content_type"`             // 内容类型
	ContentLength int64                  `json:"content_length"`           // 内容长度
	Hash          string                 `json:"hash"`                     // 响应哈希
	Encoding      string                 `json:"encoding,omitempty"`       // 编码
	Cookies       []*http.Cookie         `json:"cookies,omitempty"`        // Cookie
	RedirectURL   string                 `json:"redirect_url,omitempty"`   // 重定向URL
	ResponseTime  time.Duration          `json:"response_time"`            // 响应时间
	Timestamp     time.Time              `json:"timestamp"`                // 时间戳
	Error         string                 `json:"error,omitempty"`          // 错误信息
	Metadata      map[string]interface{} `json:"metadata,omitempty"`       // 元数据
}

// NewResponseInfo 创建新的响应信息
func NewResponseInfo() *ResponseInfo {
	return &ResponseInfo{
		Headers:   make(http.Header),
		Timestamp: time.Now(),
		Metadata:  make(map[string]interface{}),
	}
}

// FromHTTPResponse 从http.Response创建ResponseInfo
func (ri *ResponseInfo) FromHTTPResponse(resp *http.Response, body []byte, responseTime time.Duration) {
	ri.StatusCode = resp.StatusCode
	ri.Headers = resp.Header
	ri.Body = body
	ri.ContentType = resp.Header.Get("Content-Type")
	ri.ContentLength = resp.ContentLength
	ri.Hash = generateHash(body)
	ri.ResponseTime = responseTime
	ri.Timestamp = time.Now()
	
	// 获取Cookie
	ri.Cookies = resp.Cookies()
	
	// 获取重定向URL
	if location := resp.Header.Get("Location"); location != "" {
		ri.RedirectURL = location
	}
}

// IsSuccess 检查是否为成功响应
func (ri *ResponseInfo) IsSuccess() bool {
	return ri.StatusCode >= 200 && ri.StatusCode < 300
}

// IsRedirect 检查是否为重定向响应
func (ri *ResponseInfo) IsRedirect() bool {
	return ri.StatusCode >= 300 && ri.StatusCode < 400
}

// IsClientError 检查是否为客户端错误
func (ri *ResponseInfo) IsClientError() bool {
	return ri.StatusCode >= 400 && ri.StatusCode < 500
}

// IsServerError 检查是否为服务器错误
func (ri *ResponseInfo) IsServerError() bool {
	return ri.StatusCode >= 500 && ri.StatusCode < 600
}

// GetBodyString 获取响应体字符串
func (ri *ResponseInfo) GetBodyString() string {
	return string(ri.Body)
}

// Clone 克隆响应信息
func (ri *ResponseInfo) Clone() *ResponseInfo {
	clone := &ResponseInfo{
		StatusCode:    ri.StatusCode,
		Headers:       make(http.Header),
		Body:          make([]byte, len(ri.Body)),
		ContentType:   ri.ContentType,
		ContentLength: ri.ContentLength,
		Hash:          ri.Hash,
		Encoding:      ri.Encoding,
		RedirectURL:   ri.RedirectURL,
		ResponseTime:  ri.ResponseTime,
		Timestamp:     ri.Timestamp,
		Error:         ri.Error,
		Metadata:      make(map[string]interface{}),
	}
	
	// 深拷贝Headers
	for key, values := range ri.Headers {
		clone.Headers[key] = make([]string, len(values))
		copy(clone.Headers[key], values)
	}
	
	// 深拷贝Body
	copy(clone.Body, ri.Body)
	
	// 深拷贝Cookies
	if ri.Cookies != nil {
		clone.Cookies = make([]*http.Cookie, len(ri.Cookies))
		for i, cookie := range ri.Cookies {
			clone.Cookies[i] = &http.Cookie{}
			*clone.Cookies[i] = *cookie
		}
	}
	
	// 深拷贝Metadata
	for key, value := range ri.Metadata {
		clone.Metadata[key] = value
	}
	
	return clone
}

// Vulnerability 漏洞信息
type Vulnerability struct {
	ID          string            `json:"id"`                     // 漏洞唯一标识
	Type        VulnerabilityType `json:"type"`                   // 漏洞类型
	Severity    Severity          `json:"severity"`               // 严重程度
	Title       string            `json:"title"`                  // 漏洞标题
	Description string            `json:"description"`            // 漏洞描述
	URL         string            `json:"url"`                    // 漏洞URL
	Parameter   string            `json:"parameter,omitempty"`    // 漏洞参数
	Payload     string            `json:"payload,omitempty"`      // 攻击载荷
	Evidence    string            `json:"evidence,omitempty"`     // 漏洞证据
	Request     *Request          `json:"request,omitempty"`      // 原始请求
	Response    *ResponseInfo     `json:"response,omitempty"`     // 响应信息
	References  []string          `json:"references,omitempty"`   // 参考链接
	Solution    string            `json:"solution,omitempty"`     // 解决方案
	Tags        []string          `json:"tags,omitempty"`         // 标签
	CVSS        *CVSSScore        `json:"cvss,omitempty"`         // CVSS评分
	CWE         string            `json:"cwe,omitempty"`          // CWE编号
	OWASP       string            `json:"owasp,omitempty"`        // OWASP分类
	FoundAt     time.Time         `json:"found_at"`               // 发现时间
	VerifiedAt  *time.Time        `json:"verified_at,omitempty"`  // 验证时间
	Status      string            `json:"status"`                 // 状态 (new, verified, false_positive, fixed)
	Confidence  float64           `json:"confidence"`             // 置信度 (0-1)
	Metadata    map[string]string `json:"metadata,omitempty"`     // 元数据
}

// CVSSScore CVSS评分信息
type CVSSScore struct {
	Version         string  `json:"version"`                   // CVSS版本
	BaseScore       float64 `json:"base_score"`               // 基础分数
	TemporalScore   float64 `json:"temporal_score,omitempty"` // 时间分数
	EnvironmentalScore float64 `json:"environmental_score,omitempty"` // 环境分数
	Vector          string  `json:"vector,omitempty"`         // 评分向量
}

// NewVulnerability 创建新的漏洞
func NewVulnerability(vulnType VulnerabilityType, severity Severity, title, description string) *Vulnerability {
	return &Vulnerability{
		ID:          generateID(fmt.Sprintf("%s_%s_%d", vulnType, title, time.Now().Unix())),
		Type:        vulnType,
		Severity:    severity,
		Title:       title,
		Description: description,
		Tags:        make([]string, 0),
		References:  make([]string, 0),
		FoundAt:     time.Now(),
		Status:      "new",
		Confidence:  1.0,
		Metadata:    make(map[string]string),
	}
}

// Clone 克隆漏洞
func (v *Vulnerability) Clone() *Vulnerability {
	clone := &Vulnerability{
		ID:          v.ID,
		Type:        v.Type,
		Severity:    v.Severity,
		Title:       v.Title,
		Description: v.Description,
		URL:         v.URL,
		Parameter:   v.Parameter,
		Payload:     v.Payload,
		Evidence:    v.Evidence,
		References:  make([]string, len(v.References)),
		Solution:    v.Solution,
		Tags:        make([]string, len(v.Tags)),
		CWE:         v.CWE,
		OWASP:       v.OWASP,
		FoundAt:     v.FoundAt,
		Status:      v.Status,
		Confidence:  v.Confidence,
		Metadata:    make(map[string]string),
	}
	
	// 深拷贝Request
	if v.Request != nil {
		clone.Request = v.Request.Clone()
	}
	
	// 深拷贝Response
	if v.Response != nil {
		clone.Response = v.Response.Clone()
	}
	
	// 深拷贝CVSS
	if v.CVSS != nil {
		clone.CVSS = &CVSSScore{
			Version:            v.CVSS.Version,
			BaseScore:          v.CVSS.BaseScore,
			TemporalScore:      v.CVSS.TemporalScore,
			EnvironmentalScore: v.CVSS.EnvironmentalScore,
			Vector:             v.CVSS.Vector,
		}
	}
	
	// 深拷贝VerifiedAt
	if v.VerifiedAt != nil {
		verifiedAt := *v.VerifiedAt
		clone.VerifiedAt = &verifiedAt
	}
	
	// 深拷贝切片和映射
	copy(clone.References, v.References)
	copy(clone.Tags, v.Tags)
	
	for key, value := range v.Metadata {
		clone.Metadata[key] = value
	}
	
	return clone
}

// Verify 验证漏洞
func (v *Vulnerability) Verify() {
	v.Status = "verified"
	now := time.Now()
	v.VerifiedAt = &now
}

// MarkAsFalsePositive 标记为误报
func (v *Vulnerability) MarkAsFalsePositive() {
	v.Status = "false_positive"
}

// MarkAsFixed 标记为已修复
func (v *Vulnerability) MarkAsFixed() {
	v.Status = "fixed"
}

// AddTag 添加标签
func (v *Vulnerability) AddTag(tag string) {
	for _, existingTag := range v.Tags {
		if existingTag == tag {
			return
		}
	}
	v.Tags = append(v.Tags, tag)
}

// HasTag 检查是否包含标签
func (v *Vulnerability) HasTag(tag string) bool {
	for _, existingTag := range v.Tags {
		if existingTag == tag {
			return true
		}
	}
	return false
}

// GetSeverityScore 获取严重程度分数
func (v *Vulnerability) GetSeverityScore() int {
	switch v.Severity {
	case SeverityInfo:
		return 1
	case SeverityLow:
		return 2
	case SeverityMedium:
		return 3
	case SeverityHigh:
		return 4
	case SeverityCritical:
		return 5
	default:
		return 0
	}
}

// ScanResult 扫描结果
type ScanResult struct {
	ID             string           `json:"id"`                       // 结果唯一标识
	TaskID         string           `json:"task_id"`                  // 任务ID
	URL            string           `json:"url"`                      // 扫描URL
	Vulnerabilities []*Vulnerability `json:"vulnerabilities"`          // 发现的漏洞
	TotalRequests  int              `json:"total_requests"`           // 总请求数
	TotalTime      time.Duration    `json:"total_time"`               // 总耗时
	StartTime      time.Time        `json:"start_time"`               // 开始时间
	EndTime        time.Time        `json:"end_time"`                 // 结束时间
	Status         string           `json:"status"`                   // 扫描状态
	Error          string           `json:"error,omitempty"`          // 错误信息
	Statistics     *ScanStatistics  `json:"statistics,omitempty"`     // 统计信息
	Metadata       map[string]string `json:"metadata,omitempty"`      // 元数据
}

// ScanStatistics 扫描统计信息
type ScanStatistics struct {
	VulnCountBySeverity map[Severity]int            `json:"vuln_count_by_severity"` // 按严重程度统计漏洞数量
	VulnCountByType     map[VulnerabilityType]int   `json:"vuln_count_by_type"`     // 按类型统计漏洞数量
	RequestsPerSecond   float64                     `json:"requests_per_second"`    // 每秒请求数
	AverageResponseTime time.Duration               `json:"average_response_time"`  // 平均响应时间
	SuccessRate         float64                     `json:"success_rate"`           // 成功率
	ErrorCount          int                         `json:"error_count"`            // 错误数量
	TimeoutCount        int                         `json:"timeout_count"`          // 超时数量
}

// NewScanResult 创建新的扫描结果
func NewScanResult(taskID, url string) *ScanResult {
	return &ScanResult{
		ID:              generateID(fmt.Sprintf("result_%s_%s", taskID, url)),
		TaskID:          taskID,
		URL:             url,
		Vulnerabilities: make([]*Vulnerability, 0),
		StartTime:       time.Now(),
		Status:          "running",
		Statistics: &ScanStatistics{
			VulnCountBySeverity: make(map[Severity]int),
			VulnCountByType:     make(map[VulnerabilityType]int),
		},
		Metadata: make(map[string]string),
	}
}

// AddVulnerability 添加漏洞
func (sr *ScanResult) AddVulnerability(vuln *Vulnerability) {
	sr.Vulnerabilities = append(sr.Vulnerabilities, vuln)
	
	// 更新统计信息
	if sr.Statistics != nil {
		sr.Statistics.VulnCountBySeverity[vuln.Severity]++
		sr.Statistics.VulnCountByType[vuln.Type]++
	}
}

// Complete 完成扫描
func (sr *ScanResult) Complete() {
	sr.Status = "completed"
	sr.EndTime = time.Now()
	sr.TotalTime = sr.EndTime.Sub(sr.StartTime)
}

// Fail 扫描失败
func (sr *ScanResult) Fail(err error) {
	sr.Status = "failed"
	if err != nil {
		sr.Error = err.Error()
	}
	sr.EndTime = time.Now()
	sr.TotalTime = sr.EndTime.Sub(sr.StartTime)
}

// GetVulnerabilityCount 获取漏洞总数
func (sr *ScanResult) GetVulnerabilityCount() int {
	return len(sr.Vulnerabilities)
}

// GetHighSeverityCount 获取高危及以上漏洞数量
func (sr *ScanResult) GetHighSeverityCount() int {
	count := 0
	for _, vuln := range sr.Vulnerabilities {
		if vuln.Severity == SeverityHigh || vuln.Severity == SeverityCritical {
			count++
		}
	}
	return count
}

// GetVulnerabilitiesBySeverity 按严重程度获取漏洞
func (sr *ScanResult) GetVulnerabilitiesBySeverity(severity Severity) []*Vulnerability {
	var vulns []*Vulnerability
	for _, vuln := range sr.Vulnerabilities {
		if vuln.Severity == severity {
			vulns = append(vulns, vuln)
		}
	}
	return vulns
}

// GetVulnerabilitiesByType 按类型获取漏洞
func (sr *ScanResult) GetVulnerabilitiesByType(vulnType VulnerabilityType) []*Vulnerability {
	var vulns []*Vulnerability
	for _, vuln := range sr.Vulnerabilities {
		if vuln.Type == vulnType {
			vulns = append(vulns, vuln)
		}
	}
	return vulns
}

// UpdateStatistics 更新统计信息
func (sr *ScanResult) UpdateStatistics() {
	if sr.Statistics == nil {
		sr.Statistics = &ScanStatistics{
			VulnCountBySeverity: make(map[Severity]int),
			VulnCountByType:     make(map[VulnerabilityType]int),
		}
	}
	
	// 重置计数器
	for k := range sr.Statistics.VulnCountBySeverity {
		sr.Statistics.VulnCountBySeverity[k] = 0
	}
	for k := range sr.Statistics.VulnCountByType {
		sr.Statistics.VulnCountByType[k] = 0
	}
	
	// 重新计算
	for _, vuln := range sr.Vulnerabilities {
		sr.Statistics.VulnCountBySeverity[vuln.Severity]++
		sr.Statistics.VulnCountByType[vuln.Type]++
	}
	
	// 计算请求速率
	if sr.TotalTime > 0 {
		sr.Statistics.RequestsPerSecond = float64(sr.TotalRequests) / sr.TotalTime.Seconds()
	}
}

// CrawlResult 爬取结果
type CrawlResult struct {
	ID        string    `json:"id"`                   // 结果唯一标识
	TaskID    string    `json:"task_id"`              // 任务ID
	URL       string    `json:"url"`                  // 爬取URL
	URLs      []string  `json:"urls"`                 // 发现的URL
	Requests  []*Request `json:"requests"`             // 发现的请求
	Depth     int       `json:"depth"`                // 爬取深度
	StartTime time.Time `json:"start_time"`           // 开始时间
	EndTime   time.Time `json:"end_time"`             // 结束时间
	Status    string    `json:"status"`               // 爬取状态
	Error     string    `json:"error,omitempty"`      // 错误信息
	Metadata  map[string]string `json:"metadata,omitempty"` // 元数据
}

// NewCrawlResult 创建新的爬取结果
func NewCrawlResult(taskID, url string, depth int) *CrawlResult {
	return &CrawlResult{
		ID:        generateID(fmt.Sprintf("crawl_%s_%s_%d", taskID, url, depth)),
		TaskID:    taskID,
		URL:       url,
		URLs:      make([]string, 0),
		Requests:  make([]*Request, 0),
		Depth:     depth,
		StartTime: time.Now(),
		Status:    "running",
		Metadata:  make(map[string]string),
	}
}

// AddURL 添加发现的URL
func (cr *CrawlResult) AddURL(url string) {
	// 检查是否已存在
	for _, existingURL := range cr.URLs {
		if existingURL == url {
			return
		}
	}
	cr.URLs = append(cr.URLs, url)
}

// AddRequest 添加发现的请求
func (cr *CrawlResult) AddRequest(req *Request) {
	cr.Requests = append(cr.Requests, req)
}

// Complete 完成爬取
func (cr *CrawlResult) Complete() {
	cr.Status = "completed"
	cr.EndTime = time.Now()
}

// Fail 爬取失败
func (cr *CrawlResult) Fail(err error) {
	cr.Status = "failed"
	if err != nil {
		cr.Error = err.Error()
	}
	cr.EndTime = time.Now()
}

// GetURLCount 获取发现的URL数量
func (cr *CrawlResult) GetURLCount() int {
	return len(cr.URLs)
}

// GetRequestCount 获取发现的请求数量
func (cr *CrawlResult) GetRequestCount() int {
	return len(cr.Requests)
}

// Configuration 配置信息
type Configuration struct {
	// 爬虫配置
	CrawlerConfig struct {
		MaxDepth        int           `json:"max_depth"`         // 最大爬取深度
		MaxPages        int           `json:"max_pages"`         // 最大页面数
		Timeout         time.Duration `json:"timeout"`           // 超时时间
		UserAgent       string        `json:"user_agent"`        // User-Agent
		FollowRedirects bool          `json:"follow_redirects"`  // 是否跟随重定向
		MaxRedirects    int           `json:"max_redirects"`     // 最大重定向次数
		Delay           time.Duration `json:"delay"`             // 请求延迟
		Concurrency     int           `json:"concurrency"`       // 并发数
		Headers         http.Header   `json:"headers"`           // 自定义头部
		Cookies         []*http.Cookie `json:"cookies"`          // Cookie
		Proxy           string        `json:"proxy,omitempty"`   // 代理设置
	} `json:"crawler_config"`
	
	// 扫描器配置
	ScannerConfig struct {
		Timeout         time.Duration          `json:"timeout"`           // 超时时间
		MaxRetries      int                    `json:"max_retries"`       // 最大重试次数
		Concurrency     int                    `json:"concurrency"`       // 并发数
		EnabledModules  []VulnerabilityType    `json:"enabled_modules"`   // 启用的扫描模块
		PayloadSets     map[string][]*Payload  `json:"payload_sets"`      // 载荷集合
		SkipExtensions  []string               `json:"skip_extensions"`   // 跳过的文件扩展名
		CustomHeaders   http.Header            `json:"custom_headers"`    // 自定义头部
		FollowRedirects bool                   `json:"follow_redirects"`  // 是否跟随重定向
		VerifySSL       bool                   `json:"verify_ssl"`        // 是否验证SSL
		Proxy           string                 `json:"proxy,omitempty"`   // 代理设置
	} `json:"scanner_config"`
	
	// 报告配置
	ReportConfig struct {
		Format          string   `json:"format"`            // 报告格式 (json, html, xml, csv)
		OutputPath      string   `json:"output_path"`       // 输出路径
		IncludeFalsePositives bool `json:"include_false_positives"` // 是否包含误报
		MinSeverity     Severity `json:"min_severity"`      // 最小严重程度
		Template        string   `json:"template,omitempty"` // 报告模板
		CustomFields    []string `json:"custom_fields,omitempty"` // 自定义字段
	} `json:"report_config"`
	
	// 全局配置
	GlobalConfig struct {
		LogLevel        string        `json:"log_level"`         // 日志级别
		LogFile         string        `json:"log_file"`          // 日志文件
		WorkerCount     int           `json:"worker_count"`      // 工作线程数
		QueueSize       int           `json:"queue_size"`        // 队列大小
		DatabaseURL     string        `json:"database_url"`      // 数据库URL
		RedisURL        string        `json:"redis_url"`         // Redis URL
		MaxMemoryUsage  int64         `json:"max_memory_usage"`  // 最大内存使用量(MB)
		TempDir         string        `json:"temp_dir"`          // 临时目录
		EnableMetrics   bool          `json:"enable_metrics"`    // 是否启用指标收集
		MetricsPort     int           `json:"metrics_port"`      // 指标端口
		EnableProfiling bool          `json:"enable_profiling"`  // 是否启用性能分析
		ProfilingPort   int           `json:"profiling_port"`    // 性能分析端口
	} `json:"global_config"`
}

// DefaultConfiguration 返回默认配置
func DefaultConfiguration() *Configuration {
	config := &Configuration{}
	
	// 爬虫默认配置
	config.CrawlerConfig.MaxDepth = 3
	config.CrawlerConfig.MaxPages = 1000
	config.CrawlerConfig.Timeout = 30 * time.Second
	config.CrawlerConfig.UserAgent = "AutoVulnScan/1.0"
	config.CrawlerConfig.FollowRedirects = true
	config.CrawlerConfig.MaxRedirects = 5
	config.CrawlerConfig.Delay = 100 * time.Millisecond
	config.CrawlerConfig.Concurrency = 10
	config.CrawlerConfig.Headers = make(http.Header)
	
	// 扫描器默认配置
	config.ScannerConfig.Timeout = 30 * time.Second
	config.ScannerConfig.MaxRetries = 3
	config.ScannerConfig.Concurrency = 5
	config.ScannerConfig.EnabledModules = []VulnerabilityType{
		VulnTypeSQLInjection,
		VulnTypeXSS,
		VulnTypeRCE,
		VulnTypeLFI,
	}
	config.ScannerConfig.PayloadSets = make(map[string][]*Payload)
	config.ScannerConfig.SkipExtensions = []string{".jpg", ".png", ".gif", ".css", ".js", ".ico"}
	config.ScannerConfig.CustomHeaders = make(http.Header)
	config.ScannerConfig.FollowRedirects = false
	config.ScannerConfig.VerifySSL = true
	
	// 报告默认配置
	config.ReportConfig.Format = "json"
	config.ReportConfig.OutputPath = "./reports"
	config.ReportConfig.IncludeFalsePositives = false
	config.ReportConfig.MinSeverity = SeverityLow
	
	// 全局默认配置
	config.GlobalConfig.LogLevel = "info"
	config.GlobalConfig.LogFile = "./logs/autovulnscan.log"
	config.GlobalConfig.WorkerCount = 10
	config.GlobalConfig.QueueSize = 1000
	config.GlobalConfig.MaxMemoryUsage = 1024 // 1GB
	config.GlobalConfig.TempDir = "./tmp"
	config.GlobalConfig.EnableMetrics = true
	config.GlobalConfig.MetricsPort = 8080
	config.GlobalConfig.EnableProfiling = false
	config.GlobalConfig.ProfilingPort = 6060
	
	return config
}

// Validate 验证配置
func (c *Configuration) Validate() error {
	// 验证爬虫配置
	if c.CrawlerConfig.MaxDepth < 0 {
		return fmt.Errorf("爬虫最大深度不能为负数")
	}
	if c.CrawlerConfig.MaxPages <= 0 {
		return fmt.Errorf("爬虫最大页面数必须大于0")
	}
	if c.CrawlerConfig.Concurrency <= 0 {
		return fmt.Errorf("爬虫并发数必须大于0")
	}
	
	// 验证扫描器配置
	if c.ScannerConfig.MaxRetries < 0 {
		return fmt.Errorf("扫描器最大重试次数不能为负数")
	}
	if c.ScannerConfig.Concurrency <= 0 {
		return fmt.Errorf("扫描器并发数必须大于0")
	}
	
	// 验证全局配置
	if c.GlobalConfig.WorkerCount <= 0 {
		return fmt.Errorf("工作线程数必须大于0")
	}
	if c.GlobalConfig.QueueSize <= 0 {
		return fmt.Errorf("队列大小必须大于0")
	}
	
	return nil
}

// 工具函数

// generateID 生成唯一ID
func generateID(input string) string {
	hash := md5.Sum([]byte(fmt.Sprintf("%s_%d", input, time.Now().UnixNano())))
	return fmt.Sprintf("%x", hash)[:16]
}

// generateHash 生成数据哈希
func generateHash(data []byte) string {
	hash := md5.Sum(data)
	return fmt.Sprintf("%x", hash)
}

// ToJSON 转换为JSON字符串
func ToJSON(v interface{}) (string, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", fmt.Errorf("JSON序列化失败: %w", err)
	}
	return string(data), nil
}

// FromJSON 从JSON字符串解析
func FromJSON(data string, v interface{}) error {
	if err := json.Unmarshal([]byte(data), v); err != nil {
		return fmt.Errorf("JSON反序列化失败: %w", err)
	}
	return nil
}

// IsValidURL 检查URL是否有效
func IsValidURL(urlStr string) bool {
	u, err := url.Parse(urlStr)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// NormalizeURL 标准化URL
func NormalizeURL(urlStr string) (string, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return "", fmt.Errorf("解析URL失败: %w", err)
	}
	
	// 移除片段
	u.Fragment = ""
	
	// 标准化路径
	if u.Path == "" {
		u.Path = "/"
	}
	
	return u.String(), nil
}

// ExtractDomain 提取域名
func ExtractDomain(urlStr string) (string, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return "", fmt.Errorf("解析URL失败: %w", err)
	}
	return u.Host, nil
}

// IsSameDomain 检查是否为同一域名
func IsSameDomain(url1, url2 string) bool {
	domain1, err1 := ExtractDomain(url1)
	domain2, err2 := ExtractDomain(url2)
	
	if err1 != nil || err2 != nil {
		return false
	}
	
	return domain1 == domain2
}

// MergeHeaders 合并HTTP头部
func MergeHeaders(headers1, headers2 http.Header) http.Header {
	merged := make(http.Header)
	
	// 复制第一个头部
	for key, values := range headers1 {
		merged[key] = make([]string, len(values))
		copy(merged[key], values)
	}
	
	// 合并第二个头部
	for key, values := range headers2 {
		if existing, exists := merged[key]; exists {
			merged[key] = append(existing, values...)
		} else {
			merged[key] = make([]string, len(values))
			copy(merged[key], values)
		}
	}
	
	return merged
}

// FilterParameters 过滤参数
func FilterParameters(params []Parameter, predicate func(Parameter) bool) []Parameter {
	var filtered []Parameter
	for _, param := range params {
		if predicate(param) {
			filtered = append(filtered, param)
		}
	}
	return filtered
}

// MapParameters 映射参数
func MapParameters(params []Parameter, mapper func(Parameter) Parameter) []Parameter {
	mapped := make([]Parameter, len(params))
	for i, param := range params {
		mapped[i] = mapper(param)
	}
	return mapped
}

// GroupParametersByType 按类型分组参数
func GroupParametersByType(params []Parameter) map[string][]Parameter {
	groups := make(map[string][]Parameter)
	for _, param := range params {
		paramType := param.Type
		if paramType == "" {
			paramType = "unknown"
		}
		groups[paramType] = append(groups[paramType], param)
	}
	return groups
}
