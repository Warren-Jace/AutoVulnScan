// Package cmd 包含了 AutoVulnScan 的所有命令行相关逻辑。
package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// ProxyServer HTTP代理服务器
type ProxyServer struct {
	// 配置选项
	ListenAddr    string        `json:"listen_addr"`
	LogFile       string        `json:"log_file"`
	Timeout       time.Duration `json:"timeout"`
	MaxConns      int           `json:"max_connections"`
	EnableHTTPS   bool          `json:"enable_https"`
	CertFile      string        `json:"cert_file"`
	KeyFile       string        `json:"key_file"`
	EnableAuth    bool          `json:"enable_auth"`
	Username      string        `json:"username"`
	Password      string        `json:"password"`
	EnableLogging bool          `json:"enable_logging"`
	LogLevel      string        `json:"log_level"`
	
	// 过滤配置
	FilterRules   []FilterRule  `json:"filter_rules"`
	BlockedHosts  []string      `json:"blocked_hosts"`
	AllowedHosts  []string      `json:"allowed_hosts"`
	
	// 内部状态
	server        *http.Server
	logger        *log.Logger
	logFile       *os.File
	stats         *ProxyStats
	connLimiter   chan struct{}
	shutdown      chan struct{}
	wg            sync.WaitGroup
	mu            sync.RWMutex
}

// FilterRule 过滤规则
type FilterRule struct {
	Pattern string `json:"pattern"`
	Action  string `json:"action"` // "allow", "block", "log"
	Regex   *regexp.Regexp
}

// ProxyStats 代理统计信息
type ProxyStats struct {
	RequestCount    int64 `json:"request_count"`
	ResponseCount   int64 `json:"response_count"`
	BytesReceived   int64 `json:"bytes_received"`
	BytesSent       int64 `json:"bytes_sent"`
	ErrorCount      int64 `json:"error_count"`
	BlockedRequests int64 `json:"blocked_requests"`
	StartTime       time.Time `json:"start_time"`
}

// NewProxyServer 创建新的代理服务器实例
func NewProxyServer() *ProxyServer {
	return &ProxyServer{
		ListenAddr:    ":8080",
		Timeout:       30 * time.Second,
		MaxConns:      1000,
		EnableLogging: true,
		LogLevel:      "info",
		stats:         &ProxyStats{StartTime: time.Now()},
		shutdown:      make(chan struct{}),
	}
}

// Start 启动代理服务器
func (ps *ProxyServer) Start() error {
	// 初始化连接限制器
	ps.connLimiter = make(chan struct{}, ps.MaxConns)
	
	// 初始化日志
	if err := ps.initLogger(); err != nil {
		return fmt.Errorf("初始化日志失败: %w", err)
	}
	
	// 编译过滤规则
	if err := ps.compileFilterRules(); err != nil {
		return fmt.Errorf("编译过滤规则失败: %w", err)
	}
	
	// 创建HTTP服务器
	ps.server = &http.Server{
		Addr:         ps.ListenAddr,
		Handler:      ps.createHandler(),
		ReadTimeout:  ps.Timeout,
		WriteTimeout: ps.Timeout,
		IdleTimeout:  ps.Timeout * 2,
		ConnState:    ps.handleConnState,
	}
	
	// 配置TLS
	if ps.EnableHTTPS {
		if ps.CertFile == "" || ps.KeyFile == "" {
			return fmt.Errorf("启用HTTPS需要指定证书文件和密钥文件")
		}
		ps.server.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}
	
	ps.logger.Printf("代理服务器启动，监听地址: %s", ps.ListenAddr)
	
	// 启动服务器
	var err error
	if ps.EnableHTTPS {
		err = ps.server.ListenAndServeTLS(ps.CertFile, ps.KeyFile)
	} else {
		err = ps.server.ListenAndServe()
	}
	
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("启动服务器失败: %w", err)
	}
	
	return nil
}

// Stop 停止代理服务器
func (ps *ProxyServer) Stop() error {
	close(ps.shutdown)
	
	// 优雅关闭服务器
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	if ps.server != nil {
		if err := ps.server.Shutdown(ctx); err != nil {
			ps.logger.Printf("服务器关闭错误: %v", err)
		}
	}
	
	// 等待所有goroutine完成
	ps.wg.Wait()
	
	// 关闭日志文件
	if ps.logFile != nil {
		ps.logFile.Close()
	}
	
	ps.logger.Println("代理服务器已停止")
	return nil
}

// initLogger 初始化日志记录器
func (ps *ProxyServer) initLogger() error {
	if ps.LogFile != "" {
		file, err := os.OpenFile(ps.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return fmt.Errorf("打开日志文件失败: %w", err)
		}
		ps.logFile = file
		ps.logger = log.New(io.MultiWriter(os.Stdout, file), "[PROXY] ", log.LstdFlags|log.Lshortfile)
	} else {
		ps.logger = log.New(os.Stdout, "[PROXY] ", log.LstdFlags|log.Lshortfile)
	}
	return nil
}

// compileFilterRules 编译过滤规则
func (ps *ProxyServer) compileFilterRules() error {
	for i := range ps.FilterRules {
		regex, err := regexp.Compile(ps.FilterRules[i].Pattern)
		if err != nil {
			return fmt.Errorf("编译正则表达式失败 '%s': %w", ps.FilterRules[i].Pattern, err)
		}
		ps.FilterRules[i].Regex = regex
	}
	return nil
}

// createHandler 创建HTTP处理器
func (ps *ProxyServer) createHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 连接限制
		select {
		case ps.connLimiter <- struct{}{}:
			defer func() { <-ps.connLimiter }()
		default:
			http.Error(w, "服务器繁忙", http.StatusServiceUnavailable)
			atomic.AddInt64(&ps.stats.ErrorCount, 1)
			return
		}
		
		// 身份验证
		if ps.EnableAuth && !ps.authenticate(r) {
			w.Header().Set("Proxy-Authenticate", "Basic realm=\"Proxy\"")
			http.Error(w, "需要代理认证", http.StatusProxyAuthRequired)
			return
		}
		
		// 处理请求
		ps.handleRequest(w, r)
	})
}

// authenticate 身份验证
func (ps *ProxyServer) authenticate(r *http.Request) bool {
	if ps.Username == "" && ps.Password == "" {
		return true
	}
	
	username, password, ok := r.BasicAuth()
	if !ok {
		return false
	}
	
	return username == ps.Username && password == ps.Password
}

// handleRequest 处理HTTP请求
func (ps *ProxyServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&ps.stats.RequestCount, 1)
	
	// 检查是否为CONNECT方法（HTTPS隧道）
	if r.Method == http.MethodConnect {
		ps.handleHTTPSConnect(w, r)
		return
	}
	
	// 应用过滤规则
	if ps.shouldBlock(r) {
		atomic.AddInt64(&ps.stats.BlockedRequests, 1)
		http.Error(w, "请求被阻止", http.StatusForbidden)
		ps.logger.Printf("阻止请求: %s %s", r.Method, r.URL.String())
		return
	}
	
	// 记录请求
	if ps.EnableLogging {
		ps.logRequest(r)
	}
	
	// 创建反向代理
	proxy := &httputil.ReverseProxy{
		Director: ps.createDirector(),
		ModifyResponse: ps.createResponseModifier(),
		ErrorHandler: ps.createErrorHandler(),
		Transport: ps.createTransport(),
	}
	
	proxy.ServeHTTP(w, r)
}

// handleHTTPSConnect 处理HTTPS CONNECT请求
func (ps *ProxyServer) handleHTTPSConnect(w http.ResponseWriter, r *http.Request) {
	// 检查目标主机
	if ps.shouldBlockHost(r.Host) {
		atomic.AddInt64(&ps.stats.BlockedRequests, 1)
		http.Error(w, "连接被阻止", http.StatusForbidden)
		ps.logger.Printf("阻止HTTPS连接: %s", r.Host)
		return
	}
	
	ps.logger.Printf("HTTPS隧道连接: %s", r.Host)
	
	// 连接到目标服务器
	destConn, err := net.DialTimeout("tcp", r.Host, ps.Timeout)
	if err != nil {
		atomic.AddInt64(&ps.stats.ErrorCount, 1)
		http.Error(w, "连接目标服务器失败", http.StatusBadGateway)
		ps.logger.Printf("连接失败 %s: %v", r.Host, err)
		return
	}
	defer destConn.Close()
	
	// 获取客户端连接
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "不支持连接劫持", http.StatusInternalServerError)
		return
	}
	
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		atomic.AddInt64(&ps.stats.ErrorCount, 1)
		ps.logger.Printf("连接劫持失败: %v", err)
		return
	}
	defer clientConn.Close()
	
	// 发送连接成功响应
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		atomic.AddInt64(&ps.stats.ErrorCount, 1)
		ps.logger.Printf("发送连接响应失败: %v", err)
		return
	}
	
	// 开始数据转发
	ps.wg.Add(1)
	go func() {
		defer ps.wg.Done()
		ps.relay(clientConn, destConn)
	}()
}

// relay 在两个连接之间转发数据
func (ps *ProxyServer) relay(conn1, conn2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	
	// 双向数据转发
	go func() {
		defer wg.Done()
		written, _ := io.Copy(conn1, conn2)
		atomic.AddInt64(&ps.stats.BytesSent, written)
	}()
	
	go func() {
		defer wg.Done()
		written, _ := io.Copy(conn2, conn1)
		atomic.AddInt64(&ps.stats.BytesReceived, written)
	}()
	
	wg.Wait()
}

// shouldBlock 检查是否应该阻止请求
func (ps *ProxyServer) shouldBlock(r *http.Request) bool {
	// 检查主机白名单/黑名单
	if ps.shouldBlockHost(r.Host) {
		return true
	}
	
	// 应用过滤规则
	for _, rule := range ps.FilterRules {
		if rule.Regex.MatchString(r.URL.String()) {
			switch rule.Action {
			case "block":
				return true
			case "log":
				ps.logger.Printf("匹配规则 '%s': %s %s", rule.Pattern, r.Method, r.URL.String())
			}
		}
	}
	
	return false
}

// shouldBlockHost 检查是否应该阻止主机
func (ps *ProxyServer) shouldBlockHost(host string) bool {
	// 移除端口号
	hostname := host
	if strings.Contains(host, ":") {
		hostname, _, _ = net.SplitHostPort(host)
	}
	
	// 检查黑名单
	for _, blocked := range ps.BlockedHosts {
		if strings.Contains(hostname, blocked) {
			return true
		}
	}
	
	// 检查白名单
	if len(ps.AllowedHosts) > 0 {
		for _, allowed := range ps.AllowedHosts {
			if strings.Contains(hostname, allowed) {
				return false
			}
		}
		return true // 如果有白名单但不在其中，则阻止
	}
	
	return false
}

// createDirector 创建请求导向器
func (ps *ProxyServer) createDirector() func(*http.Request) {
	return func(req *http.Request) {
		// 确保请求有完整的URL
		if req.URL.Scheme == "" {
			req.URL.Scheme = "http"
		}
		if req.URL.Host == "" {
			req.URL.Host = req.Host
		}
		
		// 清理代理相关的头部
		req.Header.Del("Proxy-Connection")
		req.Header.Del("Proxy-Authenticate")
		req.Header.Del("Proxy-Authorization")
		
		// 设置X-Forwarded-For头部
		if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
			if prior, ok := req.Header["X-Forwarded-For"]; ok {
				clientIP = strings.Join(prior, ", ") + ", " + clientIP
			}
			req.Header.Set("X-Forwarded-For", clientIP)
		}
	}
}

// createResponseModifier 创建响应修改器
func (ps *ProxyServer) createResponseModifier() func(*http.Response) error {
	return func(resp *http.Response) error {
		atomic.AddInt64(&ps.stats.ResponseCount, 1)
		
		// 记录响应
		if ps.EnableLogging {
			ps.logResponse(resp)
		}
		
		// 添加代理标识头部
		resp.Header.Set("X-Proxy-By", "AutoVulnScan-Proxy")
		
		return nil
	}
}

// createErrorHandler 创建错误处理器
func (ps *ProxyServer) createErrorHandler() func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		atomic.AddInt64(&ps.stats.ErrorCount, 1)
		ps.logger.Printf("代理错误 %s %s: %v", r.Method, r.URL.String(), err)
		http.Error(w, "代理服务器错误", http.StatusBadGateway)
	}
}

// createTransport 创建HTTP传输器
func (ps *ProxyServer) createTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   ps.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // 在生产环境中应该设为false
		},
	}
}

// logRequest 记录请求
func (ps *ProxyServer) logRequest(r *http.Request) {
	if ps.LogLevel == "debug" {
		if dump, err := httputil.DumpRequest(r, true); err == nil {
			ps.logger.Printf("请求详情:\n%s", string(dump))
		}
	} else {
		ps.logger.Printf("请求: %s %s %s", r.Method, r.URL.String(), r.RemoteAddr)
	}
}

// logResponse 记录响应
func (ps *ProxyServer) logResponse(resp *http.Response) {
	if ps.LogLevel == "debug" {
		if dump, err := httputil.DumpResponse(resp, true); err == nil {
			ps.logger.Printf("响应详情:\n%s", string(dump))
		}
	} else {
		ps.logger.Printf("响应: %d %s", resp.StatusCode, resp.Status)
	}
}

// handleConnState 处理连接状态变化
func (ps *ProxyServer) handleConnState(conn net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		ps.logger.Printf("新连接: %s", conn.RemoteAddr())
	case http.StateClosed:
		ps.logger.Printf("连接关闭: %s", conn.RemoteAddr())
	}
}

// GetStats 获取统计信息
func (ps *ProxyServer) GetStats() *ProxyStats {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	
	stats := *ps.stats
	return &stats
}

// PrintStats 打印统计信息
func (ps *ProxyServer) PrintStats() {
	stats := ps.GetStats()
	uptime := time.Since(stats.StartTime)
	
	fmt.Printf("\n=== 代理服务器统计信息 ===\n")
	fmt.Printf("运行时间: %v\n", uptime)
	fmt.Printf("请求总数: %d\n", stats.RequestCount)
	fmt.Printf("响应总数: %d\n", stats.ResponseCount)
	fmt.Printf("接收字节: %d\n", stats.BytesReceived)
	fmt.Printf("发送字节: %d\n", stats.BytesSent)
	fmt.Printf("错误次数: %d\n", stats.ErrorCount)
	fmt.Printf("阻止请求: %d\n", stats.BlockedRequests)
	fmt.Printf("========================\n\n")
}

// LoadConfig 从文件加载配置
func (ps *ProxyServer) LoadConfig(filename string) error {
	// 这里可以实现从配置文件加载设置的逻辑
	// 例如JSON、YAML等格式
	return nil
}

// proxyCmd 实现了 'proxy' 子命令
var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "启动一个功能完整的HTTP/HTTPS代理服务器",
	Long: `此命令会启动一个高性能的HTTP/HTTPS代理服务器，支持以下功能：
- HTTP和HTTPS流量代理
- 请求/响应日志记录
- 访问控制和过滤
- 连接限制和超时控制
- 身份验证
- 统计信息收集
- 优雅关闭

适用于网络流量分析、调试和安全测试。`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// 创建代理服务器实例
		proxy := NewProxyServer()
		
		// 从命令行参数设置配置
		if err := setProxyConfig(proxy, cmd); err != nil {
			return fmt.Errorf("配置代理服务器失败: %w", err)
		}
		
		// 设置信号处理
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		
		// 启动代理服务器
		go func() {
			if err := proxy.Start(); err != nil {
				log.Fatalf("启动代理服务器失败: %v", err)
			}
		}()
		
		// 定期打印统计信息
		statsTicker := time.NewTicker(30 * time.Second)
		defer statsTicker.Stop()
		
		// 等待信号
		for {
			select {
			case <-sigChan:
				log.Println("收到停止信号，正在关闭代理服务器...")
				proxy.PrintStats()
				return proxy.Stop()
			case <-statsTicker.C:
				proxy.PrintStats()
			}
		}
	},
}

// setProxyConfig 从命令行参数设置代理配置
func setProxyConfig(proxy *ProxyServer, cmd *cobra.Command) error {
	var err error
	
	// 基本配置
	if proxy.ListenAddr, err = cmd.Flags().GetString("listen"); err != nil {
		return err
	}
	if proxy.LogFile, err = cmd.Flags().GetString("log-file"); err != nil {
		return err
	}
	if proxy.MaxConns, err = cmd.Flags().GetInt("max-connections"); err != nil {
		return err
	}
	if proxy.EnableLogging, err = cmd.Flags().GetBool("enable-logging"); err != nil {
		return err
	}
	if proxy.LogLevel, err = cmd.Flags().GetString("log-level"); err != nil {
		return err
	}
	
	// HTTPS配置
	if proxy.EnableHTTPS, err = cmd.Flags().GetBool("enable-https"); err != nil {
		return err
	}
	if proxy.CertFile, err = cmd.Flags().GetString("cert-file"); err != nil {
		return err
	}
	if proxy.KeyFile, err = cmd.Flags().GetString("key-file"); err != nil {
		return err
	}
	
	// 身份验证配置
	if proxy.EnableAuth, err = cmd.Flags().GetBool("enable-auth"); err != nil {
		return err
	}
	if proxy.Username, err = cmd.Flags().GetString("username"); err != nil {
		return err
	}
	if proxy.Password, err = cmd.Flags().GetString("password"); err != nil {
		return err
	}
	
	// 过滤配置
	if blockedHosts, err := cmd.Flags().GetStringSlice("blocked-hosts"); err == nil {
		proxy.BlockedHosts = blockedHosts
	}
	if allowedHosts, err := cmd.Flags().GetStringSlice("allowed-hosts"); err == nil {
		proxy.AllowedHosts = allowedHosts
	}
	
	// 超时配置
	if timeoutStr, err := cmd.Flags().GetString("timeout"); err == nil {
		if timeout, err := time.ParseDuration(timeoutStr); err == nil {
			proxy.Timeout = timeout
		}
	}
	
	return nil
}

func init() {
	rootCmd.AddCommand(proxyCmd)
	
	// 基本配置标志
	proxyCmd.Flags().StringP("listen", "l", ":8080", "代理服务器监听地址")
	proxyCmd.Flags().String("log-file", "", "日志文件路径（为空则输出到控制台）")
	proxyCmd.Flags().Int("max-connections", 1000, "最大并发连接数")
	proxyCmd.Flags().Bool("enable-logging", true, "启用请求日志记录")
	proxyCmd.Flags().String("log-level", "info", "日志级别 (debug, info, warn, error)")
	proxyCmd.Flags().String("timeout", "30s", "请求超时时间")
	
	// HTTPS配置标志
	proxyCmd.Flags().Bool("enable-https", false, "启用HTTPS支持")
	proxyCmd.Flags().String("cert-file", "", "SSL证书文件路径")
	proxyCmd.Flags().String("key-file", "", "SSL私钥文件路径")
	
	// 身份验证标志
	proxyCmd.Flags().Bool("enable-auth", false, "启用代理身份验证")
	proxyCmd.Flags().String("username", "", "认证用户名")
	proxyCmd.Flags().String("password", "", "认证密码")
	
	// 访问控制标志
	proxyCmd.Flags().StringSlice("blocked-hosts", []string{}, "阻止访问的主机列表")
	proxyCmd.Flags().StringSlice("allowed-hosts", []string{}, "允许访问的主机列表（白名单）")
	
	// 配置文件标志
	proxyCmd.Flags().String("config", "", "配置文件路径")
}
