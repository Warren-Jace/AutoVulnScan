// Package vulnscan 包含了漏洞扫描引擎的核心逻辑。
// 它负责管理和执行各种漏洞扫描插件。
package vulnscan

import (
	"context"
	"sync"

	"autovulnscan/internal/config"
	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"
)

// Engine 是漏洞扫描引擎。
// 它维护一个插件注册表，并管理扫描任务的并发执行。
type Engine struct {
	config     *config.ScannerConfig
	registry   *Registry
	httpClient *requester.HTTPClient
	taskQueue  chan *models.Request
	results    chan *Vulnerability
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewEngine 创建一个新的扫描引擎实例。
func NewEngine(cfg *config.ScannerConfig, client *requester.HTTPClient) *Engine {
	ctx, cancel := context.WithCancel(context.Background())
	return &Engine{
		config:     cfg,
		registry:   GetRegistry(),
		httpClient: client,
		taskQueue:  make(chan *models.Request, cfg.Concurrency*2),
		results:    make(chan *Vulnerability, 100),
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start 启动扫描引擎的worker协程。
// 这些worker会从任务队列中获取请求并使用注册的插件进行扫描。
func (e *Engine) Start() {
	for i := 0; i < e.config.Concurrency; i++ {
		e.wg.Add(1)
		go e.scanWorker(i)
	}
}

// Stop 停止扫描引擎并等待所有任务完成。
func (e *Engine) Stop() {
	close(e.taskQueue)
	e.wg.Wait()
	close(e.results)
	e.cancel()
}

// Submit 将一个新的HTTP请求提交到扫描队列中。
func (e *Engine) Submit(req *models.Request) {
	e.taskQueue <- req
}

// Results 返回一个通道，可以从中接收扫描发现的漏洞。
func (e *Engine) Results() <-chan *Vulnerability {
	return e.results
}

// scanWorker 是执行实际扫描工作的worker函数。
// 它从队列中消费请求，并为每个请求执行所有已启用的插件。
func (e *Engine) scanWorker(workerID int) {
	defer e.wg.Done()
	for req := range e.taskQueue {
		for _, plugin := range e.registry.GetPlugins() {
			select {
			case <-e.ctx.Done():
				return
			default:
				vulns, err := plugin.Scan(e.httpClient, req)
				if err != nil {
					// handle error
				}
				for _, v := range vulns {
					e.results <- v
				}
			}
		}
	}
}
