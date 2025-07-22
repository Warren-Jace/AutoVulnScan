// Package core contains the main orchestrator for the AutoVulnScan application.
// It coordinates the discovery, scanning, and reporting phases.
package core

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"autovulnscan/internal/ai"
	"autovulnscan/internal/config"
	"autovulnscan/internal/crawler"
	"autovulnscan/internal/dedup"
	"autovulnscan/internal/models"
	"autovulnscan/internal/output"
	"autovulnscan/internal/requester"
	"autovulnscan/internal/vulnscan"
	_ "autovulnscan/internal/vulnscan/plugins" // Important for plugin registration

	"github.com/rs/zerolog/log"
)

// Orchestrator 负责协调爬虫、扫描和报告的主流程控制器
type Orchestrator struct {
	config       *config.Settings             // 配置文件
	targetURL    string                      // 目标URL
	crawler      *crawler.Crawler            // 爬虫实例
	plugins      []vulnscan.Plugin           // 插件列表
	deduplicator *dedup.Deduplicator         // 去重模块
	aiAnalyzer   *ai.AIAnalyzer              // AI 分析器
	httpClient   *requester.HTTPClient       // HTTP客户端
	payloads     map[string][]string         // 预加载的payloads（按插件名分类）
	ctx          context.Context             // 主上下文
	cancel       context.CancelFunc          // 取消函数
}

// NewOrchestrator 创建并初始化 Orchestrator 实例
func NewOrchestrator(cfg *config.Settings, targetURL string) (*Orchestrator, error) {
	ctx, cancel := context.WithCancel(context.Background())

	httpClient := requester.NewHTTPClient(time.Duration(cfg.Spider.Timeout)*time.Second, cfg.Spider.UserAgents)

	cr, err := crawler.NewCrawler(targetURL, &cfg.Spider, httpClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create crawler: %w", err)
	}

	deduplicator := dedup.NewDeduplicator()

	var aiAnalyzer *ai.AIAnalyzer
	if cfg.AIModule.Enabled {
		aiAnalyzer, err = ai.NewAIAnalyzer(cfg.AIModule.APIKey, cfg.AIModule.Model, "")
		if err != nil {
			log.Warn().Err(err).Msg("Failed to initialize AI Analyzer, proceeding without it.")
		}
	}

	o := &Orchestrator{
		config:       cfg,
		targetURL:    targetURL,
		crawler:      cr,
		plugins:      vulnscan.GetPlugins(),
		deduplicator: deduplicator,
		aiAnalyzer:   aiAnalyzer,
		httpClient:   httpClient,
		payloads:     make(map[string][]string),
		ctx:          ctx,
		cancel:       cancel,
	}

	if err := o.loadAllPayloads(); err != nil {
		return nil, fmt.Errorf("failed to load payloads: %w", err)
	}

	return o, nil
}

// loadAllPayloads 预加载所有插件的payloads
func (o *Orchestrator) loadAllPayloads() error {
	for _, p := range o.plugins {
		payloads, err := vulnscan.LoadPayloads(p.Info().Name)
		if err != nil {
			log.Warn().Err(err).Str("plugin", p.Info().Name).Msg("Failed to load payloads for plugin")
			continue // 或者可以更优雅地处理错误
		}
		o.payloads[p.Info().Name] = payloads
	}
	return nil
}

// Start 启动主流程，包含爬取、扫描和报告
func (o *Orchestrator) Start(reporter *output.Reporter) {
	log.Info().Msg("Orchestrator starting...")
	defer log.Info().Msg("Orchestrator finished.")
	defer o.cancel()

	var wg sync.WaitGroup
	taskQueue := make(chan models.Task, o.config.Spider.Concurrency)

	// 启动工作池（多个worker协同处理任务）
	for i := 0; i < o.config.Spider.Concurrency; i++ {
		go o.worker(i, taskQueue, &wg, reporter)
	}

	// 将初始目标URL作为第一个任务加入队列
	wg.Add(1)
	taskQueue <- models.Task{URL: o.targetURL, Depth: 0}

	// 等待所有任务完成，然后关闭任务队列
	wg.Wait()
	close(taskQueue)

	log.Info().Msg("Orchestrator shutdown complete.")
}

// worker 工作协程，不断从任务队列中取任务处理
func (o *Orchestrator) worker(id int, taskQueue chan models.Task, wg *sync.WaitGroup, reporter *output.Reporter) {
	log.Debug().Int("worker_id", id).Msg("Worker started")
	for task := range taskQueue {
		// 如果是扫描任务，直接执行扫描
		if task.Request != nil {
			log.Debug().Str("url", task.Request.URL.String()).Msg("Executing scan task")
			reporter.LogParamURL(task.Request)
			o.scanRequest(o.ctx, task.Request, reporter)
			wg.Done()
			continue
		}

		// 否则为爬取任务，处理爬取逻辑
		o.handleCrawlTask(task, taskQueue, wg, reporter)
	}
	log.Debug().Int("worker_id", id).Msg("Worker finished")
}

// handleCrawlTask 处理爬取任务，包括深度检查、内容去重、链接和请求发现
func (o *Orchestrator) handleCrawlTask(task models.Task, taskQueue chan models.Task, wg *sync.WaitGroup, reporter *output.Reporter) {
	defer wg.Done()

	// 1. 检查爬取深度
	if task.Depth >= o.config.Spider.MaxDepth {
		log.Debug().Str("url", task.URL).Int("depth", task.Depth).Msg("Max depth reached, not crawling")
		return
	}

	// 2. 获取页面内容
	resp, err := o.httpClient.Get(o.ctx, task.URL, nil)
	if err != nil {
		log.Error().Err(err).Str("url", task.URL).Msg("Failed to fetch URL")
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Str("url", task.URL).Msg("Failed to read response body")
		return
	}

	// 3. 检查内容唯一性（去重）
	isUnique, err := o.deduplicator.IsUnique(task.URL, bytes.NewReader(bodyBytes))
	if err != nil {
		log.Error().Err(err).Str("url", task.URL).Msg("Deduplication check failed")
		return
	}
	if !isUnique {
		log.Debug().Str("url", task.URL).Msg("Skipping duplicate content")
		reporter.LogDeDuplicateURL(task.URL)
		return
	}

	// 4. 爬取和解析页面内容，发现新链接和可扫描请求
	links, requests, err := o.crawler.Crawl(o.ctx, task.URL, bodyBytes)
	if err != nil {
		log.Error().Err(err).Str("url", task.URL).Msg("Failed to crawl URL")
		return
	}
	reporter.LogURL(task.URL)

	// 5. 将新任务加入队列
	wg.Add(len(links) + len(requests))

	for _, link := range links {
		taskQueue <- models.Task{URL: link, Depth: task.Depth + 1}
	}
	for _, req := range requests {
		taskQueue <- models.Task{Request: req}
	}
}

// scanRequest 对单个请求执行所有插件的扫描
func (o *Orchestrator) scanRequest(ctx context.Context, req *models.Request, reporter *output.Reporter) {
	for _, plugin := range o.plugins {
		pluginCtx, cancel := context.WithTimeout(ctx, o.config.Scanner.Timeout)
		defer cancel()

		// 获取预加载的payloads
		payloads, ok := o.payloads[plugin.Info().Name]
		if !ok || len(payloads) == 0 {
			log.Debug().Str("plugin", plugin.Info().Name).Msg("No payloads loaded for plugin, skipping scan.")
			continue
		}

		// 如果启用AI模块，生成AI辅助payload
		if o.aiAnalyzer != nil {
			var paramNames []string
			for _, p := range req.Params {
				paramNames = append(paramNames, p.Name)
			}
			aiPayloads, err := o.aiAnalyzer.GeneratePayloads(pluginCtx, plugin.Info().Name, req.URL.String(), req.Method, strings.Join(paramNames, ","))
			if err != nil {
				log.Error().Err(err).Msg("Failed to generate AI payloads")
			} else {
				payloads = append(payloads, aiPayloads...)
			}
		}

		// 执行插件扫描
		vulnerabilities, err := plugin.Scan(pluginCtx, req, payloads)
		if err != nil {
			log.Error().Err(err).Str("plugin", plugin.Info().Name).Str("url", req.URL.String()).Msg("Plugin scan failed")
			continue
		}

		// 记录扫描发现的漏洞
		for _, vuln := range vulnerabilities {
			reporter.LogVulnerability(vuln)
		}
	}
}
