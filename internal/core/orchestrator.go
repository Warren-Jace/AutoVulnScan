// Package core contains the main orchestrator for the AutoVulnScan application.
// It coordinates the discovery, scanning, and reporting phases.
package core

import (
	"context"
	"fmt"
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

	"github.com/rs/zerolog/log"
	"io"
	"bytes"
)

// Orchestrator coordinates the crawling, scanning, and reporting process.
type Orchestrator struct {
	config       *config.Settings
	targetURL    string
	crawler      *crawler.Crawler
	plugins      []vulnscan.Plugin
	deduplicator *dedup.Deduplicator
	aiAnalyzer   *ai.AIAnalyzer
	httpClient   *requester.HTTPClient
	payloads     map[string][]string // Pre-loaded payloads
	ctx          context.Context
	cancel       context.CancelFunc
}

// NewOrchestrator creates a new Orchestrator.
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

func (o *Orchestrator) loadAllPayloads() error {
	for _, p := range o.plugins {
		payloads, err := vulnscan.LoadPayloads(p.Info().Name)
		if err != nil {
			log.Warn().Err(err).Str("plugin", p.Info().Name).Msg("Failed to load payloads for plugin")
			continue // Or handle error more gracefully
		}
		o.payloads[p.Info().Name] = payloads
	}
	return nil
}

// Start begins the orchestration process.
func (o *Orchestrator) Start(reporter *output.Reporter) {
	log.Info().Msg("Orchestrator starting...")
	defer log.Info().Msg("Orchestrator finished.")
	defer o.cancel()

	var wg sync.WaitGroup
	taskQueue := make(chan models.Task, o.config.Spider.Concurrency)

	// Worker pool
	for i := 0; i < o.config.Spider.Concurrency; i++ {
		wg.Add(1)
		go o.worker(i, taskQueue, &wg, reporter)
	}

	// Seed the initial URL for crawling
	taskQueue <- models.Task{URL: o.targetURL, Depth: 0}

	wg.Wait()
	close(taskQueue)
	log.Info().Msg("Orchestrator shutdown complete.")
}

// worker is a goroutine that processes tasks from the queue.
func (o *Orchestrator) worker(id int, taskQueue chan models.Task, wg *sync.WaitGroup, reporter *output.Reporter) {
	defer wg.Done()
	log.Debug().Int("worker_id", id).Msg("Worker started")

	for task := range taskQueue {
		// If the task is a scan task, execute it
		if task.Request != nil {
			log.Debug().Str("url", task.Request.URL.String()).Msg("Executing scan task")
			reporter.LogParamURL(task.Request)
			o.scanRequest(o.ctx, task.Request, reporter)
			continue
		}

		// Otherwise, it's a crawl task
		log.Info().Str("url", task.URL).Msg("Crawling URL")
		resp, err := o.httpClient.Get(o.ctx, task.URL, nil)
		if err != nil {
			log.Error().Err(err).Str("url", task.URL).Msg("Failed to fetch URL for deduplication")
			continue
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Error().Err(err).Str("url", task.URL).Msg("Failed to read response body for deduplication")
			continue
		}

		isUnique, err := o.deduplicator.IsUnique(task.URL, bytes.NewReader(bodyBytes))
		if err != nil {
			log.Error().Err(err).Str("url", task.URL).Msg("Deduplication check failed")
			continue
		}

		if !isUnique {
			log.Debug().Str("url", task.URL).Msg("Skipping duplicate content")
			reporter.LogDeDuplicateURL(task.URL)
			continue
		}

		if task.Depth >= o.config.Spider.MaxDepth {
			log.Debug().Str("url", task.URL).Int("depth", task.Depth).Msg("Max depth reached, not crawling")
			continue
		}

		links, requests, err := o.crawler.Crawl(o.ctx, task.URL)
		if err != nil {
			log.Error().Err(err).Str("url", task.URL).Msg("Failed to crawl URL")
			continue
		}
		reporter.LogURL(task.URL)

		// Add new crawl tasks
		for _, link := range links {
			wg.Add(1)
			// Use a goroutine to avoid blocking the worker
			go func(l string) {
				taskQueue <- models.Task{URL: l, Depth: task.Depth + 1}
			}(link)
		}

		// Add new scan tasks
		for _, req := range requests {
			wg.Add(1)
			go func(r *models.Request) {
				taskQueue <- models.Task{Request: r}
			}(req)
		}
	}
	log.Debug().Int("worker_id", id).Msg("Worker finished")
}

func (o *Orchestrator) scanRequest(ctx context.Context, req *models.Request, reporter *output.Reporter) {
	for _, plugin := range o.plugins {
		pluginCtx, cancel := context.WithTimeout(ctx, o.config.Scanner.Timeout)
		defer cancel()

		// Get pre-loaded payloads
		payloads, ok := o.payloads[plugin.Info().Name]
		if !ok || len(payloads) == 0 {
			log.Debug().Str("plugin", plugin.Info().Name).Msg("No payloads loaded for plugin, skipping scan.")
			continue
		}

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

		vulnerabilities, err := plugin.Scan(pluginCtx, req, payloads)
		if err != nil {
			log.Error().Err(err).Str("plugin", plugin.Info().Name).Str("url", req.URL.String()).Msg("Plugin scan failed")
			continue
		}

		for _, vuln := range vulnerabilities {
			reporter.LogVulnerability(vuln)
		}
	}
}
