// Package core contains the main orchestrator for the AutoVulnScan application.
package core

import (
	"context"
	"fmt"
	"net/url"
	"sync"

	"autovulnscan/internal/config"
	"autovulnscan/internal/crawler"
	"autovulnscan/internal/models"
	"autovulnscan/internal/output"
	"autovulnscan/internal/requester"
	"autovulnscan/internal/util"
	"autovulnscan/internal/vulnscan"

	"github.com/rs/zerolog/log"
	"golang.org/x/time/rate"
)

// Orchestrator coordinates the crawling and scanning process.
type Orchestrator struct {
	config     *config.Settings
	crawler    *crawler.Crawler
	scanEngine *vulnscan.Engine
	reporter   *output.Reporter
	limiter    *rate.Limiter
	ctx        context.Context
	cancel     context.CancelFunc
	targetURL  string
	baseURL    *url.URL
}

// NewOrchestrator creates a new Orchestrator.
func NewOrchestrator(cfg *config.Settings, client *requester.HTTPClient, r *output.Reporter, targetURL string) (*Orchestrator, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	cr, err := crawler.NewCrawler(&cfg.Spider, client)
	if err != nil {
		return nil, fmt.Errorf("failed to create crawler: %w", err)
	}

	se, err := vulnscan.NewEngine(client)
	if err != nil {
		return nil, fmt.Errorf("failed to create scan engine: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Orchestrator{
		config:     cfg,
		crawler:    cr,
		scanEngine: se,
		reporter:   r,
		limiter:    rate.NewLimiter(rate.Limit(cfg.Spider.Concurrency), cfg.Spider.Concurrency),
		ctx:        ctx,
		cancel:     cancel,
		targetURL:  targetURL,
		baseURL:    parsedURL,
	}, nil
}

// Start begins the orchestration process.
func (o *Orchestrator) Start() {
	log.Info().Msg("Orchestrator starting...")
	defer log.Info().Msg("Orchestrator finished.")
	defer o.cancel()

	var discoveryWg sync.WaitGroup
	urlsToProcess := make(chan string, o.config.Spider.Concurrency)
	newURLs := make(chan string, o.config.Spider.Concurrency)

	go o.urlManager(&discoveryWg, urlsToProcess, newURLs)

	discoveryWg.Add(1)
	go func() {
		defer discoveryWg.Done()
		newURLs <- o.targetURL
	}()

	var workerWg sync.WaitGroup
	for i := 0; i < o.config.Spider.Concurrency; i++ {
		workerWg.Add(1)
		go o.worker(&workerWg, urlsToProcess, newURLs)
	}

	discoveryWg.Wait()
	close(newURLs)
	workerWg.Wait()
}

func (o *Orchestrator) urlManager(discoveryWg *sync.WaitGroup, urlsToProcess chan<- string, newURLs <-chan string) {
	seen := make(map[string]struct{})
	for urlStr := range newURLs {
		if _, exists := seen[urlStr]; !exists {
			seen[urlStr] = struct{}{}
			discoveryWg.Add(1)
			urlsToProcess <- urlStr
		}
	}
	close(urlsToProcess)
}

func (o *Orchestrator) worker(wg *sync.WaitGroup, urlsToProcess <-chan string, newURLs chan<- string) {
	defer wg.Done()
	for urlStr := range urlsToProcess {
		o.limiter.Wait(o.ctx)

		log.Debug().Str("url", urlStr).Msg("Processing URL")

		content, extractedURLs, err := o.crawler.Crawl(o.ctx, urlStr)
		if err != nil {
			log.Warn().Err(err).Str("url", urlStr).Msg("Failed to crawl page")
			continue
		}
		o.reporter.LogURL(urlStr)

		for _, newURL := range extractedURLs {
			if util.IsInScope(newURL, o.config.Spider.Scope, o.config.Spider.Blacklist) {
				newURLs <- newURL.String()
			}
		}

		params := util.ExtractParameters(content)
		if len(params) > 0 {
			pURL := models.NewParameterizedURL(urlStr, params)
			o.reporter.LogParamURL(pURL)

			vulnerabilities := o.scanEngine.StartScan(o.ctx, pURL)
			for _, v := range vulnerabilities {
				log.Warn().Interface("vulnerability", v).Msg("Vulnerability Found!")
				o.reporter.LogVulnerability(v)
			}
		}
	}
}
