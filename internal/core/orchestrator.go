// Package core contains the main orchestrator for the AutoVulnScan application.
// It coordinates the discovery, scanning, and reporting phases.
package core

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"autovulnscan/internal/ai"
	"autovulnscan/internal/config"
	"autovulnscan/internal/crawler"
	"autovulnscan/internal/dedup"
	"autovulnscan/internal/output"
	"autovulnscan/internal/vulnscan"
	"autovulnscan/internal/requester"

	"github.com/rs/zerolog/log"
	"golang.org/x/time/rate"
)

// Orchestrator is the main coordinator for the scanning process.
type Orchestrator struct {
	config         *config.Settings
	httpClient     *requester.HTTPClient
	plugins        []vulnscan.Plugin
	crawler        *crawler.Crawler
	pageSignatures []dedup.PageSignature
	limiter        *rate.Limiter
	ctx            context.Context
	cancel         context.CancelFunc
	targetURL      string
	baseURL        *url.URL
	aiAnalyzer     *ai.AIAnalyzer
}

// NewOrchestrator creates and initializes a new Orchestrator instance.
func NewOrchestrator(cfg *config.Settings, targetURL string) (*Orchestrator, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	client := requester.NewHTTPClient(
		time.Duration(cfg.Spider.Timeout)*time.Second,
		cfg.Spider.UserAgents,
	)

	ctx, cancel := context.WithCancel(context.Background())

	crawler, err := crawler.NewCrawler(targetURL, &cfg.Spider, client)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create crawler: %w", err)
	}

	var aiAnalyzer *ai.AIAnalyzer
	if cfg.AIModule.Enabled {
		aiAnalyzer, err = ai.NewAIAnalyzer(cfg.AIModule.APIKey, cfg.AIModule.Model, "")
		if err != nil {
			log.Warn().Err(err).Msg("Failed to initialize AI Analyzer, proceeding without it.")
		}
	}

	o := &Orchestrator{
		config:         cfg,
		httpClient:     client,
		plugins:        make([]vulnscan.Plugin, 0),
		crawler:        crawler,
		pageSignatures: make([]dedup.PageSignature, 0),
		limiter:        rate.NewLimiter(rate.Limit(cfg.Spider.Concurrency), cfg.Spider.Concurrency),
		ctx:            ctx,
		cancel:         cancel,
		targetURL:      targetURL,
		baseURL:        parsedURL,
		aiAnalyzer:     aiAnalyzer,
	}

	o.registerPlugins()
	return o, nil
}

// registerPlugins initializes and registers the vulnerability scanning plugins.
func (o *Orchestrator) registerPlugins() {
	for _, vulnConfig := range o.config.Vulns {
		if vulnConfig.Type == "sqli" {
			sqliPlugin, err := vulnscan.NewSQLiPlugin(o.httpClient, "config/payloads/sqli.json")
			if err != nil {
				log.Error().Err(err).Msg("Failed to initialize SQLi plugin")
			} else {
				log.Info().Msg("SQLi plugin registered.")
				o.plugins = append(o.plugins, sqliPlugin)
			}
		}
		if vulnConfig.Type == "xss" {
			xssPlugin, err := vulnscan.NewXSSPlugin(o.httpClient, "config/payloads/xss.json")
			if err != nil {
				log.Error().Err(err).Msg("Failed to initialize XSS plugin")
			} else {
				log.Info().Msg("XSS plugin registered.")
				o.plugins = append(o.plugins, xssPlugin)
			}
		}
	}
}

// Start begins the orchestration process.
func (o *Orchestrator) Start(reporter *output.Reporter) {
	log.Info().Msg("Orchestrator starting...")
	defer log.Info().Msg("Orchestrator finished.")
	defer o.cancel()

	var wg sync.WaitGroup
	urlsToProcess := make(chan string, o.config.Spider.Concurrency)
	newURLs := make(chan string, o.config.Spider.Concurrency)
	done := make(chan bool)

	// --- URL Manager ---
	go o.runURLManager(urlsToProcess, newURLs, &wg)

	// --- Seeding ---
	wg.Add(1)
	newURLs <- o.targetURL

	// --- Worker Pool ---
	for i := 0; i < o.config.Spider.Concurrency; i++ {
		go o.worker(urlsToProcess, newURLs, &wg, reporter)
	}

	// --- Shutdown Sequence ---
	go func() {
		wg.Wait()
		close(done)
	}()

	<-done
	close(newURLs)
}

// runURLManager manages the lifecycle of URLs, ensuring no duplicates are processed.
func (o *Orchestrator) runURLManager(urlsToProcess chan<- string, newURLs <-chan string, wg *sync.WaitGroup) {
	seen := make(map[string]struct{})
	for urlStr := range newURLs {
		if _, exists := seen[urlStr]; !exists {
			seen[urlStr] = struct{}{}
			urlsToProcess <- urlStr
		} else {
			wg.Done()
		}
	}
	close(urlsToProcess)
}

// seedInitialURLs extracts starting URLs from sources like robots.txt and sitemap.
func (o *Orchestrator) seedInitialURLs(newURLs chan<- string) {
	// This function is now redundant, as the initial URL is sent directly in Start.
	// It can be expanded later to include more sources.
}

// worker is a goroutine that crawls a URL, extracts new links, finds parameters, and runs scans.
func (o *Orchestrator) worker(urlsToProcess <-chan string, newURLs chan<- string, wg *sync.WaitGroup, reporter *output.Reporter) {
	for urlStr := range urlsToProcess {
		func() {
			defer wg.Done()
			o.limiter.Wait(o.ctx)

			log.Debug().Str("url", urlStr).Msg("Crawling and processing URL")

			// 1. Crawl
			content, extractedURLs, err := o.crawler.Crawl(o.ctx, urlStr)
			if err != nil {
				log.Warn().Err(err).Str("url", urlStr).Msg("Failed to crawl page")
				return
			}
			reporter.LogURL(urlStr)

			// 2. Deduplicate content based on DOM similarity
			if o.config.Spider.SimilarityPageDom.Use {
				signature, err := dedup.GeneratePageSignature(strings.NewReader(content), o.config.Spider.SimilarityPageDom.VectorDim)
				if err != nil {
					log.Warn().Err(err).Msg("Failed to generate page signature")
				} else {
					isDup := false
					for _, existingSig := range o.pageSignatures {
						if signature.Similarity(existingSig) >= o.config.Spider.SimilarityPageDom.Similarity {
							isDup = true
							break
						}
					}
					if isDup {
						log.Debug().Str("url", urlStr).Msg("Skipping page due to DOM similarity.")
						return
					}
					o.pageSignatures = append(o.pageSignatures, signature)
				}
			}
			reporter.LogDeDuplicateURL(urlStr)

			// 3. Discover new URLs
			wg.Add(len(extractedURLs))
			for _, extractedURL := range extractedURLs {
				newURLs <- extractedURL
			}

			// 4. Extract parameters and Scan
			pURLs := o.crawler.ExtractParameters(urlStr, content)
			for _, pURL := range pURLs {
				reporter.LogParamURL(pURL)
				for _, plugin := range o.plugins {
					pluginCtx, cancelPlugin := context.WithTimeout(o.ctx, o.config.Scanner.PluginTimeout)
					defer cancelPlugin()

					var aiPayloads []string
					if o.aiAnalyzer != nil {
						var paramsStr string
						for _, p := range pURL.Params {
							paramsStr += p.Name + " "
						}
						aiPayloads, err = o.aiAnalyzer.GeneratePayloads(pluginCtx, plugin.Type(), pURL.URL, pURL.Method, paramsStr)
						if err != nil {
							log.Warn().Err(err).Msg("Failed to generate AI payloads")
						}
					}
					
					vulnerabilities, err := plugin.Scan(pluginCtx, pURL, aiPayloads)
					if err != nil {
						log.Warn().Err(err).Str("plugin", plugin.Type()).Str("url", pURL.URL).Msg("Plugin scan failed")
						continue
					}

					for _, vuln := range vulnerabilities {
						reporter.LogVulnerability(vuln)
					}
				}
			}
		}()
	}
}
