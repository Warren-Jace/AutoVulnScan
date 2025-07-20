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

	"autovulnscan/internal/config"
	"autovulnscan/internal/discovery"
	"autovulnscan/internal/plugins"
	"autovulnscan/internal/reporter"
	"autovulnscan/internal/requester"
	"autovulnscan/internal/util"

	"github.com/rs/zerolog/log"
	"golang.org/x/time/rate"
)

// Orchestrator is the main coordinator for the scanning process.
type Orchestrator struct {
	config         *config.Settings
	httpClient     *requester.HTTPClient
	plugins        []plugins.Plugin
	crawler        *discovery.Crawler
	extractor      *discovery.Extractor
	pageSignatures []discovery.PageSignature
	limiter        *rate.Limiter
	ctx            context.Context
	cancel         context.CancelFunc
	targetURL      string
	baseURL        *url.URL
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

	crawler, err := discovery.NewCrawler(targetURL, &cfg.Spider, client)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create crawler: %w", err)
	}

	o := &Orchestrator{
		config:         cfg,
		httpClient:     client,
		plugins:        make([]plugins.Plugin, 0),
		crawler:        crawler,
		extractor:      discovery.NewExtractor(),
		pageSignatures: make([]discovery.PageSignature, 0),
		limiter:        rate.NewLimiter(rate.Limit(cfg.Spider.Concurrency), cfg.Spider.Concurrency),
		ctx:            ctx,
		cancel:         cancel,
		targetURL:      targetURL,
		baseURL:        parsedURL,
	}

	o.registerPlugins()
	return o, nil
}

// registerPlugins initializes and registers the vulnerability scanning plugins.
func (o *Orchestrator) registerPlugins() {
	for _, vulnConfig := range o.config.Vulns {
		if vulnConfig.Type == "sqli" {
			sqliPlugin, err := plugins.NewSQLiPlugin(o.httpClient, "config/payloads/sqli.json")
			if err != nil {
				log.Error().Err(err).Msg("Failed to initialize SQLi plugin")
			} else {
				log.Info().Msg("SQLi plugin registered.")
				o.plugins = append(o.plugins, sqliPlugin)
			}
		}
		if vulnConfig.Type == "xss" {
			xssPlugin, err := plugins.NewXSSPlugin(o.httpClient, "config/payloads/xss.json")
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
func (o *Orchestrator) Start(reporter *reporter.Reporter) {
	log.Info().Msg("Orchestrator starting...")
	defer log.Info().Msg("Orchestrator finished.")
	defer o.cancel()

	var discoveryWg sync.WaitGroup
	urlsToProcess, newURLs := o.runURLManager(&discoveryWg)

	// --- Seeding ---
	go func() {
		discoveryWg.Add(1)
		defer discoveryWg.Done()
		newURLs <- o.targetURL
		o.seedInitialURLs(newURLs)
	}()

	// --- Worker Pool ---
	var wg sync.WaitGroup
	for i := 0; i < o.config.Spider.Concurrency; i++ {
		wg.Add(1)
		go o.worker(&wg, &discoveryWg, urlsToProcess, newURLs, reporter)
	}

	// --- Shutdown Sequence ---
	go func() {
		discoveryWg.Wait()
		close(newURLs)
	}()

	wg.Wait()
}

// runURLManager manages the lifecycle of URLs, ensuring no duplicates are processed.
func (o *Orchestrator) runURLManager(discoveryWg *sync.WaitGroup) (chan string, chan string) {
	urlsToProcess := make(chan string, o.config.Spider.Concurrency)
	newURLs := make(chan string, o.config.Spider.Concurrency)

	go func() {
		defer close(urlsToProcess)
		seen := make(map[string]struct{})
		for urlStr := range newURLs {
			if _, exists := seen[urlStr]; !exists {
				seen[urlStr] = struct{}{}
				discoveryWg.Add(1)
				urlsToProcess <- urlStr
			}
		}
	}()

	return urlsToProcess, newURLs
}

// seedInitialURLs extracts starting URLs from sources like robots.txt and sitemap.
func (o *Orchestrator) seedInitialURLs(newURLs chan<- string) {
	// Extract from robots.txt and sitemap.xml
	sourceExtractor := discovery.NewSourceExtractor(o.baseURL, o.httpClient)
	for _, source := range []string{"robotstxt", "sitemap"} {
		var links []string
		var err error
		if source == "robotstxt" {
			links, err = sourceExtractor.ExtractFromRobotsTxt(o.ctx)
		} else {
			links, err = sourceExtractor.ExtractFromSitemap(o.ctx)
		}

		if err != nil {
			log.Warn().Err(err).Str("source", source).Msg("Failed to extract URLs")
			continue
		}

		for _, link := range links {
			parsedLink, err := url.Parse(link)
			if err != nil {
				continue
			}
			if util.IsInScope(parsedLink, o.config.Spider.Scope, o.config.Spider.Blacklist) {
				newURLs <- link
			}
		}
	}
}

// worker is a goroutine that crawls a URL, extracts new links, finds parameters, and runs scans.
func (o *Orchestrator) worker(wg *sync.WaitGroup, discoveryWg *sync.WaitGroup, urlsToProcess <-chan string, newURLs chan<- string, reporter *reporter.Reporter) {
	defer wg.Done()
	for urlStr := range urlsToProcess {
		func() {
			defer discoveryWg.Done()
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
				signature, err := discovery.GeneratePageSignature(strings.NewReader(content), o.config.Spider.SimilarityPageDom.VectorDim)
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
			for _, extractedURL := range extractedURLs {
				if util.IsInScope(extractedURL, o.config.Spider.Scope, o.config.Spider.Blacklist) {
					newURLs <- extractedURL.String()
				}
			}

			// 4. Extract parameters and Scan
			pURLs := o.extractor.Extract(urlStr, content)
			for _, pURL := range pURLs {
				reporter.LogParamURL(pURL)
				for _, plugin := range o.plugins {
					pluginCtx, cancelPlugin := context.WithTimeout(o.ctx, o.config.Scanner.PluginTimeout)
					defer cancelPlugin()
					vulnerabilities, err := plugin.Scan(pluginCtx, pURL)
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
