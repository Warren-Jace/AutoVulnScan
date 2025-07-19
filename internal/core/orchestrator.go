// Package core contains the main orchestrator for the AutoVulnScan application.
// It coordinates the discovery, scanning, and reporting phases.
package core

import (
	"autovulnscan/internal/config"
	"autovulnscan/internal/discovery"
	"autovulnscan/internal/plugins"
	"autovulnscan/internal/reporter"
	"autovulnscan/internal/requester"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"bytes"

	"autovulnscan/internal/models"
	"autovulnscan/internal/util"

	"github.com/go-redis/redis/v8"
	"github.com/rs/zerolog/log"
)

// Orchestrator is the main coordinator for the scanning process.
// It manages the workflow from discovery to injection and final reporting.
type Orchestrator struct {
	config      *config.Settings
	redisClient *redis.Client
	httpClient  *requester.HTTPClient
	plugins     []plugins.Plugin
	mu          sync.Mutex
	targetURL   string
}

// NewOrchestrator creates and initializes a new Orchestrator instance.
// It sets up the HTTP client and registers plugins based on the provided configuration.
func NewOrchestrator(cfg *config.Settings, redisClient *redis.Client, targetURL string) *Orchestrator {
	client := requester.NewHTTPClient(
		time.Duration(cfg.Spider.Timeout)*time.Second,
		cfg.Spider.UserAgents,
	)

	o := &Orchestrator{
		config:      cfg,
		redisClient: redisClient,
		httpClient:  client,
		plugins:     make([]plugins.Plugin, 0),
		targetURL:   targetURL,
	}

	// Register plugins based on config
	for _, vulnConfig := range cfg.Vulns {
		if vulnConfig.Type == "sqli" {
			sqliPlugin, err := plugins.NewSQLiPlugin(client, "config/payloads/sqli.json")
			if err != nil {
				log.Error().Err(err).Msg("Failed to initialize SQLi plugin")
			} else {
				log.Info().Msg("SQLi plugin registered.")
				o.plugins = append(o.plugins, sqliPlugin)
			}
		}
		if vulnConfig.Type == "xss" {
			xssPlugin, err := plugins.NewXSSPlugin(client, "config/payloads/xss.json")
			if err != nil {
				log.Error().Err(err).Msg("Failed to initialize XSS plugin")
			} else {
				log.Info().Msg("XSS plugin registered.")
				o.plugins = append(o.plugins, xssPlugin)
			}
		}
	}

	return o
}

// Run starts the main execution loop of the orchestrator.
func (o *Orchestrator) Run(ctx context.Context) {
	log.Info().Msg("Orchestrator starting...")
	startTime := time.Now()

	bufferSize := o.config.Spider.Concurrency
	if o.config.Scan.Concurrency > bufferSize {
		bufferSize = o.config.Scan.Concurrency
	}

	pURLChan := make(chan models.ParameterizedURL, bufferSize)
	vulnChan := make(chan plugins.Vulnerability, o.config.Scan.Concurrency)
	var vulnerabilities []plugins.Vulnerability

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		o.performDiscovery(ctx, pURLChan)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		o.performInjection(ctx, pURLChan, vulnChan)
	}()

	go func() {
		wg.Wait()
		close(vulnChan)
	}()

	for v := range vulnChan {
		vulnerabilities = append(vulnerabilities, v)
	}

	endTime := time.Now()
	o.generateReport(startTime, endTime, vulnerabilities)

	log.Info().Msg("Orchestrator finished.")
}

// worker represents a single crawling worker.
func (o *Orchestrator) worker(ctx context.Context, id int, wg *sync.WaitGroup, queue chan string, crawler *discovery.Crawler, extractor *discovery.Extractor, collector *discovery.URLCollector, pageSignatures map[string]discovery.PageSignature, pURLChan chan<- models.ParameterizedURL) {
	log.Debug().Int("worker", id).Msg("Starting worker")
	defer log.Debug().Int("worker", id).Msg("Worker finished")

	for pageURL := range queue {
		log.Debug().Int("worker", id).Str("url", pageURL).Msg("Worker picked up URL")
		o.crawlAndExtract(ctx, pageURL, crawler, extractor, collector, wg, queue, pageSignatures, pURLChan)
		wg.Done()
		log.Debug().Int("worker", id).Str("url", pageURL).Msg("WaitGroup Done")
	}
}

// performDiscovery handles the crawling and extraction of URLs and parameters.
func (o *Orchestrator) performDiscovery(ctx context.Context, pURLChan chan<- models.ParameterizedURL) {
	defer close(pURLChan) // Close the channel when discovery is complete

	crawler, err := discovery.NewCrawler(o.targetURL, &o.config.Spider, o.httpClient)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create crawler")
		return
	}

	extractor := discovery.NewExtractor()
	collector := discovery.NewURLCollector(o.redisClient, "crawled_urls")
	pageSignatures := make(map[string]discovery.PageSignature)
	queue := make(chan string, o.config.Spider.Concurrency)
	var wg sync.WaitGroup

	// Seed the initial URLs
	o.seedQueue(ctx, queue, &wg, collector)

	// Crawling workers
	for i := 0; i < o.config.Spider.Concurrency; i++ {
		go o.worker(ctx, i, &wg, queue, crawler, extractor, collector, pageSignatures, pURLChan)
	}

	wg.Wait()
	close(queue)
}

// performInjection handles the vulnerability testing phase.
func (o *Orchestrator) performInjection(ctx context.Context, pURLChan <-chan models.ParameterizedURL, vulnChan chan<- plugins.Vulnerability) {
	var wg sync.WaitGroup

	// Scanning workers
	for i := 0; i < o.config.Scan.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pURL := range pURLChan {
				for _, p := range o.plugins {
					if foundVulns, err := p.Scan(ctx, pURL); err == nil {
						for _, v := range foundVulns {
							vulnChan <- v
						}
					} else {
						log.Warn().Err(err).Msg("Plugin scan failed")
					}
				}
			}
		}()
	}

	wg.Wait()
}

// seedQueue adds the initial set of URLs to the crawl queue.
func (o *Orchestrator) seedQueue(ctx context.Context, queue chan string, wg *sync.WaitGroup, collector *discovery.URLCollector) {
	initialURLs := make(map[string]struct{})
	initialURLs[o.targetURL] = struct{}{}

	parsedURL, err := url.Parse(o.targetURL)
	if err != nil {
		log.Error().Err(err).Msg("Failed to parse target URL for source extraction")
		return
	}
	sourceExtractor := discovery.NewSourceExtractor(parsedURL, o.httpClient)

	for _, source := range o.config.Spider.Sources {
		var sourceURLs []string
		var err error

		switch source {
		case "robotstxt":
			log.Info().Msg("Extracting URLs from robots.txt...")
			sourceURLs, err = sourceExtractor.ExtractFromRobotsTxt(ctx)
		case "sitemapxml":
			log.Info().Msg("Extracting URLs from sitemap.xml...")
			sourceURLs, err = sourceExtractor.ExtractFromSitemap(ctx)
		}

		if err != nil {
			log.Warn().Err(err).Str("source", source).Msg("Failed to extract URLs")
		} else {
			for _, u := range sourceURLs {
				initialURLs[u] = struct{}{}
			}
		}
	}

	for u := range initialURLs {
		parsedU, err := url.Parse(u)
		if err != nil {
			continue
		}
		if util.IsInScope(parsedU, o.config.Spider.Scope, o.config.Spider.Blacklist) {
			if added, _ := collector.Add(ctx, u); added {
				wg.Add(1)
				queue <- u
				log.Info().Str("url", u).Msg("Added initial URL to queue")
			}
		}
	}
}

// crawlAndExtract is a helper function that crawls a single page and extracts links and parameters.
func (o *Orchestrator) crawlAndExtract(
	ctx context.Context,
	pageURL string,
	crawler *discovery.Crawler,
	extractor *discovery.Extractor,
	collector *discovery.URLCollector,
	wg *sync.WaitGroup,
	queue chan string,
	pageSignatures map[string]discovery.PageSignature,
	pURLChan chan<- models.ParameterizedURL,
) {
	parsedPageURL, err := url.Parse(pageURL)
	if err != nil {
		log.Warn().Err(err).Str("url", pageURL).Msg("Failed to parse URL for scope check")
		return
	}
	if !util.IsInScope(parsedPageURL, o.config.Spider.Scope, o.config.Spider.Blacklist) {
		log.Debug().Str("url", pageURL).Msg("Skipping out-of-scope URL")
		return
	}

	log.Debug().Str("url", pageURL).Msg("Crawling page")
	newURLs, body, err := crawler.Crawl(ctx, pageURL)
	if err != nil {
		log.Warn().Err(err).Str("url", pageURL).Msg("Error crawling page, skipping.")
		if body != nil {
			body.Close()
		}
		return
	}
	defer body.Close()

	var bodyBuffer bytes.Buffer
	tee := io.TeeReader(body, &bodyBuffer)

	o.mu.Lock()
	if o.config.Spider.SimilarityPageDom.Use {
		signature, err := discovery.GeneratePageSignature(tee, o.config.Spider.SimilarityPageDom.VectorDim)
		if err != nil {
			log.Warn().Err(err).Str("url", pageURL).Msg("Failed to generate page signature")
		} else {
			for _, existingSig := range pageSignatures {
				if signature.Similarity(existingSig) > o.config.Spider.SimilarityPageDom.Similarity {
					log.Info().Str("url", pageURL).Msg("Skipping duplicate page based on content similarity.")
					o.mu.Unlock()
					return
				}
			}
			pageSignatures[pageURL] = signature
		}
	}
	o.mu.Unlock()

	paramURLs := extractor.Extract(pageURL, &bodyBuffer)
	for _, pURL := range paramURLs {
		pURLChan <- pURL
	}

	for _, newURL := range newURLs {
		parsedNewURL, err := url.Parse(newURL)
		if err != nil {
			continue
		}
		if util.IsInScope(parsedNewURL, o.config.Spider.Scope, o.config.Spider.Blacklist) {
			if added, _ := collector.Add(ctx, newURL); added {
				wg.Add(1)
				queue <- newURL
				log.Debug().Str("url", newURL).Msg("Added new URL to queue")
			}
		}
	}
}

// generateReport creates the final vulnerability report.
func (o *Orchestrator) generateReport(startTime, endTime time.Time, vulnerabilities []plugins.Vulnerability) {
	if len(vulnerabilities) == 0 {
		log.Info().Msg("No vulnerabilities found.")
		return
	}

	reportPath := filepath.Join(o.config.Reporting.Path, o.config.Reporting.VulnReportFile)
	err := reporter.GenerateReport(reportPath, vulnerabilities, startTime, endTime)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate report")
	}
}

// saveDiscoveredURLs writes the discovered parameterized URLs to a file.
func saveDiscoveredURLs(filePath string, pURLs []models.ParameterizedURL) {
	var content strings.Builder
	for _, pURL := range pURLs {
		content.WriteString(fmt.Sprintf("URL: %s\nMethod: %s\n", pURL.URL, pURL.Method))
		for _, p := range pURL.Params {
			content.WriteString(fmt.Sprintf("  Param: %s, Type: %s, Value: %s\n", p.Name, p.Type, p.Value))
		}
		content.WriteString("\n")
	}

	err := os.WriteFile(filePath, []byte(content.String()), 0644)
	if err != nil {
		log.Error().Err(err).Str("file", filePath).Msg("Failed to save discovered URLs")
	} else {
		log.Info().Str("file", filePath).Msg("Saved discovered URLs")
	}
}

// saveSpiderResults writes all discovered URLs to a file.
func saveSpiderResults(filePath string, urls []string) {
	sort.Strings(urls)
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Error().Err(err).Str("path", filePath).Msg("Failed to create spider results file")
		return
	}
	defer file.Close()

	for _, url := range urls {
		if _, err := file.WriteString(url + "\n"); err != nil {
			log.Error().Err(err).Str("path", filePath).Msg("Failed to write to spider results file")
			return
		}
	}
	log.Info().Str("path", filePath).Int("count", len(urls)).Msg("Spider results saved")
}
