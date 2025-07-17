package core

import (
	"autovulnscan/internal/config"
	"autovulnscan/internal/discovery"
	"autovulnscan/internal/plugins"
	"autovulnscan/internal/reporter"
	"autovulnscan/internal/requester"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/rs/zerolog/log"
)

// Orchestrator coordinates the entire scanning process.
type Orchestrator struct {
	config      *config.Settings
	redisClient *redis.Client
	httpClient  *requester.HTTPClient
	plugins     []plugins.Plugin
}

// NewOrchestrator creates a new orchestrator instance.
func NewOrchestrator(cfg *config.Settings, redisClient *redis.Client) *Orchestrator {
	client := requester.NewHTTPClient(
		time.Duration(cfg.Scanner.Timeout)*time.Second,
		cfg.Scanner.UserAgents,
	)

	o := &Orchestrator{
		config:      cfg,
		redisClient: redisClient,
		httpClient:  client,
		plugins:     make([]plugins.Plugin, 0),
	}

	// Register plugins based on config
	// For now, we manually register the SQLi plugin if it's in the config.
	// A more dynamic registration system could be implemented later.
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

// Run starts the execution of the three scanning phases.
func (o *Orchestrator) Run(ctx context.Context) {
	log.Info().Msg("Orchestrator starting...")
	startTime := time.Now()

	// --- Phase 2: Discovery ---
	// In this phase, we crawl the target to find all URLs and parameters.
	log.Info().Msg("[Phase 2/3] Starting Discovery (Crawling & Parameter Extraction)...")
	parameterizedURLs, err := o.performDiscovery(ctx)
	if err != nil {
		log.Fatal().Err(err).Msg("[Phase 2/3] Discovery failed")
		return
	}
	log.Info().Int("count", len(parameterizedURLs)).Msg("[Phase 2/3] Discovery complete. Found parameterized URLs.")

	// --- Phase 3: Injection ---
	// In this phase, we test the discovered URLs and parameters for vulnerabilities.
	log.Info().Msg("[Phase 3/3] Starting Injection (Vulnerability Testing)...")
	vulnerabilities := o.performInjection(ctx, parameterizedURLs)
	log.Info().Msg("[Phase 3/3] Injection complete.")

	// --- Final Report ---
	endTime := time.Now()
	o.generateReport(startTime, endTime, vulnerabilities)

	log.Info().Msg("Orchestrator finished.")
}

// performDiscovery handles the crawling and extraction of URLs and parameters.
func (o *Orchestrator) performDiscovery(ctx context.Context) ([]discovery.ParameterizedURL, error) {
	crawler, err := discovery.NewCrawler(o.config.Target.URL, o.config.Scanner.UserAgents, o.httpClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create crawler: %w", err)
	}

	extractor := discovery.NewExtractor()
	collector := discovery.NewURLCollector(o.redisClient, "crawled_urls")
	
	// This will store all unique parameterized URLs found.
	// We use a map to easily handle duplicates.
	allParameterizedURLs := make(map[string]discovery.ParameterizedURL)

	queue := make(chan string, 100)
	inQueue := make(map[string]bool)

	initialURL := o.config.Target.URL
	added, _ := collector.Add(ctx, initialURL)
	if added {
		queue <- initialURL
		inQueue[initialURL] = true
	}

	for len(queue) > 0 {
		pageURL := <-queue
		delete(inQueue, pageURL)

		log.Debug().Str("url", pageURL).Msg("Crawling page")
		newURLs, body, err := crawler.Crawl(ctx, pageURL)
		if err != nil {
			log.Warn().Err(err).Str("url", pageURL).Msg("Error crawling page, skipping.")
			if body != nil {
				body.Close()
			}
			continue
		}
		
		// Ensure the body is always closed
		defer body.Close()

		// Extract parameters from the current page
		parameterized := extractor.Extract(pageURL, body)
		for _, pURL := range parameterized {
			// Create a unique key for each parameterized URL to avoid duplicates
			key := fmt.Sprintf("%s-%s-%v", pURL.URL, pURL.Method, pURL.Params)
			if _, exists := allParameterizedURLs[key]; !exists {
				allParameterizedURLs[key] = pURL
				log.Info().Str("url", pURL.URL).Str("method", pURL.Method).Int("params", len(pURL.Params)).Msg("Found new parameterized endpoint")
			}
		}

		// Add newly found URLs to the queue for crawling
		for _, newURL := range newURLs {
			if inQueue[newURL] {
				continue
			}
			added, _ := collector.Add(ctx, newURL)
			if added {
				queue <- newURL
				inQueue[newURL] = true
			}
		}
	}
	close(queue)

	// Convert map to slice
	resultSlice := make([]discovery.ParameterizedURL, 0, len(allParameterizedURLs))
	for _, pURL := range allParameterizedURLs {
		resultSlice = append(resultSlice, pURL)
	}
	
	return resultSlice, nil
}

// performInjection handles the vulnerability testing.
func (o *Orchestrator) performInjection(ctx context.Context, pURLs []discovery.ParameterizedURL) []plugins.Vulnerability {
	var allVulnerabilities []plugins.Vulnerability
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Use a channel to control concurrency
	concurrency := o.config.Scanner.Concurrency
	if concurrency <= 0 {
		concurrency = 10 // Default concurrency
	}
	sem := make(chan struct{}, concurrency)

	for _, pURL := range pURLs {
		wg.Add(1)
		go func(pURL discovery.ParameterizedURL) {
			defer wg.Done()
			sem <- struct{}{} // Acquire a semaphore slot
			defer func() { <-sem }() // Release the slot

			for _, plugin := range o.plugins {
				vulns, err := plugin.Scan(ctx, pURL)
				if err != nil {
					log.Error().Err(err).Str("plugin", plugin.Type()).Msg("Error during plugin scan")
					continue
				}
				if len(vulns) > 0 {
					mu.Lock()
					allVulnerabilities = append(allVulnerabilities, vulns...)
					mu.Unlock()
				}
			}
		}(pURL)
	}

	wg.Wait()
	return allVulnerabilities
}

func (o *Orchestrator) generateReport(startTime, endTime time.Time, vulnerabilities []plugins.Vulnerability) {
	summary := reporter.ScanSummary{
		TargetURL:         o.config.Target.URL,
		ScanStartTime:     startTime,
		ScanEndTime:       endTime,
		TotalDuration:     endTime.Sub(startTime).String(),
		VulnerabilitiesFound: len(vulnerabilities),
	}

	finalReport := reporter.Report{
		Summary:         summary,
		Configuration:   o.config,
		Vulnerabilities: vulnerabilities,
	}

	// For now, we only support JSON reporting.
	// This could be extended to support other formats based on config.
	jsonExporter, err := reporter.NewJSONExporter("reports/report.json")
	if err != nil {
		log.Error().Err(err).Msg("Failed to create JSON exporter")
		return
	}

	if err := jsonExporter.Export(finalReport); err != nil {
		log.Error().Err(err).Msg("Failed to save JSON report")
	}
} 