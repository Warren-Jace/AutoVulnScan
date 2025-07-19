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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"bytes"
	"io"

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
	mu          sync.Mutex // Added for concurrent access to allParameterizedURLs
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

// Run starts the main execution loop of the orchestrator.
// It sequences through the discovery and injection phases and generates a final report.
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
// It uses a pool of worker goroutines to crawl pages concurrently.
func (o *Orchestrator) performDiscovery(ctx context.Context) ([]discovery.ParameterizedURL, error) {
	// Pass the entire spider config to the crawler
	crawler, err := discovery.NewCrawler(o.targetURL, &o.config.Spider, o.httpClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create crawler: %w", err)
	}

	extractor := discovery.NewExtractor()
	collector := discovery.NewURLCollector(o.redisClient, "crawled_urls")

	// This will store all unique parameterized URLs found.
	// We use a map to easily handle duplicates.
	allParameterizedURLs := make(map[string]discovery.ParameterizedURL)
	pageSignatures := make(map[string]discovery.PageSignature)

	queue := make(chan string, o.config.Spider.Concurrency)
	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < o.config.Spider.Concurrency; i++ {
		go func(workerID int) {
			log.Debug().Int("worker", workerID).Msg("Starting worker")
			for pageURL := range queue {
				log.Debug().Int("worker", workerID).Str("url", pageURL).Msg("Worker picked up URL")

				// This function will handle the crawling for a single URL
				// and add new URLs to the queue.
				o.crawlPage(ctx, pageURL, crawler, extractor, collector, &wg, queue, pageSignatures, allParameterizedURLs)

				// This is the correct place for Done()
				wg.Done()
				log.Debug().Int("worker", workerID).Str("url", pageURL).Msg("WaitGroup Done")
			}
			log.Debug().Int("worker", workerID).Msg("Worker finished")
		}(i)
	}

	// Add the initial URL to the queue
	initialURL := o.targetURL
	added, err := collector.Add(ctx, initialURL)
	if err != nil {
		log.Error().Err(err).Msg("Failed to add initial URL to collector")
		// Even if Redis fails, we can proceed with an in-memory crawl.
		// Let's manually add it to the queue.
		wg.Add(1)
		queue <- initialURL
		log.Info().Str("url", initialURL).Msg("Added initial URL to queue (Redis failed)")
	} else if added {
		wg.Add(1)
		queue <- initialURL
		log.Info().Str("url", initialURL).Msg("Added initial URL to queue")
	} else {
		log.Info().Str("url", initialURL).Msg("Initial URL already processed, skipping.")
	}

	done := make(chan struct{})
	// Wait for all workers to finish in a separate goroutine, then close the queue.
	go func() {
		wg.Wait()
		close(queue)
		log.Debug().Msg("All workers finished, queue closed.")
		done <- struct{}{} // Signal completion
	}()

	// Wait for the crawling to complete
	<-done
	log.Debug().Msg("Crawling complete.")

	// Convert map to slice
	resultSlice := make([]discovery.ParameterizedURL, 0, len(allParameterizedURLs))
	o.mu.Lock()
	for _, pURL := range allParameterizedURLs {
		resultSlice = append(resultSlice, pURL)
	}
	o.mu.Unlock()

	// --- Save Discovered URLs ---
	discoveredURLsFile := filepath.Join(o.config.Reporting.Path, o.config.Reporting.DiscoveredUrlsFile)
	saveDiscoveredURLs(discoveredURLsFile, resultSlice)

	// --- Save Spider Results ---
	spiderResultFile := filepath.Join(o.config.Reporting.Path, o.config.Reporting.SpiderResultFile)
	saveSpiderResults(spiderResultFile, collector.GetCrawledURLs())

	return resultSlice, nil
}

// crawlPage is a helper function that crawls a single page, extracts links and parameters,
// and adds new findings to the respective queues and maps.
func (o *Orchestrator) crawlPage(
	ctx context.Context,
	pageURL string,
	crawler *discovery.Crawler,
	extractor *discovery.Extractor,
	collector *discovery.URLCollector,
	wg *sync.WaitGroup,
	queue chan string,
	pageSignatures map[string]discovery.PageSignature,
	allParameterizedURLs map[string]discovery.ParameterizedURL,
) {
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

	// Use TeeReader to allow multiple reads of the response body
	var bodyBuffer bytes.Buffer
	tee := io.TeeReader(body, &bodyBuffer)

	// Generate page signature to detect duplicates based on content structure
	signature, err := discovery.GeneratePageSignature(tee, 128) // Using 128 dimensions for the embedding
	if err != nil {
		log.Warn().Err(err).Str("url", pageURL).Msg("Failed to generate page signature")
		// Continue even if signature generation fails
	} else {
		o.mu.Lock()
		isDuplicate := false
		for _, existingSig := range pageSignatures {
			if signature.Similarity(existingSig) > 0.98 { // High threshold for similarity
				isDuplicate = true
				log.Info().Str("url", pageURL).Msg("Skipping duplicate page based on content similarity.")
				break
			}
		}
		if !isDuplicate {
			pageSignatures[pageURL] = signature
		}
		o.mu.Unlock()

		if isDuplicate {
			return
		}
	}

	// Extract parameters from the current page body
	pURLs := extractor.Extract(pageURL, &bodyBuffer)
	o.mu.Lock()
	for _, pURL := range pURLs {
		paramNames := make([]string, 0, len(pURL.Params))
		for _, p := range pURL.Params {
			paramNames = append(paramNames, p.Name)
		}
		sort.Strings(paramNames)

		key := fmt.Sprintf("%s-%s-%s", pURL.URL, pURL.Method, strings.Join(paramNames, ","))
		if _, exists := allParameterizedURLs[key]; !exists {
			allParameterizedURLs[key] = pURL
			log.Info().Str("url", pURL.URL).Str("method", pURL.Method).Strs("params", paramNames).Msg("Found new unique endpoint template for scanning")
		}
	}
	o.mu.Unlock()

	// Add newly found URLs to the queue for crawling in a non-blocking way
	log.Debug().Int("count", len(newURLs)).Msg("Adding new URLs to queue")
	for _, newURL := range newURLs {
		go func(u string) {
			added, err := collector.Add(ctx, u)
			if err != nil {
				log.Error().Err(err).Str("url", u).Msg("Failed to add URL to collector")
			}
			if added {
				wg.Add(1)
				log.Debug().Str("url", u).Msg("Added new URL to waitgroup and queue")
				queue <- u
			}
		}(newURL)
	}
}

// performInjection handles the vulnerability testing phase.
// It iterates through discovered parameterized URLs and runs registered plugins against them.
func (o *Orchestrator) performInjection(ctx context.Context, pURLs []discovery.ParameterizedURL) []plugins.Vulnerability {
	var allVulnerabilities []plugins.Vulnerability
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Use a channel to control concurrency
	concurrency := o.config.Scan.Concurrency
	if concurrency <= 0 {
		concurrency = 10 // Default concurrency
	}
	sem := make(chan struct{}, concurrency)

	positionSet := make(map[string]struct{})
	for _, pos := range o.config.Scan.Positions {
		positionSet[strings.ToLower(pos)] = struct{}{}
	}

	for _, pURL := range pURLs {
		wg.Add(1)
		go func(pURL discovery.ParameterizedURL) {
			defer wg.Done()
			sem <- struct{}{}        // Acquire a semaphore slot
			defer func() { <-sem }() // Release the slot

			// Check if the parameter type is in the allowed positions
			paramInPosition := false
			for _, param := range pURL.Params {
				// Normalize parameter type to match position keys (e.g., "query" -> "get")
				paramType := strings.ToLower(param.Type)
				if paramType == "query" {
					paramType = "get"
				} else if strings.HasPrefix(paramType, "form_") {
					paramType = "post"
				}

				if _, ok := positionSet[paramType]; ok {
					paramInPosition = true
					break
				}
			}

			if !paramInPosition {
				return // Skip this parameterized URL if no parameters match the allowed positions
			}

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

// generateReport creates the final scan report and saves it to a file.
func (o *Orchestrator) generateReport(startTime, endTime time.Time, vulnerabilities []plugins.Vulnerability) {
	summary := reporter.ScanSummary{
		TargetURL:            o.targetURL,
		ScanStartTime:        startTime,
		ScanEndTime:          endTime,
		TotalDuration:        endTime.Sub(startTime).String(),
		VulnerabilitiesFound: len(vulnerabilities),
	}

	finalReport := reporter.Report{
		Summary:         summary,
		Configuration:   o.config,
		Vulnerabilities: vulnerabilities,
	}

	// Save the vulnerability report as a TXT file
	vulnReportFile := filepath.Join(o.config.Reporting.Path, o.config.Reporting.VulnReportFile)
	txtExporter, err := reporter.NewTxtExporter(vulnReportFile)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create TXT exporter")
		return
	}
	if err := txtExporter.Export(finalReport); err != nil {
		log.Error().Err(err).Msg("Failed to save TXT report")
	}
}

// saveDiscoveredURLs writes the list of unique parameterized URLs to a file.
func saveDiscoveredURLs(filePath string, pURLs []discovery.ParameterizedURL) {
	var content strings.Builder
	for _, pURL := range pURLs {
		paramNames := make([]string, len(pURL.Params))
		for i, p := range pURL.Params {
			paramNames[i] = p.Name
		}
		sort.Strings(paramNames)
		line := fmt.Sprintf("[%s] %s?%s\n", pURL.Method, pURL.URL, strings.Join(paramNames, ","))
		content.WriteString(line)
	}

	if err := os.WriteFile(filePath, []byte(content.String()), 0644); err != nil {
		log.Error().Err(err).Str("file", filePath).Msg("Failed to save discovered URLs")
	} else {
		log.Info().Str("file", filePath).Msg("Saved discovered URLs")
	}
}

func saveSpiderResults(filePath string, urls []string) {
	if filePath == "" {
		return
	}
	content := strings.Join(urls, "\n")
	err := os.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		log.Error().Err(err).Str("file", filePath).Msg("Failed to save spider results")
	} else {
		log.Info().Str("file", filePath).Msg("Saved spider results")
	}
}
