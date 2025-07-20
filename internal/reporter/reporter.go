// Package reporter handles the generation of vulnerability reports.
package reporter

import (
	"autovulnscan/internal/config"
	"autovulnscan/internal/models"
	"autovulnscan/internal/plugins"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// Reporter handles the generation of vulnerability reports.
type Reporter struct {
	mu                    sync.Mutex
	wg                    sync.WaitGroup
	spiderFile            *os.File
	spiderDeDuplicateFile *os.File
	spiderParamsFile      *os.File
	vulnFile              *os.File
	vulnCounter           int64
	reportedParamKeys     map[string]struct{}
	vulnerabilityCounts   map[string]int
}

// NewReporter creates a new Reporter.
func NewReporter(cfg config.ReportingConfig) (*Reporter, error) {
	log.Debug().Msg("Creating new reporter...")
	if err := os.MkdirAll(cfg.Path, 0755); err != nil {
		return nil, fmt.Errorf("failed to create report directory: %w", err)
	}

	sf, err := os.OpenFile(filepath.Join(cfg.Path, cfg.SpiderFile), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open spider file: %w", err)
	}
	log.Debug().Str("path", sf.Name()).Msg("Spider file opened")

	sddf, err := os.OpenFile(filepath.Join(cfg.Path, cfg.SpiderDeDuplicateFile), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		sf.Close()
		return nil, fmt.Errorf("failed to open spider de-duplicate file: %w", err)
	}
	log.Debug().Str("path", sddf.Name()).Msg("Spider de-duplicate file opened")

	spf, err := os.OpenFile(filepath.Join(cfg.Path, cfg.SpiderParamsFile), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		sf.Close()
		sddf.Close()
		return nil, fmt.Errorf("failed to open spider params file: %w", err)
	}
	log.Debug().Str("path", spf.Name()).Msg("Spider params file opened")

	vf, err := os.OpenFile(filepath.Join(cfg.Path, cfg.VulnReportFile), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		sf.Close()
		sddf.Close()
		spf.Close()
		return nil, fmt.Errorf("failed to open vulnerability report file: %w", err)
	}
	log.Debug().Str("path", vf.Name()).Msg("Vulnerability report file opened")

	return &Reporter{
		spiderFile:            sf,
		spiderDeDuplicateFile: sddf,
		spiderParamsFile:      spf,
		vulnFile:              vf,
		reportedParamKeys:     make(map[string]struct{}),
		vulnerabilityCounts:   make(map[string]int),
	}, nil
}

// Close closes all the report files.
func (r *Reporter) Close() {
	log.Debug().Msg("Waiting for reporter goroutines to finish...")
	r.wg.Wait() // Wait for all log operations to complete
	log.Debug().Msg("Reporter goroutines finished.")

	r.mu.Lock()
	defer r.mu.Unlock()

	log.Debug().Msg("Writing vulnerability summary...")
	summary := "Vulnerability Summary:\n"
	for vulnType, count := range r.vulnerabilityCounts {
		summary += fmt.Sprintf("- %s: %d\n", vulnType, count)
	}
	summary += "\n" + strings.Repeat("-", 50) + "\n\n"

	// Prepend summary to the vulnerability report
	if _, err := r.vulnFile.Stat(); err == nil {
		originalContent, err := os.ReadFile(r.vulnFile.Name())
		if err == nil {
			r.vulnFile.Seek(0, 0)
			r.vulnFile.WriteString(summary)
			r.vulnFile.Write(originalContent)
		} else {
			log.Warn().Err(err).Msg("Failed to read original vulnerability report for prepending summary")
		}
	} else {
		// If file is new or can't be statted, just write summary
		r.vulnFile.WriteString(summary)
	}
	log.Debug().Msg("Vulnerability summary written.")

	log.Debug().Msg("Closing report files...")
	r.spiderFile.Close()
	r.spiderDeDuplicateFile.Close()
	r.spiderParamsFile.Close()
	r.vulnFile.Close()
	log.Debug().Msg("Report files closed.")
}

// LogURL logs a discovered URL to the main spider log.
func (r *Reporter) LogURL(urlStr string) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.mu.Lock()
		defer r.mu.Unlock()
		log.Debug().Str("url", urlStr).Msg("Logging URL")
		if _, err := r.spiderFile.WriteString(urlStr + "\n"); err != nil {
			log.Warn().Err(err).Msg("Failed to write to spider log")
		}
	}()
}

// LogDeDuplicateURL logs a URL that has passed the similarity check.
func (r *Reporter) LogDeDuplicateURL(urlStr string) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.mu.Lock()
		defer r.mu.Unlock()
		log.Debug().Str("url", urlStr).Msg("Logging de-duplicated URL")
		if _, err := r.spiderDeDuplicateFile.WriteString(urlStr + "\n"); err != nil {
			log.Warn().Err(err).Msg("Failed to write to de-duplicate spider log")
		}
	}()
}

// LogParamURL logs a unique parameterized URL.
func (r *Reporter) LogParamURL(pURL models.ParameterizedURL) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.mu.Lock()
		defer r.mu.Unlock()
		log.Debug().Str("url", pURL.URL).Msg("Logging parameterized URL")

		parsedURL, err := url.Parse(pURL.URL)
		if err != nil {
			return // Ignore invalid URLs
		}

		// Create a unique key for the URL pattern (path + sorted parameter names)
		paramNames := make([]string, 0, len(pURL.Params))
		for _, p := range pURL.Params {
			paramNames = append(paramNames, p.Name)
		}
		sort.Strings(paramNames)
		key := parsedURL.Path + "?" + strings.Join(paramNames, "&")

		if _, exists := r.reportedParamKeys[key]; !exists {
			r.reportedParamKeys[key] = struct{}{}
			if _, err := r.spiderParamsFile.WriteString(pURL.URL + "\n"); err != nil {
				log.Warn().Err(err).Msg("Failed to write to param log")
			}
		}
	}()
}

// LogVulnerability logs a found vulnerability to the report file.
func (r *Reporter) LogVulnerability(v plugins.Vulnerability) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.mu.Lock()
		defer r.mu.Unlock()
		log.Debug().Interface("vulnerability", v).Msg("Logging vulnerability")

		r.vulnerabilityCounts[v.Type]++
		id := atomic.AddInt64(&r.vulnCounter, 1)

		var reportBlock string
		reportBlock += fmt.Sprintf("序号:           %d\n", id)
		reportBlock += fmt.Sprintf("检测时间:       %s\n", v.Timestamp.Format(time.RFC3339))
		reportBlock += fmt.Sprintf("漏洞名称:       %s\n", v.Type)
		reportBlock += fmt.Sprintf("url地址:        %s\n", v.URL)
		reportBlock += fmt.Sprintf("Payload:        %s\n", v.Payload)
		reportBlock += fmt.Sprintf("请求方式:       %s\n", v.Method)
		reportBlock += fmt.Sprintf("漏洞参数:       %s\n", v.Param)
		reportBlock += fmt.Sprintf("漏洞地址:       %s\n\n", v.VulnerableURL)

		if _, err := r.vulnFile.WriteString(reportBlock); err != nil {
			log.Error().Err(err).Msg("Failed to write to vulnerability report")
		}
	}()
}
