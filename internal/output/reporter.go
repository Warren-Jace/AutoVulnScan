// Package output handles the generation of reports and logging of scan results.
package output

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"autovulnscan/internal/config"
	"autovulnscan/internal/models"
	"autovulnscan/internal/vulnscan"

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
	vulnerabilities       []vulnscan.Vulnerability
	startTime             time.Time
	config                config.ReportingConfig
}

// NewReporter creates a new Reporter.
func NewReporter(cfg config.ReportingConfig) (*Reporter, error) {
	if err := os.MkdirAll(cfg.Path, 0755); err != nil {
		return nil, fmt.Errorf("failed to create report directory: %w", err)
	}

	sf, err := os.OpenFile(filepath.Join(cfg.Path, cfg.SpiderFile), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open spider file: %w", err)
	}

	sddf, err := os.OpenFile(filepath.Join(cfg.Path, cfg.SpiderDeDuplicateFile), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		sf.Close()
		return nil, fmt.Errorf("failed to open spider de-duplicate file: %w", err)
	}

	spf, err := os.OpenFile(filepath.Join(cfg.Path, cfg.SpiderParamsFile), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		sf.Close()
		sddf.Close()
		return nil, fmt.Errorf("failed to open spider params file: %w", err)
	}

	vf, err := os.OpenFile(filepath.Join(cfg.Path, cfg.VulnReportFile), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		sf.Close()
		sddf.Close()
		spf.Close()
		return nil, fmt.Errorf("failed to open vulnerability report file: %w", err)
	}

	return &Reporter{
		spiderFile:            sf,
		spiderDeDuplicateFile: sddf,
		spiderParamsFile:      spf,
		vulnFile:              vf,
		reportedParamKeys:     make(map[string]struct{}),
		vulnerabilityCounts:   make(map[string]int),
		vulnerabilities:       make([]vulnscan.Vulnerability, 0),
		startTime:             time.Now(),
		config:                cfg,
	}, nil
}

// Close closes all the report files and generates final summary reports.
func (r *Reporter) Close() {
	r.wg.Wait()

	r.mu.Lock()
	defer r.mu.Unlock()

	r.spiderFile.Close()
	r.spiderDeDuplicateFile.Close()
	r.spiderParamsFile.Close()

	r.writeTextSummary()
	r.vulnFile.Close()

	if err := r.generateJSONReport(); err != nil {
		log.Error().Err(err).Msg("Failed to generate JSON report")
	}
	if err := r.generateHTMLReport(); err != nil {
		log.Error().Err(err).Msg("Failed to generate HTML report")
	}
}

func (r *Reporter) writeTextSummary() {
	summary := "Vulnerability Summary:\n"
	for vulnType, count := range r.vulnerabilityCounts {
		summary += fmt.Sprintf("- %s: %d\n", vulnType, count)
	}
	summary += "\n" + strings.Repeat("-", 50) + "\n\n"

	originalContent, err := os.ReadFile(r.vulnFile.Name())
	if err == nil {
		r.vulnFile.Seek(0, 0)
		r.vulnFile.WriteString(summary)
		r.vulnFile.Write(originalContent)
	} else {
		r.vulnFile.WriteString(summary)
	}
}

// LogURL logs a discovered URL to the main spider log.
func (r *Reporter) LogURL(urlStr string) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.mu.Lock()
		defer r.mu.Unlock()
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

		parsedURL, err := url.Parse(pURL.URL)
		if err != nil {
			return
		}

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
func (r *Reporter) LogVulnerability(v vulnscan.Vulnerability) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.mu.Lock()
		defer r.mu.Unlock()

		r.vulnerabilities = append(r.vulnerabilities, v)
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

func (r *Reporter) generateJSONReport() error {
	report := r.createFinalReport()
	file, err := os.Create(filepath.Join(r.config.Path, "report.json"))
	if err != nil {
		return fmt.Errorf("failed to create JSON report file: %w", err)
	}
	defer file.Close()
	return json.NewEncoder(file).Encode(report)
}

func (r *Reporter) generateHTMLReport() error {
	report := r.createFinalReport()
	vulnJSON, err := json.Marshal(report.Vulnerabilities)
	if err != nil {
		return fmt.Errorf("failed to marshal vulnerabilities to JSON: %w", err)
	}

	templateData := struct {
		Report
		VulnerabilitiesJSON string
	}{
		Report:              report,
		VulnerabilitiesJSON: string(vulnJSON),
	}

	// In a real implementation, the template would be embedded or read from a file.
	// For now, we'll use a placeholder.
	tmpl, err := template.New("report").Parse("<h1>Scan Report</h1>")
	if err != nil {
		return err
	}

	file, err := os.Create(filepath.Join(r.config.Path, "report.html"))
	if err != nil {
		return err
	}
	defer file.Close()
	return tmpl.Execute(file, templateData)
}

func (r *Reporter) createFinalReport() Report {
	return Report{
		Summary: ScanSummary{
			ScanStartTime:     r.startTime,
			ScanEndTime:       time.Now(),
			TotalDuration:     time.Since(r.startTime).String(),
			VulnerabilitiesFound: len(r.vulnerabilities),
		},
		Vulnerabilities: r.vulnerabilities,
	}
}

type Report struct {
	Summary         ScanSummary               `json:"summary"`
	Vulnerabilities []vulnscan.Vulnerability `json:"vulnerabilities"`
}

type ScanSummary struct {
	ScanStartTime     time.Time `json:"scan_start_time"`
	ScanEndTime       time.Time `json:"scan_end_time"`
	TotalDuration     string    `json:"total_duration"`
	VulnerabilitiesFound int       `json:"vulnerabilities_found"`
}
