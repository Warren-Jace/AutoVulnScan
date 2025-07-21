// Package output handles the generation of reports and logging of scan results.
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"autovulnscan/internal/config"
	"autovulnscan/internal/models"
	"autovulnscan/internal/vulnscan"

	"github.com/rs/zerolog/log"
	"text/template"
)

// Reporter handles the output of scan results in various formats.
type Reporter struct {
	mu                    sync.Mutex
	wg                    sync.WaitGroup
	spiderFile            *os.File
	spiderDeDuplicateFile *os.File
	spiderParamsFile      *os.File
	vulnFile              *os.File
	vulnerabilities       []*vulnscan.Vulnerability
	vulnCounts            map[string]int
	reportedVulns         map[string]bool // For deduplication
	config                config.ReportingConfig
	startTime             time.Time
}

// NewReporter creates a new Reporter.
func NewReporter(outputDir string) (*Reporter, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create report directory: %w", err)
	}

	// Helper to create and write BOM
	createFileWithBOM := func(name string) (*os.File, error) {
		file, err := os.OpenFile(filepath.Join(outputDir, name), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		// Write UTF-8 BOM
		if _, err := file.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
			file.Close()
			return nil, err
		}
		return file, nil
	}

	sf, err := createFileWithBOM("urls-spider.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to open spider file: %w", err)
	}

	sddf, err := createFileWithBOM("urls-spider_de-duplicate_all.txt")
	if err != nil {
		sf.Close()
		return nil, fmt.Errorf("failed to open spider de-duplicate file: %w", err)
	}

	spf, err := createFileWithBOM("urls-spider_params.txt")
	if err != nil {
		sf.Close()
		sddf.Close()
		return nil, fmt.Errorf("failed to open spider params file: %w", err)
	}

	vf, err := createFileWithBOM("urls-Vulns.txt")
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
		vulnerabilities:       make([]*vulnscan.Vulnerability, 0),
		vulnCounts:            make(map[string]int),
		reportedVulns:         make(map[string]bool),
		startTime:             time.Now(),
		config:                config.ReportingConfig{Path: outputDir},
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
	if len(r.vulnerabilities) == 0 {
		return
	}

	var builder strings.Builder
	builder.WriteString("Vulnerability Summary:\n\n")
	builder.WriteString("--------------------------------------------------\n\n")

	for i, vuln := range r.vulnerabilities {
		vulnerableURL := vuln.VulnerableURL
		if vuln.Method == "POST" {
			vulnerableURL = fmt.Sprintf("%s [POST aams] %s=%s", vuln.URL, vuln.Param, vuln.Payload)
		}

		builder.WriteString(fmt.Sprintf("序号:           %d\n", i+1))
		builder.WriteString(fmt.Sprintf("检测时间:       %s\n", vuln.Timestamp.Format(time.RFC3339)))
		builder.WriteString(fmt.Sprintf("漏洞名称:       %s\n", vuln.Type))
		builder.WriteString(fmt.Sprintf("url地址:        %s\n", vuln.URL))
		builder.WriteString(fmt.Sprintf("Payload:        %s\n", vuln.Payload))
		builder.WriteString(fmt.Sprintf("请求方式:       %s\n", vuln.Method))
		builder.WriteString(fmt.Sprintf("漏洞参数:       %s\n", vuln.Param))
		builder.WriteString(fmt.Sprintf("漏洞地址:       %s\n\n", vulnerableURL))
	}

	builder.WriteString("Vulnerability Summary:\n")
	for name, count := range r.vulnCounts {
		builder.WriteString(fmt.Sprintf("- %s: %d\n", name, count))
	}
	builder.WriteString("\n--------------------------------------------------\n")

	r.logToFile(r.vulnFile, builder.String())
}

// LogURL logs a crawled URL.
func (r *Reporter) LogURL(url string) {
	r.logToFile(r.spiderFile, url)
}

// LogDeDuplicateURL logs a deduplicated URL.
func (r *Reporter) LogDeDuplicateURL(url string) {
	r.logToFile(r.spiderDeDuplicateFile, url)
}

// LogParamURL logs a URL with parameters.
func (r *Reporter) LogParamURL(req *models.Request) {
	r.logToFile(r.spiderParamsFile, req.URLWithParams())
}

// LogVulnerability logs a found vulnerability after checking for duplicates.
func (r *Reporter) LogVulnerability(vuln *vulnscan.Vulnerability) {
	r.mu.Lock()
	defer r.mu.Unlock()

	signature := r.getVulnerabilitySignature(vuln)
	if _, exists := r.reportedVulns[signature]; exists {
		log.Debug().Str("signature", signature).Msg("Duplicate vulnerability found, skipping.")
		return
	}

	r.vulnerabilities = append(r.vulnerabilities, vuln)
	r.vulnCounts[vuln.Type]++
	r.reportedVulns[signature] = true

	log.Info().
		Str("param", vuln.Param).
		Str("type", vuln.Type).
		Str("url", vuln.URL).
		Msg("Vulnerability Found!")
}

func (r *Reporter) getVulnerabilitySignature(vuln *vulnscan.Vulnerability) string {
	return fmt.Sprintf("%s|%s|%s|%s", vuln.Type, vuln.URL, vuln.Param, vuln.Method)
}

func (r *Reporter) generateJSONReport() error {
	report := Report{
		StartTime:            r.startTime,
		EndTime:              time.Now(),
		Duration:             time.Since(r.startTime).String(),
		Target:               r.config.Path, // This should be the target URL
		VulnerabilitiesFound: len(r.vulnerabilities),
		Vulnerabilities:      r.vulnerabilities,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal json report: %w", err)
	}

	return os.WriteFile(filepath.Join(r.config.Path, "report.json"), data, 0644)
}

func (r *Reporter) generateHTMLReport() error {
	report := r.createFinalReport()
	htmlTemplate := `
<!DOCTYPE html>
<html>
<head>
    <title>AutoVulnScan Report</title>
    <style>
        body { font-family: sans-serif; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>AutoVulnScan Report</h1>
    <p><strong>Start Time:</strong> {{.StartTime}}</p>
    <p><strong>End Time:</strong> {{.EndTime}}</p>
    <p><strong>Duration:</strong> {{.Duration}}</p>
    <p><strong>Target:</strong> {{.Target}}</p>
    <p><strong>Vulnerabilities Found:</strong> {{.VulnerabilitiesFound}}</p>
    <h2>Vulnerabilities</h2>
    <table>
        <tr>
            <th>Type</th>
            <th>URL</th>
            <th>Method</th>
            <th>Param</th>
            <th>Payload</th>
        </tr>
        {{range .Vulnerabilities}}
        <tr>
            <td>{{.Type}}</td>
            <td>{{.URL}}</td>
            <td>{{.Method}}</td>
            <td>{{.Param}}</td>
            <td>{{.Payload}}</td>
        </tr>
        {{end}}
    </table>
</body>
</html>`
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return err
	}

	file, err := os.Create(filepath.Join(r.config.Path, "report.html"))
	if err != nil {
		return err
	}
	defer file.Close()
	return tmpl.Execute(file, report)
}

func (r *Reporter) createFinalReport() Report {
	return Report{
		StartTime:            r.startTime,
		EndTime:              time.Now(),
		Duration:             time.Since(r.startTime).String(),
		Target:               r.config.Path, // This should be the target URL
		VulnerabilitiesFound: len(r.vulnerabilities),
		Vulnerabilities:      r.vulnerabilities,
	}
}

func (r *Reporter) logToFile(file *os.File, data string) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		if _, err := file.WriteString(data + "\n"); err != nil {
			log.Warn().Err(err).Msg("Failed to write to log file")
		}
	}()
}

type Report struct {
	StartTime            time.Time                  `json:"start_time"`
	EndTime              time.Time                  `json:"end_time"`
	Duration             string                     `json:"duration"`
	Target               string                     `json:"target"`
	VulnerabilitiesFound int                        `json:"vulnerabilities_found"`
	Vulnerabilities      []*vulnscan.Vulnerability `json:"vulnerabilities"`
}

type ScanSummary struct {
	ScanStartTime     time.Time `json:"scan_start_time"`
	ScanEndTime       time.Time `json:"scan_end_time"`
	TotalDuration     string    `json:"total_duration"`
	VulnerabilitiesFound int       `json:"vulnerabilities_found"`
}

// SanitizeFilename creates a valid filename from a URL.
func SanitizeFilename(urlStr string) string {
	// This function is not used in the provided code, but it's part of the new_code.
	// Keeping it as is, but it might need actual implementation if used.
	return strings.ReplaceAll(urlStr, "://", "_") + ".log"
}
