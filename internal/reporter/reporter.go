package reporter

import (
	"autovulnscan/internal/config"
	"autovulnscan/internal/plugins"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"
)

// ScanSummary provides a high-level overview of the scan results.
type ScanSummary struct {
	TargetURL            string    `json:"target_url"`
	ScanStartTime        time.Time `json:"scan_start_time"`
	ScanEndTime          time.Time `json:"scan_end_time"`
	TotalDuration        string    `json:"total_duration"`
	VulnerabilitiesFound int       `json:"vulnerabilities_found"`
}

// Report is the top-level structure for the final JSON report.
type Report struct {
	Summary         ScanSummary             `json:"summary"`
	Configuration   *config.Settings        `json:"configuration"`
	Vulnerabilities []plugins.Vulnerability `json:"vulnerabilities"`
}

// JSONExporter handles the creation of the JSON report file.
type JSONExporter struct {
	OutputPath string
}

// NewJSONExporter creates a new exporter that will write to the specified path.
func NewJSONExporter(outputPath string) (*JSONExporter, error) {
	// Ensure the output directory exists
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	return &JSONExporter{
		OutputPath: outputPath,
	}, nil
}

// Export generates and saves the JSON report.
func (e *JSONExporter) Export(report Report) error {
	file, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report to JSON: %w", err)
	}

	err = os.WriteFile(e.OutputPath, file, 0644)
	if err != nil {
		return fmt.Errorf("failed to write JSON report to file: %w", err)
	}

	log.Info().Str("path", e.OutputPath).Msg("JSON report saved successfully.")
	return nil
}

// TxtExporter handles the creation of the TXT report file.
type TxtExporter struct {
	OutputPath string
}

// NewTxtExporter creates a new exporter that will write to the specified path.
func NewTxtExporter(outputPath string) (*TxtExporter, error) {
	// Ensure the output directory exists
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	return &TxtExporter{
		OutputPath: outputPath,
	}, nil
}

// Export generates and saves the TXT report.
func (e *TxtExporter) Export(report Report) error {
	file, err := os.Create(e.OutputPath)
	if err != nil {
		return fmt.Errorf("failed to create TXT report file: %w", err)
	}
	defer file.Close()

	// --- Summary ---
	summary := report.Summary
	file.WriteString("Scan Report\n")
	file.WriteString("===================================\n")
	file.WriteString("Summary\n")
	file.WriteString("-----------------------------------\n")
	file.WriteString(fmt.Sprintf("Target URL:          %s\n", summary.TargetURL))
	file.WriteString(fmt.Sprintf("Scan Start Time:     %s\n", summary.ScanStartTime.Format(time.RFC3339)))
	file.WriteString(fmt.Sprintf("Scan End Time:       %s\n", summary.ScanEndTime.Format(time.RFC3339)))
	file.WriteString(fmt.Sprintf("Total Duration:      %s\n", summary.TotalDuration))
	file.WriteString(fmt.Sprintf("Vulnerabilities Found: %d\n", summary.VulnerabilitiesFound))
	file.WriteString("===================================\n")

	// --- Configuration ---
	cfg := report.Configuration
	file.WriteString("Configuration\n")
	file.WriteString("-----------------------------------\n")
	file.WriteString(fmt.Sprintf("Request Rate Limit:  %d\n", cfg.Scanner.RateLimit))
	file.WriteString(fmt.Sprintf("Request Timeout:     %d\n", cfg.Scanner.Timeout))
	file.WriteString(fmt.Sprintf("Max Concurrency:     %d\n", cfg.Scanner.Concurrency))
	file.WriteString(fmt.Sprintf("Output File:         %s\n", cfg.OutputFile))
	file.WriteString(fmt.Sprintf("User Agent:          %s\n", cfg.Target.URL)) // This seems incorrect, should be UserAgents
	file.WriteString("===================================\n")

	// --- Vulnerabilities ---
	file.WriteString("Vulnerabilities\n")
	file.WriteString("-----------------------------------\n")

	if len(report.Vulnerabilities) == 0 {
		file.WriteString("\nNo vulnerabilities found.\n")
	} else {
		for _, vuln := range report.Vulnerabilities {
			file.WriteString("\n")
			file.WriteString(fmt.Sprintf("Detection Time: %s\n", vuln.Timestamp.Format(time.RFC3339)))
			file.WriteString(fmt.Sprintf("Vulnerability:  %s\n", vuln.Type))
			file.WriteString(fmt.Sprintf("URL:            %s\n", vuln.URL))
			file.WriteString(fmt.Sprintf("Payload:        %s\n", vuln.Payload))
			file.WriteString("-----------------------------------\n")
		}
	}

	log.Info().Str("path", e.OutputPath).Msg("TXT report saved successfully.")
	return nil
}
