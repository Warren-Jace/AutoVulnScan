package reporter

import (
	"autovulnscan/internal/config"
	"autovulnscan/internal/plugins"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// TemplateData is a wrapper to pass both the main report and extra data to the template.
type TemplateData struct {
	Report
	VulnerabilitiesJSON string
}

// ScanSummary provides a high-level overview of the scan results.
type ScanSummary struct {
	TargetURL         string    `json:"target_url"`
	ScanStartTime     time.Time `json:"scan_start_time"`
	ScanEndTime       time.Time `json:"scan_end_time"`
	TotalDuration     string    `json:"total_duration"`
	VulnerabilitiesFound int       `json:"vulnerabilities_found"`
}

// Report is the top-level structure for the final JSON report.
type Report struct {
	Summary         ScanSummary           `json:"summary"`
	Configuration   *config.Settings      `json:"configuration"`
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

// HTMLExporter handles the creation of the HTML report file.
type HTMLExporter struct {
	OutputPath   string
	TemplatePath string
}

// NewHTMLExporter creates a new HTML exporter.
func NewHTMLExporter(outputPath, templatePath string) (*HTMLExporter, error) {
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	return &HTMLExporter{
		OutputPath:   outputPath,
		TemplatePath: templatePath,
	}, nil
}

// Export generates and saves the HTML report.
func (e *HTMLExporter) Export(report Report) error {
	// Serialize vulnerabilities to JSON to safely pass to the template's JavaScript
	vulnJSON, err := json.Marshal(report.Vulnerabilities)
	if err != nil {
		return fmt.Errorf("failed to marshal vulnerabilities to JSON: %w", err)
	}

	templateData := TemplateData{
		Report:              report,
		VulnerabilitiesJSON: string(vulnJSON),
	}

	// Add a custom function to the template for string manipulation
	funcMap := template.FuncMap{
		"ToLower": strings.ToLower,
	}

	tmpl, err := template.New(filepath.Base(e.TemplatePath)).Funcs(funcMap).ParseFiles(e.TemplatePath)
	if err != nil {
		return fmt.Errorf("failed to parse HTML template: %w", err)
	}

	file, err := os.Create(e.OutputPath)
	if err != nil {
		return fmt.Errorf("failed to create HTML report file: %w", err)
	}
	defer file.Close()

	err = tmpl.Execute(file, templateData)
	if err != nil {
		return fmt.Errorf("failed to execute HTML template: %w", err)
	}

	log.Info().Str("path", e.OutputPath).Msg("HTML report saved successfully.")
	return nil
} 