// Package reporter handles the generation of vulnerability reports.
package reporter

import (
	"autovulnscan/internal/plugins"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// GenerateReport creates a formatted vulnerability report and saves it to a file.
func GenerateReport(filePath string, vulnerabilities []plugins.Vulnerability, startTime, endTime time.Time) error {
	var report strings.Builder

	// --- Report Header ---
	report.WriteString("--- AutoVulnScan Report ---\n\n")
	report.WriteString(fmt.Sprintf("Scan Start Time: %s\n", startTime.Format(time.RFC3339)))
	report.WriteString(fmt.Sprintf("Scan End Time:   %s\n", endTime.Format(time.RFC3339)))
	report.WriteString(fmt.Sprintf("Total Duration:    %s\n", endTime.Sub(startTime).String()))
	report.WriteString(fmt.Sprintf("Vulnerabilities Found: %d\n\n", len(vulnerabilities)))

	// --- Vulnerability Details ---
	if len(vulnerabilities) > 0 {
		report.WriteString("--- Vulnerability Details ---\n\n")
		for i, v := range vulnerabilities {
			report.WriteString(fmt.Sprintf("序号:           %d\n", i+1))
			report.WriteString(fmt.Sprintf("检测时间:       %s\n", v.Timestamp.Format(time.RFC3339)))
			report.WriteString(fmt.Sprintf("漏洞名称:       %s\n", v.Type))
			report.WriteString(fmt.Sprintf("url地址:        %s\n", v.URL))
			report.WriteString(fmt.Sprintf("Payload:        %s\n", v.Payload))
			report.WriteString(fmt.Sprintf("请求方式:       %s\n", v.Method))
			report.WriteString(fmt.Sprintf("漏洞参数:       %s\n", v.Param))
			report.WriteString(fmt.Sprintf("漏洞地址:       %s\n\n", v.VulnerableURL))
		}
	} else {
		report.WriteString("No vulnerabilities were found during the scan.\n")
	}

	// --- Write to File ---
	err := os.WriteFile(filePath, []byte(report.String()), 0644)
	if err != nil {
		log.Error().Err(err).Str("file", filePath).Msg("Failed to save vulnerability report")
		return err
	}

	log.Info().Str("file", filePath).Msg("Vulnerability report saved successfully")
	return nil
}
