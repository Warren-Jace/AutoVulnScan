// Package reporter handles the generation of vulnerability reports.
package reporter

import (
	"autovulnscan/internal/config"
	"autovulnscan/internal/models"
	"autovulnscan/internal/plugins"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// Reporter handles the generation of vulnerability reports.
type Reporter struct {
	mu          sync.Mutex
	spiderFile  *os.File
	paramFile   *os.File
	vulnFile    *os.File
	vulnCounter int64
}

// NewReporter creates a new Reporter.
func NewReporter(cfg config.ReportingConfig) (*Reporter, error) {
	if err := os.MkdirAll(cfg.Path, 0755); err != nil {
		return nil, fmt.Errorf("failed to create report directory: %w", err)
	}

	spiderFilePath := filepath.Join(cfg.Path, cfg.SpiderResultFile)
	paramFilePath := filepath.Join(cfg.Path, cfg.ParamFile)
	vulnFilePath := filepath.Join(cfg.Path, cfg.VulnReportFile)

	sf, err := os.OpenFile(spiderFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open spider log file: %w", err)
	}

	pf, err := os.OpenFile(paramFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		sf.Close()
		return nil, fmt.Errorf("failed to open param log file: %w", err)
	}

	vf, err := os.OpenFile(vulnFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		sf.Close()
		pf.Close()
		return nil, fmt.Errorf("failed to open vulnerability report file: %w", err)
	}

	return &Reporter{
		spiderFile: sf,
		paramFile:  pf,
		vulnFile:   vf,
	}, nil
}

// Close closes all the report files.
func (r *Reporter) Close() {
	r.spiderFile.Close()
	r.paramFile.Close()
	r.vulnFile.Close()
}

// LogURL logs a discovered URL.
func (r *Reporter) LogURL(urlStr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err := r.spiderFile.WriteString(urlStr + "\n"); err != nil {
		log.Warn().Err(err).Msg("Failed to write to spider log")
	}
}

// LogParamURL logs a URL with discovered parameters.
func (r *Reporter) LogParamURL(pURL models.ParameterizedURL) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err := r.paramFile.WriteString(pURL.URL + "\n"); err != nil {
		log.Warn().Err(err).Msg("Failed to write to param log")
	}
}

// LogVulnerability logs a found vulnerability to the report file in the specified format.
func (r *Reporter) LogVulnerability(v plugins.Vulnerability) {
	r.mu.Lock()
	defer r.mu.Unlock()

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
}
