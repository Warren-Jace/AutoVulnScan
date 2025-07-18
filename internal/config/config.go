package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Target specifies the URL to be scanned.
type Target struct {
	URL string `yaml:"url"`
}

// Scanner contains configuration options for the scanner engine.
type Scanner struct {
	Concurrency         int      `yaml:"concurrency"`
	Timeout             int      `yaml:"timeout"`
	Retries             int      `yaml:"retries"`
	UserAgents          []string `yaml:"user_agents"`
	SimilarityThreshold float64  `yaml:"similarity_threshold"`
}

// VulnConfig defines which vulnerabilities to scan for and their configurations.
type VulnConfig struct {
	Type    string `yaml:"type"`
	Enabled bool   `yaml:"enabled"`
}

// Reporting defines the output formats for the scan report.
type Reporting struct {
	Format []string `yaml:"format"`
}

type AI struct {
	APIKey  string `yaml:"api_key"`
	Model   string `yaml:"model"`
	BaseURL string `yaml:"base_url"`
}

// Settings is the main configuration structure for the application.
type Settings struct {
	Target    Target       `yaml:"target"`
	Scanner   Scanner      `yaml:"scanner"`
	Vulns     []VulnConfig `yaml:"vulns"`
	Reporting Reporting    `yaml:"reporting"`
	AI        AI           `yaml:"ai"`
}

// LoadConfig reads the configuration from the given file path.
func LoadConfig(path string) (*Settings, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Settings
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
} 