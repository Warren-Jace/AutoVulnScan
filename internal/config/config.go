// Package config handles the loading and parsing of the application's configuration.
// It uses the Viper library to read from a YAML file and environment variables.
package config

import (
	"strings"

	"github.com/spf13/viper"
)

// Settings defines the overall configuration structure for the AutoVulnScan application.
// It mirrors the structure of the vuln_config.yaml file and is populated by Viper.
type Settings struct {
	Target    TargetConfig    `mapstructure:"target"`
	Scanner   ScannerConfig   `mapstructure:"scanner"`
	Reporting ReportingConfig `mapstructure:"reporting"`
	AIModule  AIModuleConfig  `mapstructure:"ai_module"`
	Vulns     []VulnConfig    `mapstructure:"vulnerabilities"`
	Redis     RedisConfig     `mapstructure:"redis"`
}

// TargetConfig holds the configuration related to the scan target.
type TargetConfig struct {
	URL            string     `mapstructure:"url"`
	Depth          int        `mapstructure:"depth"`
	AllowedDomains []string   `mapstructure:"allowed_domains"`
	ExcludePaths   []string   `mapstructure:"exclude_paths"`
	Auth           AuthConfig `mapstructure:"auth"`
}

// AuthConfig specifies the authentication details for the target.
type AuthConfig struct {
	Type  string `mapstructure:"type"`
	Value string `mapstructure:"value"`
}

// ReportingConfig defines how the scan results are reported.
type ReportingConfig struct {
	Path               string `mapstructure:"path"`
	VulnReportFile     string `mapstructure:"vuln_report_file"`
	DiscoveredUrlsFile string `mapstructure:"discovered_urls_file"`
}

// RedisConfig holds the configuration for the Redis client.
type RedisConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	URL     string `mapstructure:"url"`
}

// ScannerConfig contains settings for the scanner's behavior, like concurrency and timeouts.
type ScannerConfig struct {
	Concurrency int      `mapstructure:"concurrency"`
	Timeout     int      `mapstructure:"timeout"`
	Retries     int      `mapstructure:"retries"`
	RateLimit   int      `mapstructure:"rate_limit"`
	UserAgents  []string `mapstructure:"user_agents"`
	Positions   []string `mapstructure:"positions"`
}

// AIModuleConfig holds settings for the optional AI-powered analysis module.
type AIModuleConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Model   string `mapstructure:"model"`
	APIKey  string `mapstructure:"api_key"`
}

// VulnConfig specifies which vulnerabilities to scan for and with what parameters.
type VulnConfig struct {
	Type       string   `mapstructure:"type"`
	Parameters []string `mapstructure:"parameters"`
}

// LoadConfig reads configuration from a file in the given path and unmarshals it
// into a Settings struct. It uses Viper to handle YAML files and environment variables.
func LoadConfig(path string) (config Settings, err error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("vuln_config")
	viper.SetConfigType("yaml")

	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	err = viper.ReadInConfig()
	if err != nil {
		return
	}

	err = viper.Unmarshal(&config)
	return
}
