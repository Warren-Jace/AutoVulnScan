// Package config handles the loading and parsing of the application's configuration.
package config

import (
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Settings defines the overall configuration structure for the AutoVulnScan application.
type Settings struct {
	Debug     bool              `mapstructure:"debug"`
	Proxy     string            `mapstructure:"proxy"`
	Headers   map[string]string `mapstructure:"headers"`
	Spider    SpiderConfig      `mapstructure:"spider"`
	Scanner   ScannerConfig     `mapstructure:"scanner"`
	Reporting ReportingConfig   `mapstructure:"reporting"`
	Redis     RedisConfig       `mapstructure:"redis"`
	AIModule  AIModuleConfig    `mapstructure:"ai_module"`
	Vulns     []VulnConfig      `mapstructure:"vulnerabilities"`
}

// SpiderConfig holds all configuration related to the crawling phase.
type SpiderConfig struct {
	Concurrency         int                     `mapstructure:"concurrency"`
	Limit               int                     `mapstructure:"limit"`
	Timeout             int                     `mapstructure:"timeout"`
	MaxDepth            int                     `mapstructure:"max_depth"`
	MaxPageVisitPerSite int                     `mapstructure:"max_page_visit_per_site"`
	Scope               []string                `mapstructure:"scope"`
	Blacklist           []string                `mapstructure:"blacklist"`
	Cookies             map[string]string       `mapstructure:"cookies"`
	SimilarityPageDom   SimilarityPageDomConfig `mapstructure:"similarity_page_dom"`
	UserAgents          []string                `mapstructure:"user_agents"`
	DynamicCrawler      DynamicCrawlerConfig    `mapstructure:"dynamic_crawler"`
	Sources             []string                `mapstructure:"sources"`
}

// SimilarityPageDomConfig configures the DOM similarity algorithm.
type SimilarityPageDomConfig struct {
	Use        bool    `mapstructure:"use"`
	Threshold  int     `mapstructure:"threshold"`
	Similarity float64 `mapstructure:"similarity"`
	VectorDim  int     `mapstructure:"vector_dim"`
}

// ScanConfig contains settings for the scanner's behavior.
type ScanConfig struct {
	Concurrency      int      `mapstructure:"concurrency"`
	Limit            int      `mapstructure:"limit"`
	FilterThreshold  int      `mapstructure:"filter_threshold"`
	HiddenParameters []string `mapstructure:"hidden_parameters"`
	Positions        []string `mapstructure:"positions"`
	Timeout          int      `mapstructure:"timeout"`
}

// ScannerConfig defines the settings for the vulnerability scanner.
type ScannerConfig struct {
	PluginTimeout time.Duration `mapstructure:"plugin_timeout"`
	Concurrency   int           `mapstructure:"concurrency"`
}

// ReportingConfig defines the settings for generating reports.
type ReportingConfig struct {
	Path             string `mapstructure:"path"`
	VulnReportFile   string `mapstructure:"vuln_report_file"`
	SpiderResultFile string `mapstructure:"spider_result_file"`
	ParamFile        string `mapstructure:"discovered_urls_file"`
}

// RedisConfig defines the settings for Redis connection.
type RedisConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	URL     string `mapstructure:"url"`
}

// DynamicCrawlerConfig holds settings for the headless browser-based crawler.
type DynamicCrawlerConfig struct {
	Enabled  bool `mapstructure:"enabled"`
	Headless bool `mapstructure:"headless"`
}

// AIModuleConfig holds settings for the optional AI-powered analysis module.
type AIModuleConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Model   string `mapstructure:"model"`
	APIKey  string `mapstructure:"api_key"`
}

// VulnConfig specifies which vulnerabilities to scan for.
type VulnConfig struct {
	Type string `mapstructure:"type"`
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
