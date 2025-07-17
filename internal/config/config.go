package config

import (
	"github.com/spf13/viper"
	"strings"
)

// Settings mirrors the structure of the vuln_config.yaml file.
type Settings struct {
	Target    TargetConfig    `mapstructure:"target"`
	Scanner   ScannerConfig   `mapstructure:"scanner"`
	Reporting ReportingConfig `mapstructure:"reporting"`
	AIModule  AIModuleConfig  `mapstructure:"ai_module"`
	Vulns     []VulnConfig    `mapstructure:"vulnerabilities"`
}

type TargetConfig struct {
	URL            string       `mapstructure:"url"`
	Depth          int          `mapstructure:"depth"`
	AllowedDomains []string     `mapstructure:"allowed_domains"`
	ExcludePaths   []string     `mapstructure:"exclude_paths"`
	Auth           AuthConfig   `mapstructure:"auth"`
}

type AuthConfig struct {
	Type  string `mapstructure:"type"`
	Value string `mapstructure:"value"`
}

type ScannerConfig struct {
	Concurrency int      `mapstructure:"concurrency"`
	Timeout     int      `mapstructure:"timeout"`
	Retries     int      `mapstructure:"retries"`
	RateLimit   int      `mapstructure:"rate_limit"`
	UserAgents  []string `mapstructure:"user_agents"`
}

type ReportingConfig struct {
	Format []string `mapstructure:"format"`
	Path   string   `mapstructure:"path"`
}

type AIModuleConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Model   string `mapstructure:"model"`
	APIKey  string `mapstructure:"api_key"`
}

type VulnConfig struct {
	Type       string   `mapstructure:"type"`
	Parameters []string `mapstructure:"parameters"`
}

// LoadConfig reads configuration from file or environment variables.
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