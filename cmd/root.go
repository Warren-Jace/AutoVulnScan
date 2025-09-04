package cmd

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"autovulnscan/internal/config"
)

var (
	cfgFile     string
	verbose     bool
	GlobalConfig *config.GlobalConfig
)

var rootCmd = &cobra.Command{
	Use:   "autovulnscan",
	Short: "AutoVulnScan is an intelligent automated vulnerability scanning tool",
	Long: `🚀 AutoVulnScan - Intelligent Web Vulnerability Scanner

A comprehensive and modular vulnerability scanner that combines dynamic crawling, 
parameter analysis, and AI-driven detection capabilities.

Features:
  • 🕷️  Intelligent web crawling with similarity detection
  • 🔍 Advanced vulnerability scanning (XSS, SQLi, etc.)
  • 🤖 AI-powered analysis and payload generation
  • 📊 Comprehensive reporting and result management
  • ⚡ High-performance concurrent scanning
  • 🔧 Flexible configuration and plugin system

Examples:
  # Spider mode - crawl and scan
  autovulnscan spider --url "http://example.com" --max-pages 50
  
  # Proxy mode - passive scanning
  autovulnscan proxy --port 8080
  
  # Show help
  autovulnscan --help`,
	Version: "2.0.0",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Initialize logging
		if verbose {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
			log.Debug().Msg("Debug logging enabled")
		} else {
			zerolog.SetGlobalLevel(zerolog.InfoLevel)
		}

		// Display banner
		displayBanner()

		// Load configuration
		if err := loadConfig(); err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Force debug level if verbose flag is set
		if verbose {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
			log.Debug().Msg("Debug logging forced enabled after config load")
		}

		log.Info().Msg("AutoVulnScan initialized successfully")
		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "Config file path (default: config.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().StringP("output", "o", "./reports", "Output directory path")

	// Bind flags to viper
	viper.BindPFlag("output_dir", rootCmd.PersistentFlags().Lookup("output"))
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
}

// initConfig reads in config file and ENV variables if set
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("./config")
	}

	// Environment variables
	viper.AutomaticEnv()

	// Read config file
	if err := viper.ReadInConfig(); err == nil {
		log.Debug().Str("config_file", viper.ConfigFileUsed()).Msg("Using config file")
	} else {
		log.Debug().Msg("No config file found, using defaults")
	}
}

// loadConfig loads and validates configuration
func loadConfig() error {
	// Set defaults
	viper.SetDefault("app.debug", false)
	viper.SetDefault("app.work_dir", "./workspace")
	viper.SetDefault("network.request.timeout", "30s")
	viper.SetDefault("spider.performance.concurrency", 5)
	viper.SetDefault("spider.performance.max_pages", 100)
	viper.SetDefault("logging.level", "info")

	// Validate required directories
	workDir := viper.GetString("app.work_dir")
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return fmt.Errorf("failed to create work directory: %w", err)
	}

	outputDir := viper.GetString("output_dir")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Initialize global configuration
	GlobalConfig = config.GetDefaultConfig()
	
	// Unmarshal configuration
	if err := viper.Unmarshal(GlobalConfig); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}
	
	// Initialize database if enabled
	if GlobalConfig.Database.Enabled {
		initDatabase()
	}
	
	return nil
}

// displayBanner shows the application banner
func displayBanner() {
	banner := `
    ___        __   __   ____   _   _   _   _    ____    _   _    _    
   /   |      / /  / /  / __ \ / | / | / | / |  / __ \  / | / |  / |   
  / /| |     / /  / /  / /_/ //  |/  |/  |/ | / /_/ / /  |/  | /  |   
 / ___ |    / /__/ /  / ____// /|  /|  /|  / / ____/ / /|  /|  / /| |  
/_/  |_|   /_____/  /_/     /_/ |_/_/ |_/_/ /_/     /_/ |_/_/ /_/ |_| 
                                                                        
🚀 Intelligent Web Vulnerability Scanner v2.0.0
🔧 Built with Go • Powered by AI • Designed for Security
`
	fmt.Print(banner)
}
