package cmd

import (
	"bufio"
	"fmt"
	"os"
	"sync"

	"autovulnscan/internal/config"
	"autovulnscan/internal/core"
	"autovulnscan/internal/logger"
	"autovulnscan/internal/output"

	"github.com/spf13/cobra"
)

var spiderCmd = &cobra.Command{
	Use:   "spider",
	Short: "Crawl a website and scan for vulnerabilities",
	Long:  `Spider mode crawls a given URL, discovers endpoints, and performs vulnerability checks.`,
	Run: func(cmd *cobra.Command, args []string) {
		url, _ := cmd.Flags().GetString("url")
		file, _ := cmd.Flags().GetString("file")

		if url == "" && file == "" {
			fmt.Println("Please provide a URL with the -u flag or a file with the -f flag.")
			os.Exit(1)
		}

		// Load configuration
		cfg, err := config.LoadConfig(configFile)
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			os.Exit(1)
		}

		// Override output directory if provided
		if outputDir != "" {
			cfg.Reporting.Path = outputDir
		}

		// Setup logger
		logger.Init(cfg.Debug)

		// Process URLs
		var urls []string
		if url != "" {
			urls = append(urls, url)
		}
		if file != "" {
			fileUrls, err := readLines(file)
			if err != nil {
				fmt.Printf("Error reading URLs from file: %v\n", err)
				os.Exit(1)
			}
			urls = append(urls, fileUrls...)
		}

		var wg sync.WaitGroup
		for _, u := range urls {
			wg.Add(1)
			go func(targetURL string) {
				defer wg.Done()
				scanURL(targetURL, cfg)
			}(u)
		}
		wg.Wait()
	},
}

func scanURL(url string, cfg config.Settings) {
	// Create orchestrator
	orchestrator, err := core.NewOrchestrator(&cfg, url)
	if err != nil {
		fmt.Printf("Error creating orchestrator for %s: %v\n", url, err)
		return
	}

	// Create reporter
	reporter, err := output.NewReporter(cfg.Reporting.Path)
	if err != nil {
		fmt.Printf("Error creating reporter for %s: %v\n", url, err)
		return
	}
	defer reporter.Close()

	// Start scan
	orchestrator.Start(reporter)
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func init() {
	rootCmd.AddCommand(spiderCmd)
	spiderCmd.Flags().StringP("url", "u", "", "Target URL to scan")
	spiderCmd.Flags().StringP("file", "f", "", "File containing a list of URLs to scan")
	spiderCmd.Flags().StringVarP(&outputDir, "output-dir", "o", "", "Directory to save output files (overrides config)")
} 