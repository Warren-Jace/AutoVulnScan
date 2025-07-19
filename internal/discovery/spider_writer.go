package discovery

import (
	"bufio"
	"fmt"
	"os"
	"sync"
)

// SpiderWriter handles writing spider results to file
type SpiderWriter struct {
	mu     sync.Mutex
	file   *os.File
	writer *bufio.Writer
}

// NewSpiderWriter creates a new SpiderWriter instance
func NewSpiderWriter(filename string) (*SpiderWriter, error) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open spider result file: %w", err)
	}

	return &SpiderWriter{
		file:   file,
		writer: bufio.NewWriter(file),
	}, nil
}

// WriteResult writes a crawl result to file
func (w *SpiderWriter) WriteResult(result *CrawlResult) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Write the URL and its method
	if _, err := w.writer.WriteString(fmt.Sprintf("%s %s\n", result.Method, result.URL)); err != nil {
		return err
	}

	// Write parameters if any
	if len(result.Parameters) > 0 {
		if _, err := w.writer.WriteString("Parameters:\n"); err != nil {
			return err
		}
		for key, value := range result.Parameters {
			if _, err := w.writer.WriteString(fmt.Sprintf("  %s: %s\n", key, value)); err != nil {
				return err
			}
		}
	}

	// Write discovered links
	if len(result.Links) > 0 {
		if _, err := w.writer.WriteString("Discovered Links:\n"); err != nil {
			return err
		}
		for _, link := range result.Links {
			if _, err := w.writer.WriteString(fmt.Sprintf("  %s\n", link)); err != nil {
				return err
			}
		}
	}

	// Add a separator
	if _, err := w.writer.WriteString("\n---\n\n"); err != nil {
		return err
	}

	return w.writer.Flush()
}

// Close closes the file
func (w *SpiderWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.writer.Flush(); err != nil {
		return err
	}
	return w.file.Close()
}
