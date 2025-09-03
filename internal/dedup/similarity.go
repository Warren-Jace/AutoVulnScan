package dedup

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"sync"

	"github.com/PuerkitoBio/goquery"
	"github.com/rs/zerolog/log"
)

// SimilarityConfig holds deduplication configuration
type SimilarityConfig struct {
	Enabled           bool    `json:"enabled"`
	Threshold         int     `json:"threshold"`         // 网站阈值，同个domain相似度大于这个数开启过滤
	Similarity        float64 `json:"similarity"`        // 相似度阈值，大于这个数判定相似
	VectorDimension   int     `json:"vector_dimension"`  // 向量维度
	MinElements       int     `json:"min_elements"`      // 最少DOM元素数阈值
	ContentThreshold  float64 `json:"content_threshold"` // 内容相似度阈值
	MinContentLength  int     `json:"min_content_length"` // 最小内容长度
}

// PageVector represents a page's feature vector
type PageVector struct {
	URL       string
	Vector    []float64
	Hash      string
	Elements  int
	Content   string
	Timestamp int64
}

// SimilarityEngine handles page similarity detection
type SimilarityEngine struct {
	config     SimilarityConfig
	vectors    map[string]*PageVector
	vectorsMu  sync.RWMutex
	stats      map[string]int // domain -> similar page count
	statsMu    sync.RWMutex
}

// NewSimilarityEngine creates a new similarity engine
func NewSimilarityEngine(config SimilarityConfig) *SimilarityEngine {
	return &SimilarityEngine{
		config:  config,
		vectors: make(map[string]*PageVector),
		stats:   make(map[string]int),
	}
}

// ProcessPage processes a page and determines if it should be deduplicated
func (e *SimilarityEngine) ProcessPage(url, html string) (bool, error) {
	if !e.config.Enabled {
		return false, nil
	}

	// Parse HTML
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		return false, fmt.Errorf("failed to parse HTML: %w", err)
	}

	// Extract domain
	domain := extractDomain(url)
	
	// Check if we should enable filtering for this domain
	e.statsMu.RLock()
	similarCount := e.stats[domain]
	e.statsMu.RUnlock()

	if similarCount < e.config.Threshold {
		// Not enough pages to enable filtering yet
		e.addPage(url, doc, html)
		return false, nil
	}

	// Generate feature vector
	vector := e.generateFeatureVector(doc, html)
	
	// Check similarity with existing pages
	if e.isSimilar(url, vector) {
		log.Debug().Str("url", url).Msg("Page filtered due to similarity")
		return true, nil
	}

	// Add new page
	e.addPage(url, doc, html)
	return false, nil
}

// generateFeatureVector creates a feature vector from DOM structure
func (e *SimilarityEngine) generateFeatureVector(doc *goquery.Document, html string) *PageVector {
	vector := &PageVector{
		URL:      "",
		Vector:   make([]float64, e.config.VectorDimension),
		Elements: doc.Find("*").Length(),
		Content:  extractTextContent(doc),
	}

	// Generate DOM structure hash
	vector.Hash = e.generateDOMHash(doc)
	
	// Generate feature vector based on DOM structure
	e.generateDOMVector(doc, vector)
	
	// Generate content-based features
	e.generateContentVector(vector)

	return vector
}

// generateDOMHash creates a hash of DOM structure
func (e *SimilarityEngine) generateDOMHash(doc *goquery.Document) string {
	var structure strings.Builder
	
	doc.Find("*").Each(func(i int, s *goquery.Selection) {
		tagName := s.Get(0).Data
		structure.WriteString(tagName)
		
		// Add class and ID information
		if class, exists := s.Attr("class"); exists {
			structure.WriteString("." + class)
		}
		if id, exists := s.Attr("id"); exists {
			structure.WriteString("#" + id)
		}
		structure.WriteString("|")
	})
	
	hash := md5.Sum([]byte(structure.String()))
	return hex.EncodeToString(hash[:])
}

// generateDOMVector creates DOM-based feature vector
func (e *SimilarityEngine) generateDOMVector(doc *goquery.Document, vector *PageVector) {
	// Count different types of elements
	tagCounts := make(map[string]int)
	doc.Find("*").Each(func(i int, s *goquery.Selection) {
		tagName := s.Get(0).Data
		tagCounts[tagName]++
	})
	
	// Convert to vector (normalize counts)
	maxCount := float64(vector.Elements)
	if maxCount == 0 {
		return
	}
	
	idx := 0
	for _, count := range tagCounts {
		if idx >= len(vector.Vector) {
			break
		}
		vector.Vector[idx] = float64(count) / maxCount
		idx++
	}
}

// generateContentVector creates content-based feature vector
func (e *SimilarityEngine) generateContentVector(vector *PageVector) {
	if len(vector.Content) < e.config.MinContentLength {
		return
	}
	
	// Simple content features
	words := strings.Fields(vector.Content)
	wordCount := len(words)
	
	if wordCount > 0 {
		// Word density
		vector.Vector[len(vector.Vector)-1] = float64(wordCount) / float64(len(vector.Content))
	}
}

// isSimilar checks if a page is similar to existing pages
func (e *SimilarityEngine) isSimilar(url string, vector *PageVector) bool {
	domain := extractDomain(url)
	
	e.vectorsMu.RLock()
	defer e.vectorsMu.RUnlock()
	
	for existingURL, existingVector := range e.vectors {
		if extractDomain(existingURL) != domain {
			continue
		}
		
		// Check hash similarity first (fast path)
		if vector.Hash == existingVector.Hash {
			return true
		}
		
		// Check vector similarity
		similarity := cosineSimilarity(vector.Vector, existingVector.Vector)
		if similarity > e.config.Similarity {
			return true
		}
		
		// Check content similarity
		if e.config.ContentThreshold > 0 {
			contentSim := contentSimilarity(vector.Content, existingVector.Content)
			if contentSim > e.config.ContentThreshold {
				return true
			}
		}
	}
	
	return false
}

// addPage adds a new page to the engine
func (e *SimilarityEngine) addPage(url string, doc *goquery.Document, html string) {
	vector := e.generateFeatureVector(doc, html)
	vector.URL = url
	
	e.vectorsMu.Lock()
	e.vectors[url] = vector
	e.vectorsMu.Unlock()
	
	// Update domain statistics
	domain := extractDomain(url)
	e.statsMu.Lock()
	e.stats[domain]++
	e.statsMu.Unlock()
}

// cosineSimilarity calculates cosine similarity between two vectors
func cosineSimilarity(a, b []float64) float64 {
	if len(a) != len(b) {
		return 0.0
	}
	
	var dotProduct, normA, normB float64
	
	for i := 0; i < len(a); i++ {
		dotProduct += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}
	
	if normA == 0 || normB == 0 {
		return 0.0
	}
	
	return dotProduct / (math.Sqrt(normA) * math.Sqrt(normB))
}

// contentSimilarity calculates content similarity using Jaccard index
func contentSimilarity(a, b string) float64 {
	if a == "" || b == "" {
		return 0.0
	}
	
	wordsA := strings.Fields(strings.ToLower(a))
	wordsB := strings.Fields(strings.ToLower(b))
	
	// Create word sets
	setA := make(map[string]bool)
	for _, word := range wordsA {
		if len(word) > 2 { // Filter out very short words
			setA[word] = true
		}
	}
	
	setB := make(map[string]bool)
	for _, word := range wordsB {
		if len(word) > 2 {
			setB[word] = true
		}
	}
	
	// Calculate intersection and union
	intersection := 0
	for word := range setA {
		if setB[word] {
			intersection++
		}
	}
	
	union := len(setA) + len(setB) - intersection
	
	if union == 0 {
		return 0.0
	}
	
	return float64(intersection) / float64(union)
}

// extractTextContent extracts text content from DOM
func extractTextContent(doc *goquery.Document) string {
	// Remove script and style elements
	doc.Find("script, style").Remove()
	
	// Get text content
	text := doc.Text()
	
	// Clean up whitespace
	text = strings.Join(strings.Fields(text), " ")
	
	return text
}

// extractDomain extracts domain from URL
func extractDomain(url string) string {
	// Simple domain extraction
	if strings.HasPrefix(url, "http://") {
		url = url[7:]
	} else if strings.HasPrefix(url, "https://") {
		url = url[8:]
	}
	
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}
	
	return url
}

// GetStats returns deduplication statistics
func (e *SimilarityEngine) GetStats() map[string]interface{} {
	e.vectorsMu.RLock()
	e.statsMu.RLock()
	defer e.vectorsMu.RUnlock()
	defer e.statsMu.RUnlock()
	
	return map[string]interface{}{
		"total_pages":     len(e.vectors),
		"domain_stats":    e.stats,
		"enabled":         e.config.Enabled,
		"similarity_threshold": e.config.Similarity,
	}
}
