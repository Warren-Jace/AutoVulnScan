// Package dedup provides functionalities for deduplicating web pages based on content similarity.
package dedup

import (
	"crypto/sha1"
	"encoding/binary"
	"io"
	"math"
	"strings"

	"golang.org/x/net/html"
)

const (
	// defaultVectorDimensions determines the size of the feature vector for each page.
	defaultVectorDimensions = 64
)

// PageSignature represents the feature vector of a parsed HTML page.
type PageSignature []int

// GeneratePageSignature creates a feature vector from an HTML document.
func GeneratePageSignature(body io.Reader, dimensions int) (PageSignature, error) {
	if dimensions <= 0 {
		dimensions = defaultVectorDimensions
	}
	vector := make(PageSignature, dimensions)
	doc, err := html.Parse(body)
	if err != nil {
		return nil, err
	}

	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.TextNode && strings.TrimSpace(n.Data) != "" {
			h := sha1.New()
			h.Write([]byte(n.Data))
			hashBytes := h.Sum(nil)
			hashInt := binary.BigEndian.Uint64(hashBytes[:8])
			dimension := int(hashInt % uint64(dimensions))
			vector[dimension]++
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}

	traverse(doc)
	return vector, nil
}

// Similarity calculates the cosine similarity between two page signatures.
func (ps PageSignature) Similarity(other PageSignature) float64 {
	if len(ps) != len(other) {
		return 0.0
	}

	var dotProduct, mag1, mag2 float64
	for i := 0; i < len(ps); i++ {
		dotProduct += float64(ps[i] * other[i])
		mag1 += float64(ps[i] * ps[i])
		mag2 += float64(other[i] * other[i])
	}

	if mag1 == 0 || mag2 == 0 {
		return 0.0
	}

	return dotProduct / (math.Sqrt(mag1) * math.Sqrt(mag2))
} 