package similarity

import (
	"crypto/sha1"
	"encoding/binary"
	"io"
	"math"
	"strings"

	"golang.org/x/net/html"
)

const (
	// VectorDimensions determines the size of the feature vector for each page.
	VectorDimensions = 64
	// DepthWeight is a multiplier to give more significance to nodes deeper in the DOM.
	DepthWeight = 10
)

// DOMVector represents the feature vector of a parsed HTML page.
type DOMVector [VectorDimensions]int

// NewDOMVector creates a feature vector from an HTML document.
// It traverses the DOM, hashing each node's content and using the hash
// to increment a value in the vector, weighted by the node's depth.
func NewDOMVector(body io.Reader) (DOMVector, error) {
	var vector DOMVector
	doc, err := html.Parse(body)
	if err != nil {
		return vector, err
	}

	var traverse func(*html.Node, int)
	traverse = func(n *html.Node, depth int) {
		if n.Type == html.TextNode && strings.TrimSpace(n.Data) != "" {
			// Hash the content of the text node
			h := sha1.New()
			h.Write([]byte(n.Data))
			hashBytes := h.Sum(nil)

			// Use the first 8 bytes of the hash as a uint64
			hashInt := binary.BigEndian.Uint64(hashBytes[:8])

			// Determine which dimension of the vector to update
			dimension := hashInt % VectorDimensions

			// Update the vector, weighting by depth
			vector[dimension] += depth * DepthWeight
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c, depth+1)
		}
	}

	traverse(doc, 1)
	return vector, nil
}

// CosineSimilarity calculates the similarity between two DOM vectors.
// It returns a value between 0 (not similar) and 1 (identical).
func CosineSimilarity(v1, v2 DOMVector) float64 {
	var dotProduct, magV1, magV2 float64
	for i := 0; i < VectorDimensions; i++ {
		dotProduct += float64(v1[i] * v2[i])
		magV1 += float64(v1[i] * v1[i])
		magV2 += float64(v2[i] * v2[i])
	}

	if magV1 == 0 || magV2 == 0 {
		return 0
	}

	return dotProduct / (math.Sqrt(magV1) * math.Sqrt(magV2))
} 