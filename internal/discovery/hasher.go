package discovery

import (
	"crypto/sha1"
	"io"
	"math"

	"golang.org/x/net/html"
)

// PageSignature represents the structural embedding of a web page.
type PageSignature []int

// GeneratePageSignature parses an HTML document and generates a signature based on its DOM structure.
// The signature is an embedding vector created using a technique inspired by Simhash.
func GeneratePageSignature(r io.Reader, dimensions int) (PageSignature, error) {
	doc, err := html.Parse(r)
	if err != nil {
		return nil, err
	}

	embedding := make([]int, dimensions)
	var traverse func(*html.Node, int)

	traverse = func(n *html.Node, depth int) {
		if n.Type == html.ElementNode {
			// Hash the tag name. Hashing attributes as well could be a future improvement.
			hash := sha1.Sum([]byte(n.Data))

			// Project the hash into the embedding vector, weighted by depth.
			// This captures both the content and the structure.
			value := int(uint(hash[0])<<24|uint(hash[1])<<16|uint(hash[2])<<8|uint(hash[3])) * depth
			index := value % dimensions
			if index < 0 {
				index = -index
			}
			embedding[index]++
		}

		// Recursively traverse child nodes.
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c, depth+1)
		}
	}

	traverse(doc, 0)
	return PageSignature(embedding), nil
}

// cosineSimilarity calculates the cosine similarity between two vectors.
func cosineSimilarity(v1, v2 []int) float64 {
	if len(v1) != len(v2) || len(v1) == 0 {
		return 0.0
	}

	var dotProduct, normV1, normV2 float64
	for i := 0; i < len(v1); i++ {
		dotProduct += float64(v1[i] * v2[i])
		normV1 += float64(v1[i] * v1[i])
		normV2 += float64(v2[i] * v2[i])
	}

	if normV1 == 0 || normV2 == 0 {
		return 0.0
	}

	return dotProduct / (math.Sqrt(normV1) * math.Sqrt(normV2))
}

// Similarity calculates the cosine similarity between two page signatures.
func (s1 PageSignature) Similarity(s2 PageSignature) float64 {
	return cosineSimilarity(s1, s2)
}
