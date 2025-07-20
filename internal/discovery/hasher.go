// Package discovery contains components for finding new URLs and parameters.
package discovery

import (
	"crypto/sha256"
	"fmt"
	"sync"
)

// Hasher is responsible for content-based deduplication of web pages.
type Hasher struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

// NewHasher creates a new Hasher.
func NewHasher() *Hasher {
	return &Hasher{
		seen: make(map[string]struct{}),
	}
}

// IsDuplicate checks if the content has been seen before.
// If not, it marks the content as seen.
func (h *Hasher) IsDuplicate(content string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(content)))
	if _, exists := h.seen[hash]; exists {
		return true
	}

	h.seen[hash] = struct{}{}
	return false
}
