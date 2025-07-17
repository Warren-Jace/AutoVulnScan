package requester

import (
	"math/rand"
	"net/http"
	"sync"
	"time"
)

// HTTPClient is a wrapper around the standard http.Client that provides
// additional features like User-Agent rotation.
type HTTPClient struct {
	client     *http.Client
	userAgents []string
	rand       *rand.Rand
	mu         sync.Mutex
}

// NewHTTPClient creates a new instance of our custom HTTPClient.
func NewHTTPClient(timeout time.Duration, userAgents []string) *HTTPClient {
	return &HTTPClient{
		client: &http.Client{
			Timeout: timeout,
			// TODO: Add transport settings for retries, rate limiting etc.
		},
		userAgents: userAgents,
		// Seed the random number generator
		rand: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Do wraps the standard http.Client's Do method, adding a random User-Agent
// to each outgoing request if userAgents are available.
func (c *HTTPClient) Do(req *http.Request) (*http.Response, error) {
	// Set a random user agent from the list
	if len(c.userAgents) > 0 {
		c.mu.Lock()
		ua := c.userAgents[c.rand.Intn(len(c.userAgents))]
		c.mu.Unlock()
		req.Header.Set("User-Agent", ua)
	} else {
		// Fallback user agent
		req.Header.Set("User-Agent", "AutoVulnScan-Go/0.1")
	}

	return c.client.Do(req)
}

// GetClient returns the underlying *http.Client.
// This can be useful if direct access to the standard client is needed.
func (c *HTTPClient) GetClient() *http.Client {
	return c.client
} 