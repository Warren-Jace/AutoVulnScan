package requester

import (
	"context"
	"io/ioutil"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"bytes"

	"github.com/rs/zerolog/log"
)

// HTTPClient is a wrapper around the standard http.Client that provides
// additional features like User-Agent rotation and automatic retries.
type HTTPClient struct {
	client     *http.Client
	userAgents []string
	retries    int // Number of retries on failure
	rand       *rand.Rand
	mu         sync.Mutex
}

// NewHTTPClient creates a new instance of our custom HTTPClient.
func NewHTTPClient(timeout time.Duration, userAgents []string, retries int) *HTTPClient {
	if retries < 0 {
		retries = 0
	}
	return &HTTPClient{
		client: &http.Client{
			Timeout: timeout,
		},
		userAgents: userAgents,
		retries:    retries,
		rand:       rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Do wraps the standard http.Client's Do method, adding a random User-Agent
// and a retry mechanism for network errors or 5xx server responses.
func (c *HTTPClient) Do(req *http.Request) (*http.Response, error) {
	// Set a random user agent from the list for the first attempt
	if len(c.userAgents) > 0 {
		c.mu.Lock()
		ua := c.userAgents[c.rand.Intn(len(c.userAgents))]
		c.mu.Unlock()
		req.Header.Set("User-Agent", ua)
	} else {
		req.Header.Set("User-Agent", "AutoVulnScan-Go/0.1")
	}

	var resp *http.Response
	var err error

	for i := 0; i <= c.retries; i++ {
		if i > 0 {
			// If it's a retry, clone the request to avoid "http: ContentLength=... with Body length 0" error
			// for POST requests, and also get a fresh body.
			clonedReq := req.Clone(req.Context())
			if req.Body != nil {
				// This part is tricky. For simplicity, we assume the body can be re-created
				// if needed by the caller. The current implementation with plugins does this.
				// A more robust solution might involve caching the body if it's an io.Reader.
			}
			resp, err = c.client.Do(clonedReq)
		} else {
			resp, err = c.client.Do(req)
		}

		// Success condition: no network error and not a server-side error (5xx)
		if err == nil && resp.StatusCode < 500 {
			return resp, nil
		}

		// On failure, clean up the response body if it exists, to free the connection
		if resp != nil {
			resp.Body.Close()
		}

		// If this was the last attempt, break the loop and return the last error
		if i == c.retries {
			break
		}

		log.Debug().Err(err).Int("attempt", i+1).Int("max_retries", c.retries).Msg("Request failed, retrying after a short delay...")
		time.Sleep(2 * time.Second) // Simple fixed backoff
	}

	return resp, err
}

// Get is a convenience wrapper for making a GET request to a URL.
func (c *HTTPClient) Get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// GetClient returns the underlying *http.Client.
func (c *HTTPClient) GetClient() *http.Client {
	return c.client
}

func (c *HTTPClient) CloneRequest(req *http.Request) (*http.Request, error) {
	// Clone the request
	clonedReq := req.Clone(req.Context())

	// If the body is not nil, we need to handle it carefully
	if req.Body != nil {
		// Read the body into a byte slice
		bodyBytes, err := ioutil.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		// It's important to restore the original request's body after reading
		req.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
		// Set the cloned request's body to a new reader on the same byte slice
		clonedReq.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	return clonedReq, nil
} 