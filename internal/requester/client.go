// Package requester provides a flexible HTTP client for making requests.
package requester

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"time"
)

// HTTPClient is a wrapper around the standard http.Client with additional features.
type HTTPClient struct {
	client     *http.Client
	userAgents []string
}

// NewHTTPClient creates a new HTTPClient with a specified timeout and a list of user agents.
func NewHTTPClient(timeout time.Duration, userAgents []string) *HTTPClient {
	return &HTTPClient{
		client: &http.Client{
			Timeout: timeout,
		},
		userAgents: userAgents,
	}
}

// Do sends an HTTP request and returns an HTTP response.
// It automatically sets a random User-Agent from the provided list.
func (c *HTTPClient) Do(req *http.Request) (*http.Response, error) {
	if len(c.userAgents) > 0 {
		ua := c.userAgents[rand.Intn(len(c.userAgents))]
		req.Header.Set("User-Agent", ua)
	}
	return c.client.Do(req)
}

// BuildURLWithPayload constructs a new URL by adding a payload to a specific parameter.
func (c *HTTPClient) BuildURLWithPayload(baseURL, paramName, payload string) (string, error) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse base URL: %w", err)
	}
	q := parsedURL.Query()
	q.Set(paramName, payload)
	parsedURL.RawQuery = q.Encode()
	return parsedURL.String(), nil
}
