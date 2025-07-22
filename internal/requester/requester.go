// Package requester provides a flexible HTTP client for making requests.
package requester

import (
	"bytes"
	"context"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPClient is a custom, thread-safe HTTP client.
type HTTPClient struct {
	client     *http.Client
	userAgents []string
}

// NewHTTPClient creates a new HTTPClient with specified timeout and user agents.
func NewHTTPClient(timeout int, userAgents []string) *HTTPClient {
	return &HTTPClient{
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		},
		userAgents: userAgents,
	}
}

// Do sends an HTTP request and returns an HTTP response. It also handles setting a random User-Agent.
func (c *HTTPClient) Do(req *http.Request) (*http.Response, error) {
	if len(c.userAgents) > 0 {
		ua := c.userAgents[rand.Intn(len(c.userAgents))]
		req.Header.Set("User-Agent", ua)
	}
	return c.client.Do(req)
}

// Get sends a GET request to the specified URL.
func (c *HTTPClient) Get(ctx context.Context, urlStr string, headers http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return nil, err
	}
	if headers != nil {
		req.Header = headers
	}
	return c.Do(req)
}

// Post sends a POST request to the specified URL with the given body.
func (c *HTTPClient) Post(ctx context.Context, urlStr, contentType string, body io.Reader, headers http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", urlStr, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	if headers != nil {
		for key, values := range headers {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}
	return c.Do(req)
}

// PostForm sends a POST request with form data.
func (c *HTTPClient) PostForm(ctx context.Context, urlStr string, data url.Values, headers http.Header) (*http.Response, error) {
	return c.Post(ctx, urlStr, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()), headers)
}

// PostJSON sends a POST request with JSON data.
func (c *HTTPClient) PostJSON(ctx context.Context, urlStr string, body []byte, headers http.Header) (*http.Response, error) {
	return c.Post(ctx, urlStr, "application/json", bytes.NewBuffer(body), headers)
}

// NewRequest creates a new HTTP request. This is a convenience wrapper around http.NewRequest.
func (c *HTTPClient) NewRequest(method, urlStr string, body io.Reader) (*http.Request, error) {
	return http.NewRequest(method, urlStr, body)
}

// BuildURL constructs a URL with a given parameter and payload, useful for testing.
func (c *HTTPClient) BuildURL(base, param, payload string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base // Return base URL on parse error
	}
	q := u.Query()
	q.Set(param, payload)
	u.RawQuery = q.Encode()
	return u.String()
}
