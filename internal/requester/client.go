// Package requester provides an HTTP client for making requests to the target.
package requester

import (
	"autovulnscan/internal/models"
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPClient is a wrapper around the standard http.Client that provides
// additional functionality like random user agent selection.
type HTTPClient struct {
	client     *http.Client
	userAgents []string
}

// Request represents a prepared HTTP request with its payload.
type Request struct {
	*http.Request
	Payload string
}

// NewHTTPClient creates a new HTTPClient with a specified timeout and a list of user agents.
func NewHTTPClient(timeout time.Duration, userAgents []string) *HTTPClient {
	return &HTTPClient{
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		userAgents: userAgents,
	}
}

// Do executes an HTTP request and returns the response. It automatically
// sets a random User-Agent header from the configured list.
func (c *HTTPClient) Do(req *http.Request) (*http.Response, error) {
	if len(c.userAgents) > 0 {
		rand.Seed(time.Now().UnixNano())
		req.Header.Set("User-Agent", c.userAgents[rand.Intn(len(c.userAgents))])
	}
	return c.client.Do(req)
}

// BuildRequest creates a new HTTP request with the payload injected into the specified parameter.
func (c *HTTPClient) BuildRequest(pURL models.ParameterizedURL, param, payload string) (*Request, error) {
	payloads := map[string]string{param: payload}
	return c.BuildRequestWithPayloads(pURL, payloads)
}

// BuildRequestWithPayloads creates a new HTTP request with multiple payloads injected into the specified parameters.
func (c *HTTPClient) BuildRequestWithPayloads(pURL models.ParameterizedURL, payloads map[string]string) (*Request, error) {
	var req *http.Request
	var err error

	targetURL, err := url.Parse(pURL.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL for request building: %w", err)
	}

	if pURL.Method == "POST" {
		data := url.Values{}
		for _, p := range pURL.Params {
			if payload, ok := payloads[p.Name]; ok {
				data.Set(p.Name, payload)
			} else {
				data.Set(p.Name, p.Value)
			}
		}
		req, err = http.NewRequest("POST", targetURL.String(), strings.NewReader(data.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else { // Default to GET
		q := targetURL.Query()
		for _, p := range pURL.Params {
			if payload, ok := payloads[p.Name]; ok {
				q.Set(p.Name, payload)
			} else {
				q.Set(p.Name, p.Value)
			}
		}
		targetURL.RawQuery = q.Encode()
		req, err = http.NewRequest("GET", targetURL.String(), nil)
		if err != nil {
			return nil, err
		}
	}

	// For simplicity, we'll just join the payloads for the request's Payload field.
	// This field is mostly for context, and the individual payloads are what matter.
	var payloadValues []string
	for _, p := range payloads {
		payloadValues = append(payloadValues, p)
	}

	return &Request{Request: req, Payload: strings.Join(payloadValues, ", ")}, nil
}

// ReadBody reads the response body and returns it as a string. It also ensures the body is closed.
func ReadBody(resp *http.Response) (string, error) {
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// CopyBody creates a copy of the response body that can be read multiple times.
func CopyBody(resp *http.Response) (io.ReadCloser, io.ReadCloser) {
	var buf bytes.Buffer
	tee := io.TeeReader(resp.Body, &buf)
	return io.NopCloser(&buf), io.NopCloser(tee)
}
