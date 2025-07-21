// Package requester provides an HTTP client for making requests to the target.
package requester

import (
	"bytes"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"autovulnscan/internal/models"
)

// HTTPClient is a wrapper around the standard http.Client that provides
// additional features like User-Agent rotation and automatic retries.
type HTTPClient struct {
	client     *http.Client
	userAgents []string
	retries    int
	rand       *rand.Rand
	mu         sync.Mutex
}

// NewHTTPClient creates a new instance of our custom HTTPClient.
func NewHTTPClient(timeout time.Duration, userAgents []string) *HTTPClient {
	return &HTTPClient{
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		userAgents: userAgents,
		retries:    3, // Default retries
		rand:       rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Do wraps the standard http.Client's Do method, adding a random User-Agent
// and a retry mechanism for network errors or 5xx server responses.
func (c *HTTPClient) Do(req *http.Request) (*http.Response, error) {
	if len(c.userAgents) > 0 {
		c.mu.Lock()
		ua := c.userAgents[c.rand.Intn(len(c.userAgents))]
		c.mu.Unlock()
		req.Header.Set("User-Agent", ua)
	}

	var resp *http.Response
	var err error

	for i := 0; i <= c.retries; i++ {
		if i > 0 {
			time.Sleep(2 * time.Second)
		}

		clonedReq := req.Clone(req.Context())
		if req.Body != nil {
			bodyBytes, _ := io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			clonedReq.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		resp, err = c.client.Do(clonedReq)
		if err == nil && resp.StatusCode < 500 {
			return resp, nil
		}

		if resp != nil {
			resp.Body.Close()
		}
	}

	return resp, err
}

// BuildRequest creates a new HTTP request with the payload injected into the specified parameter.
func (c *HTTPClient) BuildRequest(pURL models.ParameterizedURL, param, payload string) (*models.Request, error) {
	payloads := map[string]string{param: payload}
	return c.BuildRequestWithPayloads(pURL, payloads)
}

// BuildRequestWithPayloads creates a new HTTP request with multiple payloads injected.
func (c *HTTPClient) BuildRequestWithPayloads(pURL models.ParameterizedURL, payloads map[string]string) (*models.Request, error) {
	var req *http.Request
	var err error

	targetURL, err := url.Parse(pURL.URL)
	if err != nil {
		return nil, err
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
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	} else {
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
	}

	if err != nil {
		return nil, err
	}
	return &models.Request{Request: req}, nil
}

// ReadBody reads the response body and returns it as a string.
func ReadBody(resp *http.Response) (string, error) {
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}
