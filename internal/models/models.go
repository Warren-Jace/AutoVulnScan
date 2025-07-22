// Package models contains the data structures for the AutoVulnScan application.
package models

import (
	"net/http"
)

// Request represents a discovered HTTP request with its parameters.
type Request struct {
	*http.Request
	Params []Parameter
}

// Parameter represents a single parameter (e.g., from a query string or form body).
type Parameter struct {
	Name  string
	Value string
}

// ParameterizedURL represents a URL with its identified parameters.
type ParameterizedURL struct {
	URL    string
	Params []Parameter
}

// NewParameterizedURL creates a new ParameterizedURL.
func NewParameterizedURL(urlStr string, params []Parameter) ParameterizedURL {
	return ParameterizedURL{
		URL:    urlStr,
		Params: params,
	}
}

// Payload represents a payload used for testing vulnerabilities.
type Payload struct {
	Value       string `json:"value"`
	Description string `json:"description"`
}

// URLWithParams returns the URL with query parameters for GET requests.
func (r *Request) URLWithParams() string {
	if r.Method == "GET" && len(r.Params) > 0 {
		var params []string
		for _, p := range r.Params {
			params = append(params, p.Name+"="+p.Value)
		}
		return r.URL.String() + "?" + params[0] // Assuming only one param for simplicity, adjust if multiple
	}
	return r.URL.String()
}

// Task represents a unit of work for the orchestrator, which can be a URL to crawl or a request to scan.
type Task struct {
	URL     string
	Depth   int
	Request *Request // If not nil, this is a scan task
}
