// Package models provides the data structures used throughout the AutoVulnScan application.
package models

import (
	"fmt"
	"net/http"
	"strings"
)

// Parameter represents a single parameter (e.g., in a query string, form, or header).
type Parameter struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
	Type  string `json:"type"`
}

// ParameterizedURL holds a URL and the parameters discovered for it.
type ParameterizedURL struct {
	URL    string      `json:"url"`
	Method string      `json:"method"`
	Params []Parameter `json:"params"`
}

// Payload defines the structure for a single XSS payload.
type Payload struct {
	Value       string `json:"value"`
	Description string `json:"description"`
}

// Request is a wrapper around http.Request to be used in the application.
type Request struct {
	*http.Request
	Params []Parameter
}

// URLWithParams returns the URL with query parameters for GET requests.
func (r *Request) URLWithParams() string {
	if r.Method == "GET" && len(r.Params) > 0 {
		var params []string
		for _, p := range r.Params {
			params = append(params, fmt.Sprintf("%s=%s", p.Name, p.Value))
		}
		return r.URL.String() + "?" + strings.Join(params, "&")
	}
	return r.URL.String()
}

// Task represents a unit of work for the orchestrator, which can be a URL to crawl or a request to scan.
type Task struct {
	URL     string
	Depth   int
	Request *Request // If not nil, this is a scan task
}
