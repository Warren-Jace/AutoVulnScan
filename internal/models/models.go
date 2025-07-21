// Package models contains the data structures used across the application.
package models

import "net/http"

// Parameter represents a single injectable parameter found in a URL.
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
}
