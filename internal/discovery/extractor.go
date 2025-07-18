package discovery

import (
	"autovulnscan/internal/util"
	"fmt"
	"io"
	"net/url"
	"strings"

	"regexp"

	"github.com/PuerkitoBio/goquery"
	"github.com/rs/zerolog/log"
)

// Parameter represents a single injectable parameter found in a URL.
// This could be from a query string, a form, or the URL path itself.
type Parameter struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
	Type  string `json:"type"`
}

// ParameterizedURL holds a URL and the parameters discovered for it.
// This is the primary data structure passed from the Discovery phase to the Injection phase.
type ParameterizedURL struct {
	URL    string      `json:"url"`
	Method string      `json:"method"`
	Params []Parameter `json:"params"`
}

// Extractor is responsible for finding injectable parameters in URLs and HTML content.
type Extractor struct{}

// NewExtractor creates a new parameter extractor.
func NewExtractor() *Extractor {
	return &Extractor{}
}

// Extract finds all parameters from a given URL string and its HTML body.
// It returns a slice of ParameterizedURL structs, covering query params, path params, and form inputs.
func (e *Extractor) Extract(pageURL string, body io.Reader) []ParameterizedURL {
	results := make([]ParameterizedURL, 0)
	baseParsedURL, err := url.Parse(pageURL)
	if err != nil {
		log.Warn().Err(err).Str("url", pageURL).Msg("Extractor failed to parse page URL")
		return results
	}

	// 1. Extract parameters from the URL query string
	if len(baseParsedURL.Query()) > 0 {
		queryParams := make([]Parameter, 0)
		for name, values := range baseParsedURL.Query() {
			value := ""
			if len(values) > 0 {
				value = values[0]
			}
			queryParams = append(queryParams, Parameter{
				Name:  name,
				Value: value,
				Type:  "query",
			})
		}

		// Create a ParameterizedURL for the query parameters found.
		// The URL used for testing should be the base path without the query string.
		urlForTesting := *baseParsedURL
		urlForTesting.RawQuery = ""
		results = append(results, ParameterizedURL{
			URL:    urlForTesting.String(),
			Method: "GET",
			Params: queryParams,
		})
	}

	// 1b. Extract parameters from the URL path
	pathParams := e.extractPathParams(baseParsedURL)
	if len(pathParams) > 0 {
		results = append(results, ParameterizedURL{
			URL:    baseParsedURL.String(),
			Method: "GET", // Path parameters are typically accessed via GET
			Params: pathParams,
		})
	}

	// 2. Extract parameters from HTML forms in the body
	doc, err := goquery.NewDocumentFromReader(body)
	if err != nil {
		// Log the error but don't stop, as query params might have been found.
		log.Warn().Err(err).Str("url", pageURL).Msg("Extractor failed to parse HTML body")
		return results
	}

	doc.Find("form").Each(func(i int, form *goquery.Selection) {
		action, _ := form.Attr("action")
		method, _ := form.Attr("method")
		if method == "" {
			method = "GET" // Default form method is GET
		}

		actionURL := util.ResolveURL(baseParsedURL, action)
		if actionURL == nil {
			log.Debug().Str("form_action", action).Str("base_url", pageURL).Msg("Could not resolve form action URL")
			return // Skip this form
		}

		formParams := make([]Parameter, 0)
		form.Find("input, textarea, select").Each(func(j int, input *goquery.Selection) {
			name, exists := input.Attr("name")
			if !exists || name == "" {
				return // Inputs without a name are not submitted
			}

			// Exclude submit/reset/button inputs as they are not typically injectable parameters.
			inputType, _ := input.Attr("type")
			inputType = strings.ToLower(inputType)
			if inputType == "submit" || inputType == "reset" || inputType == "button" {
				return
			}

			value, _ := input.Attr("value")

			formParams = append(formParams, Parameter{
				Name:  name,
				Value: value,
				Type:  "form_" + strings.ToLower(input.Nodes[0].Data), // e.g. "form_input", "form_textarea"
			})
		})

		if len(formParams) > 0 {
			results = append(results, ParameterizedURL{
				URL:    actionURL.String(),
				Method: strings.ToUpper(method),
				Params: formParams,
			})
		}
	})

	return results
}

// pathParamRegex is used to find parts of a URL path that look like parameters
// (e.g., numeric IDs, UUIDs). This is a best-effort regex.
var pathParamRegex = regexp.MustCompile(`/\d+/?$|/[a-fA-F0-9-]{36}/?$`)

// extractPathParams uses a regex to find and extract parameter-like segments from the URL path.
func (e *Extractor) extractPathParams(u *url.URL) []Parameter {
	params := make([]Parameter, 0)
	matches := pathParamRegex.FindAllString(u.Path, -1)
	for i, match := range matches {
		// Clean up the match (remove slashes)
		value := strings.ReplaceAll(match, "/", "")
		// Create a generic name for the path parameter
		name := fmt.Sprintf("path_param_%d", i+1)
		params = append(params, Parameter{
			Name:  name,
			Value: value,
			Type:  "path",
		})
	}
	return params
}
