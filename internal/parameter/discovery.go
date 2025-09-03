package parameter

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/PuerkitoBio/goquery"
)

// DiscoveryConfig holds parameter discovery configuration
type DiscoveryConfig struct {
	FindHiddenParameters    bool     `json:"find_hidden_parameters"`
	FindFromJavaScript      bool     `json:"find_from_javascript"`
	FindFromForms           bool     `json:"find_from_forms"`
	FindFromURLs            bool     `json:"find_from_urls"`
	GroupSize               int      `json:"group_size"`
	CommonParameters        []string `json:"common_parameters"`
}

// Parameter represents a discovered parameter
type Parameter struct {
	Name        string `json:"name"`
	Type        string `json:"type"`        // get, post, cookie, header, uri
	Source      string `json:"source"`      // form, js, url, common
	Context     string `json:"context"`     // HTML context where found
	Confidence  int    `json:"confidence"`  // 0-100 confidence level
	URL         string `json:"url"`         // URL where parameter was found
}

// DiscoveryEngine handles parameter discovery
type DiscoveryEngine struct {
	config     DiscoveryConfig
	parameters map[string]*Parameter
	paramsMu   sync.RWMutex
}

// NewDiscoveryEngine creates a new parameter discovery engine
func NewDiscoveryEngine(config DiscoveryConfig) *DiscoveryEngine {
	if config.CommonParameters == nil {
		config.CommonParameters = []string{
			"key", "token", "auth", "session", "redirect", "return",
			"callback", "next", "target", "action", "id", "page",
			"search", "query", "keyword", "q", "s", "file", "path",
			"url", "admin", "debug", "test", "dev",
		}
	}
	
	return &DiscoveryEngine{
		config:     config,
		parameters: make(map[string]*Parameter),
	}
}

// DiscoverParameters discovers parameters from HTML content
func (e *DiscoveryEngine) DiscoverParameters(url, html string) ([]*Parameter, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		return nil, err
	}

	var allParams []*Parameter

	// Discover from forms
	if e.config.FindFromForms {
		formParams := e.discoverFromForms(doc, url)
		allParams = append(allParams, formParams...)
	}

	// Discover from JavaScript
	if e.config.FindFromJavaScript {
		jsParams := e.discoverFromJavaScript(doc, url)
		allParams = append(allParams, jsParams...)
	}

	// Discover from URLs
	if e.config.FindFromURLs {
		urlParams := e.discoverFromURLs(url)
		allParams = append(allParams, urlParams...)
	}

	// Discover common parameters
	if e.config.FindHiddenParameters {
		commonParams := e.discoverCommonParameters(doc, url)
		allParams = append(allParams, commonParams...)
	}

	// Deduplicate and store
	e.storeParameters(allParams)

	return allParams, nil
}

// discoverFromForms finds parameters in HTML forms
func (e *DiscoveryEngine) discoverFromForms(doc *goquery.Document, url string) []*Parameter {
	var params []*Parameter

	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		method := strings.ToLower(s.AttrOr("method", "get"))
		
		s.Find("input, select, textarea").Each(func(j int, input *goquery.Selection) {
			name := input.AttrOr("name", "")
			if name == "" {
				return
			}

			paramType := input.AttrOr("type", "text")
			param := &Parameter{
				Name:       name,
				Type:       method,
				Source:     "form",
				Context:    "form_input",
				Confidence: 100,
				URL:        url,
			}

			// Adjust confidence based on input type
			switch paramType {
			case "hidden":
				param.Confidence = 95
			case "password":
				param.Confidence = 90
			case "submit", "button":
				param.Confidence = 30
			default:
				param.Confidence = 80
			}

			params = append(params, param)
		})
	})

	return params
}

// discoverFromJavaScript finds parameters in JavaScript code
func (e *DiscoveryEngine) discoverFromJavaScript(doc *goquery.Document, url string) []*Parameter {
	var params []*Parameter

	// Find script tags
	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		scriptContent := s.Text()
		if scriptContent == "" {
			return
		}

		// Look for AJAX requests and API calls
		jsParams := e.extractJSParameters(scriptContent)
		for _, name := range jsParams {
			param := &Parameter{
				Name:       name,
				Type:       "get", // Default assumption
				Source:     "javascript",
				Context:    "script_tag",
				Confidence: 70,
				URL:        url,
			}
			params = append(params, param)
		}
	})

	return params
}

// extractJSParameters extracts parameter names from JavaScript code
func (e *DiscoveryEngine) extractJSParameters(jsCode string) []string {
	var params []string
	
	// Simple patterns for parameter extraction
	urlPattern := regexp.MustCompile(`\?(\w+)=`)
	urlMatches := urlPattern.FindAllStringSubmatch(jsCode, -1)
	for _, match := range urlMatches {
		if len(match) > 1 {
			params = append(params, match[1])
		}
	}
	
	// Look for common parameter patterns
	paramPattern := regexp.MustCompile(`['"`](\w+)['"`]\s*:`)
	paramMatches := paramPattern.FindAllStringSubmatch(jsCode, -1)
	for _, match := range paramMatches {
		if len(match) > 1 {
			params = append(params, match[1])
		}
	}

	return params
}

// discoverFromURLs finds parameters in URL structure
func (e *DiscoveryEngine) discoverFromURLs(url string) []*Parameter {
	var params []*Parameter

	// Extract query parameters
	if idx := strings.Index(url, "?"); idx != -1 {
		query := url[idx+1:]
		paramPairs := strings.Split(query, "&")
		
		for _, pair := range paramPairs {
			if idx := strings.Index(pair, "="); idx != -1 {
				name := pair[:idx]
				param := &Parameter{
					Name:       name,
					Type:       "get",
					Source:     "url",
					Context:    "query_string",
					Confidence: 100,
					URL:        url,
				}
				params = append(params, param)
			}
		}
	}

	return params
}

// discoverCommonParameters finds common hidden parameters
func (e *DiscoveryEngine) discoverCommonParameters(doc *goquery.Document, url string) []*Parameter {
	var params []*Parameter

	for _, commonParam := range e.config.CommonParameters {
		// Check if parameter exists in forms
		if doc.Find(fmt.Sprintf("input[name='%s'], input[name=\"%s\"]", commonParam, commonParam)).Length() > 0 {
			continue // Already found in forms
		}

		// Check if parameter exists in JavaScript
		jsContent := doc.Find("script").Text()
		if strings.Contains(jsContent, commonParam) {
			param := &Parameter{
				Name:       commonParam,
				Type:       "get", // Default assumption
				Source:     "common",
				Context:    "javascript_reference",
				Confidence: 60,
				URL:        url,
			}
			params = append(params, param)
		}
	}

	return params
}

// storeParameters stores discovered parameters
func (e *DiscoveryEngine) storeParameters(params []*Parameter) {
	e.paramsMu.Lock()
	defer e.paramsMu.Unlock()

	for _, param := range params {
		key := param.URL + ":" + param.Name
		e.parameters[key] = param
	}
}

// GetParameters returns all discovered parameters
func (e *DiscoveryEngine) GetParameters() []*Parameter {
	e.paramsMu.RLock()
	defer e.paramsMu.RUnlock()

	params := make([]*Parameter, 0, len(e.parameters))
	for _, param := range e.parameters {
		params = append(params, param)
	}

	return params
}

// GetParametersByType returns parameters filtered by type
func (e *DiscoveryEngine) GetParametersByType(paramType string) []*Parameter {
	e.paramsMu.RLock()
	defer e.paramsMu.RUnlock()

	var params []*Parameter
	for _, param := range e.parameters {
		if param.Type == paramType {
			params = append(params, param)
		}
	}

	return params
}
