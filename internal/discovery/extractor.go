package discovery

import (
	"autovulnscan/internal/models"
	"autovulnscan/internal/util"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/rs/zerolog/log"
)

// Extractor is responsible for finding injectable parameters in URLs and HTML content.
type Extractor struct{}

// NewExtractor creates a new parameter extractor.
func NewExtractor() *Extractor {
	return &Extractor{}
}

// Extract finds all parameters from a given URL string and its HTML body.
// It returns a slice of ParameterizedURL structs, covering query params, path params, and form inputs.
func (e *Extractor) Extract(pageURL string, body io.Reader) []models.ParameterizedURL {
	results := make([]models.ParameterizedURL, 0)
	baseParsedURL, err := url.Parse(pageURL)
	if err != nil {
		log.Warn().Err(err).Str("url", pageURL).Msg("Extractor failed to parse page URL")
		return results
	}

	// 1. Extract parameters from the URL query string
	if len(baseParsedURL.Query()) > 0 {
		queryParams := make([]models.Parameter, 0)
		for name, values := range baseParsedURL.Query() {
			value := ""
			if len(values) > 0 {
				value = values[0]
			}
			queryParams = append(queryParams, models.Parameter{
				Name:  name,
				Value: value,
				Type:  "query",
			})
		}

		// Create a ParameterizedURL for the query parameters found.
		urlForTesting := *baseParsedURL
		urlForTesting.RawQuery = ""
		results = append(results, models.ParameterizedURL{
			URL:    urlForTesting.String(),
			Method: "GET",
			Params: queryParams,
		})
	}

	// 1b. Extract parameters from the URL path
	pathParams := e.extractPathParams(baseParsedURL)
	if len(pathParams) > 0 {
		results = append(results, models.ParameterizedURL{
			URL:    baseParsedURL.String(),
			Method: "GET",
			Params: pathParams,
		})
	}

	// 2. Extract parameters from HTML forms in the body
	doc, err := goquery.NewDocumentFromReader(body)
	if err != nil {
		log.Warn().Err(err).Str("url", pageURL).Msg("Extractor failed to parse HTML body")
		return results
	}

	results = append(results, e.extractFromForms(doc, baseParsedURL)...)
	jsParams := e.extractFromJavaScript(doc, baseParsedURL)
	if len(jsParams.Params) > 0 {
		results = append(results, jsParams)
	}
	hiddenParams := e.extractHiddenInputs(doc, baseParsedURL)
	if len(hiddenParams.Params) > 0 {
		results = append(results, hiddenParams)
	}
	commonParams := e.extractCommonParameters(baseParsedURL)
	if len(commonParams.Params) > 0 {
		results = append(results, commonParams)
	}

	return results
}

// extractFromForms extracts parameters from HTML forms
func (e *Extractor) extractFromForms(doc *goquery.Document, baseURL *url.URL) []models.ParameterizedURL {
	results := make([]models.ParameterizedURL, 0)

	doc.Find("form").Each(func(i int, form *goquery.Selection) {
		action, _ := form.Attr("action")
		method, _ := form.Attr("method")
		if method == "" {
			method = "GET"
		}

		actionURL := util.ResolveURL(baseURL, action)
		if actionURL == nil {
			actionURL = baseURL
		}

		formParams := make([]models.Parameter, 0)
		form.Find("input, textarea, select, button").Each(func(j int, input *goquery.Selection) {
			name, exists := input.Attr("name")
			if !exists || name == "" {
				return
			}

			inputType, _ := input.Attr("type")
			inputType = strings.ToLower(inputType)
			if inputType == "submit" || inputType == "reset" || inputType == "button" {
				return
			}

			value, _ := input.Attr("value")
			if input.Nodes[0].Data == "select" {
				input.Find("option[selected]").Each(func(k int, option *goquery.Selection) {
					if optionValue, exists := option.Attr("value"); exists {
						value = optionValue
					} else {
						value = option.Text()
					}
				})
			}

			paramType := "form_" + strings.ToLower(input.Nodes[0].Data)
			if inputType != "" {
				paramType += "_" + inputType
			}

			formParams = append(formParams, models.Parameter{
				Name:  name,
				Value: value,
				Type:  paramType,
			})
		})

		if len(formParams) > 0 {
			results = append(results, models.ParameterizedURL{
				URL:    actionURL.String(),
				Method: strings.ToUpper(method),
				Params: formParams,
			})
		}
	})

	return results
}

// extractFromJavaScript extracts parameters from JavaScript code in the page
func (e *Extractor) extractFromJavaScript(doc *goquery.Document, baseURL *url.URL) models.ParameterizedURL {
	jsParams := make([]models.Parameter, 0)
	paramMap := make(map[string]struct{})

	doc.Find("script").Each(func(i int, script *goquery.Selection) {
		scriptContent := script.Text()
		ajaxParamRegex := regexp.MustCompile(`(?:data|params):\s*{([^}]+)}`)
		ajaxMatches := ajaxParamRegex.FindAllStringSubmatch(scriptContent, -1)
		for _, match := range ajaxMatches {
			if len(match) > 1 {
				paramPairs := strings.Split(match[1], ",")
				for _, pair := range paramPairs {
					parts := strings.Split(pair, ":")
					if len(parts) >= 2 {
						paramName := strings.Trim(parts[0], " '\"\t\n\r")
						if paramName != "" && !strings.Contains(paramName, "(") {
							paramMap[paramName] = struct{}{}
						}
					}
				}
			}
		}

		urlParamRegex := regexp.MustCompile(`[?&]([a-zA-Z0-9_\-]+)=`)
		urlMatches := urlParamRegex.FindAllStringSubmatch(scriptContent, -1)
		for _, match := range urlMatches {
			if len(match) > 1 {
				paramMap[match[1]] = struct{}{}
			}
		}

		formFieldRegex := regexp.MustCompile(`(?:getElementById|getElementsByName|querySelector|querySelectorAll|name=["'])["']([a-zA-Z0-9_\-]+)["']`)
		formMatches := formFieldRegex.FindAllStringSubmatch(scriptContent, -1)
		for _, match := range formMatches {
			if len(match) > 1 {
				paramMap[match[1]] = struct{}{}
			}
		}
	})

	for param := range paramMap {
		jsParams = append(jsParams, models.Parameter{
			Name:  param,
			Value: "",
			Type:  "javascript",
		})
	}

	return models.ParameterizedURL{
		URL:    baseURL.String(),
		Method: "POST",
		Params: jsParams,
	}
}

// extractHiddenInputs extracts hidden inputs that might be outside forms
func (e *Extractor) extractHiddenInputs(doc *goquery.Document, baseURL *url.URL) models.ParameterizedURL {
	hiddenParams := make([]models.Parameter, 0)
	paramMap := make(map[string]struct{})

	doc.Find("input[type='hidden']").Each(func(i int, input *goquery.Selection) {
		name, exists := input.Attr("name")
		if exists && name != "" {
			isInForm := input.ParentsFiltered("form").Length() > 0
			if !isInForm {
				paramMap[name] = struct{}{}
			}
		}
	})

	for param := range paramMap {
		hiddenParams = append(hiddenParams, models.Parameter{
			Name:  param,
			Value: "",
			Type:  "hidden_input",
		})
	}

	return models.ParameterizedURL{
		URL:    baseURL.String(),
		Method: "POST",
		Params: hiddenParams,
	}
}

// extractCommonParameters checks for common parameter names in the URL
func (e *Extractor) extractCommonParameters(baseURL *url.URL) models.ParameterizedURL {
	commonParams := []string{
		"id", "page", "search", "query", "keyword", "q", "s", "key", "token",
		"file", "path", "dir", "action", "type", "category", "cat", "view",
		"callback", "jsonp", "format", "redirect", "redirectUrl", "return",
		"next", "target", "url", "site", "lang", "language", "locale",
		"debug", "test", "mode", "admin", "user", "username", "password",
		"email", "name", "sort", "order", "limit", "offset", "start", "end",
		"date", "month", "year", "time", "filter", "tag", "status",
	}
	params := make([]models.Parameter, 0)
	existingParams := make(map[string]struct{})
	for param := range baseURL.Query() {
		existingParams[param] = struct{}{}
	}
	for _, param := range commonParams {
		if _, exists := existingParams[param]; !exists {
			params = append(params, models.Parameter{
				Name:  param,
				Value: "",
				Type:  "common_param",
			})
		}
	}
	return models.ParameterizedURL{
		URL:    baseURL.String(),
		Method: "GET",
		Params: params,
	}
}

var pathParamRegex = regexp.MustCompile(`/\d+/?$|/[a-fA-F0-9-]{36}/?$|/(?:id|user|product|article|post|page|category|item|file|image|document|resource|api)/([^/]+)/?$`)

func (e *Extractor) extractPathParams(u *url.URL) []models.Parameter {
	params := make([]models.Parameter, 0)
	matches := pathParamRegex.FindAllStringSubmatch(u.Path, -1)
	for i, match := range matches {
		value := strings.ReplaceAll(match[0], "/", "")
		name := fmt.Sprintf("path_param_%d", i+1)
		if len(match) > 1 && match[1] != "" {
			value = match[1]
			pathParts := strings.Split(match[0], "/")
			for _, part := range pathParts {
				if part != "" && part != value {
					name = part
					break
				}
			}
		}
		params = append(params, models.Parameter{
			Name:  name,
			Value: value,
			Type:  "path",
		})
	}

	pathParts := strings.Split(u.Path, "/")
	for _, part := range pathParts {
		if part == "" || part == "api" || part == "v1" || part == "v2" {
			continue
		}
		if (strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}")) ||
			(strings.HasPrefix(part, ":")) {
			name := part
			name = strings.TrimPrefix(name, "{")
			name = strings.TrimSuffix(name, "}")
			name = strings.TrimPrefix(name, ":")
			params = append(params, models.Parameter{
				Name:  name,
				Value: "",
				Type:  "path_template",
			})
		}
	}
	return params
}
