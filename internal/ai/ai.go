// Package ai provides functionalities for integrating with AI models for tasks like
// payload generation and vulnerability analysis.
package ai

import (
	"context"
	"fmt"
	"strings"

	openai "github.com/sashabaranov/go-openai"
)

// AIAnalyzer is a client for interacting with an AI model.
type AIAnalyzer struct {
	aiClient *openai.Client
	model    string
}

// NewAIAnalyzer creates a new AIAnalyzer instance.
func NewAIAnalyzer(apiKey, model, baseURL string) (*AIAnalyzer, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("AI API key is not configured")
	}
	config := openai.DefaultConfig(apiKey)
	if baseURL != "" {
		config.BaseURL = baseURL
	}

	client := openai.NewClientWithConfig(config)

	return &AIAnalyzer{
		aiClient: client,
		model:    model,
	}, nil
}

// GeneratePayloads uses the AI model to generate context-aware payloads.
func (a *AIAnalyzer) GeneratePayloads(ctx context.Context, vulnerabilityType string, url string, method string, params string) ([]string, error) {
	prompt := `
You are a professional penetration testing expert. Your task is to generate a series of brief, effective payloads for security testing.

**Vulnerability Type:**
` + vulnerabilityType + `

**Target Information:**
- URL: ` + url + `
- HTTP Method: ` + method + `
- Parameters: ` + params + `

**Instructions:**
1.  Based on the vulnerability type and target information, create a list of concise and effective payloads.
2.  The payloads should be directly usable for injection attacks.
3.  Return **only** a list of payloads, with each payload on a new line. Do not include any other text, explanations, or formatting.
4.  If the vulnerability type is not recognized or you cannot generate payloads, return an empty response.

**BEGIN PAYLOADS**
`

	resp, err := a.aiClient.CreateChatCompletion(
		ctx,
		openai.ChatCompletionRequest{
			Model: a.model,
			Messages: []openai.ChatCompletionMessage{
				{
					Role:    openai.ChatMessageRoleUser,
					Content: prompt,
				},
			},
		},
	)

	if err != nil {
		return nil, err
	}

	if len(resp.Choices) > 0 {
		content := resp.Choices[0].Message.Content
		return parseResponse(content), nil
	}

	return []string{}, nil
}

// parseResponse extracts payloads from the AI's raw response string.
func parseResponse(response string) []string {
	// Split by newline and filter out any empty lines.
	payloads := strings.Split(response, "\n")
	var cleanedPayloads []string
	for _, p := range payloads {
		if strings.TrimSpace(p) != "" {
			cleanedPayloads = append(cleanedPayloads, strings.TrimSpace(p))
		}
	}
	return cleanedPayloads
} 