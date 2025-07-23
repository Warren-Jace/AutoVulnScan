// Package ai 提供了与大语言模型（LLM）集成以执行安全相关任务的功能，
// 例如生成上下文感知的攻击载荷或分析潜在的漏洞。
package ai

import (
	"context"
	"fmt"
	"strings"

	openai "github.com/sashabaranov/go-openai"
)

// AIAnalyzer 是一个与AI模型进行交互的客户端。
type AIAnalyzer struct {
	aiClient *openai.Client
	model    string
}

// NewAIAnalyzer 创建一个新的 AIAnalyzer 实例。
//
// 参数:
//
//	apiKey (string): 用于访问AI服务的API密钥。
//	model (string): 要使用的AI模型的名称 (例如, "gpt-3.5-turbo")。
//	baseURL (string): (可选) AI服务的备用基础URL，可用于代理或兼容其他OpenAI API的服务。
func NewAIAnalyzer(apiKey, model, baseURL string) (*AIAnalyzer, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("AI API密钥未配置")
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

// GeneratePayloads 使用AI模型为给定的漏洞场景生成上下文感知的攻击载荷。
//
// 改进建议:
//
//	当前的prompt是硬编码的。为了增加灵活性，可以将prompt模板作为配置项，
//	或使用Go的 text/template 包来根据不同场景动态渲染更复杂的prompt。
//
// 未来扩展:
//
//	可以添加新的方法，如 AnalyzeVulnerability，将HTTP请求和响应发送给AI，
//	让其判断是否存在漏洞并提供详细的分析报告。
func (a *AIAnalyzer) GeneratePayloads(ctx context.Context, vulnerabilityType string, url string, method string, params string) ([]string, error) {
	// 这个prompt的设计至关重要，它为AI设定了角色、任务、上下文和输出格式。
	// - 角色设定: "You are a professional penetration testing expert." (你是一位专业的渗透测试专家。)
	// - 任务描述: "generate a series of brief, effective payloads for security testing." (为安全测试生成一系列简洁有效的载荷。)
	// - 上下文信息: 提供了漏洞类型、URL、HTTP方法和参数，让AI的输出更具针对性。
	// - 输出格式要求: "Return **only** a list of payloads...Do not include any other text..." (只返回载荷列表，不要包含任何其他文本...)
	//   这使得AI的返回结果更容易被程序解析。
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
		return nil, fmt.Errorf("调用AI模型失败: %w", err)
	}

	if len(resp.Choices) > 0 {
		content := resp.Choices[0].Message.Content
		return parseResponse(content), nil
	}

	return []string{}, nil
}

// parseResponse 从AI返回的原始字符串中解析出载荷列表。
// 它通过按换行符分割，并移除空行和多余的空格来实现。
func parseResponse(response string) []string {
	payloads := strings.Split(response, "\n")
	var cleanedPayloads []string
	for _, p := range payloads {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			cleanedPayloads = append(cleanedPayloads, trimmed)
		}
	}
	return cleanedPayloads
}
