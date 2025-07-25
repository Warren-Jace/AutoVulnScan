// Package ai 提供了与人工智能模型（如大型语言模型）交互的功能。
// 它可以用于生成动态的、上下文感知的漏洞扫描payloads，
// 或对扫描结果进行更智能的分析和验证。
package ai

import (
	"context"
	"fmt"
	"strings"

	"github.com/tmc/langchaingo/llms"
	"github.com/tmc/langchaingo/llms/ollama"
)

// AIAnalyzer 封装了与AI模型交互的所有逻辑。
// 它作为一个适配器，可以与多种不同的AI模型提供商（如Ollama）进行通信。
type AIAnalyzer struct {
	client llms.Model // `llms.Model` 是一个通用接口，代表任何兼容的语言模型。
}

// NewAIAnalyzer 创建并初始化一个新的 AIAnalyzer 实例。
//
// 参数:
//
//	apiKey (string): 用于访问AI服务的API密钥。
//	modelName (string): 要使用的具体AI模型的名称 (例如, "ollama/llama2")。
//	baseURL (string): （可选）AI服务的自定义API端点。如果为空，则使用默认端点。
//
// 返回:
//
//	(*AIAnalyzer, error): 初始化后的AIAnalyzer实例或在发生错误时返回error。
func NewAIAnalyzer(apiKey, modelName, baseURL string) (*AIAnalyzer, error) {
	var client llms.Model
	var err error

	// 根据模型名称选择并初始化合适的AI模型客户端。
	// 这种设计使得添加对新模型的支持变得容易。
	switch {
	case strings.HasPrefix(modelName, "ollama/"):
		// 如果模型名称以 "ollama/" 开头，则使用Ollama客户端。
		model := strings.TrimPrefix(modelName, "ollama/")
		client, err = ollama.New(ollama.WithModel(model))
		if err != nil {
			return nil, fmt.Errorf("初始化Ollama模型失败: %w", err)
		}
	default:
		// 如果模型名称不匹配任何已知的前缀，则返回错误。
		return nil, fmt.Errorf("不支持的AI模型: %s", modelName)
	}

	return &AIAnalyzer{client: client}, nil
}

// GeneratePayloads 使用AI模型为特定的漏洞类型和上下文生成payloads。
//
// 参数:
//
//	ctx (context.Context): 用于控制请求的生命周期 (例如, 设置超时或取消)。
//	vulnType (string): 漏洞类型 (例如, "xss", "sqli")。
//	url (string): 目标URL，为AI提供上下文信息。
//	method (string): HTTP请求方法 (例如, "GET", "POST")。
//	param (string): 正在被测试的参数名称。
//
// 返回:
//
//	([]string, error): 由AI生成的payloads列表或在发生错误时返回error。
func (a *AIAnalyzer) GeneratePayloads(ctx context.Context, vulnType, url, method, param string) ([]string, error) {
	if a.client == nil {
		return nil, fmt.Errorf("AI客户端未初始化")
	}

	// 构建一个详细的、结构化的提示 (prompt)，以引导AI生成高质量的payloads。
	// 提示中包含了漏洞类型、目标URL、方法、参数等关键信息，
	// 并明确要求AI以特定格式（逗号分隔）返回结果。
	prompt := fmt.Sprintf(
		"为 %s 漏洞生成5个创造性的测试payloads。\n"+
			"目标详情:\n"+
			"- URL: %s\n"+
			"- 方法: %s\n"+
			"- 参数: %s\n"+
			"请仅返回一个逗号分隔的payloads列表，不要包含任何其他解释或格式化。",
		vulnType, url, method, param,
	)

	// 调用AI模型生成内容。
	// `llms.WithTemperature(0.7)` 调整生成内容的多样性，值越高，结果越随机和创造性。
	completion, err := llms.GenerateFromSinglePrompt(ctx, a.client, prompt, llms.WithTemperature(0.7))
	if err != nil {
		return nil, fmt.Errorf("从AI模型生成payloads失败: %w", err)
	}

	// AI返回的结果是一个单一的字符串，其中包含了多个由逗号分隔的payloads。
	// 这里我们将这个字符串分割成一个字符串切片。
	payloads := strings.Split(completion, ",")
	for i := range payloads {
		// 清理每个payload，移除可能存在的多余空格或换行符。
		payloads[i] = strings.TrimSpace(payloads[i])
	}

	return payloads, nil
}
