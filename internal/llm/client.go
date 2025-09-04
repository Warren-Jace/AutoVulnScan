package llm

// Client LLM客户端接口
type Client interface {
	Query(prompt string) (string, error)
}

// NewClient 创建新的LLM客户端
func NewClient(provider, model, apiKey string) (Client, error) {
	// 简化实现，实际应该根据不同的提供商创建不同的客户端
	return &MockClient{}, nil
}

// MockClient 模拟LLM客户端
type MockClient struct{}

// Query 查询LLM
func (c *MockClient) Query(prompt string) (string, error) {
	return "Mock response for: " + prompt, nil
}