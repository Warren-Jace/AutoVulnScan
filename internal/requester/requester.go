package requester

// Requester HTTP请求接口
type Requester interface {
	Get(url string, headers map[string]string) (string, error)
	Post(url string, body string, headers map[string]string) (string, error)
}

// NewRequester 创建新的请求器实例
func NewRequester() (Requester, error) {
	// 简化实现
	return &MockRequester{}, nil
}

// MockRequester 模拟请求器
type MockRequester struct{}

// Get 发送GET请求
func (r *MockRequester) Get(url string, headers map[string]string) (string, error) {
	// 简化实现
	return "Mock GET response", nil
}

// Post 发送POST请求
func (r *MockRequester) Post(url string, body string, headers map[string]string) (string, error) {
	// 简化实现
	return "Mock POST response", nil
}