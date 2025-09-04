package browser

// Browser 浏览器接口
type Browser interface {
	Navigate(url string) error
	GetHTML() (string, error)
	Close() error
}

// NewBrowser 创建新的浏览器实例
func NewBrowser() (Browser, error) {
	// 简化实现
	return &MockBrowser{}, nil
}

// MockBrowser 模拟浏览器
type MockBrowser struct{}

// Navigate 导航到指定URL
func (b *MockBrowser) Navigate(url string) error {
	// 简化实现
	return nil
}

// GetHTML 获取页面HTML
func (b *MockBrowser) GetHTML() (string, error) {
	// 简化实现
	return "<html><body>Mock HTML content</body></html>", nil
}

// Close 关闭浏览器
func (b *MockBrowser) Close() error {
	// 简化实现
	return nil
}