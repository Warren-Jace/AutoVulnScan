package browser

// Browser 浏览器接口
type Browser interface {
	Navigate(url string) error
	GetHTML() (string, error)
	Close() error
}

// BrowserService 浏览器服务接口
type BrowserService interface {
	NewBrowser() (Browser, error)
	GetVersion() string
	IsAvailable() bool
}

// NewBrowser 创建新的浏览器实例
func NewBrowser() (Browser, error) {
	// 简化实现
	return &MockBrowser{}, nil
}

// NewBrowserService 创建新的浏览器服务实例
func NewBrowserService() BrowserService {
	return &MockBrowserService{}
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

// MockBrowserService 模拟浏览器服务
type MockBrowserService struct{}

// NewBrowser 创建新的浏览器实例
func (s *MockBrowserService) NewBrowser() (Browser, error) {
	return &MockBrowser{}, nil
}

// GetVersion 获取浏览器版本
func (s *MockBrowserService) GetVersion() string {
	return "Mock Browser Service v1.0"
}

// IsAvailable 检查浏览器服务是否可用
func (s *MockBrowserService) IsAvailable() bool {
	return true
}