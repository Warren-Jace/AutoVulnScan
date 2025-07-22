// Package vulnscan 提供漏洞扫描插件的注册和管理功能
package vulnscan

import "sync"

var (
	// registeredPlugins 存储所有已注册的扫描插件
	// 使用全局变量来维护插件注册表，确保所有插件都能被统一管理
	registeredPlugins []Plugin

	// mu 互斥锁，用于保护 registeredPlugins 的并发访问
	// 确保在多协程环境下插件注册和获取操作的线程安全
	mu sync.Mutex
)

// RegisterPlugin 将一个插件添加到注册表中
// 这个函数通常在插件包的 init() 函数中调用，实现插件的自动注册
// 参数:
//   - p: 要注册的插件实例，必须实现 Plugin 接口
func RegisterPlugin(p Plugin) {
	mu.Lock()                                        // 获取互斥锁，防止并发写入
	defer mu.Unlock()                                // 函数结束时释放锁
	registeredPlugins = append(registeredPlugins, p) // 将插件添加到注册表
}

// GetPlugins 返回所有已注册插件的副本切片
// 返回副本而不是原始切片，防止外部代码意外修改插件注册表
// 返回:
//   - []Plugin: 包含所有已注册插件的切片副本
func GetPlugins() []Plugin {
	mu.Lock()         // 获取互斥锁，防止并发读写冲突
	defer mu.Unlock() // 函数结束时释放锁

	// Return a copy to prevent modification of the original slice.
	// 创建并返回插件切片的副本，防止外部修改原始注册表
	plugins := make([]Plugin, len(registeredPlugins)) // 创建与原切片相同长度的新切片
	copy(plugins, registeredPlugins)                  // 复制所有插件到新切片
	return plugins                                    // 返回副本切片
}
