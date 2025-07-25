// Package vulnscan 提供漏洞扫描插件的注册和管理功能
package vulnscan

import (
	"fmt"
	"sync"

	"github.com/rs/zerolog/log"
)

var (
	// registeredPlugins 存储所有已注册的扫描插件
	// 使用全局变量来维护插件注册表，确保所有插件都能被统一管理
	registeredPlugins []Plugin

	// mu 读写互斥锁，用于保护 registeredPlugins 的并发访问
	// 使用RWMutex提高读取性能，因为GetPlugins调用频率通常高于RegisterPlugin
	mu sync.RWMutex

	// pluginNames 用于快速检查插件名称重复
	// 避免注册重复名称的插件
	pluginNames map[string]bool

	// once 确保初始化只执行一次
	once sync.Once
)

// initRegistry 初始化插件注册表
func initRegistry() {
	pluginNames = make(map[string]bool)
	log.Debug().Msg("插件注册表初始化完成")
}

// validatePlugin 验证插件的有效性
func validatePlugin(p Plugin) error {
	if p == nil {
		return fmt.Errorf("插件不能为空")
	}

	info := p.Info()
	if info.Name == "" {
		return fmt.Errorf("插件名称不能为空")
	}

	if info.Version == "" {
		log.Warn().Str("plugin", info.Name).Msg("插件版本为空")
	}

	if info.Author == "" {
		log.Warn().Str("plugin", info.Name).Msg("插件作者为空")
	}

	// 检查插件名称长度
	if len(info.Name) > 100 {
		return fmt.Errorf("插件名称过长，不能超过100个字符")
	}

	return nil
}

// isPluginRegistered 检查插件是否已经注册
func isPluginRegistered(pluginName string) bool {
	// 注意：此函数假设已经获取了锁
	return pluginNames[pluginName]
}

// addPluginToRegistry 将插件添加到注册表
func addPluginToRegistry(p Plugin) {
	// 注意：此函数假设已经获取了锁
	info := p.Info()

	registeredPlugins = append(registeredPlugins, p)
	pluginNames[info.Name] = true

	log.Info().
		Str("name", info.Name).
		Str("version", info.Version).
		Str("author", info.Author).
		Int("totalPlugins", len(registeredPlugins)).
		Msg("插件注册成功")
}

// RegisterPlugin 将一个插件添加到注册表中
// 这个函数通常在插件包的 init() 函数中调用，实现插件的自动注册
// 参数:
//   - p: 要注册的插件实例，必须实现 Plugin 接口
func RegisterPlugin(p Plugin) {
	// 确保注册表已初始化
	once.Do(initRegistry)

	// 验证插件有效性
	if err := validatePlugin(p); err != nil {
		log.Error().
			Err(err).
			Msg("插件验证失败，跳过注册")
		return
	}

	info := p.Info()

	// 获取写锁
	mu.Lock()
	defer mu.Unlock()

	// 检查插件是否已经注册
	if isPluginRegistered(info.Name) {
		log.Warn().
			Str("name", info.Name).
			Str("version", info.Version).
			Msg("插件已存在，跳过重复注册")
		return
	}

	// 检查注册表容量，防止无限增长
	const maxPlugins = 1000
	if len(registeredPlugins) >= maxPlugins {
		log.Error().
			Str("name", info.Name).
			Int("currentCount", len(registeredPlugins)).
			Int("maxPlugins", maxPlugins).
			Msg("插件注册表已满，无法注册新插件")
		return
	}

	// 添加插件到注册表
	addPluginToRegistry(p)
}

// GetPlugins 返回所有已注册插件的副本切片
// 返回副本而不是原始切片，防止外部代码意外修改插件注册表
// 返回:
//   - []Plugin: 包含所有已注册插件的切片副本
func GetPlugins() []Plugin {
	// 确保注册表已初始化
	once.Do(initRegistry)

	// 获取读锁，允许并发读取
	mu.RLock()
	defer mu.RUnlock()

	// 如果没有插件，返回空切片
	if len(registeredPlugins) == 0 {
		log.Debug().Msg("插件注册表为空")
		return []Plugin{}
	}

	// 创建并返回插件切片的副本，防止外部修改原始注册表
	// 预分配容量以提高性能
	plugins := make([]Plugin, 0, len(registeredPlugins))

	// 过滤空插件并复制有效插件
	validPluginCount := 0
	for _, plugin := range registeredPlugins {
		if plugin != nil {
			plugins = append(plugins, plugin)
			validPluginCount++
		} else {
			log.Warn().Msg("发现空插件，已跳过")
		}
	}

	log.Debug().
		Int("totalRegistered", len(registeredPlugins)).
		Int("validPlugins", validPluginCount).
		Msg("获取插件列表完成")

	return plugins
}

// GetPluginCount 获取已注册插件的数量（用于监控和调试）
func GetPluginCount() int {
	once.Do(initRegistry)

	mu.RLock()
	defer mu.RUnlock()

	return len(registeredPlugins)
}

// GetPluginByName 根据名称获取特定插件（用于调试和测试）
func GetPluginByName(name string) Plugin {
	if name == "" {
		log.Warn().Msg("插件名称为空")
		return nil
	}

	once.Do(initRegistry)

	mu.RLock()
	defer mu.RUnlock()

	for _, plugin := range registeredPlugins {
		if plugin != nil && plugin.Info().Name == name {
			log.Debug().Str("name", name).Msg("找到指定插件")
			return plugin
		}
	}

	log.Debug().Str("name", name).Msg("未找到指定插件")
	return nil
}

// ListPluginNames 获取所有已注册插件的名称列表（用于调试和监控）
func ListPluginNames() []string {
	once.Do(initRegistry)

	mu.RLock()
	defer mu.RUnlock()

	if len(registeredPlugins) == 0 {
		return []string{}
	}

	names := make([]string, 0, len(registeredPlugins))
	for _, plugin := range registeredPlugins {
		if plugin != nil {
			names = append(names, plugin.Info().Name)
		}
	}

	log.Debug().
		Int("pluginCount", len(names)).
		Strs("pluginNames", names).
		Msg("获取插件名称列表完成")

	return names
}

// ClearPlugins 清空插件注册表（主要用于测试）
func ClearPlugins() {
	mu.Lock()
	defer mu.Unlock()

	oldCount := len(registeredPlugins)
	registeredPlugins = registeredPlugins[:0] // 保留底层数组，只重置长度

	// 清空插件名称映射
	for name := range pluginNames {
		delete(pluginNames, name)
	}

	log.Info().
		Int("clearedCount", oldCount).
		Msg("插件注册表已清空")
}
