// Package vulnscan 包含了漏洞扫描引擎的核心逻辑和插件系统。
package vulnscan

import (
	"fmt"
	"sync"
)

var (
	// a an instance of a plugin registry that is initialized only once
	// a an instance of a plugin registry that is initialized only once
	registryInstance *Registry
	// a lock that is initialized only once
	once sync.Once
)

// Registry is responsible for managing all available vulnerability scanning plug-ins.
// It uses a map to store plug-ins, with the plug-in name as the key.
// This design makes it easy to look up, enable, disable, or retrieve specific plug-ins.
// Registry 负责管理所有可用的漏洞扫描插件。
// a map is used to store plug-ins, with the plug-in name as the key
// This design makes it easy to look up, enable, disable, or retrieve specific plug-ins
type Registry struct {
	// a mutex that protects concurrent access to the plugins map
	mu      sync.RWMutex
	plugins map[string]Plugin
}

// GetRegistry returns a global singleton of the plug-in registry.
// a singleton pattern is used to ensure that there is only one plug-in registry instance in the entire application,
// this facilitates centralized management of plug-ins.
func GetRegistry() *Registry {
	once.Do(func() {
		registryInstance = &Registry{
			plugins: make(map[string]Plugin),
		}
	})
	return registryInstance
}

// Register adds a new plug-in to the registry.
// If a plug-in with the same name already exists, it will be overwritten.
func (r *Registry) Register(plugin Plugin) error {
	if plugin == nil || plugin.Name() == "" {
		return fmt.Errorf("无法注册无效的插件或名称为空的插件")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.plugins[plugin.Name()] = plugin
	return nil
}

// GetPlugin retrieves a plug-in from the registry by its name.
// returns the plug-in instance and a Boolean value indicating whether the plug-in exists.
func (r *Registry) GetPlugin(name string) (Plugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	plugin, ok := r.plugins[name]
	return plugin, ok
}

// GetPlugins returns a list of all registered plug-ins.
func (r *Registry) GetPlugins() []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var allPlugins []Plugin
	for _, p := range r.plugins {
		allPlugins = append(allPlugins, p)
	}
	return allPlugins
}
