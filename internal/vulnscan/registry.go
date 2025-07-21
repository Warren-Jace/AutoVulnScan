package vulnscan

import "sync"

var (
	registeredPlugins []Plugin
	mu                sync.Mutex
)

// RegisterPlugin adds a plugin to the registry.
func RegisterPlugin(p Plugin) {
	mu.Lock()
	defer mu.Unlock()
	registeredPlugins = append(registeredPlugins, p)
}

// GetPlugins returns a slice of all registered plugins.
func GetPlugins() []Plugin {
	mu.Lock()
	defer mu.Unlock()
	// Return a copy to prevent modification of the original slice.
	plugins := make([]Plugin, len(registeredPlugins))
	copy(plugins, registeredPlugins)
	return plugins
} 