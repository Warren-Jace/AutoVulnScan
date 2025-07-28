// Package vulnscan 提供漏洞扫描插件的注册和管理功能
package vulnscan

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// PluginRegistry 插件注册表结构
type PluginRegistry struct {
	// 核心存储
	plugins     map[string]Plugin    // 按名称索引的插件
	pluginList  []Plugin            // 插件列表（保持注册顺序）
	categories  map[string][]Plugin // 按分类索引的插件
	priorities  map[string]int      // 插件优先级
	
	// 状态管理
	pluginStates map[string]PluginRegistryState
	
	// 并发控制
	mu sync.RWMutex
	
	// 配置
	config RegistryConfig
	
	// 统计信息
	stats RegistryStats
	
	// 生命周期管理
	initialized bool
	closed      bool
	ctx         context.Context
	cancel      context.CancelFunc
}

// RegistryConfig 注册表配置
type RegistryConfig struct {
	MaxPlugins          int           `json:"max_plugins"`           // 最大插件数量
	EnableValidation    bool          `json:"enable_validation"`     // 启用插件验证
	EnableMetrics       bool          `json:"enable_metrics"`        // 启用指标收集
	AllowDuplicates     bool          `json:"allow_duplicates"`      // 允许重复插件
	AutoInitialize      bool          `json:"auto_initialize"`       // 自动初始化插件
	InitTimeout         time.Duration `json:"init_timeout"`          // 初始化超时
	ValidationTimeout   time.Duration `json:"validation_timeout"`    // 验证超时
	EnableCategoryIndex bool          `json:"enable_category_index"` // 启用分类索引
	EnablePrioritySort  bool          `json:"enable_priority_sort"`  // 启用优先级排序
}

// PluginRegistryState 插件注册状态
type PluginRegistryState struct {
	RegisteredAt time.Time              `json:"registered_at"`
	Status       PluginStatus           `json:"status"`
	LastError    string                 `json:"last_error"`
	InitAttempts int                    `json:"init_attempts"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// PluginStatus 插件状态枚举
type PluginStatus int

const (
	PluginStatusUnknown PluginStatus = iota
	PluginStatusRegistered
	PluginStatusInitializing
	PluginStatusReady
	PluginStatusError
	PluginStatusDisabled
)

// String 返回状态字符串
func (s PluginStatus) String() string {
	switch s {
	case PluginStatusRegistered:
		return "Registered"
	case PluginStatusInitializing:
		return "Initializing"
	case PluginStatusReady:
		return "Ready"
	case PluginStatusError:
		return "Error"
	case PluginStatusDisabled:
		return "Disabled"
	default:
		return "Unknown"
	}
}

// RegistryStats 注册表统计信息
type RegistryStats struct {
	TotalPlugins       int                    `json:"total_plugins"`
	ReadyPlugins       int                    `json:"ready_plugins"`
	ErrorPlugins       int                    `json:"error_plugins"`
	DisabledPlugins    int                    `json:"disabled_plugins"`
	ByCategory         map[string]int         `json:"by_category"`
	ByStatus           map[PluginStatus]int   `json:"by_status"`
	RegistrationTimes  map[string]time.Time   `json:"registration_times"`
	LastUpdate         time.Time              `json:"last_update"`
}

// PluginFilter 插件过滤器
type PluginFilter struct {
	Names      []string       `json:"names"`       // 按名称过滤
	Categories []string       `json:"categories"`  // 按分类过滤
	Status     []PluginStatus `json:"status"`      // 按状态过滤
	MinPriority int           `json:"min_priority"` // 最小优先级
	MaxPriority int           `json:"max_priority"` // 最大优先级
	Tags       []string       `json:"tags"`        // 按标签过滤
}

// 全局注册表实例
var (
	globalRegistry *PluginRegistry
	registryOnce   sync.Once
)

// 默认配置
var defaultRegistryConfig = RegistryConfig{
	MaxPlugins:          1000,
	EnableValidation:    true,
	EnableMetrics:       true,
	AllowDuplicates:     false,
	AutoInitialize:      true,
	InitTimeout:         30 * time.Second,
	ValidationTimeout:   10 * time.Second,
	EnableCategoryIndex: true,
	EnablePrioritySort:  true,
}

// GetGlobalRegistry 获取全局注册表实例
func GetGlobalRegistry() *PluginRegistry {
	registryOnce.Do(func() {
		globalRegistry = NewPluginRegistry(defaultRegistryConfig)
	})
	return globalRegistry
}

// NewPluginRegistry 创建新的插件注册表
func NewPluginRegistry(config RegistryConfig) *PluginRegistry {
	ctx, cancel := context.WithCancel(context.Background())
	
	registry := &PluginRegistry{
		plugins:      make(map[string]Plugin),
		pluginList:   make([]Plugin, 0),
		categories:   make(map[string][]Plugin),
		priorities:   make(map[string]int),
		pluginStates: make(map[string]PluginRegistryState),
		config:       config,
		ctx:          ctx,
		cancel:       cancel,
		stats: RegistryStats{
			ByCategory: make(map[string]int),
			ByStatus:   make(map[PluginStatus]int),
			RegistrationTimes: make(map[string]time.Time),
		},
	}
	
	log.Info().
		Int("max_plugins", config.MaxPlugins).
		Bool("enable_validation", config.EnableValidation).
		Bool("auto_initialize", config.AutoInitialize).
		Msg("插件注册表创建完成")
	
	return registry
}

// RegisterPlugin 注册插件
func (r *PluginRegistry) RegisterPlugin(p Plugin) error {
	return r.RegisterPluginWithPriority(p, 0)
}

// RegisterPluginWithPriority 注册带优先级的插件
func (r *PluginRegistry) RegisterPluginWithPriority(p Plugin, priority int) error {
	if r.closed {
		return fmt.Errorf("注册表已关闭")
	}

	// 验证插件
	if err := r.validatePlugin(p); err != nil {
		return fmt.Errorf("插件验证失败: %w", err)
	}

	info := p.Info()
	
	r.mu.Lock()
	defer r.mu.Unlock()

	// 检查重复
	if !r.config.AllowDuplicates {
		if _, exists := r.plugins[info.Name]; exists {
			return fmt.Errorf("插件 %s 已存在", info.Name)
		}
	}

	// 检查容量
	if len(r.plugins) >= r.config.MaxPlugins {
		return fmt.Errorf("注册表已满，最大容量: %d", r.config.MaxPlugins)
	}

	// 注册插件
	r.plugins[info.Name] = p
	r.pluginList = append(r.pluginList, p)
	r.priorities[info.Name] = priority
	
	// 更新分类索引
	if r.config.EnableCategoryIndex {
		r.updateCategoryIndex(info.Category, p)
	}

	// 设置初始状态
	r.pluginStates[info.Name] = PluginRegistryState{
		RegisteredAt: time.Now(),
		Status:       PluginStatusRegistered,
		Metadata:     make(map[string]interface{}),
	}

	// 更新统计
	r.updateStats()

	log.Info().
		Str("name", info.Name).
		Str("version", info.Version).
		Str("category", info.Category).
		Int("priority", priority).
		Int("total_plugins", len(r.plugins)).
		Msg("插件注册成功")

	// 自动初始化
	if r.config.AutoInitialize {
		go r.initializePlugin(p)
	}

	return nil
}

// validatePlugin 验证插件
func (r *PluginRegistry) validatePlugin(p Plugin) error {
	if p == nil {
		return fmt.Errorf("插件不能为空")
	}

	info := p.Info()
	
	// 基础验证
	if strings.TrimSpace(info.Name) == "" {
		return fmt.Errorf("插件名称不能为空")
	}
	
	if len(info.Name) > 100 {
		return fmt.Errorf("插件名称过长，不能超过100个字符")
	}
	
	if !r.isValidPluginName(info.Name) {
		return fmt.Errorf("插件名称包含无效字符")
	}

	// 版本验证
	if strings.TrimSpace(info.Version) == "" {
		log.Warn().Str("plugin", info.Name).Msg("插件版本为空")
	}

	// 扩展验证
	if r.config.EnableValidation {
		ctx, cancel := context.WithTimeout(r.ctx, r.config.ValidationTimeout)
		defer cancel()
		
		if err := r.validatePluginExtended(ctx, p); err != nil {
			return fmt.Errorf("扩展验证失败: %w", err)
		}
	}

	return nil
}

// validatePluginExtended 扩展验证
func (r *PluginRegistry) validatePluginExtended(ctx context.Context, p Plugin) error {
	// 检查插件是否实现了必要的接口
	info := p.Info()
	
	// 验证插件依赖
	for _, dep := range info.Dependencies {
		if !r.hasPlugin(dep) {
			log.Warn().
				Str("plugin", info.Name).
				Str("dependency", dep).
				Msg("插件依赖未满足")
		}
	}
	
	// 如果插件支持初始化验证
	if validator, ok := p.(interface{ Validate() error }); ok {
		if err := validator.Validate(); err != nil {
			return fmt.Errorf("插件自验证失败: %w", err)
		}
	}
	
	return nil
}

// isValidPluginName 检查插件名称是否有效
func (r *PluginRegistry) isValidPluginName(name string) bool {
	// 只允许字母、数字、下划线和连字符
	for _, char := range name {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '_' || char == '-') {
			return false
		}
	}
	return true
}

// hasPlugin 检查插件是否存在
func (r *PluginRegistry) hasPlugin(name string) bool {
	_, exists := r.plugins[name]
	return exists
}

// updateCategoryIndex 更新分类索引
func (r *PluginRegistry) updateCategoryIndex(category string, p Plugin) {
	if category == "" {
		category = "uncategorized"
	}
	
	if r.categories[category] == nil {
		r.categories[category] = make([]Plugin, 0)
	}
	
	r.categories[category] = append(r.categories[category], p)
}

// updateStats 更新统计信息
func (r *PluginRegistry) updateStats() {
	r.stats.TotalPlugins = len(r.plugins)
	r.stats.LastUpdate = time.Now()
	
	// 重置计数器
	for status := range r.stats.ByStatus {
		r.stats.ByStatus[status] = 0
	}
	
	// 统计状态
	for _, state := range r.pluginStates {
		r.stats.ByStatus[state.Status]++
		
		switch state.Status {
		case PluginStatusReady:
			r.stats.ReadyPlugins++
		case PluginStatusError:
			r.stats.ErrorPlugins++
		case PluginStatusDisabled:
			r.stats.DisabledPlugins++
		}
	}
	
	// 统计分类
	for category := range r.stats.ByCategory {
		r.stats.ByCategory[category] = 0
	}
	
	for category, plugins := range r.categories {
		r.stats.ByCategory[category] = len(plugins)
	}
}

// initializePlugin 初始化插件
func (r *PluginRegistry) initializePlugin(p Plugin) {
	info := p.Info()
	
	r.mu.Lock()
	state := r.pluginStates[info.Name]
	state.Status = PluginStatusInitializing
	state.InitAttempts++
	r.pluginStates[info.Name] = state
	r.mu.Unlock()
	
	log.Debug().Str("plugin", info.Name).Msg("开始初始化插件")
	
	ctx, cancel := context.WithTimeout(r.ctx, r.config.InitTimeout)
	defer cancel()
	
	var err error
	done := make(chan struct{})
	
	go func() {
		defer close(done)
		if initializer, ok := p.(interface{ Initialize() error }); ok {
			err = initializer.Initialize()
		}
	}()
	
	select {
	case <-done:
		r.mu.Lock()
		state = r.pluginStates[info.Name]
		if err != nil {
			state.Status = PluginStatusError
			state.LastError = err.Error()
			log.Error().
				Err(err).
				Str("plugin", info.Name).
				Msg("插件初始化失败")
		} else {
			state.Status = PluginStatusReady
			state.LastError = ""
			log.Info().
				Str("plugin", info.Name).
				Msg("插件初始化成功")
		}
		r.pluginStates[info.Name] = state
		r.updateStats()
		r.mu.Unlock()
		
	case <-ctx.Done():
		r.mu.Lock()
		state = r.pluginStates[info.Name]
		state.Status = PluginStatusError
		state.LastError = "初始化超时"
		r.pluginStates[info.Name] = state
		r.updateStats()
		r.mu.Unlock()
		
		log.Error().
			Str("plugin", info.Name).
			Dur("timeout", r.config.InitTimeout).
			Msg("插件初始化超时")
	}
}

// GetPlugins 获取所有插件
func (r *PluginRegistry) GetPlugins() []Plugin {
	return r.GetPluginsWithFilter(PluginFilter{})
}

// GetPluginsWithFilter 根据过滤器获取插件
func (r *PluginRegistry) GetPluginsWithFilter(filter PluginFilter) []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	var result []Plugin
	
	for _, p := range r.pluginList {
		if r.matchesFilter(p, filter) {
			result = append(result, p)
		}
	}
	
	// 按优先级排序
	if r.config.EnablePrioritySort {
		sort.Slice(result, func(i, j int) bool {
			nameI := result[i].Info().Name
			nameJ := result[j].Info().Name
			return r.priorities[nameI] > r.priorities[nameJ]
		})
	}
	
	return result
}

// matchesFilter 检查插件是否匹配过滤器
func (r *PluginRegistry) matchesFilter(p Plugin, filter PluginFilter) bool {
	info := p.Info()
	
	// 按名称过滤
	if len(filter.Names) > 0 {
		found := false
		for _, name := range filter.Names {
			if info.Name == name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	// 按分类过滤
	if len(filter.Categories) > 0 {
		found := false
		for _, category := range filter.Categories {
			if info.Category == category {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	// 按状态过滤
	if len(filter.Status) > 0 {
		state := r.pluginStates[info.Name]
		found := false
		for _, status := range filter.Status {
			if state.Status == status {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	// 按优先级过滤
	priority := r.priorities[info.Name]
	if filter.MinPriority != 0 && priority < filter.MinPriority {
		return false
	}
	if filter.MaxPriority != 0 && priority > filter.MaxPriority {
		return false
	}
	
	// 按标签过滤
	if len(filter.Tags) > 0 {
		for _, filterTag := range filter.Tags {
			found := false
			for _, pluginTag := range info.Tags {
				if pluginTag == filterTag {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	
	return true
}

// GetPluginByName 根据名称获取插件
func (r *PluginRegistry) GetPluginByName(name string) Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	return r.plugins[name]
}

// GetPluginsByCategory 根据分类获取插件
func (r *PluginRegistry) GetPluginsByCategory(category string) []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	plugins := r.categories[category]
	if plugins == nil {
		return []Plugin{}
	}
	
	// 返回副本
	result := make([]Plugin, len(plugins))
	copy(result, plugins)
	return result
}

// GetPluginCount 获取插件数量
func (r *PluginRegistry) GetPluginCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	return len(r.plugins)
}

// GetStats 获取统计信息
func (r *PluginRegistry) GetStats() RegistryStats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	return r.stats
}

// ListPluginNames 获取所有插件名称
func (r *PluginRegistry) ListPluginNames() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	names := make([]string, 0, len(r.plugins))
	for name := range r.plugins {
		names = append(names, name)
	}
	
	sort.Strings(names)
	return names
}

// ListCategories 获取所有分类
func (r *PluginRegistry) ListCategories() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	categories := make([]string, 0, len(r.categories))
	for category := range r.categories {
		categories = append(categories, category)
	}
	
	sort.Strings(categories)
	return categories
}

// EnablePlugin 启用插件
func (r *PluginRegistry) EnablePlugin(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	state, exists := r.pluginStates[name]
	if !exists {
		return fmt.Errorf("插件 %s 不存在", name)
	}
	
	if state.Status == PluginStatusDisabled {
		state.Status = PluginStatusRegistered
		r.pluginStates[name] = state
		r.updateStats()
		
		log.Info().Str("plugin", name).Msg("插件已启用")
		
		// 重新初始化
		if r.config.AutoInitialize {
			if plugin := r.plugins[name]; plugin != nil {
				go r.initializePlugin(plugin)
			}
		}
	}
	
	return nil
}

// DisablePlugin 禁用插件
func (r *PluginRegistry) DisablePlugin(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	state, exists := r.pluginStates[name]
	if !exists {
		return fmt.Errorf("插件 %s 不存在", name)
	}
	
	state.Status = PluginStatusDisabled
	r.pluginStates[name] = state
	r.updateStats()
	
	log.Info().Str("plugin", name).Msg("插件已禁用")
	return nil
}

// UnregisterPlugin 注销插件
func (r *PluginRegistry) UnregisterPlugin(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	plugin, exists := r.plugins[name]
	if !exists {
		return fmt.Errorf("插件 %s 不存在", name)
	}
	
	// 清理资源
	if cleaner, ok := plugin.(interface{ Cleanup() error }); ok {
		if err := cleaner.Cleanup(); err != nil {
			log.Warn().
				Err(err).
				Str("plugin", name).
				Msg("插件清理失败")
		}
	}
	
	// 从各种索引中移除
	delete(r.plugins, name)
	delete(r.pluginStates, name)
	delete(r.priorities, name)
	
	// 从列表中移除
	for i, p := range r.pluginList {
		if p.Info().Name == name {
			r.pluginList = append(r.pluginList[:i], r.pluginList[i+1:]...)
			break
		}
	}
	
	// 从分类索引中移除
	info := plugin.Info()
	category := info.Category
	if category == "" {
		category = "uncategorized"
	}
	
	if categoryPlugins := r.categories[category]; categoryPlugins != nil {
		for i, p := range categoryPlugins {
			if p.Info().Name == name {
				r.categories[category] = append(categoryPlugins[:i], categoryPlugins[i+1:]...)
				break
			}
		}
		
		// 如果分类为空则删除
		if len(r.categories[category]) == 0 {
			delete(r.categories, category)
		}
	}
	
	r.updateStats()
	
	log.Info().Str("plugin", name).Msg("插件已注销")
	return nil
}

// Clear 清空注册表
func (r *PluginRegistry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	oldCount := len(r.plugins)
	
	// 清理所有插件
	for name, plugin := range r.plugins {
		if cleaner, ok := plugin.(interface{ Cleanup() error }); ok {
			if err := cleaner.Cleanup(); err != nil {
				log.Warn().
					Err(err).
					Str("plugin", name).
					Msg("插件清理失败")
			}
		}
	}
	
	// 清空所有映射
	r.plugins = make(map[string]Plugin)
	r.pluginStates = make(map[string]PluginRegistryState)
	r.priorities = make(map[string]int)
	r.categories = make(map[string][]Plugin)
	r.pluginList = r.pluginList[:0]
	
	r.updateStats()
	
	log.Info().
		Int("cleared_count", oldCount).
		Msg("插件注册表已清空")
}

// Close 关闭注册表
func (r *PluginRegistry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	if r.closed {
		return nil
	}
	
	r.closed = true
	r.cancel()
	
	// 清理所有插件
	for name, plugin := range r.plugins {
		if cleaner, ok := plugin.(interface{ Cleanup() error }); ok {
			if err := cleaner.Cleanup(); err != nil {
				log.Warn().
					Err(err).
					Str("plugin", name).
					Msg("插件清理失败")
			}
		}
	}
	
	log.Info().
		Int("total_plugins", len(r.plugins)).
		Msg("插件注册表已关闭")
	
	return nil
}

// 兼容性函数 - 保持向后兼容
func RegisterPlugin(p Plugin) {
	if err := GetGlobalRegistry().RegisterPlugin(p); err != nil {
		log.Error().Err(err).Msg("插件注册失败")
	}
}

func GetPlugins() []Plugin {
	return GetGlobalRegistry().GetPlugins()
}

func GetPluginCount() int {
	return GetGlobalRegistry().GetPluginCount()
}

func GetPluginByName(name string) Plugin {
	return GetGlobalRegistry().GetPluginByName(name)
}

func ListPluginNames() []string {
	return GetGlobalRegistry().ListPluginNames()
}

func ClearPlugins() {
	GetGlobalRegistry().Clear()
}
