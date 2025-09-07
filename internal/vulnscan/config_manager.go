// Package vulnscan 提供了核心的漏洞扫描引擎和插件管理机制。
package vulnscan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/rs/zerolog/log"
)

// ConfigManager 配置管理器接口
type ConfigManager interface {
	// LoadConfig 加载配置
	LoadConfig(configPath string) error
	// SaveConfig 保存配置
	SaveConfig(configPath string) error
	// GetPluginConfig 获取插件配置
	GetPluginConfig(pluginName string) (PluginConfig, error)
	// SetPluginConfig 设置插件配置
	SetPluginConfig(pluginName string, config PluginConfig) error
	// GetGlobalConfig 获取全局配置
	GetGlobalConfig() (GlobalConfig, error)
	// SetGlobalConfig 设置全局配置
	SetGlobalConfig(config GlobalConfig) error
	// ValidateConfig 验证配置
	ValidateConfig(config interface{}) error
	// ResetToDefault 重置为默认配置
	ResetToDefault(pluginName string) error
}

// GlobalConfig 全局配置
type GlobalConfig struct {
	Version         string            `json:"version"`
	LastUpdated     time.Time         `json:"last_updated"`
	DefaultTimeout  time.Duration     `json:"default_timeout"`
	MaxRetries      int               `json:"max_retries"`
	RateLimitRPS    int               `json:"rate_limit_rps"`
	FollowRedirects bool              `json:"follow_redirects"`
	VerifySSL       bool              `json:"verify_ssl"`
	UserAgent       string            `json:"user_agent"`
	CustomHeaders   map[string]string `json:"custom_headers"`
	PluginConfigs   map[string]PluginConfig `json:"plugin_configs"`
}

// DefaultGlobalConfig 默认全局配置
func DefaultGlobalConfig() GlobalConfig {
	return GlobalConfig{
		Version:         "1.0.0",
		LastUpdated:     time.Now(),
		DefaultTimeout:  30 * time.Second,
		MaxRetries:      3,
		RateLimitRPS:    10,
		FollowRedirects: true,
		VerifySSL:       false,
		UserAgent:       "AutoVulnScan/1.0",
		CustomHeaders:   make(map[string]string),
		PluginConfigs:   make(map[string]PluginConfig),
	}
}

// DefaultConfigManager 默认配置管理器
type DefaultConfigManager struct {
	globalConfig    GlobalConfig
	defaultConfigs  map[string]PluginConfig
	configFilePath  string
}

// NewDefaultConfigManager 创建默认配置管理器
func NewDefaultConfigManager() *DefaultConfigManager {
	manager := &DefaultConfigManager{
		globalConfig:   DefaultGlobalConfig(),
		defaultConfigs: make(map[string]PluginConfig),
	}
	manager.initializeDefaultConfigs()
	return manager
}

// initializeDefaultConfigs 初始化默认插件配置
func (cm *DefaultConfigManager) initializeDefaultConfigs() {
	// XSS插件默认配置
	cm.defaultConfigs["xss"] = PluginConfig{
		Enabled:    true,
		Priority:   1,
		ScanOptions: ScanOptions{
			Timeout:         30 * time.Second,
			MaxRetries:      3,
			RateLimitRPS:    10,
			FollowRedirects: true,
			VerifySSL:       false,
			UserAgent:       "AutoVulnScan/1.0",
			MaxPayloads:     50,
			SkipDuplicates:  true,
			EnableDeepScan:  false,
			CustomHeaders:   make(map[string]string),
		},
		CustomConfig: map[string]interface{}{
			"enable_reflection_check":    true,
			"enable_dom_based_check":     true,
			"enable_context_analysis":    true,
			"confidence_threshold":       0.7,
			"max_response_diff":          100,
			"max_response_diff_ratio":    0.1,
			"enable_waf_detection":       true,
			"waf_threshold":             5,
			"enable_cache":              true,
			"cache_size":                1000,
			"cache_ttl":                 300,
		},
		PayloadConfig: PayloadConfig{
			UseBuiltIn:    true,
			UseCustom:     false,
			CustomPayloads: []string{},
			MaxLength:     1000,
			Encoding:      "none",
		},
	}

	// SQL注入插件默认配置
	cm.defaultConfigs["sqli"] = PluginConfig{
		Enabled:    true,
		Priority:   2,
		ScanOptions: ScanOptions{
			Timeout:         30 * time.Second,
			MaxRetries:      3,
			RateLimitRPS:    5,  // SQL注入检测较慢，降低并发
			FollowRedirects: true,
			VerifySSL:       false,
			UserAgent:       "AutoVulnScan/1.0",
			MaxPayloads:     100,
			SkipDuplicates:  true,
			EnableDeepScan:  false,
			CustomHeaders:   make(map[string]string),
		},
		CustomConfig: map[string]interface{}{
			"enable_error_based":        true,
			"enable_boolean_based":       true,
			"enable_time_based":         true,
			"enable_union_based":        true,
			"confidence_threshold":       0.7,
			"time_threshold":            5 * time.Second,
			"max_response_diff":         100,
			"max_response_diff_ratio":   0.1,
			"enable_waf_detection":      true,
			"waf_threshold":            5,
			"enable_cache":              true,
			"cache_size":                1000,
			"cache_ttl":                 300,
			"max_workers":               3,
		},
		PayloadConfig: PayloadConfig{
			UseBuiltIn:    true,
			UseCustom:     false,
			CustomPayloads: []string{},
			MaxLength:     1000,
			Encoding:      "none",
		},
	}
}

// LoadConfig 加载配置
func (cm *DefaultConfigManager) LoadConfig(configPath string) error {
	cm.configFilePath = configPath

	// 检查配置文件是否存在
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Info().Str("path", configPath).Msg("配置文件不存在，将使用默认配置")
		return nil
	}

	// 读取配置文件
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %w", err)
	}

	// 解析配置
	var config GlobalConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("解析配置文件失败: %w", err)
	}

	cm.globalConfig = config
	log.Info().Str("path", configPath).Msg("配置加载成功")
	return nil
}

// SaveConfig 保存配置
func (cm *DefaultConfigManager) SaveConfig(configPath string) error {
	// 确保目录存在
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建配置目录失败: %w", err)
	}

	// 更新时间戳
	cm.globalConfig.LastUpdated = time.Now()

	// 序列化配置
	data, err := json.MarshalIndent(cm.globalConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}

	// 写入配置文件
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("写入配置文件失败: %w", err)
	}

	log.Info().Str("path", configPath).Msg("配置保存成功")
	return nil
}

// GetPluginConfig 获取插件配置
func (cm *DefaultConfigManager) GetPluginConfig(pluginName string) (PluginConfig, error) {
	// 首先检查全局配置中是否有插件配置
	if config, exists := cm.globalConfig.PluginConfigs[pluginName]; exists {
		return config, nil
	}

	// 如果全局配置中没有，则返回默认配置
	if defaultConfig, exists := cm.defaultConfigs[pluginName]; exists {
		return defaultConfig, nil
	}

	return PluginConfig{}, fmt.Errorf("未找到插件 %s 的配置", pluginName)
}

// SetPluginConfig 设置插件配置
func (cm *DefaultConfigManager) SetPluginConfig(pluginName string, config PluginConfig) error {
	// 验证配置
	if err := cm.ValidateConfig(config); err != nil {
		return fmt.Errorf("插件配置验证失败: %w", err)
	}

	// 更新全局配置
	if cm.globalConfig.PluginConfigs == nil {
		cm.globalConfig.PluginConfigs = make(map[string]PluginConfig)
	}
	cm.globalConfig.PluginConfigs[pluginName] = config
	return nil
}

// GetGlobalConfig 获取全局配置
func (cm *DefaultConfigManager) GetGlobalConfig() (GlobalConfig, error) {
	return cm.globalConfig, nil
}

// SetGlobalConfig 设置全局配置
func (cm *DefaultConfigManager) SetGlobalConfig(config GlobalConfig) error {
	// 验证配置
	if err := cm.ValidateConfig(config); err != nil {
		return fmt.Errorf("全局配置验证失败: %w", err)
	}

	cm.globalConfig = config
	return nil
}

// ValidateConfig 验证配置
func (cm *DefaultConfigManager) ValidateConfig(config interface{}) error {
	v := reflect.ValueOf(config)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		return fmt.Errorf("配置必须是结构体或结构体指针")
	}

	// 检查ScanOptions中的超时设置
	if pluginConfig, ok := config.(PluginConfig); ok {
		if pluginConfig.ScanOptions.Timeout <= 0 {
			return fmt.Errorf("超时时间必须大于0")
		}
		if pluginConfig.ScanOptions.MaxRetries < 0 {
			return fmt.Errorf("最大重试次数不能小于0")
		}
		if pluginConfig.ScanOptions.RateLimitRPS <= 0 {
			return fmt.Errorf("每秒请求数限制必须大于0")
		}
		if pluginConfig.ScanOptions.MaxPayloads <= 0 {
			return fmt.Errorf("最大payload数量必须大于0")
		}
	}

	// 检查GlobalConfig中的设置
	if globalConfig, ok := config.(GlobalConfig); ok {
		if globalConfig.DefaultTimeout <= 0 {
			return fmt.Errorf("默认超时时间必须大于0")
		}
		if globalConfig.MaxRetries < 0 {
			return fmt.Errorf("最大重试次数不能小于0")
		}
		if globalConfig.RateLimitRPS <= 0 {
			return fmt.Errorf("每秒请求数限制必须大于0")
		}
	}

	return nil
}

// ResetToDefault 重置为默认配置
func (cm *DefaultConfigManager) ResetToDefault(pluginName string) error {
	if defaultConfig, exists := cm.defaultConfigs[pluginName]; exists {
		return cm.SetPluginConfig(pluginName, defaultConfig)
	}
	return fmt.Errorf("未找到插件 %s 的默认配置", pluginName)
}

// GetConfigPath 获取配置文件路径
func (cm *DefaultConfigManager) GetConfigPath() string {
	return cm.configFilePath
}

// SetConfigPath 设置配置文件路径
func (cm *DefaultConfigManager) SetConfigPath(path string) {
	cm.configFilePath = path
}

// GetConfigManager 获取配置管理器
func GetConfigManager() ConfigManager {
	return NewDefaultConfigManager()
}