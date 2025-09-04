// Package plugin 提供了插件管理功能
package plugin

import (
	"fmt"
	"plugin"
	"reflect"
	"sync"

	"github.com/rs/zerolog/log"

	"autovulnscan/internal/models"
)

// PluginType 插件类型
type PluginType string

const (
	// ScannerPluginType 扫描器插件类型
	ScannerPluginType PluginType = "scanner"
	// CrawlerPluginType 爬虫插件类型
	CrawlerPluginType PluginType = "crawler"
	// ReporterPluginType 报告插件类型
	ReporterPluginType PluginType = "reporter"
	// ProcessorPluginType 处理器插件类型
	ProcessorPluginType PluginType = "processor"
)

// PluginInfo 插件信息
type PluginInfo struct {
	Name        string     `json:"name" yaml:"name"`
	Version     string     `json:"version" yaml:"version"`
	Description string     `json:"description" yaml:"description"`
	Author      string     `json:"author" yaml:"author"`
	Type        PluginType `json:"type" yaml:"type"`
	Enabled     bool       `json:"enabled" yaml:"enabled"`
	Path        string     `json:"path" yaml:"path"`
}

// Plugin 插件接口
type Plugin interface {
	// GetInfo 获取插件信息
	GetInfo() *PluginInfo
	// Init 初始化插件
	Init(config interface{}) error
	// Execute 执行插件
	Execute(ctx interface{}) (interface{}, error)
	// Cleanup 清理插件资源
	Cleanup() error
}

// ScannerPlugin 扫描器插件接口
type ScannerPlugin interface {
	Plugin
	// Scan 扫描目标
	Scan(target string, options map[string]interface{}) ([]*models.Vulnerability, error)
	// GetSupportedTypes 获取支持的漏洞类型
	GetSupportedTypes() []string
	// GetSupportedSeverities 获取支持的严重性级别
	GetSupportedSeverities() []string
}

// CrawlerPlugin 爬虫插件接口
type CrawlerPlugin interface {
	Plugin
	// Crawl 爬取目标
	Crawl(target string, options map[string]interface{}) ([]*models.CrawlResult, error)
	// GetSupportedSchemes 获取支持的URL协议
	GetSupportedSchemes() []string
}

// ReporterPlugin 报告插件接口
type ReporterPlugin interface {
	Plugin
	// Generate 生成报告
	Generate(data interface{}, options map[string]interface{}) ([]byte, error)
	// GetSupportedFormats 获取支持的报告格式
	GetSupportedFormats() []string
}

// ProcessorPlugin 处理器插件接口
type ProcessorPlugin interface {
	Plugin
	// Process 处理数据
	Process(data interface{}, options map[string]interface{}) (interface{}, error)
	// GetInputType 获取输入数据类型
	GetInputType() reflect.Type
	// GetOutputType 获取输出数据类型
	GetOutputType() reflect.Type
}

// PluginManager 插件管理器
type PluginManager struct {
	plugins map[string]Plugin
	mutex   sync.RWMutex
}

// NewPluginManager 创建新的插件管理器
func NewPluginManager() *PluginManager {
	return &PluginManager{
		plugins: make(map[string]Plugin),
	}
}

// LoadPlugin 加载插件
func (pm *PluginManager) LoadPlugin(path string) (Plugin, error) {
	// 加载插件
	p, err := plugin.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open plugin: %w", err)
	}

	// 获取插件符号
	symPlugin, err := p.Lookup("Plugin")
	if err != nil {
		return nil, fmt.Errorf("failed to lookup Plugin symbol: %w", err)
	}

	// 类型断言
	pluginInstance, ok := symPlugin.(Plugin)
	if !ok {
		return nil, fmt.Errorf("unexpected type from module symbol")
	}

	// 获取插件信息
	info := pluginInstance.GetInfo()
	info.Path = path

	// 初始化插件
	if err := pluginInstance.Init(nil); err != nil {
		return nil, fmt.Errorf("failed to initialize plugin: %w", err)
	}

	// 添加到管理器
	pm.mutex.Lock()
	pm.plugins[info.Name] = pluginInstance
	pm.mutex.Unlock()

	log.Info().Str("name", info.Name).Str("version", info.Version).Str("type", string(info.Type)).Msg("Plugin loaded successfully")

	return pluginInstance, nil
}

// UnloadPlugin 卸载插件
func (pm *PluginManager) UnloadPlugin(name string) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pluginInstance, exists := pm.plugins[name]
	if !exists {
		return fmt.Errorf("plugin not found: %s", name)
	}

	// 清理插件资源
	if err := pluginInstance.Cleanup(); err != nil {
		log.Error().Err(err).Str("name", name).Msg("Failed to cleanup plugin")
	}

	// 从管理器中移除
	delete(pm.plugins, name)

	log.Info().Str("name", name).Msg("Plugin unloaded successfully")

	return nil
}

// GetPlugin 获取插件
func (pm *PluginManager) GetPlugin(name string) (Plugin, error) {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	pluginInstance, exists := pm.plugins[name]
	if !exists {
		return nil, fmt.Errorf("plugin not found: %s", name)
	}

	return pluginInstance, nil
}

// ListPlugins 列出所有插件
func (pm *PluginManager) ListPlugins() []*PluginInfo {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	var infos []*PluginInfo
	for _, pluginInstance := range pm.plugins {
		infos = append(infos, pluginInstance.GetInfo())
	}

	return infos
}

// ListPluginsByType 根据类型列出插件
func (pm *PluginManager) ListPluginsByType(pluginType PluginType) []*PluginInfo {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	var infos []*PluginInfo
	for _, pluginInstance := range pm.plugins {
		info := pluginInstance.GetInfo()
		if info.Type == pluginType {
			infos = append(infos, info)
		}
	}

	return infos
}

// EnablePlugin 启用插件
func (pm *PluginManager) EnablePlugin(name string) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pluginInstance, exists := pm.plugins[name]
	if !exists {
		return fmt.Errorf("plugin not found: %s", name)
	}

	info := pluginInstance.GetInfo()
	info.Enabled = true

	log.Info().Str("name", name).Msg("Plugin enabled")

	return nil
}

// DisablePlugin 禁用插件
func (pm *PluginManager) DisablePlugin(name string) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pluginInstance, exists := pm.plugins[name]
	if !exists {
		return fmt.Errorf("plugin not found: %s", name)
	}

	info := pluginInstance.GetInfo()
	info.Enabled = false

	log.Info().Str("name", name).Msg("Plugin disabled")

	return nil
}

// IsPluginEnabled 检查插件是否启用
func (pm *PluginManager) IsPluginEnabled(name string) bool {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	pluginInstance, exists := pm.plugins[name]
	if !exists {
		return false
	}

	return pluginInstance.GetInfo().Enabled
}

// ExecutePlugin 执行插件
func (pm *PluginManager) ExecutePlugin(name string, ctx interface{}) (interface{}, error) {
	pluginInstance, err := pm.GetPlugin(name)
	if err != nil {
		return nil, err
	}

	info := pluginInstance.GetInfo()
	if !info.Enabled {
		return nil, fmt.Errorf("plugin is disabled: %s", name)
	}

	return pluginInstance.Execute(ctx)
}

// ExecuteScannerPlugin 执行扫描器插件
func (pm *PluginManager) ExecuteScannerPlugin(name string, target string, options map[string]interface{}) ([]*models.Vulnerability, error) {
	pluginInstance, err := pm.GetPlugin(name)
	if err != nil {
		return nil, err
	}

	info := pluginInstance.GetInfo()
	if !info.Enabled {
		return nil, fmt.Errorf("plugin is disabled: %s", name)
	}

	if info.Type != ScannerPluginType {
		return nil, fmt.Errorf("plugin is not a scanner plugin: %s", name)
	}

	scannerPlugin, ok := pluginInstance.(ScannerPlugin)
	if !ok {
		return nil, fmt.Errorf("plugin does not implement ScannerPlugin interface: %s", name)
	}

	return scannerPlugin.Scan(target, options)
}

// ExecuteCrawlerPlugin 执行爬虫插件
func (pm *PluginManager) ExecuteCrawlerPlugin(name string, target string, options map[string]interface{}) ([]*models.CrawlResult, error) {
	pluginInstance, err := pm.GetPlugin(name)
	if err != nil {
		return nil, err
	}

	info := pluginInstance.GetInfo()
	if !info.Enabled {
		return nil, fmt.Errorf("plugin is disabled: %s", name)
	}

	if info.Type != CrawlerPluginType {
		return nil, fmt.Errorf("plugin is not a crawler plugin: %s", name)
	}

	crawlerPlugin, ok := pluginInstance.(CrawlerPlugin)
	if !ok {
		return nil, fmt.Errorf("plugin does not implement CrawlerPlugin interface: %s", name)
	}

	return crawlerPlugin.Crawl(target, options)
}

// ExecuteReporterPlugin 执行报告插件
func (pm *PluginManager) ExecuteReporterPlugin(name string, data interface{}, options map[string]interface{}) ([]byte, error) {
	pluginInstance, err := pm.GetPlugin(name)
	if err != nil {
		return nil, err
	}

	info := pluginInstance.GetInfo()
	if !info.Enabled {
		return nil, fmt.Errorf("plugin is disabled: %s", name)
	}

	if info.Type != ReporterPluginType {
		return nil, fmt.Errorf("plugin is not a reporter plugin: %s", name)
	}

	reporterPlugin, ok := pluginInstance.(ReporterPlugin)
	if !ok {
		return nil, fmt.Errorf("plugin does not implement ReporterPlugin interface: %s", name)
	}

	return reporterPlugin.Generate(data, options)
}

// ExecuteProcessorPlugin 执行处理器插件
func (pm *PluginManager) ExecuteProcessorPlugin(name string, data interface{}, options map[string]interface{}) (interface{}, error) {
	pluginInstance, err := pm.GetPlugin(name)
	if err != nil {
		return nil, err
	}

	info := pluginInstance.GetInfo()
	if !info.Enabled {
		return nil, fmt.Errorf("plugin is disabled: %s", name)
	}

	if info.Type != ProcessorPluginType {
		return nil, fmt.Errorf("plugin is not a processor plugin: %s", name)
	}

	processorPlugin, ok := pluginInstance.(ProcessorPlugin)
	if !ok {
		return nil, fmt.Errorf("plugin does not implement ProcessorPlugin interface: %s", name)
	}

	return processorPlugin.Process(data, options)
}

// ReloadPlugin 重新加载插件
func (pm *PluginManager) ReloadPlugin(name string) (Plugin, error) {
	// 获取现有插件
	pluginInstance, err := pm.GetPlugin(name)
	if err != nil {
		return nil, err
	}

	// 获取插件路径
	info := pluginInstance.GetInfo()
	path := info.Path

	// 卸载插件
	if err := pm.UnloadPlugin(name); err != nil {
		return nil, fmt.Errorf("failed to unload plugin: %w", err)
	}

	// 重新加载插件
	newPluginInstance, err := pm.LoadPlugin(path)
	if err != nil {
		return nil, fmt.Errorf("failed to reload plugin: %w", err)
	}

	return newPluginInstance, nil
}

// GetScannerPlugins 获取所有扫描器插件
func (pm *PluginManager) GetScannerPlugins() []ScannerPlugin {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	var plugins []ScannerPlugin
	for _, pluginInstance := range pm.plugins {
		info := pluginInstance.GetInfo()
		if info.Type == ScannerPluginType && info.Enabled {
			if scannerPlugin, ok := pluginInstance.(ScannerPlugin); ok {
				plugins = append(plugins, scannerPlugin)
			}
		}
	}

	return plugins
}

// GetCrawlerPlugins 获取所有爬虫插件
func (pm *PluginManager) GetCrawlerPlugins() []CrawlerPlugin {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	var plugins []CrawlerPlugin
	for _, pluginInstance := range pm.plugins {
		info := pluginInstance.GetInfo()
		if info.Type == CrawlerPluginType && info.Enabled {
			if crawlerPlugin, ok := pluginInstance.(CrawlerPlugin); ok {
				plugins = append(plugins, crawlerPlugin)
			}
		}
	}

	return plugins
}

// GetReporterPlugins 获取所有报告插件
func (pm *PluginManager) GetReporterPlugins() []ReporterPlugin {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	var plugins []ReporterPlugin
	for _, pluginInstance := range pm.plugins {
		info := pluginInstance.GetInfo()
		if info.Type == ReporterPluginType && info.Enabled {
			if reporterPlugin, ok := pluginInstance.(ReporterPlugin); ok {
				plugins = append(plugins, reporterPlugin)
			}
		}
	}

	return plugins
}

// GetProcessorPlugins 获取所有处理器插件
func (pm *PluginManager) GetProcessorPlugins() []ProcessorPlugin {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	var plugins []ProcessorPlugin
	for _, pluginInstance := range pm.plugins {
		info := pluginInstance.GetInfo()
		if info.Type == ProcessorPluginType && info.Enabled {
			if processorPlugin, ok := pluginInstance.(ProcessorPlugin); ok {
				plugins = append(plugins, processorPlugin)
			}
		}
	}

	return plugins
}

// GetSupportedVulnTypes 获取所有支持的漏洞类型
func (pm *PluginManager) GetSupportedVulnTypes() []string {
	typeSet := make(map[string]bool)

	for _, scannerPlugin := range pm.GetScannerPlugins() {
		for _, vulnType := range scannerPlugin.GetSupportedTypes() {
			typeSet[vulnType] = true
		}
	}

	var types []string
	for vulnType := range typeSet {
		types = append(types, vulnType)
	}

	return types
}

// GetSupportedVulnSeverities 获取所有支持的漏洞严重性级别
func (pm *PluginManager) GetSupportedVulnSeverities() []string {
	severitySet := make(map[string]bool)

	for _, scannerPlugin := range pm.GetScannerPlugins() {
		for _, severity := range scannerPlugin.GetSupportedSeverities() {
			severitySet[severity] = true
		}
	}

	var severities []string
	for severity := range severitySet {
		severities = append(severities, severity)
	}

	return severities
}

// GetSupportedReportFormats 获取所有支持的报告格式
func (pm *PluginManager) GetSupportedReportFormats() []string {
	formatSet := make(map[string]bool)

	for _, reporterPlugin := range pm.GetReporterPlugins() {
		for _, format := range reporterPlugin.GetSupportedFormats() {
			formatSet[format] = true
		}
	}

	var formats []string
	for format := range formatSet {
		formats = append(formats, format)
	}

	return formats
}

// GetSupportedCrawlSchemes 获取所有支持的爬取协议
func (pm *PluginManager) GetSupportedCrawlSchemes() []string {
	schemeSet := make(map[string]bool)

	for _, crawlerPlugin := range pm.GetCrawlerPlugins() {
		for _, scheme := range crawlerPlugin.GetSupportedSchemes() {
			schemeSet[scheme] = true
		}
	}

	var schemes []string
	for scheme := range schemeSet {
		schemes = append(schemes, scheme)
	}

	return schemes
}

// Close 关闭插件管理器
func (pm *PluginManager) Close() error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// 清理所有插件
	for name, pluginInstance := range pm.plugins {
		if err := pluginInstance.Cleanup(); err != nil {
			log.Error().Err(err).Str("name", name).Msg("Failed to cleanup plugin")
		}
	}

	// 清空插件列表
	pm.plugins = make(map[string]Plugin)

	log.Info().Msg("Plugin manager closed")

	return nil
}

// PluginContext 插件上下文
type PluginContext struct {
	// 插件管理器
	Manager *PluginManager
	// 插件配置
	Config map[string]interface{}
	// 插件数据
	Data map[string]interface{}
}

// NewPluginContext 创建新的插件上下文
func NewPluginContext(manager *PluginManager) *PluginContext {
	return &PluginContext{
		Manager: manager,
		Config:  make(map[string]interface{}),
		Data:    make(map[string]interface{}),
	}
}

// GetConfig 获取配置
func (ctx *PluginContext) GetConfig(key string) (interface{}, bool) {
	value, exists := ctx.Config[key]
	return value, exists
}

// SetConfig 设置配置
func (ctx *PluginContext) SetConfig(key string, value interface{}) {
	ctx.Config[key] = value
}

// GetData 获取数据
func (ctx *PluginContext) GetData(key string) (interface{}, bool) {
	value, exists := ctx.Data[key]
	return value, exists
}

// SetData 设置数据
func (ctx *PluginContext) SetData(key string, value interface{}) {
	ctx.Data[key] = value
}

// GetPlugin 获取插件
func (ctx *PluginContext) GetPlugin(name string) (Plugin, error) {
	return ctx.Manager.GetPlugin(name)
}

// ExecutePlugin 执行插件
func (ctx *PluginContext) ExecutePlugin(name string, pluginCtx interface{}) (interface{}, error) {
	return ctx.Manager.ExecutePlugin(name, pluginCtx)
}

// BasePlugin 基础插件实现
type BasePlugin struct {
	info *PluginInfo
}

// NewBasePlugin 创建新的基础插件
func NewBasePlugin(name, version, description, author string, pluginType PluginType) *BasePlugin {
	return &BasePlugin{
		info: &PluginInfo{
			Name:        name,
			Version:     version,
			Description: description,
			Author:      author,
			Type:        pluginType,
			Enabled:     true,
		},
	}
}

// GetInfo 获取插件信息
func (p *BasePlugin) GetInfo() *PluginInfo {
	return p.info
}

// Init 初始化插件
func (p *BasePlugin) Init(config interface{}) error {
	// 默认实现，子类可以覆盖
	return nil
}

// Execute 执行插件
func (p *BasePlugin) Execute(ctx interface{}) (interface{}, error) {
	// 默认实现，子类必须覆盖
	return nil, fmt.Errorf("not implemented")
}

// Cleanup 清理插件资源
func (p *BasePlugin) Cleanup() error {
	// 默认实现，子类可以覆盖
	return nil
}

// BaseScannerPlugin 基础扫描器插件实现
type BaseScannerPlugin struct {
	*BasePlugin
}

// NewBaseScannerPlugin 创建新的基础扫描器插件
func NewBaseScannerPlugin(name, version, description, author string) *BaseScannerPlugin {
	return &BaseScannerPlugin{
		BasePlugin: NewBasePlugin(name, version, description, author, ScannerPluginType),
	}
}

// GetSupportedTypes 获取支持的漏洞类型
func (p *BaseScannerPlugin) GetSupportedTypes() []string {
	// 默认实现，子类可以覆盖
	return []string{}
}

// GetSupportedSeverities 获取支持的严重性级别
func (p *BaseScannerPlugin) GetSupportedSeverities() []string {
	// 默认实现，子类可以覆盖
	return []string{"Critical", "High", "Medium", "Low", "Info"}
}

// Scan 扫描目标
func (p *BaseScannerPlugin) Scan(target string, options map[string]interface{}) ([]*models.Vulnerability, error) {
	// 默认实现，子类必须覆盖
	return nil, fmt.Errorf("not implemented")
}

// BaseCrawlerPlugin 基础爬虫插件实现
type BaseCrawlerPlugin struct {
	*BasePlugin
}

// NewBaseCrawlerPlugin 创建新的基础爬虫插件
func NewBaseCrawlerPlugin(name, version, description, author string) *BaseCrawlerPlugin {
	return &BaseCrawlerPlugin{
		BasePlugin: NewBasePlugin(name, version, description, author, CrawlerPluginType),
	}
}

// GetSupportedSchemes 获取支持的URL协议
func (p *BaseCrawlerPlugin) GetSupportedSchemes() []string {
	// 默认实现，子类可以覆盖
	return []string{"http", "https"}
}

// Crawl 爬取目标
func (p *BaseCrawlerPlugin) Crawl(target string, options map[string]interface{}) ([]*models.CrawlResult, error) {
	// 默认实现，子类必须覆盖
	return nil, fmt.Errorf("not implemented")
}

// BaseReporterPlugin 基础报告插件实现
type BaseReporterPlugin struct {
	*BasePlugin
}

// NewBaseReporterPlugin 创建新的基础报告插件
func NewBaseReporterPlugin(name, version, description, author string) *BaseReporterPlugin {
	return &BaseReporterPlugin{
		BasePlugin: NewBasePlugin(name, version, description, author, ReporterPluginType),
	}
}

// GetSupportedFormats 获取支持的报告格式
func (p *BaseReporterPlugin) GetSupportedFormats() []string {
	// 默认实现，子类可以覆盖
	return []string{"html", "json", "csv", "pdf"}
}

// Generate 生成报告
func (p *BaseReporterPlugin) Generate(data interface{}, options map[string]interface{}) ([]byte, error) {
	// 默认实现，子类必须覆盖
	return nil, fmt.Errorf("not implemented")
}

// BaseProcessorPlugin 基础处理器插件实现
type BaseProcessorPlugin struct {
	*BasePlugin
}

// NewBaseProcessorPlugin 创建新的基础处理器插件
func NewBaseProcessorPlugin(name, version, description, author string) *BaseProcessorPlugin {
	return &BaseProcessorPlugin{
		BasePlugin: NewBasePlugin(name, version, description, author, ProcessorPluginType),
	}
}

// GetInputType 获取输入数据类型
func (p *BaseProcessorPlugin) GetInputType() reflect.Type {
	// 默认实现，子类可以覆盖
	return reflect.TypeOf(&struct{}{})
}

// GetOutputType 获取输出数据类型
func (p *BaseProcessorPlugin) GetOutputType() reflect.Type {
	// 默认实现，子类可以覆盖
	return reflect.TypeOf(&struct{}{})
}

// Process 处理数据
func (p *BaseProcessorPlugin) Process(data interface{}, options map[string]interface{}) (interface{}, error) {
	// 默认实现，子类必须覆盖
	return nil, fmt.Errorf("not implemented")
}