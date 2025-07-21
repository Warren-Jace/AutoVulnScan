# AutoVulnScan 插件开发规范

## 插件目录
- 所有插件放在 internal/vulnscan/plugins/ 目录下，每个插件一个文件。

## 插件接口
- 必须实现 VulnPlugin 接口：
    - Name() string
    - Detect(ctx context.Context, req *ScanRequest) ([]*VulnResult, error)

## 注册机制
- 在插件文件的 init() 函数中调用 RegisterPlugin 注册自身。

## 返回结果
- 检测到的漏洞需严格按照 VulnResult 结构体返回，方便统一输出和报告。

## 测试与CI
- 每个插件应有对应的单元测试文件。
- 提交前请确保通过 go fmt、goimports、golangci-lint 校验。

## 代码注释
- 所有导出类型和函数必须有 GoDoc 注释。
- 复杂逻辑需有详细注释说明。

## 贡献流程
- 请先阅读 CONTRIBUTING.md，遵循团队协作流程。 