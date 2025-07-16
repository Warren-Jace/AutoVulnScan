# 常见问题解答 (FAQ)

### Q1: AutoVulnScan 支持哪些类型的漏洞？

**A:** 开箱即用的版本支持 XSS, SQLi, SSRF, XXE, 和 RCE。但您可以通过开发自己的插件来扩展其能力。

### Q2: 我如何为一个需要登录的网站配置扫描？

**A:** 您可以在 `config/vuln_config.yaml` 文件的 `target.auth` 部分配置身份认证。目前支持 Cookie 和 JWT 等方式。

### Q3: AI 模块是必须的吗？

**A:** 不是。您可以在配置文件中将 `ai_module.enable` 设置为 `false`。在这种情况下，系统将依赖于传统的、基于模式匹配的扫描逻辑。

### Q4: 扫描速度很慢，如何优化？

**A:** 您可以调整 `config/vuln_config.yaml` 中 `scanner.concurrency` 的值来增加并发请求数。但请注意，过高的并发可能会对目标服务器造成压力或导致您的 IP被封禁。
