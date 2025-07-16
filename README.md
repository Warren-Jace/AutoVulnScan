# AutoVulnScan

## 简介

AutoVulnScan 是一款功能强大的自动化漏洞扫描工具，旨在帮助开发人员和安全专业人员识别和解决 Web 应用程序中的安全漏洞。它采用模块化设计，易于扩展，并集成了 AI 技术以提高扫描的准确性和效率。

## 主要功能

- **全面的漏洞检测**: 支持多种常见的 Web 漏洞，如 SQL 注入、XSS、SSRF、RCE 和 XXE。
- **自动化与智能化**: 利用 AI 模型分析扫描结果，智能识别潜在漏洞，减少误报。
- **高度可扩展**: 基于插件的架构，允许轻松添加新的漏洞检测模块。
- **灵活的配置**: 支持通过 YAML 文件进行详细配置，满足不同扫描场景的需求。
- **异步扫描引擎**: 基于 `asyncio` 和 `httpx` 构建，实现高性能的并发扫描。
- **多格式报告**: 支持生成 HTML、JSON 和 Markdown 格式的详细扫描报告。

## 安装指南

1.  **克隆项目**:
    ```bash
    git clone https://github.com/your-username/AutoVulnScan.git
    cd AutoVulnScan
    ```

2.  **创建并激活虚拟环境**:
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **安装依赖**:
    ```bash
    pip install -r requirements.txt
    ```

## 使用方法

1.  **配置扫描**:
    - 复制 `config/vuln_config.yaml.example` 并重命名为 `config/vuln_config.yaml`。
    - 编辑 `config/vuln_config.yaml` 文件，设置目标 URL 和其他扫描参数。

2.  **运行扫描**:
    ```bash
    python main.py --target-url https://example.com
    ```

    或者，使用配置文件中的 URL：
    ```bash
    python main.py -c config/vuln_config.yaml
    ```

## 贡献

我们欢迎任何形式的贡献！无论是提交 issue、修复 bug 还是开发新功能，请随时创建 Pull Request。

## 许可证

本项目基于 MIT 许可证开源。
