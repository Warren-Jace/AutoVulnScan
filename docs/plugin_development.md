# AutoVulnScan 插件开发指南

AutoVulnScan 采用插件化架构，您可以轻松地开发自己的漏洞扫描插件。

## 1. 插件基础

所有插件都必须继承自 `plugins.base_plugin.BasePlugin` 抽象基类，并实现其定义的接口。

```python
from plugins.base_plugin import BasePlugin, Vulnerability
from typing import Optional, Any

class MyCustomPlugin(BasePlugin):

    @property
    def name(self) -> str:
        return "my-custom-vuln"

    async def analyze(self, response: Any, payload: str) -> Optional[Vulnerability]:
        # 在这里实现您的漏洞分析逻辑
        if "vulnerable pattern" in response.text:
            return Vulnerability(
                url=response.url,
                plugin_name=self.name,
                description="A custom vulnerability was found.",
                confidence="High",
                severity="Medium",
                payload=payload,
                param={} # 填充参数信息
            )
        return None
```

## 2. 关键方法

### `name` (属性)

返回插件的唯一名称。这个名称将用于在配置文件中启用或禁用该插件。

### `analyze` (异步方法)

这是插件的核心逻辑。它接收一个 `httpx.Response` 对象和一个 `payload` 字符串作为输入。您需要在此方法中分析响应，以确定是否存在漏洞。

如果发现漏洞，应返回一个 `Vulnerability` 对象；否则，返回 `None`。

## 3. 插件加载

只需将您的插件文件（例如 `my_custom_plugin.py`）放入 `plugins/` 目录下，Orchestrator 将在启动时自动发现并加载它。

确保您的插件已在 `config/vuln_config.yaml` 文件的 `vulns` 列表中被启用。



