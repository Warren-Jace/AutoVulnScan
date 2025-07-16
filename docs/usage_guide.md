# AutoVulnScan 使用指南

本指南将引导您如何安装、配置和运行 AutoVulnScan。

## 1. 安装

### 1.1 环境要求

- Python 3.8+
- pip

### 1.2 安装步骤

1.  **克隆项目**:
    ```bash
    git clone https://github.com/your-username/AutoVulnScan.git
    cd AutoVulnScan
    ```

2.  **创建并激活虚拟环境** (推荐):
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **安装依赖**:
    ```bash
    pip install -r requirements.txt
    ```

## 2. 配置

AutoVulnScan 的所有扫描行为都通过一个 YAML 配置文件来控制。默认配置文件路径为 `config/vuln_config.yaml`。

您可以复制 `config/vuln_config.yaml` 并进行修改，或从头开始创建自己的配置文件。

详细的配置项说明，请参考[配置文件详解](config_details.md)。

## 3. 运行扫描

您可以通过命令行启动扫描。

- **使用默认配置扫描指定 URL**:
  ```bash
  python main.py --target-url https://example.com
  ```

- **使用指定配置文件**:
  ```bash
  python main.py --config-path /path/to/your/config.yaml
  ```

扫描完成后，报告将生成在配置文件中指定的 `output.path` 目录下。
