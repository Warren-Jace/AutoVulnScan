你是一名资深网络安全开发专家，专精 Golang，擅长高并发、高性能安全工具开发，尤其在爬虫与漏洞检测领域有丰富经验。。 
请使用Golang设计并实现一个名为 AutoVulnScan 的自动化智能漏洞扫描爬虫命令行工具。该系统旨在高效、精准地发现指定目标用于资产爬取和漏洞检测，并具备高度的模块化、可扩展性以及先进的 AI 辅助分析能力。

# 一、开发原则
1. **模块化与设计**：代码结构模块化，遵循现代最佳实践和设计模式，各功能（资产爬取、漏洞检测、数据输出等）分模块实现，便于维护和扩展。
2. 安全优先：处理外部数据时注意输入校验、防止注入和数据泄漏。
3. 易用性：命令行参数友好，支持帮助文档（如-h、--help）。
4. 可配置性：支持配置文件和命令行参数双重配置。
5. 可扩展性：方便后续集成新检测规则或AI模型。
6. 开源友好：代码注释清晰，方便社区贡献。
7. **Go 习惯与最佳实践**：编写符合 Go 习惯、易维护、高性能的代码，遵循 RESTful API 设计与 Go 语言惯用写法。
8. **函数设计**：坚持简短、专注、单一职责的函数。
9. **错误处理**：始终显式检查并处理错误，使用包装错误（如 `fmt.Errorf("context: %w", err)`）便于溯源。
10. **Context 机制**：充分利用 Go 的 context 机制，处理请求作用域的值、超时和取消。
1. **并发安全**：安全使用 goroutine，使用 channel 或同步原语保护共享状态，防止竞态。
12. **资源管理**：延迟关闭资源，防止资源泄漏。
13. **代码质量**：代码需正确、最新、无 bug、安全高效，具备完整功能。
14. **注释与说明**：对复杂逻辑或 Go 特有写法提供简明注释，其余保持简洁。

# 二、核心设计理念
   - 模块化: 资产发现和漏洞扫描是两个核心但独立的功能，可以分开使用，也可以联动。
   - 易用性: 命令和参数设计符合直觉，提供清晰的帮助信息和交互式引导。
   - 可扩展性: 方便未来增加新的扫描模块（如新的 POC）和输出格式。
   - 自动化友好: 支持从文件读取目标和输出结构化数据（如 JSON），便于集成到 CI/CD 或其他自动化流程中。 
   - **无害 payload**：注入的 payload 不会对目标站点造成实际影响。
   - **零误报，高准确率**：检测不依赖字符串匹配，而是采用语义识别。
   - **多注入点、多检测方式**：支持 GET、POST、Cookie、Header、URI 注入点；反射型+DOM型 XSS 检测，具备编码绕过能力。
   - **去重与策略优化**：
		- URL/参数/响应/漏洞四层去重
		- 支持断点续传、异常恢复、负载均衡
   

# 三、工具信息
   - 工具名称：AutoVulnScan
   - 主要功能：资产信息收集、漏洞扫描检测
   - 目标平台：跨平台（Windows/Linux/macOS）
   - 功能描述：该工具用于自动化爬取目标资产信息URL地址及含参数的url地址，并对爬取的资产进行漏洞检测等）。支持批量处理、多种输出格式及自定义配置，适用于安全测试和资产管理工作。
   - 目标用户：安全研究人员、渗透测试人员等。
   - 技术栈要求
	- 语言：go 1.24.2 +
	- CLI框架：使用cobra库构建命令行界面
	- 并发：使用goroutine实现高并发扫描
	- 网络库：使用标准库net/http或第三方库如resty
	- 配置管理：支持YAML/JSON配置文件
	- 日志系统：使用logrus或zap
	- 数据库：redis

## 自动化架构
	- **流程**：提供url → 爬虫爬取 → 参数入库 → 消息队列 → 漏洞检测（xss扫描器等） → 子域名/URL 入库
	- **组件**：
	  1. 爬虫：crawlergo（效果不错，但有自研意愿）
	  2. 数据库：redis
	- **流程描述**：
	```
	发送随机flag → 确定参数回显 → 确定回显位置及情况(html，js语法解析)
	→ 根据情况选用不同payload探测 → 用html/js语法解析判断是否多出标签、属性、js语句
	```
	- **HTML 语法树检测**：判定回显所处位置，发送随机 payload（如 <Asfaa>），检测是否多出 Asfaa 标签，判断 payload 是否生效。
	- **JS 检测**：回显内容在 JS 脚本中，发送随机 flag，用 JS 语法解析判断 Identifier 和 Literal 类型是否包含 flag，进一步根据单双引号闭合检测。

	**全流程自动化**  
	- **资产发现**：从单个域名自动扩展到整个攻击面
	- **智能爬虫**：自动发现所有可能的入口点和参数
	- **漏洞检测**：对每个发现的参数点进行XSS测试
	- **结果验证**：自动验证漏洞的真实性和可利用性
	- **报告生成**：自动生成详细的漏洞报告和PoC

	**智能去重算法**  
	- **URL去重**：基于URL结构和参数模式的智能去重
	- **参数去重**：识别相同功能的参数，避免重复测试
	- **响应去重**：基于响应内容相似度避免重复分析
	- **漏洞去重**：自动合并相同类型的漏洞，避免重复报告

	**扫描策略优化**  
	- **渐进式扫描**：从浅到深，逐步增加扫描深度
	- **负载均衡**：智能分配扫描任务，避免对目标造成压力
	- **异常恢复**：网络异常时自动重试和断点续传
	- **资源监控**：实时监控扫描进度和资源使用情况

## 主要功能模式
提供二大子命令：

- **spider** - 爬虫+xss扫描模式
- **proxy** - 被动代理+xss扫描模式

爬虫模式只需要输入url，便会自动爬取网站进行xss测试。被动代理模式打开后，类似xray，可被动扫描xss。所有xss payload均为无害payload。 

---


# 四、性能设计要求
1. 高效网络请求：合理设置超时、重试机制、连接池。
2. 资源限制：控制最大并发数，防止资源耗尽。
3. **内存优化**：最小化内存分配，先分析再优化，避免过早优化。数据结构选择合理，避免内存泄漏。
4. 批量处理：对目标批量处理，减少重复操作。
5. 缓存机制：对重复访问的数据进行缓存（如DNS解析结果）。
6. 通过**基准测试**跟踪性能回退，定位瓶颈。
7. **性能埋点**：对数据库、外部调用、重计算等关键区域进行性能监控。
8. 并发安全：worker pool 控制 goroutine，channel 传递任务，sync 包同步，context 优雅取消：
	- Goroutine 池：使用 worker pool 控制并发，防止 Goroutine 泄漏。
	- 通道（Channel）通信：安全传递任务和结果，避免竞态条件。
	- 同步机制：合理使用 sync 包（WaitGroup、Mutex 等）。
	- 错误处理：并发任务中的错误要集中收集和处理。
	- 优雅关闭：支持中断信号（如 Ctrl+C）下的资源释放与任务终止。
	- 严格保证 goroutine 的安全使用，利用 channel 或同步原语保护共享状态。
	- 通过 context 实现 goroutine 的取消，避免泄漏与死锁。

# 五、项目结构
```
AutoVulnScan/
├── cmd/                # CLI入口
│   └── autovulnscan.go
├── internal/
│   ├── config/         # 配置与参数解析
│   ├── crawler/        # 静态/动态爬虫
│   ├── dedup/          # DOM相似度去重
│   ├── vulnscan/       # 漏洞检测引擎与插件
│   │   ├── plugins/    # 插件目录（每个漏洞类型一个文件）
│   │   │   ├── xss.go
│   │   │   └── sqli.go
│   │   ├── engine.go   # 插件调度与聚合
│   │   └── plugin.go   # 插件接口与注册
│   ├── ai/             # AI辅助分析
│   ├── output/         # 日志与报告输出
│   └── utils/          # 工具函数
├── docs/               # README、ARCHITECTURE.md、CONTRIBUTING.md、plugins.md
├── go.mod
└── main.go             # 项目启动入口
```

# 六、核心功能模块
## 1. **资产爬取模块**
   - 请输入要扫描的目标（支持url地址）
   - 扫描深度（浅层/深度，默认为浅层）
   - 支持多种协议（HTTP/HTTPS）。
   - 递归爬取、深度与广度可配置。
   - 反爬机制处理：支持User-Agent伪造、IP代理、请求速率控制等。
   - 静态爬虫：基于请求/HTML解析，参考colly/gospider
   - 动态爬虫：基于Chromium（可集成chromedp/rod），支持JS渲染、表单填充、反反爬
   - 策略切换：静态优先，动态补充
   - 调度与深度/广度优先：支持DFS/BFS
   - URL参数识别与泛化：正则+Levenshtein距离
   - **重复率去除（相似度去重机制（页面内容/DOM 树））**：基于 DOM 相似度，将网页转为 DOM 结构，节点内容 hash，结合节点深度与权重，生成 embedding（如 `[1,2,3,...]`），用余弦相似度去重。
   - 支持 JavaScript 渲染、表单自动填充、反反爬虫
   - 自动识别重要页面如登录页、表单页等
   - 动态参数发现（HTML + JS 中）
   - URL 模式泛化（正则 + Levenshtein）

###  相似度爬虫
内置的相似度爬虫系统是专门为XSS扫描优化的智能爬虫：
**相似度算法**  
- **页面内容相似度**：基于页面DOM结构、文本内容计算相似度
- **URL模式识别**：识别参数化URL模式，避免重复爬取相同结构的页面
- **表单结构分析**：分析表单字段相似性，优先爬取结构差异较大的表单
- **动态阈值调整**：根据网站特点自动调整相似度阈值

**效率优化**  
- **智能过滤**：自动过滤90%以上的重复或相似页面
- **优先级队列**：高价值页面优先爬取（如登录页、管理后台、表单页面）
- **深度控制**：智能控制爬虫深度，避免陷入无限循环
- **资源节约**：大幅减少无效请求，节省时间和带宽资源
 
**爬虫特色**  
- **JavaScript渲染**：支持SPA单页应用和动态内容渲染
- **表单自动填充**：智能识别表单字段，自动填充测试数据
- **Cookie管理**：自动管理会话状态，保持登录状态持续爬取
- **反反爬策略**：内置多种反反爬机制，应对各种反爬虫措施


## 2. **漏洞检测模块**
   - 对指定目标或已收集的资产进行漏洞扫描。
   - XSS检测
   - 支持自定义检测插件或规则。
   - 集成AI模型辅助检测（如payload生成、漏洞结果分析）。
   - ......
### 2.1. XSS 检测设计
#### 1. 检测思路
- **语义化 AST 检测**：通过 DOM 差异+AST 分析发现真正的 XSS
- **上下文感知**：根据 HTML/JS/CSS/URI 上下文调整测试方式
- **核心流程**（伪代码）：
  ```
  向页面注入无害 payload（例：<svg/onload=console.log(1)>）
  页面响应转 AST（esprima、acorn、jsdom）
  比较注入前后 DOM/AST 差异
  判断 payload 是否“生效”（进入可执行上下文）
  ```

#### 2. 请求生成与编码绕过

- **注入位置**：GET/POST/Cookie/Header/URI
- **payload 构造**：多种编码绕过（URL编码、HTML实体、Base64、大小写变化等）
- **上下文识别**：自动判断 payload 应注入到哪种上下文（HTML属性、标签内、JS中等）
- **payload 生成**：支持 deepseek 生成 payload

#### 3. **技术原理**  
- **无害payload**：发送特制的无害测试载荷，不会对目标网站造成任何影响或破坏
- **AST语法树分析**：将响应内容转换为抽象语法树（Abstract Syntax Tree），从语义层面分析DOM结构变化
- **DOM差异检测**：通过对比注入前后的DOM结构，精确识别XSS执行点
- **上下文感知**：智能识别不同的HTML上下文环境（属性值、标签内容、JavaScript代码块等）

#### 4. **检测优势**  
- **准确率100%**：基于语义分析，消除传统基于字符串匹配的误报问题
- **零误报**：不依赖特征码匹配，而是通过实际的DOM变化验证漏洞存在
- **绕过WAF**：无害payload天然具备WAF绕过能力，不触发安全防护
- **深度检测**：能够发现复杂的DOM-XSS和存储型XSS

#### 5. 多模式支持
支持所有主流的XSS攻击向量，确保漏洞发现的全面性：

**支持的注入点**  
- **GET参数**：URL查询参数注入检测
- **POST参数**：表单数据和JSON数据注入
- **Cookie参数**：Cookie值注入检测
- **HTTP Header**：自定义请求头注入检测
- **URI路径**：URL路径参数注入检测

**检测技术**  
- **反射型XSS**：立即回显的XSS漏洞检测
- **DOM型XSS**：基于JavaScript的DOM操作XSS检测

**上下文适配**  
- **HTML上下文**：标签内容、属性值等不同位置的注入
- **JavaScript上下文**：JS代码块、事件处理器中的注入
- **CSS上下文**：样式表中的注入检测
- **URL上下文**：href、src等URL属性中的注入
- ... 等等

**编码绕过**  
- **多重编码**：支持HTML、URL、JavaScript、base64等多种编码方式
- **编码组合**：自动尝试各种编码组合绕过过滤
- **字符集测试**：测试不同字符集下的注入可能性
- **大小写变换**：利用大小写不敏感特性绕过过滤
---


## 3. **配置与参数（internal/config）**
默认使用 config.yaml 配置文件，一般默认配置即可正常使用。
   - 支持命令行参数、配置文件和环境变量
   - 可配置AI模型、爬虫策略、扫描插件、并发度等
   - **config.yaml 配置项**：
		- 代理设置
		- 黑名单/Cookie 管理
		- 爬虫参数、扫描参数、输出控制
		- GAU 接入（可选）
	- **子命令结构**：
		- spider（主动扫描）
		- proxy（被动代理，hook 代理流量）
### 命令行帮助
大部分功能也可从命令行使用，如果配置文件和命令行指令相冲突，命令行指令优先级最高。

```bash
AutoVulnScan --help
```

输出信息：
```
AutoVulnScan by w8ay. version:v3.6.3


NAME:
   AutoVulnScan - xss scanner

USAGE:
   AutoVulnScan [global options] command [command options]

VERSION:
   v1.0.3

COMMANDS:
   spider   爬虫+xss
   proxy    被动代理+xss
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --config value      配置文件路径，默认为config.yaml (default: "config.yaml")
   --output-dir value  输出文件路径,默认为当前路径
   --help, -h          show help
   --version, -v       print the version
```
#### Spider 模式（爬虫扫描）

一般使用这个模式，输入url就可以进行扫描了。漏洞默认以markdown和json格式输出。

##### 单URL扫描

```bash
AutoVulnScan spider -url xxx.com
```

##### 从文件读取URL扫描

```bash
AutoVulnScan spider -file urls.txt
```

##### 查看Spider模式帮助

```bash
AutoVulnScan spider -h
```

#### Proxy 模式（被动代理）

##### 生成证书

```bash
./AutoVulnScan proxy --generate-ca
```

证书会生成到 `certs` 文件夹，需要信任 `cacert.pem` 证书。

##### 启动被动代理

```bash
./AutoVulnScan proxy
```

**默认代理地址**：`127.0.0.1:8080`

##### 查看Proxy模式帮助

```bash
AutoVulnScan proxy -h
```
### 配置选项

#### 全局选项

- `--config value` : 配置文件路径，默认为config.yaml
- `--output-dir value` : 输出文件路径，默认为当前路径
- `--help, -h` : 显示帮助信息
- `--version, -v` : 显示版本信息

#### 使用说明
1. **Spider模式**：主动爬虫扫描模式，输入目标URL后自动爬取并进行XSS测试
2. **Proxy模式**：被动代理扫描模式，类似于xray的工作方式，通过代理流量进行XSS检测
3. **无害检测**：所有XSS payload均为无害payload，不会对目标网站造成影响

### config.yaml 配置文件
高阶玩家可自行修改配置，达到最好的效果。以下是完整的配置文件说明：

### 基础配置

#### 调试与代理设置

```yaml
debug: True # 调试模式
proxy: ""   # 代理配置
```

##### 配置说明

- **debug**: 启用调试模式，会输出详细的调试信息，便于排查问题和了解扫描过程
- **proxy**: HTTP代理配置，格式为 `http://proxy_host:port` 或 `socks5://proxy_host:port`，留空则不使用代理

##### 使用场景

- **调试模式**: 首次使用或遇到问题时建议开启，正式使用时可关闭以减少日志输出
- **代理配置**: 在需要通过代理访问目标、隐藏真实IP或绕过网络限制时使用

#### Headers 配置

```yaml
headers: # 网页header
  User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
```

##### 配置说明

- **User-Agent**: 自定义浏览器标识，模拟真实浏览器行为
- 可添加其他HTTP头：如 `Referer`、`Accept-Language`、`Authorization` 等

##### 最佳实践

```yaml
headers:
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
  Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
  Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
  Accept-Encoding: gzip, deflate
  Connection: keep-alive
```

### GAU 配置

```yaml
gau:
  enable: False # 启用gau
  include_sub: True # 是否包含子域名
  with_spider: True # 是否再爬虫获取更多url
```

#### GAU (GetAllUrls) 说明

GAU是一个被动URL收集工具，可以从多个数据源收集历史URL：

##### 配置详解

- **enable**: 是否启用GAU功能，开启后会从第三方数据源收集URL
- **include_sub**: 是否包含子域名的URL，建议开启以获得更全面的URL覆盖
- **with_spider**: GAU收集到URL后是否再次进行爬虫，建议开启以发现更多链接

##### 数据源

GAU会从以下数据源收集URL：
- **Wayback Machine**: 互联网档案馆的历史页面
- **Common Crawl**: 开源网页爬虫数据
- **Virus Total**: 安全厂商的URL情报
- **URLScan**: 网页扫描服务的数据

### 爬虫配置

```yaml
spider: # 爬虫设置
  concurrency: 500 # 爬虫并发数量
  limit: 30 # 每秒限制并发数量
  timeout: 20
  max_depth: 12                     # 最大页面深度限制
  max_page_visit_per_site: 5000     # 每个站点最多访问的页面数量
  crawler_priority: depth-first # 爬虫优先级算法 depth-first 深度优先 breadth-first 广度优先
  no_scope: False # 指定此参数，爬虫将不受范围限制，但是受最大深度限制
  only_root_scope: False  # 只限制根域名范围，如www.baidu.com，将限制爬虫范围为 *.baidu.com
```

#### 性能控制参数

##### 并发与限速

- **concurrency: 500**: 爬虫并发数量，建议根据目标网站承受能力调整
  - 小型网站: 50-100
  - 中型网站: 200-300  
  - 大型网站: 500-1000
- **limit: 30**: 每秒请求限制，避免对目标造成过大压力
- **timeout: 20**: 单个请求超时时间（秒），网络较慢时可适当增加

##### 深度与范围控制

- **max_depth: 12**: 最大爬虫深度，从起始URL开始的最大跳转层数
- **max_page_visit_per_site: 5000**: 每个站点最多访问页面数，防止爬虫陷入无限循环
- **crawler_priority**: 爬虫优先级算法
  - `depth-first`: 深度优先，优先爬取更深层的页面
  - `breadth-first`: 广度优先，优先爬取同层级的页面

##### 范围限制

- **no_scope: False**: 是否受范围限制
  - `True`: 不受域名范围限制，但受深度限制
  - `False`: 严格按照域名范围爬取
- **only_root_scope: False**: 是否只限制根域名
  - `True`: 如输入`www.example.com`，爬取范围为`*.example.com`
  - `False`: 严格按照输入的域名爬取

#### 相似度过滤配置

##### URL泛化过滤

```yaml
  similarity_url: # 启用Url泛化过滤相同网站
    use: False  # 是否启用
    threshold: 10 #url泛化阈值
```

**功能说明**: 通过URL模式识别过滤相似的URL结构

**使用场景**: 
- 电商网站的商品页面：`/product/{id}`
- 用户资料页面：`/user/{uid}`
- 文章详情页面：`/article/{aid}`

**配置建议**:
- 内容管理系统: `threshold: 5-10`
- 电商平台: `threshold: 20-50`
- 社交网站: `threshold: 10-30`

##### DOM相似度过滤

```yaml
  similarity_page_dom: # 启用DOM相似度算法过滤相同网站
    use: True # 是否启用
    threshold: 5 # 网站阈值，同个domain相似度大于这个数开启过滤
    similarity: 0.95 # 相似度阈值，大于这个数判定相似
    vector_dim: 5000 # 向量维度
```

**技术原理**: 
- 将页面DOM结构转换为向量
- 计算向量间的余弦相似度
- 过滤相似度超过阈值的页面

**参数调优**:
- **threshold: 5**: 同域名下发现5个以上相似页面时开启过滤
- **similarity: 0.95**: 相似度阈值，越高过滤越严格
  - 模板网站: 0.98-0.99 (页面结构高度相似)
  - 动态网站: 0.90-0.95 (页面内容变化较大)
  - 个人博客: 0.85-0.90 (页面布局相对简单)
- **vector_dim: 5000**: 向量维度，影响计算精度和性能

##### 简单Hash去重

```yaml
  simile_hash: # 简单hash算法去重
    use: False
```

**功能说明**: 基于页面内容的简单哈希去重，速度快但精度较低

**使用建议**: DOM相似度过滤已经足够精确，通常不需要开启

#### 数据源与字典配置

```yaml
  sources: # 使用哪些源获得更多url
    - robotstxt
    - sitemapxml
  spider_rule_dir: ./spider_rules # 规则文件目录
  directory_dict: ./dict # 目录字典，会扫描相关目录
```

##### URL数据源

- **robotstxt**: 从`robots.txt`文件中提取URL和路径信息
- **sitemapxml**: 从`sitemap.xml`文件中获取站点地图URL


##### 目录字典

- **directory_dict**: 常见目录和文件的字典路径
- 内置常见目录: `admin/`, `backup/`, `test/`, `api/` 等

#### 访问控制配置

```yaml
  black_list: # 黑名单
    - ".google.com"
    - ".facebook.com"
  cookies:
    "*.example.com": "cookie1=1;cookie2=2"
    "a.example2.com": "cookie3=3;cookie4=4"
```

##### 黑名单配置

**功能说明**: 防止爬虫访问第三方域名或无关网站

**配置示例**:
```yaml
black_list:
  - ".google.com"
  - ".facebook.com"
  - ".twitter.com"
  - ".linkedin.com"
```

##### Cookie配置（新增功能）

**功能说明**: 为不同域名配置不同的Cookie，支持通配符匹配

**使用场景**:
- **登录状态**: 配置登录后的Session Cookie
- **多子域**: 为不同子域名配置专用Cookie
- **A/B测试**: 配置特定的测试Cookie

**配置示例**:
```yaml
cookies:
  "*.example.com": "sessionid=abc123;csrftoken=def456"
  "admin.example.com": "admin_token=xyz789;role=admin"
  "api.example.com": "api_key=key123;version=v2"
```

### 扫描器配置

```yaml
scan: # 扫描器配置
  concurrency: 300 # 扫描器并发数量
  limit: 30 # 每秒限制并发数量
  filter_threshold: 30 # 防止重复的xss报告，每个域名xss最多报告的阈值
  found_hidden_parameter: True # 从页面中发现隐藏参数
  found_hidden_parameter_from_js: False
  parameter_group_size: 40
  timeout: 30 # 超时时间 单位(秒)
```

#### 性能参数

- **concurrency: 300**: 扫描器并发数量，影响扫描速度
- **limit: 30**: 每秒扫描请求限制，避免触发WAF
- **timeout: 30**: 扫描请求超时时间

#### 参数发现配置

##### 隐藏参数发现

- **found_hidden_parameter: True**: 从HTML页面中发现隐藏的input参数
- **found_hidden_parameter_from_js: False**: 从JavaScript代码中发现参数（新增功能）

**JavaScript参数发现**:
- 分析JS中的AJAX请求
- 提取API接口参数
- 识别动态生成的参数

##### 参数处理优化

- **parameter_group_size: 40**: 参数分组大小，影响扫描效率
- **filter_threshold: 30**: 每个域名最多报告的XSS漏洞数量，防止重复报告

#### 扫描位置配置

```yaml
  position: # 扫描参数位置，可选 get,post,uri,header,cookie
    - get
    - post
    - uri
```

##### 支持的注入位置

- **get**: URL查询参数
- **post**: POST请求体参数
- **uri**: URL路径参数
- **header**: HTTP请求头（可选）
- **cookie**: Cookie参数（可选）

#### 输出配置

```yaml
  output: # 支持生成json和markdown格式，为空则不生成
    response: False # 保存返回包
    response_header: True # 保存返回header
```

##### 输出选项

- **response: False**: 是否保存完整的HTTP响应内容
  - 开启后会增加存储空间占用
  - 便于漏洞验证和分析
- **response_header: True**: 是否保存HTTP响应头
  - 用于分析服务器信息
  - 检测安全头配置

#### 隐藏参数字典

```yaml
  hidden_parameters: # 内置用于GET探测的隐藏参数
    - key
    - redirect
    - region
    - action
    - l
```

##### 内置参数说明

这些是从实战经验中总结的常见隐藏参数：

- **key**: 密钥参数，常用于加密和验证
- **redirect**: 重定向参数，容易出现开放重定向漏洞
- **region**: 地区参数，可能影响页面内容
- **action**: 操作参数，指定要执行的动作
- **l**: 语言参数，影响页面显示语言

### 配置优化建议

#### 性能调优

##### 高性能配置（适用于大型目标）

```yaml
spider:
  concurrency: 1000
  limit: 50
  max_page_visit_per_site: 10000
  similarity_page_dom:
    similarity: 0.98
scan:
  concurrency: 500
  parameter_group_size: 60
  filter_threshold: 50
```

##### 精确扫描配置（适用于小型目标）

```yaml
spider:
  concurrency: 100
  limit: 10
  max_depth: 20
  similarity_page_dom:
    similarity: 0.90
scan:
  concurrency: 50
  found_hidden_parameter_from_js: True
  parameter_group_size: 20
```

#### 隐蔽性配置

```yaml
spider:
  concurrency: 50
  limit: 5
  timeout: 60
headers:
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
  Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
  Accept-Language: en-US,en;q=0.5
  Connection: keep-alive
  Upgrade-Insecure-Requests: 1
```

#### 特定场景配置

##### SPA单页应用

```yaml
spider:
  spider_with_rule: True
  found_hidden_parameter_from_js: True
  max_depth: 8
  similarity_page_dom:
    similarity: 0.85
```

##### 大型电商网站

```yaml
spider:
  similarity_url:
    use: True
    threshold: 50
  max_page_visit_per_site: 20000
scan:
  filter_threshold: 100
```

##### 企业内网测试

```yaml
spider:
  concurrency: 200
  limit: 20
  only_root_scope: False
  no_scope: False
scan:
  found_hidden_parameter_from_js: True
  output:
    response: True
    response_header: True
``` 

## 4. 去重机制
	- **DOM相似度去重（internal/dedup）**
		- DOM转AST
		- 节点内容Hash+深度权重Embedding
		- 余弦相似度判重
	- **URL 去重**：结构+参数相似性判断
	- **响应内容去重**：hash 去重
	- **DOM/AST 树去重**：DOM 树或 AST 树向量去重

## 5. ** AI辅助（internal/ai）**
   - 支持多模型（deepseek/llama3，本地/私有化API）
   - 用于payload生成、智能判定、页面重要性识别等   

## 6. **结果处理与日志模块**
   - 分级日志：DEBUG、INFO、WARN、ERROR四个级别
   - 日志轮转：按大小或时间自动轮转日志文件
   - 多格式输出（txt/JSON））
   - 结果去重
   - 日志记录：详细记录爬取与检测过程，支持日志分级（INFO/ERROR/DEBUG）。
   - **日志高亮**：日志输出支持高亮，发现漏洞时在控制台以醒目颜色标记。
   - 请输入并发线程数（默认10）：  
   - 是否使用代理
   - 资产清单：发现的所有资产信息汇总
   - 统计信息：扫描覆盖率、发现数量等统计数据
  

# 七、 输出规范
## 日志输出：保存至log.txt
## 爬虫结果：
1. 所有URL保存至 urls-spider.txt
2. DOM相似度去重后保存至 urls-spider_de-duplicate_all.txt
3. 参数化URL去重后保存至 urls-spider_params.txt
4. URL去重规则：同路径同参数名，参数值不同视为重复，仅保留一个，如下面内容视为重复
  ```
  http://testphp.vulnweb.com/product.php?pic=1
  http://testphp.vulnweb.com/product.php?pic=7
  ```

## 漏洞报告：
1. 严格格式输出，保存至 urls-Vulns.txt
2. 字段：序号、检测时间、漏洞名称、url地址、Payload、请求方式、漏洞参数、漏洞地址（复现地址，GET完整拼接，POST加参数说明）
3. “漏洞地址”字段必须为实际可复现漏洞的完整请求地址：  
  1）对于GET请求，请将payload插入到对应参数，拼接成完整URL。例如：  http://example.com/test?param1=value1&vuln_param=<payload>
  2） 对于POST请求，漏洞地址字段可写为： URL + “ [POST参数] param1=value1&vuln_param=<payload>”
4. 输出案例：
```
序号:           5
检测时间:       2025-07-19T01:30:41+08:00
漏洞名称:       XSS
url地址:        http://testphp.vulnweb.com/hpp/
Payload:        <script>alert('AutoVulnScanXSS')</script>
请求方式:       GET
漏洞参数:       pp
漏洞地址:       http://testphp.vulnweb.com/hpp/?pp=<script>alert('AutoVulnScanXSS')</script>

序号:           6
检测时间:       2025-07-19T01:30:41+08:00
漏洞名称:       XSS
url地址:        http://testphp.vulnweb.com/hpp/
Payload:        <script>alert('AutoVulnScanXSS')</script>
请求方式:       POST
漏洞参数:       pp
漏洞地址:       http://testphp.vulnweb.com/hpp/  [POST参数] pp=<script>alert('AutoVulnScanXSS')</script>
```

# 八、插件开发与维护规范（docs/plugins.md）
1. 插件放于 internal/vulnscan/plugins/
2. 实现 VulnPlugin 接口（Name、Detect方法）
3. 插件需在 init() 注册自身
4. 返回 VulnResult 结构体，便于统一输出
5. 每个插件有对应单元测试
6. 必须有 GoDoc 注释，复杂逻辑有详细说明
7. 遵循团队协作流程，详见 CONTRIBUTING.md
```
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

```

# 九、文档与规范
1. 代码注释：关键逻辑、接口、结构体注释齐全。
2. README 文档：包含功能介绍、用法示例、依赖说明、常见问题。
3. 命名规范：变量、函数、包名遵循 Go 语言规范。
4. 单元测试：关键模块和核心逻辑配备测试用例。
5. CI/CD 集成：自动化测试与构建流程。
6. 架构设计：系统架构图和模块关系
7. API文档：内部接口文档
8. 使用手册：详细的命令参数说明和使用示例
9. 配置文档：配置文件格式和参数说明 
10. 公共函数与包使用 **GoDoc 风格注释**。
11. 维护 `CONTRIBUTING.md` 和 `ARCHITECTURE.md`，指导团队实践。
12. 使用 `go fmt`、`goimports`、`golangci-lint` 保证命名一致性与格式规范。

# 十、代码运行检测机制
   - 自检机制：启动自检，检测配置、依赖、网络连通性等。
   - 错误日志：详细记录运行时错误和异常，便于定位问题。


# 十一、参考开源项目核心原理总结
1. katana：静态+动态融合、去重机制优秀、插件化，地址为https://github.com/projectdiscovery/katana
2. crawlergo：Chromium驱动、表单自动填充、反反爬虫，地址为https://github.com/Qianlitp/crawlergo
3. colly/gospider：高并发静态爬虫、易扩展，地址为https://github.com/jaeles-project/gospider、https://github.com/gocolly/colly
4. crawlab：分布式调度、可视化管理，地址为https://github.com/crawlab-team/crawlab

## 三款主流工具的检测逻辑参考
### 1. XSStrike

#### a. DOM XSS 检测

- 通过正则分析敏感函数：

  ```
  sources = r'document\\.(URL|documentURI|URLUnencoded|baseURI|cookie|referrer)|location\\.(href|search|hash|pathname)|window\\.name|history\\.(pushState|replaceState)(local|session)Storage'
  sinks = r'eval|evaluate|execCommand|assign|navigate|getResponseHeaderopen|showModalDialog|Function|set(Timeout|Interval|Immediate)|execScript|crypto.generateCRMFRequest|ScriptElement\\.(src|text|textContent|innerText)|.*?\\.onEventName|document\\.(write|writeln)|.*?\\.innerHTML|Range\\.createContextualFragment|(document|window)\\.location'
  scripts = re.findall(r'(?i)(?s)<script[^>]*>(.*?)</script>', response)
  ```

- 提取 script 内容，用正则找敏感点（准确度有限，仅辅助，不适合自动化扫描）。

#### b. 内置参数爆破

- 内置常见参数名，检测参数发现：

  ```
  blindParams = [
    'redirect', 'redir', 'url', 'link', 'goto', 'debug', '_debug', 'test', 'get', ...
    'message'
  ]
  ```

#### c. HTML解析与回显分析

- 通过 HTML 解析，确定参数回显位置（标签内、属性内、注释、JS中），据此选择 payload。

---

### 2. Xray

#### a. Script 内回显检测

- 针对如下 case：

  ```
  <script>
     $var ='var a = \"'.$_GET['q'].'\";';
     echo $var;
  </script>
  ```

- 顺序发送 payload：pdrjzsqc，"-pdrjzsqc-"，</sCrIpT><ojyrqvrzar> 等，最后确定 payload。

#### b. Script 注释回显检测

  ```
  <script>
  var a = 11;
  // inline <?php echo $_GET["a"];?>
  /* <?php echo $_GET["b"];?> */
  </script>
  ```

- 发送 payload：\n;chxdsdkm;// 和 \n;prompt(1);// 进行判定。

#### c. 标签内内容检测

  ```
  <textarea><?php echo $_GET["w"];?></textarea>
  ```

- 顺序发送 payload：spzzmsntfzikatuchsvu，</tExTaReA><lixoorqfwj>，</TeXtArEa>sCrIpT...，最终确定 payload。

#### d. style 属性内容检测

  ```
  <input style="color:<?php echo $_GET["e"];?>"/>
  ```

- 顺序发送 payload：kmbrocvz，expression(a(kmbrocvz))

#### e. HTML 标签属性内容检测

  ```
  <input style="color:3" value="<?php echo $_GET["r"];?>"/>
  ```

- 顺序发送 payload：spzzmsntfzikatuchsvu，"ljxxrwom="，'ljxxrwom='，ljxxrwom=，接着发送 \"><vkvjfzrtgi>，\">ScRiPtvkvjfzrtgiScRiPt 等，最终 payload 为 \"><img src=1>，"OnMoUsEoVeR=prompt(1)//"

#### f. JS 事件属性检测

  ```
  <img src=1 onerror="a<?php echo htmlspecialchars($_GET["a"]);?>" />
  ```

- 返回 payload 为 prompt(1)，即把 onerror 后内容当作 JS 执行。

- 参考 awvs，检测指定事件属性名（如 onerror、onload、onclick 等，详见原文属性名列表）。

#### g. HTML 注释内内容检测

  ```
  <!--
         this is comment
         <?php echo $t;?>
     -->
  ```

- 发送 payload：spzzmsntfzikatuchsvu，--><husyfmzvuq>，--!><oamtgwmoiz>，确认 --> 或 --!> 未被过滤后，再发送如下内容：

  ```
  <bvwpmjtngz>
     sCrIpTbvwpmjtngzsCrIpT
     ImGsRcOnErRoRbvwpmjtngz>
     sVgOnLoAdbvwpmjtngz>
     iFrAmEsRcJaVaScRiPtbvwpmjtngz>
     aHrEfJaVaScRiPtbvwpmjtngzcLiCkA
     InPuTaUtOfOcUsOnFoCuSbvwpmjtngz>
  ```

---

### 3. Awvs

- 规则全面，针对多种情况（meta 标签 content、script、src、AngularJs 等）。
- 对参数名进行严格判断，只检测指定属性 key，宁愿漏报也不误报（与 Xray 的宽泛策略对比）。

---


# 十二、代码质量与可维护性
我的设计原则已经包含了代码规范、注释、单一职责、错误处理、并发安全等内容，但可以更明确地强调如下：
1. 分层解耦：每个模块只关心自身职责，接口清晰，便于修改和扩展。
2. 接口与依赖倒置：关键能力（如漏洞检测、AI分析）通过接口抽象，主流程依赖接口，具体实现可热插拔。
3. 单元测试：每个核心包都应有单元测试，保证重构安全。
4. 文档完善：每个包、每个导出函数都有GoDoc注释，复杂逻辑有详细说明。维护 ARCHITECTURE.md，长期指导团队。
5. 插件化机制：明确插件注册、生命周期、接口约束，便于第三方开发和维护。

# 十三、使用的 AI 大模型
   - 模型类型：如 deepseek等。
   - 应用场景：辅助漏洞检测、资产识别等。
   - 调用方式：本地推理或API调用。
   - 模型更新：支持热更新或模型切换。
   - model: "deepseek/deepseek-v3" # 或 "ollama/llama3" 等，支持配置本地或私有模型    api_key: "sk-bb716bfbdb56496aa8eba12fd7400a70"


# 十四、代码运行检测
每次运行代码时，你要尊重客观事实，对于运行的结果，你还要检测日志信息中是否存在报错信息，需及时进行处理优化，对于修改的代码，你需要站在全局的视角，即从代码的框架，后期维护，代码运行效率的方面考虑问题，而不是仅注重局部的代码；
