package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"

	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"

	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/rs/zerolog/log"
)

// XSSPlugin 用于检测跨站脚本攻击（XSS）漏洞
// 支持反射型XSS检测，通过注入payload并验证是否在响应中被反射
type XSSPlugin struct {
	httpClient      *requester.HTTPClient // HTTP客户端，用于发送测试请求
	info            PluginInfo            // 插件基本信息
	reflectionRegex *regexp.Regexp        // 用于检测payload反射的正则表达式
	contextPatterns []contextPattern      // 不同上下文的检测模式
}

// contextPattern 定义不同HTML上下文的检测模式
type contextPattern struct {
	name        string         // 上下文名称
	pattern     *regexp.Regexp // 匹配模式
	description string         // 描述
}

// NewXSSPlugin creates a new XSSPlugin.
// NewXSSPlugin 创建一个新的XSS插件实例
// 参数:
//   - client: HTTP客户端实例，用于发送扫描请求
//
// 返回:
//   - *XSSPlugin: 初始化完成的XSS插件实例
func NewXSSPlugin(client *requester.HTTPClient) *XSSPlugin {
	// 编译用于检测payload反射的正则表达式
	reflectionRegex := regexp.MustCompile(`(?i)<script[^>]*>.*?</script>|javascript:|on\w+\s*=|<img[^>]*src\s*=|<iframe[^>]*src\s*=`)

	// 定义不同HTML上下文的检测模式
	contextPatterns := []contextPattern{
		{
			name:        "script_tag",
			pattern:     regexp.MustCompile(`(?i)<script[^>]*>([^<]*)</script>`),
			description: "Script tag context",
		},
		{
			name:        "attribute_value",
			pattern:     regexp.MustCompile(`(?i)\w+\s*=\s*["']([^"']*?)["']`),
			description: "HTML attribute value context",
		},
		{
			name:        "html_content",
			pattern:     regexp.MustCompile(`(?i)>([^<]*?)<`),
			description: "HTML content context",
		},
		{
			name:        "javascript_string",
			pattern:     regexp.MustCompile(`(?i)["']([^"']*?)["']`),
			description: "JavaScript string context",
		},
	}

	return &XSSPlugin{
		httpClient:      client,
		reflectionRegex: reflectionRegex,
		contextPatterns: contextPatterns,
		info: PluginInfo{
			Name:        "xss",                                              // 插件名称标识符
			Description: "Checks for Cross-Site Scripting vulnerabilities.", // 插件功能描述
			Author:      "AutoVulnScan",                                     // 插件作者
			Version:     "0.2.0",                                            // 插件版本号
		},
	}
}

// Info 返回插件的基本信息
// 实现Plugin接口的Info方法
// 返回:
//   - PluginInfo: 包含插件名称、描述、作者和版本的信息结构
func (p *XSSPlugin) Info() PluginInfo {
	return p.info
}

// Scan 执行XSS漏洞扫描
// 遍历所有参数和payload组合，测试每个可能的注入点
// 参数:
//   - ctx: 上下文对象，用于控制扫描超时和取消
//   - req: 要扫描的HTTP请求对象
//   - payloads: XSS测试payload列表
//
// 返回:
//   - []*Vulnerability: 发现的XSS漏洞列表
//   - error: 扫描过程中的错误
func (p *XSSPlugin) Scan(ctx context.Context, req *models.Request, payloads []string) ([]*Vulnerability, error) {
	var vulnerabilities []*Vulnerability

	// 遍历请求中的所有参数
	for _, param := range req.Params {
		// 对每个参数测试所有payload
		for _, payload := range payloads {
			// 测试单个payload在特定参数上的效果
			vuln, err := p.testPayload(ctx, req, param.Name, payload)
			if err != nil {
				// 记录测试失败的警告，但继续测试其他payload
				log.Warn().Err(err).
					Str("url", req.URL.String()).
					Str("param", param.Name).
					Str("payload", payload).
					Msg("XSS test failed")
				continue
			}
			// 如果发现漏洞，添加到结果列表
			if vuln != nil {
				vulnerabilities = append(vulnerabilities, vuln)
				// 为了提高效率，发现一个漏洞后可以跳过该参数的其他payload测试
				// 但这里保持完整扫描以发现所有可能的漏洞类型
			}
		}
	}

	return vulnerabilities, nil
}

// testPayload 在特定参数上测试单个payload
// 通过修改参数值注入payload，然后检查响应中是否反射了该payload
// 参数:
//   - ctx: 上下文对象
//   - originalReq: 原始HTTP请求
//   - paramName: 要测试的参数名称
//   - payload: 要注入的XSS payload
//
// 返回:
//   - *Vulnerability: 如果发现漏洞则返回漏洞信息，否则返回nil
//   - error: 测试过程中的错误
func (p *XSSPlugin) testPayload(ctx context.Context, originalReq *models.Request, paramName, payload string) (*Vulnerability, error) {
	// 克隆原始请求以避免修改原始数据
	newReq := cloneRequest(originalReq)

	// 根据请求方法注入payload
	if err := p.injectPayload(newReq, paramName, payload); err != nil {
		return nil, fmt.Errorf("failed to inject payload: %w", err)
	}

	// 发送包含payload的请求
	resp, err := p.httpClient.Do(newReq.Request.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// 多层次检测XSS漏洞
	if p.detectReflection(body, payload) {
		// 获取反射上下文信息
		context := p.analyzeReflectionContext(body, payload)

		// 使用DOM验证进一步确认漏洞
		domVerified := p.verifyWithDOM(ctx, newReq)

		// 创建漏洞报告
		vuln := &Vulnerability{
			Type:          p.info.Name,              // 漏洞类型
			URL:           originalReq.URL.String(), // 原始URL
			Payload:       payload,                  // 触发漏洞的payload
			Param:         paramName,                // 存在漏洞的参数
			Method:        originalReq.Method,       // HTTP方法
			VulnerableURL: newReq.URL.String(),      // 包含payload的完整URL
		}

		// 添加额外的漏洞信息
		if context != "" {
			log.Info().
				Str("context", context).
				Str("url", originalReq.URL.String()).
				Str("param", paramName).
				Bool("dom_verified", domVerified).
				Msg("XSS vulnerability detected")
		}

		return vuln, nil
	}

	return nil, nil
}

// injectPayload 将payload注入到指定参数中
// 参数:
//   - req: 要修改的请求对象
//   - paramName: 参数名称
//   - payload: 要注入的payload
//
// 返回:
//   - error: 注入过程中的错误
func (p *XSSPlugin) injectPayload(req *models.Request, paramName, payload string) error {
	if req.Request.Method == "POST" {
		// 处理POST请求：修改请求体中的参数
		bodyBytes, err := io.ReadAll(req.Request.Body)
		if err != nil {
			return fmt.Errorf("failed to read request body: %w", err)
		}
		req.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		// 检测Content-Type以确定如何处理请求体
		contentType := req.Request.Header.Get("Content-Type")

		if strings.Contains(contentType, "application/json") {
			// 处理JSON请求体
			return p.injectJSONPayload(req, paramName, payload, bodyBytes)
		} else {
			// 处理表单数据
			return p.injectFormPayload(req, paramName, payload, bodyBytes)
		}
	} else {
		// 处理GET请求：修改URL查询参数
		q := req.Request.URL.Query()
		q.Set(paramName, payload) // 设置查询参数值为payload
		req.Request.URL.RawQuery = q.Encode()
	}

	return nil
}

// injectFormPayload 向表单数据中注入payload
func (p *XSSPlugin) injectFormPayload(req *models.Request, paramName, payload string, bodyBytes []byte) error {
	form, err := url.ParseQuery(string(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to parse form data: %w", err)
	}

	form.Set(paramName, payload) // 设置参数值为payload
	req.Request.Body = io.NopCloser(strings.NewReader(form.Encode()))
	req.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return nil
}

// injectJSONPayload 向JSON数据中注入payload
func (p *XSSPlugin) injectJSONPayload(req *models.Request, paramName, payload string, bodyBytes []byte) error {
	var jsonData map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &jsonData); err != nil {
		return fmt.Errorf("failed to parse JSON data: %w", err)
	}

	// 注入payload到指定字段
	jsonData[paramName] = payload

	// 重新编码JSON
	newBody, err := json.Marshal(jsonData)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON data: %w", err)
	}

	req.Request.Body = io.NopCloser(bytes.NewReader(newBody))
	req.Request.Header.Set("Content-Type", "application/json")

	return nil
}

// detectReflection 检测payload是否在响应中被反射
// 使用多种检测方法提高准确性
func (p *XSSPlugin) detectReflection(body []byte, payload string) bool {
	bodyStr := string(body)

	// 1. 直接字符串匹配
	if strings.Contains(bodyStr, payload) {
		return true
	}

	// 2. URL编码检测
	if strings.Contains(bodyStr, url.QueryEscape(payload)) {
		return true
	}

	// 3. HTML实体编码检测
	htmlEncoded := strings.ReplaceAll(payload, "<", "&lt;")
	htmlEncoded = strings.ReplaceAll(htmlEncoded, ">", "&gt;")
	htmlEncoded = strings.ReplaceAll(htmlEncoded, "\"", "&quot;")
	htmlEncoded = strings.ReplaceAll(htmlEncoded, "'", "&#x27;")
	if strings.Contains(bodyStr, htmlEncoded) {
		return true
	}

	// 4. 使用正则表达式检测潜在的XSS模式
	if p.reflectionRegex.MatchString(bodyStr) {
		// 进一步检查是否包含我们的payload片段
		payloadParts := strings.Fields(payload)
		for _, part := range payloadParts {
			if len(part) > 3 && strings.Contains(bodyStr, part) {
				return true
			}
		}
	}

	return false
}

// analyzeReflectionContext 分析payload反射的上下文
// 返回payload出现的HTML上下文信息
func (p *XSSPlugin) analyzeReflectionContext(body []byte, payload string) string {
	bodyStr := string(body)

	for _, pattern := range p.contextPatterns {
		matches := pattern.pattern.FindAllStringSubmatch(bodyStr, -1)
		for _, match := range matches {
			if len(match) > 1 && strings.Contains(match[1], payload) {
				return pattern.name
			}
		}
	}

	return "unknown"
}

// verifyWithDOM 使用无头浏览器确认反射的payload是否可执行
// 通过监听JavaScript对话框事件来检测XSS payload是否成功执行
// 参数:
//   - ctx: 上下文对象
//   - req: 包含payload的请求对象
//
// 返回:
//   - bool: 如果payload成功执行（触发alert等）则返回true
func (p *XSSPlugin) verifyWithDOM(ctx context.Context, req *models.Request) bool {
	// 创建带超时的上下文
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// 创建Chrome浏览器执行器上下文
	allocCtx, cancel := chromedp.NewExecAllocator(timeoutCtx, append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),                           // 启用无头模式
		chromedp.Flag("ignore-certificate-errors", true),          // 忽略证书错误
		chromedp.Flag("disable-web-security", true),               // 禁用Web安全策略
		chromedp.Flag("disable-features", "VizDisplayCompositor"), // 禁用某些功能以提高稳定性
	)...)
	defer cancel()

	// 创建浏览器任务上下文
	taskCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// 监听多种JavaScript事件
	var alertTriggered bool
	var consoleErrors []string

	chromedp.ListenTarget(taskCtx, func(ev interface{}) {
		switch e := ev.(type) {
		case *page.EventJavascriptDialogOpening:
			// 检测到JavaScript对话框打开事件，说明XSS payload执行成功
			alertTriggered = true
			log.Debug().Str("dialog_type", string(e.Type)).Msg("JavaScript dialog detected")
		case *runtime.EventConsoleAPICalled:
			// 监听console.log等调用
			if e.Type == runtime.APITypeError {
				for _, arg := range e.Args {
					if arg.Value != nil {
						consoleErrors = append(consoleErrors, string(arg.Value))
					}
				}
			}
		case *runtime.EventExceptionThrown:
			// 监听JavaScript异常
			if e.ExceptionDetails != nil && e.ExceptionDetails.Exception != nil {
				log.Debug().Str("exception", e.ExceptionDetails.Exception.Description).Msg("JavaScript exception detected")
			}
		}
	})

	var err error
	if req.Method == "POST" {
		// 对于POST请求，需要在浏览器中提交表单
		err = p.postWithChrome(taskCtx, req)
	} else {
		// 对于GET请求，直接导航到包含payload的URL
		err = chromedp.Run(taskCtx,
			chromedp.Navigate(req.URL.String()),
			chromedp.Sleep(2*time.Second), // 等待页面加载和JavaScript执行
		)
	}

	if err != nil {
		log.Debug().Err(err).Msg("DOM verification failed")
		return false
	}

	// 记录console错误信息用于调试
	if len(consoleErrors) > 0 {
		log.Debug().Strs("console_errors", consoleErrors).Msg("Console errors detected during DOM verification")
	}

	return alertTriggered
}

// postWithChrome 使用Chrome浏览器提交POST请求
// 通过JavaScript动态创建表单并提交，模拟POST请求的执行
// 参数:
//   - ctx: 浏览器上下文
//   - req: 要提交的POST请求对象
//
// 返回:
//   - error: 提交过程中的错误
func (p *XSSPlugin) postWithChrome(ctx context.Context, req *models.Request) error {
	// 读取请求体数据
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}
	req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // 恢复请求体以供后续使用

	// 检查Content-Type以确定如何处理数据
	contentType := req.Request.Header.Get("Content-Type")

	if strings.Contains(contentType, "application/json") {
		return p.postJSONWithChrome(ctx, req, bodyBytes)
	} else {
		return p.postFormWithChrome(ctx, req, bodyBytes)
	}
}

// postFormWithChrome 使用Chrome提交表单数据
func (p *XSSPlugin) postFormWithChrome(ctx context.Context, req *models.Request, bodyBytes []byte) error {
	// 解析表单数据
	formValues, err := url.ParseQuery(string(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to parse form data: %w", err)
	}

	// 将表单数据转换为JSON格式，便于在JavaScript中使用
	formJSON, err := json.Marshal(formValues)
	if err != nil {
		return fmt.Errorf("failed to marshal form data: %w", err)
	}

	// 构造JavaScript代码，动态创建并提交表单
	script := fmt.Sprintf(`
        // 创建表单元素
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = '%s';
        
        // 解析表单字段数据
        const fields = %s;
        
        // 为每个字段创建隐藏输入元素
        for (const key in fields) {
            if (fields.hasOwnProperty(key)) {
                const hiddenField = document.createElement('input');
                hiddenField.type = 'hidden';
                hiddenField.name = key;
                hiddenField.value = Array.isArray(fields[key]) ? fields[key][0] : fields[key];
                form.appendChild(hiddenField);
            }
        }
        
        // 将表单添加到页面并提交
        document.body.appendChild(form);
        form.submit();
    `, req.URL.String(), string(formJSON))

	// 执行浏览器操作
	return chromedp.Run(ctx,
		// 导航到空白页面以获得DOM上下文
		chromedp.Navigate("about:blank"),
		// 等待页面加载
		chromedp.Sleep(1*time.Second),
		// 执行JavaScript代码提交表单
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, _, err := runtime.Evaluate(script).Do(ctx)
			return err
		}),
		// 等待表单提交和页面响应
		chromedp.Sleep(3*time.Second),
	)
}

// postJSONWithChrome 使用Chrome提交JSON数据
func (p *XSSPlugin) postJSONWithChrome(ctx context.Context, req *models.Request, bodyBytes []byte) error {
	// 构造JavaScript代码发送JSON请求
	script := fmt.Sprintf(`
        fetch('%s', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: %s
        }).then(response => response.text()).then(data => {
            document.body.innerHTML = data;
        }).catch(error => {
            console.error('Error:', error);
        });
    `, req.URL.String(), string(bodyBytes))

	// 执行浏览器操作
	return chromedp.Run(ctx,
		chromedp.Navigate("about:blank"),
		chromedp.Sleep(1*time.Second),
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, _, err := runtime.Evaluate(script).Do(ctx)
			return err
		}),
		chromedp.Sleep(3*time.Second),
	)
}

// isReflected 检查payload是否在响应中被反射
// 使用goquery解析HTML并检查payload是否出现在页面文本中
// 参数:
//   - body: 响应体字节数组
//   - payload: 要检查的payload字符串
//
// 返回:
//   - bool: 如果payload被反射则返回true
//   - error: 解析过程中的错误
func isReflected(body []byte, payload string) (bool, error) {
	// 使用goquery解析HTML文档
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return false, err
	}

	// 检查payload是否出现在HTML文本内容中
	if strings.Contains(doc.Text(), payload) {
		return true, nil
	}

	// 检查payload是否出现在HTML源码中（包括属性值）
	htmlContent, err := doc.Html()
	if err != nil {
		return false, err
	}

	return strings.Contains(htmlContent, payload), nil
}
