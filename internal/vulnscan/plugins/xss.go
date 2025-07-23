// Package plugins 包含了所有具体的漏洞扫描插件实现。
package plugins

import (
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"

	"autovulnscan/internal/browser"
	"autovulnscan/internal/models"
	"autovulnscan/internal/requester"
	"autovulnscan/internal/util"
	"autovulnscan/internal/vulnscan"

	"github.com/rs/zerolog/log"
)

// XSSPlugin 实现了用于检测反射型跨站脚本（XSS）漏洞的插件。
type XSSPlugin struct {
	browserService  *browser.BrowserService
	reflectionRegex *regexp.Regexp
}

// init 函数会在包初始化时被调用，用于自动注册插件。
func init() {
	// 注意：这里的 BrowserService 初始化为 nil。
	// 理想的架构是在程序启动时创建一个单一的BrowserService实例，
	// 然后通过某种方式（如修改RegisterPlugin的签名）将其注入到所有需要它的插件中。
	// 在当前实现下，我们将在首次需要时（即第一次调用Scan）才初始化它。
	vulnscan.RegisterPlugin(&XSSPlugin{
		reflectionRegex: regexp.MustCompile(`(?i)<script[^>]*>.*?</script>|javascript:|on\w+\s*=|<img[^>]*src\s*=|<iframe[^>]*src\s*=`),
	})
}

// Info 返回插件的元数据。
func (p *XSSPlugin) Info() vulnscan.PluginInfo {
	return vulnscan.PluginInfo{
		Name:        "xss",
		Description: "检测反射型跨站脚本（XSS）漏洞。",
		Author:      "AutoVulnScan Team",
		Version:     "1.0",
	}
}

// lazyInitBrowserService 懒加载浏览器服务。
func (p *XSSPlugin) lazyInitBrowserService() error {
	if p.browserService == nil {
		// 这里的配置应该是从主配置中获取的，暂时硬编码用于演示。
		// TODO: 将浏览器配置注入到插件中。
		cfg := browser.Config{
			Headless:  true,
			UserAgent: "AutoVulnScan XSS Verifier",
		}
		service, err := browser.NewBrowserService(cfg)
		if err != nil {
			return err
		}
		p.browserService = service
	}
	return nil
}

// Scan 对给定的HTTP请求执行XSS扫描。
func (p *XSSPlugin) Scan(client *requester.HTTPClient, req *models.Request) ([]*vulnscan.Vulnerability, error) {
	if err := p.lazyInitBrowserService(); err != nil {
		log.Error().Err(err).Msg("初始化浏览器服务失败，跳过XSS DOM验证")
	}

	var vulnerabilities []*vulnscan.Vulnerability
	payloads, err := vulnscan.LoadPayloads("xss")
	if err != nil {
		return nil, err
	}

	for _, param := range req.Params {
		for _, payload := range payloads {
			vuln, err := p.testPayload(client, req, param.Name, payload)
			if err != nil {
				log.Warn().Err(err).Str("url", req.URL.String()).Msg("XSS payload test failed")
				continue
			}
			if vuln != nil {
				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}
	return vulnerabilities, nil
}

// testPayload 在特定参数上测试单个XSS payload。
func (p *XSSPlugin) testPayload(client *requester.HTTPClient, originalReq *models.Request, paramName, payload string) (*vulnscan.Vulnerability, error) {
	newReq := util.CloneRequest(originalReq)

	if err := p.injectPayload(newReq, paramName, payload); err != nil {
		return nil, err
	}

	resp, err := client.Do(newReq.Request)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if p.detectReflection(body, payload) {
		// 如果检测到反射，并且浏览器服务可用，则进行DOM验证
		if p.browserService != nil {
			// 为了使用 CheckXSSFromHTML，我们需要构造一个包含反射内容的完整HTML页面
			// 这是一个简化的模拟，实际效果取决于服务器如何返回内容
			htmlToCheck := string(body)
			verified, err := p.browserService.CheckXSSFromHTML(htmlToCheck)
			if err != nil {
				log.Warn().Err(err).Msg("XSS DOM验证时出错")
			}
			if !verified {
				log.Info().Str("url", originalReq.URL.String()).Str("param", paramName).Msg("XSS反射被发现，但DOM验证未触发。可能是一个误报或非典型的XSS。")
				return nil, nil // 如果DOM验证不通过，我们认为它不是一个确定的漏洞
			}
		}

		return &vulnscan.Vulnerability{
			Type:          p.Info().Name,
			URL:           originalReq.URL.String(),
			Payload:       payload,
			Param:         paramName,
			Method:        originalReq.Method,
			VulnerableURL: newReq.Request.URL.String(),
			Timestamp:     time.Now(),
		}, nil
	}

	return nil, nil
}

// injectPayload 将payload注入到请求中。
func (p *XSSPlugin) injectPayload(req *models.Request, paramName, payload string) error {
	if req.Method == "POST" {
		// 对于POST请求，我们需要读取body并重新构建它。
		// 注意：这种方式不适用于 multipart/form-data。
		var bodyBytes []byte
		if req.Body != nil {
			bodyBytes, _ = io.ReadAll(req.Body)
			req.Body.Close() // 关闭原始body
		}

		form, err := url.ParseQuery(string(bodyBytes))
		if err != nil {
			// 如果不是合法的form-urlencoded数据，则直接返回错误。
			return err
		}
		form.Set(paramName, payload)
		newBody := form.Encode()
		req.Body = io.NopCloser(strings.NewReader(newBody))
		req.ContentLength = int64(len(newBody))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		q := req.URL.Query()
		q.Set(paramName, payload)
		req.URL.RawQuery = q.Encode()
	}
	return nil
}

// detectReflection 检测payload是否在响应体中被反射。
func (p *XSSPlugin) detectReflection(body []byte, payload string) bool {
	bodyStr := string(body)

	// 1. 直接字符串匹配
	if strings.Contains(bodyStr, payload) {
		return true
	}

	// 2. 检查HTML实体编码后的反射
	encodedPayload := strings.Replace(payload, "<", "&lt;", -1)
	encodedPayload = strings.Replace(encodedPayload, ">", "&gt;", -1)
	if strings.Contains(bodyStr, encodedPayload) {
		return true
	}

	// 3. 检查URL编码后的反射
	if strings.Contains(bodyStr, url.QueryEscape(payload)) {
		return true
	}

	return false
}
