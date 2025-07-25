// Package cmd 包含了 AutoVulnScan 的所有命令行相关逻辑。
package cmd

import (
	"log"
	"net/http"
	"net/http/httputil"

	"github.com/spf13/cobra"
)

// proxyCmd 实现了 'proxy' 子命令，用于启动一个简单的HTTP代理服务器。
// 这个代理服务器可以用来拦截和检查通过它的HTTP流量，便于调试和分析。
var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "启动一个简单的HTTP代理服务器，用于流量检查",
	Long:  `此命令会启动一个监听在指定地址的HTTP代理。所有通过此代理的请求和响应都将被完整地打印到控制台，这对于分析应用程序的网络行为非常有用。`,
	Run: func(cmd *cobra.Command, args []string) {
		// 从命令行标志获取监听地址
		listenAddr, _ := cmd.Flags().GetString("listen")
		log.Printf("代理服务器正在监听 %s", listenAddr)

		// 创建一个新的反向代理处理器
		// ReverseProxy 是一个HTTP处理器，它接收传入的HTTP请求，
		// 并将其转发到另一个服务器，然后将响应写回原始客户端。
		proxy := &httputil.ReverseProxy{
			// Director 是一个函数，它会被每个传入的请求调用。
			// 它的职责是修改请求，使其能够被正确地转发到目标服务器。
			Director: func(req *http.Request) {
				// 打印原始请求的详细信息
				dump, err := httputil.DumpRequest(req, true)
				if err != nil {
					log.Printf("转储请求失败: %v", err)
				} else {
					log.Printf("接收到请求:\n%s", string(dump))
				}
			},
			// ModifyResponse 是一个函数，它会在收到来自目标服务器的响应后被调用。
			// 它的职责是修改响应，然后再将其发送回原始客户端。
			ModifyResponse: func(resp *http.Response) error {
				// 打印响应的详细信息
				dump, err := httputil.DumpResponse(resp, true)
				if err != nil {
					log.Printf("转储响应失败: %v", err)
				} else {
					log.Printf("收到响应:\n%s", string(dump))
				}
				return nil
			},
		}

		// 启动HTTP服务器，并将所有请求都交由代理处理器处理。
		// 如果启动失败，程序将以致命错误退出。
		log.Fatal(http.ListenAndServe(listenAddr, proxy))
	},
}

func init() {
	rootCmd.AddCommand(proxyCmd)
	// 为 'proxy' 命令添加一个名为 "listen" 的命令行标志，用于指定代理服务器的监听地址。
	// 第一个参数是标志的名称，第二个是缩写，第三个是默认值，第四个是帮助信息。
	proxyCmd.Flags().StringP("listen", "l", ":8080", "代理服务器的监听地址")
}
