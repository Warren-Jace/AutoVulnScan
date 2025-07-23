// Package main 是程序的入口包
package main

import "autovulnscan/cmd"

// main 函数是程序的入口函数
func main() {
	// 调用 cmd 包的 Execute 函数来执行程序
	cmd.Execute()
}
