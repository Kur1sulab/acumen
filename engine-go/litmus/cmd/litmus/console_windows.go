//go:build windows

package main

import "syscall"

// Windows 控制台默认代码页是 936(GBK)，而 Go 往 stdout 写的是 UTF-8 字节流。
// 不切代码页的直接后果：现场跑出来满屏「鍙戠幇 2 鏉」，报告里的中文全成乱码，
// 客户 VDI 上第一眼就以为工具坏了。
//
// 这里只调 kernel32 三个导出函数，不引入 golang.org/x/sys —— 那会给 go.mod
// 加 require，违背「静态单文件、零第三方依赖」的交付前提。
var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procSetConsoleCP       = kernel32.NewProc("SetConsoleCP")
	procSetConsoleOutputCP = kernel32.NewProc("SetConsoleOutputCP")
	procGetConsoleOutputCP = kernel32.NewProc("GetConsoleOutputCP")
)

const cpUTF8 = 65001

// initConsole 把控制台输入/输出代码页都切成 UTF-8。
// 输出被重定向（> file / 管道）时没有控制台，调用会失败 —— 忽略即可，
// 那种情况下字节是原样落盘的，本来就是 UTF-8。
func initConsole() {
	if procSetConsoleOutputCP.Find() == nil {
		procSetConsoleOutputCP.Call(cpUTF8)
	}
	if procSetConsoleCP.Find() == nil {
		procSetConsoleCP.Call(cpUTF8)
	}
}

// consoleCodePage 返回当前控制台输出代码页；无控制台时返回 0。
func consoleCodePage() int {
	if procGetConsoleOutputCP.Find() != nil {
		return 0
	}
	r, _, _ := procGetConsoleOutputCP.Call()
	return int(r)
}
