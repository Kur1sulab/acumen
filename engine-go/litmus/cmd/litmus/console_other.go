//go:build !windows

package main

// 非 Windows 平台的空实现。终端本来就是 UTF-8（或由 LANG 决定），
// 不需要也不应该去动代码页。
func initConsole() {}

// consoleCodePage 在非 Windows 上无意义，返回 0 让调用方显示「不适用」。
func consoleCodePage() int { return 0 }
