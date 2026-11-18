//go:build !windows

package main

import "os"

// myUID 让 doctor 能显示「是不是 root」。Kali / 跳板机上跑的时候这一行很关键：
// 非 root 扫 SYN 会静默降级成 connect 扫描，端口广度直接掉一个档。
func myUID() int { return os.Geteuid() }
