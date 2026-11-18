//go:build windows

package main

// Windows 没有 uid 概念，用 SID 判断管理员要麻烦得多（还要 OpenProcessToken）。
// doctor 只用来回答「我是不是以高权限在跑」，Windows 上返回 -1 表示不适用。
func myUID() int { return -1 }
