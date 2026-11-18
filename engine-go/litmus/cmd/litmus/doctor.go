package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// cmdDoctor 在陌生环境里先跑一次：客户 VDI、跳板机、只读共享盘、域受限桌面。
//
// 现场最贵的成本不是技术难度，是「不知道卡在哪一步」。工具拷进 VDI 后第一件事
// 不该是直接扫，而是确认四件事：能不能写盘、中文会不会乱码、网络栈通不通、
// 时钟对不对（时间戳错乱会让证据链失真）。doctor 就是把这四件事一次性摊开。
func cmdDoctor(args []string) int {
	line := strings.Repeat("─", 62)
	fmt.Printf("%s\n litmus doctor —— 陌生环境自检\n%s\n\n", line, line)

	bad := 0

	// ── 1. 环境 ────────────────────────────────────────────────
	fmt.Println("[环境]")
	exe, _ := os.Executable()
	cwd, _ := os.Getwd()
	fmt.Printf("  %s%s (%s/%s, %s)\n", pad("版本", 12), Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
	fmt.Printf("  %s%s\n", pad("可执行文件", 12), exe)
	fmt.Printf("  %s%s\n", pad("工作目录", 12), cwd)
	fmt.Printf("  %s%s\n", pad("临时目录", 12), os.TempDir())
	now := time.Now()
	_, offset := now.Zone()
	fmt.Printf("  %s%s (UTC%+03d:%02d)\n", pad("系统时间", 12), now.Format("2006-01-02 15:04:05"), offset/3600, abs(offset/60)%60)
	fmt.Printf("  %s%s\n", pad("运行身份", 12), userLabel())

	// ── 2. 写盘 ────────────────────────────────────────────────
	fmt.Println("\n[写盘]")
	// VDI 上从只读共享盘、映射盘、受保护目录启动是常态。
	// 这不是理论风险 —— 写不进去就等于跑不了，必须提前暴露。
	targets := []struct{ name, dir string }{
		{"当前目录", cwd},
		{"默认输出", filepath.Join(cwd, "runs")},
		{"临时目录", filepath.Join(os.TempDir(), "litmus-doctor")},
	}
	for _, t := range targets {
		ok, why := dirWritable(t.dir)
		if ok {
			fmt.Printf("  %s ✓ 可写   %s\n", pad(t.name, 10), t.dir)
		} else {
			fmt.Printf("  %s ✗ 不可写 %s\n             原因: %s\n", pad(t.name, 10), t.dir, why)
			if t.name != "当前目录" {
				bad++
			}
		}
	}

	// ── 3. 控制台 ──────────────────────────────────────────────
	fmt.Println("\n[控制台]")
	if runtime.GOOS == "windows" {
		cp := consoleCodePage()
		switch {
		case cp == 65001:
			fmt.Printf("  %s%d (UTF-8) ✓\n", pad("代码页", 10), cp)
		case cp == 0:
			fmt.Printf("  %s无控制台（输出被重定向，字节原样落盘）\n", pad("代码页", 10))
		default:
			fmt.Printf("  %s%d ✗ 不是 UTF-8，中文会乱码\n", pad("代码页", 10), cp)
			bad++
		}
	} else {
		fmt.Printf("  %s不适用（%s 终端默认 UTF-8）\n", pad("代码页", 10), runtime.GOOS)
	}
	fmt.Printf("  中文渲染   发现 2 条  严重=0  高危=0  低危=1  信息=1\n")
	fmt.Printf("              ↑ 上一行若显示为方块/问号，说明终端字体缺中文字形\n")

	// ── 4. 网络 ────────────────────────────────────────────────
	fmt.Println("\n[网络]")
	ifaces, _ := net.Interfaces()
	nUp := 0
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		var v4 []string
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				v4 = append(v4, ipn.String())
			}
		}
		if len(v4) == 0 {
			continue
		}
		nUp++
		fmt.Printf("  %s %s\n", pad(trunc(ifc.Name, 12), 16), strings.Join(v4, ", "))
	}
	if nUp == 0 {
		fmt.Println("  ✗ 没有已启用的 IPv4 网卡 —— 检查 VDI 网络适配器")
		bad++
	}
	// 回环连通性：连一个必然没人监听的端口，拿到 connection refused 就说明栈是通的。
	c, err := net.DialTimeout("tcp", "127.0.0.1:1", 900*time.Millisecond)
	if err != nil {
		if strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "积极拒绝") {
			fmt.Printf("  回环测试   ✓ 网络栈正常（127.0.0.1:1 如预期被拒）\n")
		} else {
			fmt.Printf("  回环测试   ✗ %v\n", err)
			bad++
		}
	} else {
		c.Close()
		fmt.Printf("  回环测试   ✓ 127.0.0.1:1 有服务在听（异常但不影响扫描）\n")
	}

	// ── 结论 ───────────────────────────────────────────────────
	fmt.Printf("\n%s\n", line)
	if bad == 0 {
		fmt.Println(" 结论：环境可跑。直接开始，例如：")
		fmt.Println("   litmus run -t 10.0.0.0/24 -p top1000 --out runs/first")
		fmt.Println("\n 报告产物：<out>/report.html（浏览器打开，自包含无外链）")
		fmt.Println("           <out>/report.md   <out>/findings.json")
	} else {
		fmt.Printf(" 结论：发现 %d 处需要处理，见上方 ✗ 项。\n", bad)
	}
	fmt.Println(line)
	return 0
}

// pad 按「显示宽度」补空格。Go 的 %-10s 数的是字节，中文一个字 3 字节，
// 用它对齐必然错位 —— 现场看报告的人第一印象就是「这工具怎么歪的」。
func pad(s string, w int) string {
	n := 0
	for _, r := range s {
		if r >= 0x1100 && (r <= 0x115F || r == 0x2329 || r == 0x232A ||
			(r >= 0x2E80 && r <= 0xA4CF) || (r >= 0xAC00 && r <= 0xD7A3) ||
			(r >= 0xF900 && r <= 0xFAFF) || (r >= 0xFE30 && r <= 0xFE6F) ||
			(r >= 0xFF00 && r <= 0xFF60) || (r >= 0xFFE0 && r <= 0xFFE6)) {
			n += 2
		} else {
			n++
		}
	}
	if n >= w {
		return s
	}
	return s + strings.Repeat(" ", w-n)
}

// dirWritable 真写一个文件再删，不靠权限位猜 —— ACL、只读挂载、AV 拦截
// 都能让 os.Stat 看起来正常而写不进去。
func dirWritable(dir string) (bool, string) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, err.Error()
	}
	f := filepath.Join(dir, ".litmus-write-test")
	if err := os.WriteFile(f, []byte("ok"), 0o644); err != nil {
		return false, err.Error()
	}
	// 删不掉不算致命：Windows 上 AV 可能短暂持有句柄。
	_ = os.Remove(f)
	return true, ""
}

func userLabel() string {
	u := os.Getenv("USER")
	if u == "" {
		u = os.Getenv("USERNAME")
	}
	if u == "" {
		u = "未知"
	}
	if uid := myUID(); uid >= 0 {
		if uid == 0 {
			return u + " (uid 0, root)"
		}
		return fmt.Sprintf("%s (uid %d)", u, uid)
	}
	return u
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
