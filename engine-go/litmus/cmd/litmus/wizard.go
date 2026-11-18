package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// wizard 是给「双击 exe」准备的入口。
//
// 客户 VDI 上没人会开 cmd 敲一长串参数 —— 双击后窗口闪一下就消失，第一反应是
// 「这工具坏了」。所以：无参数 + 连着终端 → 进问答；只要给了参数（脚本、批处理、
// 自动化）→ 行为完全不变。两条路互不干扰。
func interactiveWizard() int {
	return wizardRun(os.Stdin, os.Stdout)
}

// wizardRun 与 IO 解耦，好让测试能喂字符串进去。
// 现场的问答是工具在 VDI 上的唯一入口，不能只靠手工点一次就算验证过。
func wizardRun(in io.Reader, out io.Writer) int {
	r := bufio.NewReader(in)

	fmt.Fprintln(out, "──────────────────────────────────────────────────────────────")
	fmt.Fprintf(out, " litmus2 %s —— 内网授权渗透验证框架\n", Version)
	fmt.Fprintln(out, "──────────────────────────────────────────────────────────────")
	fmt.Fprintln(out, " 直接回车 = 用方括号里的默认值；输入 q 退出。")
	fmt.Fprintln(out)

	// 第一项必须给：没有目标什么都没意义。
	var targets string
	for {
		fmt.Fprint(out, " 目标（IP / IP段 / URL，多个用逗号分隔）: ")
		line, err := r.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" && err != nil {
			fmt.Fprintln(out, "\n 没有读到输入，退出。")
			return 2
		}
		if line == "q" || line == "Q" {
			return 0
		}
		if line != "" {
			targets = line
			break
		}
		fmt.Fprintln(out, "   ↑ 这项不能空着。")
	}

	ports := ask(r, out, " 端口（top100 / top1000 / full / 80,443,1-1024）", "top100")
	intensity := ask(r, out, " 强度（low / normal / high）", "normal")
	threads := ask(r, out, " 并发数（回车=按强度自动）", "")
	creds := ask(r, out, " 口令尝试次数上限（0=不做口令尝试）", "3")
	outDir := ask(r, out, " 输出目录", defaultOutDir())

	fmt.Fprintln(out)
	fmt.Fprintln(out, " ── 即将执行 ──────────────────────────────────────────────")
	fmt.Fprintf(out, "   目标   : %s\n", targets)
	fmt.Fprintf(out, "   端口   : %s\n", ports)
	fmt.Fprintf(out, "   强度   : %s\n", intensity)
	if threads != "" {
		fmt.Fprintf(out, "   并发   : %s\n", threads)
	}
	fmt.Fprintf(out, "   口令   : 最多 %s 次/服务\n", creds)
	fmt.Fprintf(out, "   输出   : %s\n", outDir)
	fmt.Fprintln(out, " ──────────────────────────────────────────────────────────")
	fmt.Fprint(out, " 开始？[Y/n]: ")
	ans, _ := r.ReadString('\n')
	ans = strings.ToLower(strings.TrimSpace(ans))
	if ans != "" && ans != "y" && ans != "yes" && ans != "是" {
		fmt.Fprintln(out, " 已取消。")
		return 0
	}
	fmt.Fprintln(out)

	// 复用 run 的参数解析，保证向导与命令行走同一条代码路径 ——
	// 否则「双击能跑但命令行跑不一样」这种分叉最难查。
	// 目标里的逗号拆成多个 -t，run 的 -t 本来就支持重复。
	args := []string{"-p", ports, "--intensity", intensity, "--creds", creds, "--out", outDir}
	for _, t := range strings.Split(targets, ",") {
		if t = strings.TrimSpace(t); t != "" {
			args = append(args, "-t", t)
		}
	}
	if threads != "" {
		args = append(args, "--threads", threads)
	}
	return cmdRun(args)
}

// ask 读一行，空则取默认。stdin 提前 EOF 时返回默认，不让程序卡死在 EOF 上。
func ask(r *bufio.Reader, out io.Writer, prompt, def string) string {
	if def != "" {
		fmt.Fprintf(out, "%s [%s]: ", prompt, def)
	} else {
		fmt.Fprintf(out, "%s: ", prompt)
	}
	line, err := r.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" && err != nil {
		fmt.Fprintln(out)
		return def
	}
	if line == "" || line == "q" || line == "Q" {
		return def
	}
	return line
}

// defaultOutDir 优先用桌面，让报告一眼能看见；桌面不可用时退回临时目录。
// VDI 上桌面常被重定向到服务器路径（\\fileserver\users\xxx\Desktop），写不进去
// 也不奇怪，所以每一步都验一下而不是假设。
func defaultOutDir() string {
	name := "litmus-" + nowStamp()
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		for _, sub := range []string{"Desktop", "桌面", filepath.Join("OneDrive", "Desktop")} {
			d := filepath.Join(home, sub)
			if fi, err := os.Stat(d); err == nil && fi.IsDir() {
				if ok, _ := dirWritable(filepath.Join(d, ".litmus-probe")); ok {
					return filepath.Join(d, name)
				}
			}
		}
	}
	if cwd, err := os.Getwd(); err == nil {
		return filepath.Join(cwd, name)
	}
	return filepath.Join(os.TempDir(), name)
}

func nowStamp() string { return time.Now().Format("20060102-150405") }

// isTerminal 判断 stdout 是不是连着终端。双击 exe 会新开控制台（是终端），
// 重定向到文件/管道时不是 —— 那种情况下不该弹问答，直接打用法。
func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil || fi == nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
