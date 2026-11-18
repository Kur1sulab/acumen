// Package cli —— `all` 子命令：一键全流程编排。
//
// 对应 yata.py:120-178 的 cmd_all（唯一行为基准）：
//   - 目标自动识别 IP / 域名，两条流水线分支；
//   - 每个模块级步骤都包一层 _run_step（yata.py:44-62）：发 start/done|fail
//     进度事件，fatal=true 时异常上抛终止流水线，fatal=false 时降级为警告；
//   - 步骤顺序、警告文案、输出目录语义与 Python 逐项对齐，不做"优化"。
//
// 终态差异（Go 侧比 Python 多）：patchdiff 不在 all 里跑（Python 同）——
// 它需要 -r 指定本地仓库，无法从 target 推导。
package cli

import (
	"fmt"

	"github.com/Kur1sulab/kara/engine-go/apiunauth"
	"github.com/Kur1sulab/kara/engine-go/fingerprint"
	"github.com/Kur1sulab/kara/engine-go/paths"
	"github.com/Kur1sulab/kara/engine-go/report"
	"github.com/Kur1sulab/kara/engine-go/subdomain"
)

// step 是 _run_step 的 Go 版：发事件 + 按 fatal 决定是否把错误当致命。
// 返回 (值, 是否继续)：err != nil && fatal 时调用方立即退出非零。
func step(name string, fatal bool, fn func() error) error {
	emit("start", name, "")
	if err := fn(); err != nil {
		emit("fail", name, err.Error())
		if fatal {
			return err
		}
		fmt.Printf("[!] %s 失败（不影响主流程）: %v\n", name, err)
		return nil
	}
	emit("done", name, "")
	return nil
}

// runAll 执行一键全流程，返回进程退出码。
func runAll(target string) int {
	out, err := MakeOutdir(target)
	if err != nil {
		fmt.Printf("[!] 输出目录创建失败: %v\n", err)
		return 1
	}

	if IsIP(target) {
		return runAllIP(target, out)
	}
	return runAllDomain(target, out)
}

// runAllIP：内网 IP 目标 —— 端口 → 指纹 → 路径 → API。
//
// 老版本这里是「IP 反查域名 → ICP 备案」，两个都要连公网服务（hackertarget / apihz），
// 断网环境里第一步就卡死。现在只做目标身上能直接看到的事。
func runAllIP(target, out string) int {
	_ = step("portscan", false, func() error { return runPortStep(target, out) })

	base := PickBase(target)
	fmt.Printf("[*] 目标站点探测 base = %s\n", base)

	_ = step("fingerprint", false, func() error {
		fingerprint.RunFingerprint(base, out)
		return nil
	})
	_ = step("paths", false, func() error {
		_, err := paths.RunPaths(base, out)
		return err
	})
	_ = step("api", false, func() error {
		_, err := apiunauth.RunAPI(base, out, false)
		return err
	})
	_ = step("jsintel", false, func() error { return runJSStep(base, out) })
	_ = step("baseline", false, func() error {
		return runBaselineStep(base, target, out)
	})

	return finishAll(out, target)
}

// runAllDomain：域名目标 —— 本地 DNS 子域爆破 → 验活 → 指纹 → 路径 → API → JS → 端口 → 基线。
func runAllDomain(target, out string) int {
	if err := step("subdomain", true, func() error {
		res, err := subdomain.RunOptions(nil, target, out, subdomain.Options{})
		if err != nil {
			return err
		}
		fmt.Printf("[*] 本地 DNS 爆破：字典 %d 条，命中 %d 个子域（无泛解析: %v）\n",
			res.Words, len(res.Found), !res.Wildcard)
		return nil
	}); err != nil {
		fmt.Printf("[!] subdomain: %v\n", err)
		return 1
	}

	// 命中后验证存活（DNS 已通过，这里补 HTTP 探活，走的是目标自己）
	_ = step("verify", false, func() error {
		subdomain.RunVerify(out, 8, true)
		return nil
	})

	base := PickBase(target)
	fmt.Printf("[*] 目标站点探测 base = %s\n", base)

	if err := step("fingerprint", true, func() error {
		fingerprint.RunFingerprint(base, out)
		return nil
	}); err != nil {
		fmt.Printf("[!] fingerprint: %v\n", err)
		return 1
	}
	if err := step("paths", true, func() error {
		_, err := paths.RunPaths(base, out)
		return err
	}); err != nil {
		fmt.Printf("[!] paths: %v\n", err)
		return 1
	}
	if err := step("api", true, func() error {
		_, err := apiunauth.RunAPI(base, out, false)
		return err
	}); err != nil {
		fmt.Printf("[!] api: %v\n", err)
		return 1
	}

	_ = step("jsintel", false, func() error { return runJSStep(base, out) })
	_ = step("portscan", false, func() error { return runPortStep(target, out) })
	_ = step("baseline", false, func() error { return runBaselineStep(base, target, out) })
	_ = step("cve", false, func() error { return runCVEStep(base, out) })

	return finishAll(out, target)
}

// finishAll：report 收尾（聚合资产档案 + 证据包），Python 侧同为 fatal 步骤。
func finishAll(out, target string) int {
	if err := step("report", true, func() error {
		report.RunReport(out, target)
		return nil
	}); err != nil {
		fmt.Printf("[!] report: %v\n", err)
		return 1
	}
	fmt.Printf("[+] 全流程完成，输出目录: %s\n", out)
	return 0
}
