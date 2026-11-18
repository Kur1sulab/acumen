// strike：Kara 的深度验证模式（原生实现，不再依赖外部 litmus 二进制）。
//
// 分工没变，归属变了：只读观测（fingerprint/paths/api/…）来自引擎自己的模块；
// 「这是不是真漏洞、能不能打进去」由内建的验证内核做（engine-go/litmus/*，
// 移植自 litmus2，零第三方依赖）。它现在跟其它模式一样，是同一条流水线里的一步：
// 产物落在 out/<target>/strike/，由 Kara 的解析器归一化入账，可复验、可导出。
package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Kur1sulab/kara/engine-go/litmus/engine"
	"github.com/Kur1sulab/kara/engine-go/litmus/model"
	"github.com/Kur1sulab/kara/engine-go/litmus/report"
)

const strikeUsage = "strike -t <target> [-o <dir>] [--intensity low|normal|high] " +
	"[--ports top100|top1000|full|80,443] [--allow-public] [-q]"

// runStrike 跑一轮深度验证。返回进程退出码（命中与否不改变退出码）。
func runStrike(rest []string, cmd string) int {
	fs := newFlagSet()
	target := fs.String("t", "", "")
	targetAlias := fs.String("target", "", "")
	outFlag := fs.String("o", "", "输出目录（默认 out/<target>/strike）")
	intensity := fs.String("intensity", "normal", "强度档位：low / normal / high")
	ports := fs.String("ports", "", "端口范围：top100 / top1000 / full / 80,443,1-1024")
	threads := fs.Int("threads", 0, "并发线程（0 = 按强度档）")
	allowPublic := fs.Bool("allow-public", false, "允许公网目标（内网框架默认只放行私网/回环）")
	noAuth := fs.Bool("no-auth-probe", false, "跳过服务级真登验证")
	noWeb := fs.Bool("no-web", false, "跳过 Web 侧检查")
	templates := fs.String("templates", "", "nuclei 模板目录（可选）")
	creds := fs.Int("creds", -1, "口令尝试次数上限（-1 = 按强度档，0 = 不做口令尝试）")
	quiet := fs.Bool("q", false, "安静模式（只打最终汇总）")
	if c := parseOrUsage(fs, rest, cmd, strikeUsage); c != -1 {
		return c
	}
	tgt := pickAliasLastWins(rest, map[string]*string{"-t": target, "--target": targetAlias})
	if strings.TrimSpace(tgt) == "" {
		return missingArgs(cmd, strikeUsage)
	}

	emit("start", "strike", tgt)

	outDir := strings.TrimSpace(*outFlag)
	if outDir == "" {
		base, err := MakeOutdir(tgt)
		if err != nil {
			fmt.Printf("[!] 输出目录创建失败: %v\n", err)
			emit("fail", "strike", err.Error())
			return 1
		}
		outDir = filepath.Join(base, "strike")
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Printf("[!] 输出目录创建失败: %v\n", err)
		emit("fail", "strike", err.Error())
		return 1
	}

	var credPtr *int
	if *creds >= 0 {
		v := *creds
		credPtr = &v
	}
	opts := engine.NewOptions(*intensity, *threads, 0, *allowPublic, *ports, 0,
		outDir, filepath.Join(outDir, "state"), false, false,
		*templates, credPtr, *noAuth, *noWeb, !*quiet)

	eng := engine.New(opts)
	res, runErr := eng.Run([]string{tgt})
	if runErr != nil {
		fmt.Printf("[!] 验证失败: %v\n", runErr)
		emit("fail", "strike", runErr.Error())
		return 1
	}

	// 顺序不能反：报告里要引用 evidence/ 的相对路径
	if _, err := engine.WriteEvidence(res.Findings, outDir); err != nil && !*quiet {
		fmt.Printf("[!] 写证据失败: %v\n", err)
	}
	paths, err := report.WriteReports(res, outDir)
	if err != nil {
		fmt.Printf("[!] 写报告失败: %v\n", err)
		emit("fail", "strike", err.Error())
		return 1
	}

	counts := map[string]int{}
	for _, f := range res.Findings {
		counts[f.Severity]++
	}
	fmt.Printf("[+] 深度验证完成：%d 条（", len(res.Findings))
	parts := make([]string, 0, 5)
	for _, s := range model.Severities {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", model.SevCN[s], counts[s]))
		}
	}
	fmt.Printf("%s）\n", strings.Join(parts, " / "))
	for _, f := range res.Findings {
		fmt.Printf("    [%s/%s] %s  @ %s\n", f.SevCNOf(), f.Level, f.Name, f.Target)
	}
	fmt.Printf("    数据 -> %s\n", paths.JSON)

	// 覆盖率（三态）也打出来：没测的检查项不能伪装成「没漏洞」
	skips := 0
	for _, c := range res.Coverage {
		if c.State == "skip" {
			skips++
		}
	}
	if skips > 0 {
		fmt.Printf("    覆盖：%d 项跳过（原因见 findings.json 的 coverage）\n", skips)
	}
	emit("done", "strike", fmt.Sprintf("%d 条命中", len(res.Findings)))
	return 0
}
