package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Kur1sulab/kara/engine-go/litmus/engine"
	"github.com/Kur1sulab/kara/engine-go/litmus/model"
	"github.com/Kur1sulab/kara/engine-go/litmus/report"
	"github.com/Kur1sulab/kara/engine-go/litmus/scope"
)

// cmdRun 跑一轮：目标 → 引擎 → 证据 → 报告 → 汇总打印。
//
// 落盘顺序与 Python 版 litmus.py 的 cmd_run 一致：
// 先证据（每条发现一个 txt），再报告（md + 自包含 html + findings.json）。
// 顺序不能反 —— 报告里要引用 evidence/ 的相对路径。
func cmdRun(args []string) int {
	a, err := parseRunArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "参数错误: %v\n", err)
		return 2
	}
	opts := a.toOptions()

	raws, err := a.rawTargets()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}
	if len(raws) == 0 {
		fmt.Fprintln(os.Stderr, "没有目标。用 -t <IP/CIDR/URL> 或 -T <文件> 指定。")
		return 2
	}

	out := opts.OutDir
	if out == "" {
		out = filepath.Join("runs", time.Now().Format("20060102-150405"))
	}
	opts.OutDir = out
	if opts.StateDir == "" {
		opts.StateDir = filepath.Join(out, "state")
	}
	// VDI 上从只读共享盘、映射网络盘、受保护目录启动是常态：MkdirAll 会失败。
	// 直接退出等于「工具拷进去了却跑不了」，比结果落在临时目录糟糕得多。
	// 所以退一级到系统临时目录，并把实际落点明确打出来 —— 别让人找不到报告。
	if err := os.MkdirAll(out, 0o755); err != nil {
		fallback := filepath.Join(os.TempDir(), "litmus-runs", time.Now().Format("20060102-150405"))
		fmt.Fprintf(os.Stderr, "[!] 输出目录 %s 不可写（%v）\n", out, err)
		fmt.Fprintf(os.Stderr, "[!] 改用临时目录：%s\n", fallback)
		out = fallback
		opts.OutDir = out
		opts.StateDir = filepath.Join(out, "state")
		if err2 := os.MkdirAll(out, 0o755); err2 != nil {
			fmt.Fprintf(os.Stderr, "建输出目录失败（连临时目录也不可写）: %v\n", err2)
			return 1
		}
	}

	eng := engine.New(opts)
	res, err := eng.Run(raws)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}

	// 1) 证据
	evPaths, err := engine.WriteEvidence(res.Findings, out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] 写证据失败: %v\n", err)
	}

	// 2) 报告（md + html + findings.json 一次写全）
	paths, err := report.WriteReports(res, out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] 写报告失败: %v\n", err)
	}

	// 3) 汇总
	counts := map[string]int{}
	for _, f := range res.Findings {
		counts[f.Severity]++
	}
	fmt.Println("\n" + "==============================================================")
	fmt.Printf("发现 %d 条  ", len(res.Findings))
	parts := ""
	for _, s := range model.Severities {
		parts += fmt.Sprintf("%s=%d  ", model.SevCN[s], counts[s])
	}
	fmt.Println(parts)
	for _, f := range res.Findings {
		fmt.Printf("  %s [%s/%s] %s  @ %s\n", f.ID, f.SevCNOf(), f.Level, f.Name, f.Target)
	}
	fmt.Println("--------------------------------------------------------------")
	fmt.Printf("报告   : %s\n", paths.Markdown)
	fmt.Printf("         %s\n", paths.HTML)
	fmt.Printf("数据   : %s\n", paths.JSON)
	if len(evPaths) > 0 {
		fmt.Printf("证据   : %d 份 → %s\n", len(evPaths), filepath.Join(out, "evidence"))
	}
	if len(res.Findings) > 0 {
		fmt.Printf("复验   : %d 条 → litmus replay -f %s --id <ID>\n",
			len(res.Findings), filepath.Join(out, "findings.json"))
	}
	fmt.Printf("耗时   : %ss\n", formatElapsed(res.Elapsed))
	fmt.Println("==============================================================")

	if a.asJSON {
		summary := map[string]interface{}{
			"run_id":   res.RunID,
			"counts":   counts,
			"findings": summarize(res.Findings),
			"reports": map[string]string{
				"markdown": paths.Markdown, "html": paths.HTML, "json": paths.JSON,
			},
			"out": out,
		}
		b, _ := json.MarshalIndent(summary, "", "  ")
		fmt.Println(string(b))
	}
	return 0
}

func summarize(fs []*model.Finding) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(fs))
	for _, f := range fs {
		out = append(out, map[string]interface{}{
			"id": f.ID, "name": f.Name, "severity": f.Severity,
			"level": f.Level, "target": f.Target, "poc": f.PoC,
		})
	}
	return out
}

func formatElapsed(v float64) string {
	if v == float64(int64(v)) {
		return fmt.Sprintf("%d.0", int64(v))
	}
	return fmt.Sprintf("%g", v)
}

// 以下子命令在协议模块全部装配后补实；现在明确报「未实现」而不是假装成功。
func cmdSelftest(args []string) int {
	fmt.Fprintln(os.Stderr, "selftest: 待接入（用 go test ./... 验证各包）")
	return 1
}

func cmdReport(args []string) int {
	fmt.Fprintln(os.Stderr, "report: 待接入（读 findings.json 重渲染）")
	return 1
}

func cmdDiff(args []string) int {
	fmt.Fprintln(os.Stderr, "diff: 待接入")
	return 1
}

func cmdResume(args []string) int {
	fmt.Fprintln(os.Stderr, "resume: 待接入（用 run --resume --out <目录> 续跑）")
	return 1
}

var _ = scope.Expand // 保留 import 用于将来的 resume 子命令
