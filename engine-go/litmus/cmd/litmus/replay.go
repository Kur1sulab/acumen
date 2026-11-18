package main

// replay.go —— 单条发现的「就地复验」。
//
// 与 Python 版 pocgen.py 的关键差别：Python 生成 poc/*.py 脚本，靠
// `python3 poc/LS-001-xxx.py` 复验；但 Go 版存在的理由就是「目标机没有 Python」，
// 生成 .py 等于把交付物钉死在一个不存在的解释器上。
//
// 所以这里把 PoC 做成二进制内置的子命令：读 findings.json 找到那条发现，
// 按 check 名分发到对应的探针重跑一遍，再把「原证据」与「本次证据」并排打出来。
// 判定标准很硬：本次必须重新拿到同样的结论才算复验通过；拿不到就是「已消失」。

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Kur1sulab/kara/engine-go/litmus/httpc"
	"github.com/Kur1sulab/kara/engine-go/litmus/model"
	"github.com/Kur1sulab/kara/engine-go/litmus/tpl"
	"github.com/Kur1sulab/kara/engine-go/litmus/webcheck"
	"github.com/Kur1sulab/kara/engine-go/litmus/winproto"
)

// replayFinding findings.json 里的一条记录（只取复验用得到的字段）
type replayFinding struct {
	ID       string `json:"id"`
	Check    string `json:"check"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Level    string `json:"level"`
	Target   string `json:"target"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Scheme   string `json:"scheme"`
	Evidence string `json:"evidence"`
}

type replayFile struct {
	Findings []replayFinding `json:"findings"`
	// Opts 只取复验时需要的那几项。模板类发现（tpl-*）必须知道当初
	// 用的是哪个模板目录，否则复验只能干瞪眼。
	Opts struct {
		Templates string `json:"templates"`
	} `json:"opts"`
}

func cmdReplay(args []string) int {
	var (
		file    string
		id      string
		timeout = 8.0
	)
	rest := args
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		next := func() string {
			if i+1 < len(rest) {
				i++
				return rest[i]
			}
			return ""
		}
		switch a {
		case "-f", "--file", "--findings":
			file = next()
		case "--id", "-i":
			id = next()
		case "--timeout":
			if v, err := strconv.ParseFloat(next(), 64); err == nil && v > 0 {
				timeout = v
			}
		case "--list", "-l":
			if file == "" {
				fmt.Fprintln(os.Stderr, "--list 需要先给 -f findings.json")
				return 2
			}
			return replayList(file)
		case "-h", "--help":
			fmt.Print(replayUsage)
			return 0
		default:
			fmt.Fprintf(os.Stderr, "未知参数: %s\n%s", a, replayUsage)
			return 2
		}
	}
	if file == "" || id == "" {
		fmt.Fprint(os.Stderr, replayUsage)
		return 2
	}

	rf, err := loadReplayFile(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读 %s 失败: %v\n", file, err)
		return 1
	}
	var target *replayFinding
	for i := range rf.Findings {
		if strings.EqualFold(rf.Findings[i].ID, id) {
			target = &rf.Findings[i]
			break
		}
	}
	if target == nil {
		fmt.Fprintf(os.Stderr, "findings.json 里没有 id=%s\n", id)
		fmt.Fprintf(os.Stderr, "用 --list 看全部：litmus replay -f %s --list\n", file)
		return 2
	}

	fmt.Printf("=== 复验 %s · %s ===\n", target.ID, target.Name)
	fmt.Printf("目标   : %s\n", target.Target)
	fmt.Printf("等级   : %s / %s\n", sevCN(target.Severity), target.Level)
	fmt.Println()
	fmt.Println("--- 原始证据（来自 findings.json）---")
	fmt.Println(strings.TrimRight(target.Evidence, "\n"))
	fmt.Println()

	got, cannot := replayOne(*target, timeout, rf.Opts.Templates)
	fmt.Println("--- 本次复验 ---")
	if cannot != "" {
		fmt.Printf("（无法复验：%s）\n", cannot)
		fmt.Println()
		fmt.Println("判定：**未复验** —— 这次的环境和原始扫描不一致，既不能说还在，也不能说没了。")
		return 3
	}
	if got == nil {
		fmt.Println("（探针未返回任何结论）")
		fmt.Println()
		fmt.Println("判定：**已消失 / 无法复现** —— 这条发现现在不成立，别写进最终报告。")
		return 1
	}
	fmt.Println(strings.TrimRight(got.Evidence, "\n"))
	fmt.Println()

	fmt.Println("--- 判定 ---")
	if got.Check == target.Check {
		fmt.Printf("✅ 复现成功：本次仍拿到 check=%s，与原始记录一致。\n", got.Check)
		if got.Evidence == target.Evidence {
			fmt.Println("   证据逐字相同。")
		} else {
			fmt.Println("   证据有差异（时间戳/端口顺序/会话随机数是正常的；")
			fmt.Println("   若差异落在判定依据那一行，说明服务端行为变了，要看两段原文比对）。")
		}
		fmt.Printf("   证据落盘：%s\n", saveReplayEvidence(target.ID, got.Evidence))
		return 0
	}
	fmt.Printf("⚠️ 结论变了：原 %s → 本次 %s\n", target.Check, got.Check)
	fmt.Println("   目标可能补了修复，也可能换了服务。按当前实际行为改报告，别沿用旧结论。")
	return 1
}

// replayOne 按 check 名分发复验。
// replayOne 重跑一条发现的探针。
//
// 返回两个值：found 是复验结果（nil = 探针跑通了但没再命中）；
// cannot 非空表示「这次根本没法测」（比如模板目录没了），
// 此时必须报「未复验」而不是「已消失」—— 后者会被当成漏洞已修复。
func replayOne(f replayFinding, timeout float64, tplDir string) (*model.Finding, string) {
	d := time.Duration(timeout * float64(time.Second))
	host := f.Host
	if host == "" {
		host = hostOfTarget(f.Target)
	}
	check := f.Check

	switch {
	case strings.HasPrefix(check, "tpl-"):
		// 模板类：重新加载模板再打一遍。模板目录记在 findings.json 的
		// opts 里，目录被移走就只能报「无法复验」。
		tid := strings.TrimPrefix(check, "tpl-")
		if tplDir == "" {
			return nil, "原始扫描用了模板，但 findings.json 里没记模板目录"
		}
		if fi, err := os.Stat(tplDir); err != nil || !fi.IsDir() {
			return nil, "模板目录不存在: " + tplDir
		}
		tmpls, _ := tpl.LoadDir(tplDir, 0)
		base := f.Target
		if i := strings.LastIndex(base, "/"); i > 8 {
			base = base[:i]
		}
		eng := tpl.NewEngine(d)
		for _, t := range tmpls {
			if !strings.EqualFold(t.ID, tid) {
				continue
			}
			out := eng.Run(t, base)
			if out.Error != "" {
				return nil, "模板执行失败: " + out.Error
			}
			if !out.Matched {
				return nil, ""
			}
			return &model.Finding{
				Check: check, Name: t.Name, Severity: t.Severity,
				Target: base, Host: host, Port: f.Port,
				Level:    "L2",
				Evidence: strings.Join(out.Evidence, "\n"),
			}, ""
		}
		return nil, "模板目录里找不到 id=" + tid
	case strings.HasPrefix(check, "smb"):
		return winproto.ProbeSMB(host, portOr(f.Port, 445), d), ""
	case strings.HasPrefix(check, "ldap"):
		return winproto.ProbeLDAP(host, portOr(f.Port, 389), d, f.Port == 636 || f.Port == 3269), ""
	case strings.HasPrefix(check, "rdp"):
		return winproto.ProbeRDP(host, portOr(f.Port, 3389), d), ""
	case strings.HasPrefix(check, "authz/"):
		// authz 族依赖 scan.Ctx（登录入口、已爬落点、探测预算），findings.json
		// 没保存这些前提，重放只能拿残缺上下文去猜。更要紧的是不能落到下面的
		// webcheck 分支 —— 那会报「已消失」，让现场把真发现从报告里删掉。
		return nil, "authz 检查项尚未接入 replay（需要完整 scan.Ctx 上下文），请用 litmus run 重扫该端口复验"
	}

	// Web 类：整组重跑，再挑同 check 的那条
	base := f.Target
	if i := strings.Index(base, "?"); i > 0 {
		base = base[:i]
	}
	if i := strings.LastIndex(base, "/"); i > 8 { // 保留 scheme://host:port
		base = base[:i]
	}
	pool := httpc.NewPool(4, 0, d, false)
	defer pool.Close()
	res, _ := webcheck.CheckWeb(pool, base, webcheck.Opts{Timeout: d})
	for _, x := range res {
		if x.Check == check {
			return x, ""
		}
	}
	return nil, ""
}

func replayList(file string) int {
	rf, err := loadReplayFile(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读 %s 失败: %v\n", file, err)
		return 1
	}
	sort.Slice(rf.Findings, func(i, j int) bool { return rf.Findings[i].ID < rf.Findings[j].ID })
	fmt.Printf("%-8s %-10s %-4s %-34s %s\n", "ID", "等级", "级别", "检查项", "目标")
	for _, f := range rf.Findings {
		fmt.Printf("%-8s %-10s %-4s %-34s %s\n",
			f.ID, sevCN(f.Severity), f.Level, f.Check, f.Target)
	}
	fmt.Printf("\n共 %d 条。复验某条：litmus replay -f %s --id %s\n",
		len(rf.Findings), file, firstID(rf.Findings))
	return 0
}

func loadReplayFile(p string) (*replayFile, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var rf replayFile
	if err := json.Unmarshal(b, &rf); err != nil {
		return nil, err
	}
	return &rf, nil
}

func saveReplayEvidence(id, evidence string) string {
	dir := filepath.Join("replay", time.Now().Format("20060102-150405"))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "(写盘失败: " + err.Error() + ")"
	}
	p := filepath.Join(dir, id+".txt")
	if err := os.WriteFile(p, []byte(evidence), 0o644); err != nil {
		return "(写盘失败: " + err.Error() + ")"
	}
	return p
}

func hostOfTarget(t string) string {
	s := t
	if i := strings.Index(s, "://"); i > 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i > 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, ":"); i > 0 && !strings.Contains(s[i:], "]") {
		s = s[:i]
	}
	return s
}

func portOr(p, def int) int {
	if p > 0 {
		return p
	}
	return def
}

func sevCN(s string) string {
	if v, ok := model.SevCN[s]; ok {
		return v
	}
	return s
}

func firstID(fs []replayFinding) string {
	if len(fs) == 0 {
		return "<ID>"
	}
	return fs[0].ID
}

const replayUsage = `用法：
  litmus replay -f findings.json --list
  litmus replay -f findings.json --id LS-001 [--timeout 8]

参数：
  -f, --file       findings.json 路径（run 产物）
  --id             要复验的发现 ID
  --timeout        单次复验超时秒数，默认 8
  --list           列出全部发现（ID / 等级 / 检查项 / 目标）
`
