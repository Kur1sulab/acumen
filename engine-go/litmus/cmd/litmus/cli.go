package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Kur1sulab/kara/engine-go/litmus/engine"
	"github.com/Kur1sulab/kara/engine-go/litmus/scope"
)

// strList 可重复的字符串参数（-t a -t b）
type strList []string

func (s *strList) String() string { return strings.Join(*s, ",") }
func (s *strList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// optInt 区分「没传」与「传了 0」
type optInt struct {
	set bool
	v   int
}

func (o *optInt) String() string {
	if !o.set {
		return ""
	}
	return strconv.Itoa(o.v)
}
func (o *optInt) Set(v string) error {
	n, err := strconv.Atoi(v)
	if err != nil {
		return fmt.Errorf("需要整数: %q", v)
	}
	o.v, o.set = n, true
	return nil
}

// runArgs 一次 run 的原始参数
type runArgs struct {
	targets   strList
	files     strList
	ports     string
	intensity string
	threads   int
	timeout   float64
	allowPub  bool
	maxHosts  int
	outDir    string
	stateDir  string
	resume    bool
	diff      bool
	templates string
	creds     optInt
	noAuth    bool
	noWeb     bool
	asJSON    bool
	quiet     bool
}

// parseRunArgs 解析 run 子命令参数。
//
// 参数名与 Python 版 argparse **逐字对齐**（-t/--target、-T/--target-file、
// -p/--ports、--state-db 等）——现场手册写的是 Python 版命令，
// 两边参数不一致等于手册作废。
func parseRunArgs(args []string) (*runArgs, error) {
	fs := flag.NewFlagSet("litmus run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var a runArgs
	fs.Var(&a.targets, "t", "目标：IP / host:port / CIDR / URL，可重复")
	fs.Var(&a.targets, "target", "同 -t")
	fs.Var(&a.files, "T", "目标文件（每行一个，# 注释），可重复")
	fs.Var(&a.files, "target-file", "同 -T")
	fs.StringVar(&a.ports, "p", "", "端口：top100 / top1000 / full / 80,443,1-1024")
	fs.StringVar(&a.ports, "ports", "", "同 -p")
	fs.StringVar(&a.intensity, "intensity", "normal", "强度档位：low / normal / high")
	fs.IntVar(&a.threads, "threads", 0, "并发数（0=按强度档）")
	fs.Float64Var(&a.timeout, "timeout", 0, "单次连接超时秒数（0=按强度档）")
	fs.BoolVar(&a.allowPub, "allow-public", false, "允许公网目标（默认只放行私网/回环）")
	fs.IntVar(&a.maxHosts, "max-hosts", 256, "CIDR 展开主机数上限")
	fs.StringVar(&a.outDir, "out", "", "输出目录（默认 runs/<时间戳>）")
	fs.StringVar(&a.stateDir, "state-db", "", "状态库目录（默认 <out>/state）")
	fs.BoolVar(&a.resume, "resume", false, "续跑：跳过已完成主机")
	fs.BoolVar(&a.diff, "diff", false, "与上一轮对比（新增/仍在/已修复）")
	fs.StringVar(&a.templates, "templates", "", "nuclei 模板目录（可选）")
	fs.Var(&a.creds, "creds", "口令尝试次数上限（0=不做口令尝试）")
	fs.BoolVar(&a.noAuth, "no-auth-probe", false, "跳过服务级真登验证")
	fs.BoolVar(&a.noWeb, "no-web", false, "跳过 Web 侧检查")
	fs.BoolVar(&a.asJSON, "json", false, "末尾打印 JSON 摘要")
	fs.BoolVar(&a.quiet, "q", false, "安静模式")
	fs.BoolVar(&a.quiet, "quiet", false, "同 -q")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("多余的参数: %v（目标请用 -t）", fs.Args())
	}
	return &a, nil
}

// toOptions 转成 engine.Options
func (a *runArgs) toOptions() *engine.Options {
	out := a.outDir
	if out == "" {
		out = engine.NewTimestampedOutDir()
	}
	var creds *int
	if a.creds.set {
		v := a.creds.v
		creds = &v
	}
	return engine.NewOptions(a.intensity, a.threads, a.timeout, a.allowPub,
		a.ports, a.maxHosts, out, a.stateDir, a.resume, a.diff,
		a.templates, creds, a.noAuth, a.noWeb, !a.quiet)
}

// rawTargets 读 -t 与 -T 合并去重
func (a *runArgs) rawTargets() ([]string, error) {
	return scope.ParseTargets(a.targets, a.files)
}
