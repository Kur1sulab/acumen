package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Profile 一档强度的全部参数
type Profile struct {
	Ports      string
	Threads    int
	Timeout    float64
	HTTPBudget int
	CrawlPages int
	CrawlDepth int
	Creds      int
	RPS        int
	Templates  int
}

// Intensity 三档强度。数值与 Python 版逐项对齐 —— 改动会直接改变
// 现场行为（并发、超时、口令尝试次数），不是调参，是改战术。
var Intensity = map[string]Profile{
	"low": {Ports: "top100", Threads: 32, Timeout: 2.0, HTTPBudget: 100,
		CrawlPages: 50, CrawlDepth: 1, Creds: 0, RPS: 20, Templates: 60},
	"normal": {Ports: "top1000", Threads: 64, Timeout: 2.5, HTTPBudget: 200,
		CrawlPages: 100, CrawlDepth: 2, Creds: 10, RPS: 50, Templates: 200},
	"high": {Ports: "full", Threads: 128, Timeout: 3.0, HTTPBudget: 400,
		CrawlPages: 300, CrawlDepth: 3, Creds: 30, RPS: 100, Templates: 800},
}

// Options 一轮运行的全部参数
type Options struct {
	Intensity   string  `json:"intensity"`
	Threads     int     `json:"threads"`
	Timeout     float64 `json:"timeout"`
	AllowPublic bool    `json:"allow_public"`
	Ports       string  `json:"ports"`
	MaxHosts    int     `json:"max_hosts"`
	OutDir      string  `json:"out_dir"`
	StateDir    string  `json:"state_dir"`
	Resume      bool    `json:"resume"`
	Diff        bool    `json:"diff"`
	Templates   string  `json:"templates"`
	Creds       int     `json:"creds"`
	NoAuthProbe bool    `json:"no_auth_probe"`
	NoWeb       bool    `json:"no_web"`
	Verbose     bool    `json:"verbose"`

	// 派生字段（来自强度档）
	HTTPBudget int `json:"http_budget"`
	CrawlPages int `json:"crawl_pages"`
	CrawlDepth int `json:"crawl_depth"`
	RPS        int `json:"rps"`
	MaxTpl     int `json:"max_templates"`
}

// NewOptions 按强度档填充默认值，再让显式参数覆盖。
//
// creds 用 *int 而不是 int：Python 版是 `creds=None` 表示「没指定」，
// 而 0 是「显式要求不做口令尝试」，两者语义不同。
func NewOptions(intensity string, threads int, timeout float64, allowPublic bool,
	ports string, maxHosts int, outDir, stateDir string, resume, diff bool,
	templates string, creds *int, noAuthProbe, noWeb, verbose bool) *Options {

	if _, ok := Intensity[intensity]; !ok {
		intensity = "normal"
	}
	prof := Intensity[intensity]
	if threads <= 0 {
		threads = prof.Threads
	}
	if timeout <= 0 {
		timeout = prof.Timeout
	}
	if ports == "" {
		ports = prof.Ports
	}
	if maxHosts <= 0 {
		maxHosts = 256
	}
	if outDir == "" {
		outDir = "runs"
	}
	if stateDir == "" {
		stateDir = filepath.Join(outDir, "state")
	}
	c := prof.Creds
	if creds != nil {
		c = *creds
	}
	return &Options{
		Intensity: intensity, Threads: threads, Timeout: timeout,
		AllowPublic: allowPublic, Ports: ports, MaxHosts: maxHosts,
		OutDir: outDir, StateDir: stateDir, Resume: resume, Diff: diff,
		Templates: templates, Creds: c, NoAuthProbe: noAuthProbe,
		NoWeb: noWeb, Verbose: verbose,
		HTTPBudget: prof.HTTPBudget, CrawlPages: prof.CrawlPages,
		CrawlDepth: prof.CrawlDepth, RPS: prof.RPS, MaxTpl: prof.Templates,
	}
}

// NewTimestampedOutDir 默认输出目录 runs/<时间戳>
func NewTimestampedOutDir() string {
	ts := strings.NewReplacer("-", "", ":", "", "T", "-", "+", "p").Replace(nowCompact())
	return filepath.Join("runs", ts)
}

func nowCompact() string {
	// 与 Python 的 strftime("%Y%m%d-%H%M%S") 等价
	return time.Now().Format("20060102-150405")
}

// EnsureDirs 建输出目录与证据目录
func (o *Options) EnsureDirs() error {
	for _, d := range []string{o.OutDir, filepath.Join(o.OutDir, "evidence"),
		filepath.Join(o.OutDir, "poc"), o.StateDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("建目录 %s 失败: %w", d, err)
		}
	}
	return nil
}

// Summary 一行参数摘要（日志用）
func (o *Options) Summary() string {
	return fmt.Sprintf("intensity=%s ports=%s threads=%d timeout=%.1fs creds=%d allow_public=%v",
		o.Intensity, o.Ports, o.Threads, o.Timeout, o.Creds, o.AllowPublic)
}

// asMap 把参数展平成 map，对齐 Python 的 Options.to_dict()。
//
// 走 JSON 往返而不是手写 map：字段多（20 个），手写必漏，
// 而漏掉的字段会让 findings.json 里的 opts 与 Python 版对不上。
func (o *Options) asMap() (map[string]interface{}, error) {
	b, err := json.Marshal(o)
	if err != nil {
		return nil, err
	}
	out := map[string]interface{}{}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}
