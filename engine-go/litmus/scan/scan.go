// Package scan 定义跨家族统一的检查项接口与注册表。
//
// 存在理由很实际：漏洞分族（暴露面 / 注入 / 认证 / 框架 / 云），
// 各族由不同文件甚至不同人写，但客户看到的必须是一张覆盖表。
// 如果每个族自己记覆盖，迟早出现「A 族记了 ok、B 族忘了记」，
// 覆盖表就开始撒谎。所以注册和记账收口到这里。
package scan

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Kur1sulab/kara/engine-go/litmus/httpc"
	"github.com/Kur1sulab/kara/engine-go/litmus/model"
)

// 三态。任何检查项跑完必须自报其中一个 —— 
// 「我也不知道算不算测了」不是合法状态。
const (
	StateOK   = "ok"
	StateSkip = "skip"
	StateNA   = "na"
)

// Ctx 一次检查执行所需的全部上下文。
type Ctx struct {
	Target  string // 原始目标串，写进报告
	Base    string // 归一化根 URL，如 http://10.0.0.1:8080
	Host    string
	Port    int
	Scheme  string
	Pool    *httpc.Pool
	Timeout time.Duration
	Soft404 *Soft404 // 软 404 基线，可为 nil（非 Web 场景）
	URLs    []string // 爬虫落点，注入/越权类检查从这里面取参
	MaxProbe int     // 本项探测次数上限，防把目标打挂
}

// ProbeBudget 剩余可用探测次数。
func (c *Ctx) ProbeBudget() int {
	if c.MaxProbe <= 0 {
		return 400
	}
	return c.MaxProbe
}

// Meta 检查项元信息。Name 全局唯一，直接进覆盖表。
//
// 命名约定 "<family>/<what>"，如 injection/sqli-error。
// 覆盖表按 Name 逐行显示，所以粒度要细到「客户能问出这个问题」的程度：
// 他会问「你测 SQL 注入了吗」，不会问「你跑 webcheck 了吗」。
type Meta struct {
	Name     string
	Family   string
	Title    string
	Severity string
	Owasp    string
	CWE      string
}

// Result 一次检查的产出。
type Result struct {
	Findings []*model.Finding
	State    string // ok / skip / na
	Reason   string // skip 时必须写清为什么没测
	Tested   int    // 实际发出的探测次数
}

func OK(n int, f ...*model.Finding) Result {
	return Result{Findings: f, State: StateOK, Tested: n}
}
func Skip(reason string) Result { return Result{State: StateSkip, Reason: reason} }
func NA(reason string) Result   { return Result{State: StateNA, Reason: reason} }

// Check 一个检查项。
type Check struct {
	Meta
	Run func(*Ctx) Result
}

var (
	mu       sync.RWMutex
	registry []Check
	seen     = map[string]bool{}
)

// Register 注册检查项。
//
// 重名直接 panic：两个检查项同名会让覆盖表互相覆盖，
// 结果是「测了的」把「没测的」抹掉 —— 这正是覆盖表最不能犯的错。
func Register(cs ...Check) {
	mu.Lock()
	defer mu.Unlock()
	for _, c := range cs {
		if c.Name == "" || c.Family == "" || c.Run == nil {
			panic("scan: 检查项缺 Name/Family/Run: " + c.Name)
		}
		if seen[c.Name] {
			panic("scan: 检查项重名 " + c.Name)
		}
		seen[c.Name] = true
		registry = append(registry, c)
	}
}

// All 全部已注册检查项（按家族再按名字排序，保证覆盖表顺序稳定）。
func All() []Check {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Check, len(registry))
	copy(out, registry)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Family 取某家族的检查项。
func Family(fam string) []Check {
	var out []Check
	for _, c := range All() {
		if c.Family == fam {
			out = append(out, c)
		}
	}
	return out
}

// Families 全部家族名（去重有序）。
func Families() []string {
	seenF := map[string]bool{}
	var out []string
	for _, c := range All() {
		if !seenF[c.Family] {
			seenF[c.Family] = true
			out = append(out, c.Family)
		}
	}
	sort.Strings(out)
	return out
}

// Summary 覆盖表的一句话摘要，给报表头部用。
func Summary(covs []*model.Coverage) string {
	var ok, skip, na int
	for _, c := range covs {
		switch c.State {
		case StateOK:
			ok++
		case StateSkip:
			skip++
		case StateNA:
			na++
		}
	}
	total := ok + skip + na
	if total == 0 {
		return "未执行任何检查项"
	}
	// 总数必须写在最前面。客户拿到报告第一眼要的是「一共测了几项」，
	// 让他拿计算器加三个数是不礼貌的。
	return fmt.Sprintf("共 %d 项：已测 %d / 未测 %d / 不适用 %d", total, ok, skip, na)
}

// ---------------------------------------------------------------- 软 404

// Soft404 软 404 基线。很多站点对任意路径都返回 200 + 一张模板页，
// 不做基线就会把每个路径都当成「命中」。
type Soft404 struct {
	Soft   bool   `json:"soft"`
	Status int    `json:"status"`
	Len    int    `json:"len"`
	Sig    string `json:"sig"`
	Same   bool   `json:"same"`
	Sample string `json:"sample"`
}

// SigOf 响应体指纹。
func SigOf(b []byte) string {
	s := sha1.Sum(b)
	return hex.EncodeToString(s[:])[:16]
}

// IsReal 判断响应是不是真内容，而不是软 404 那张皮。
func IsReal(baseline *Soft404, status int, body []byte, marker string, minLen int) bool {
	if minLen <= 0 {
		minLen = 40
	}
	if status != 200 && status != 206 {
		return false
	}
	txt := string(body)
	if marker != "" && strings.Contains(txt, marker) {
		return true
	}
	if baseline == nil || !baseline.Soft {
		return len(body) >= minLen
	}
	if SigOf(body) == baseline.Sig {
		return false
	}
	diff := len(body) - baseline.Len
	if diff < 0 {
		diff = -diff
	}
	thresh := int(float64(baseline.Len) * 0.05)
	if thresh < 32 {
		thresh = 32
	}
	if diff < thresh {
		return false
	}
	return len(body) >= minLen
}
