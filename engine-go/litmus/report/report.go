// 关于 PoC 行的偏离：Python 版渲染成「python3 poc/xxx.py」，Go 版交付物是静态
// 二进制、不生成 .py，所以改成直接给 litmus replay 命令。归一时间/耗时/PoC 三项
// 后，报告其余部分仍与 Python 原版逐字节一致（report_test 守着这条线）。
//
// Package report 渲染交付报告：Markdown + 自包含 HTML。
//
// 口径（这是对外交付物，每句话都要扛得住审核）：
//   - 一级结构按等级：严重 → 高危 → 中危 → 低危 → 信息
//   - 每条必须有：证据（原文）+ 复现命令 + PoC 路径 + 影响 + 修复
//   - 未测项单独一节列出原因，绝不与「测了没问题」混在一起
//   - 凭据只出现打码值
//   - HTML 自包含：无外链 CSS/JS/字体，断网双击可看
package report

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Kur1sulab/kara/engine-go/litmus/model"
)

// DiffItem 差异条目。用 map 而不是 struct，因为 findings.json 里
// diff 的字段可能随版本增删，强类型会丢字段。
type DiffItem map[string]interface{}

// Diff 与上一轮的差异
type Diff struct {
	New   []DiffItem `json:"new"`
	Still []DiffItem `json:"still"`
	Fixed []DiffItem `json:"fixed"`
}

// Result 一轮运行的完整结果（对应 Python 版 res dict）
type Result struct {
	RunID    int                    `json:"run_id"`
	Opts     map[string]interface{} `json:"opts"`
	Elapsed  float64                `json:"elapsed"`
	Findings []*model.Finding       `json:"findings"`
	Coverage []*model.Coverage      `json:"coverage"`
	Diff     *Diff                  `json:"diff,omitempty"`
}

// pyFloat 对齐 Python 的 str(float)：
//
//	str(12.0) -> "12.0"      （Go 的 %g 会给 "12"）
//	str(12.345) -> "12.345"
//
// 报告里的「耗时」是给人看的，两边必须逐字一致，否则 oracle 差分永远失败。
func pyFloat(v float64) string {
	if math.IsInf(v, 0) || math.IsNaN(v) {
		return "nan"
	}
	if v == math.Trunc(v) && math.Abs(v) < 1e16 {
		return strconv.FormatFloat(v, 'f', 1, 64)
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}

func cnt(findings []*model.Finding) map[string]int {
	c := map[string]int{}
	for _, s := range model.Severities {
		c[s] = 0
	}
	for _, f := range findings {
		c[f.Severity]++
	}
	return c
}

// meta 报告头信息
type meta struct {
	RunID     int
	Time      string
	Elapsed   float64
	Intensity interface{}
	Ports     interface{}
	Threads   interface{}
	Hosts     interface{}
}

func buildMeta(res *Result) meta {
	m := meta{
		RunID:   res.RunID,
		Time:    model.NowISO(),
		Elapsed: res.Elapsed,
	}
	if res.Opts != nil {
		m.Intensity = res.Opts["intensity"]
		m.Ports = res.Opts["ports"]
		m.Threads = res.Opts["threads"]
	}
	set := map[string]bool{}
	for _, f := range res.Findings {
		if f.Host != "" {
			set[f.Host] = true
		}
	}
	if len(set) > 0 {
		m.Hosts = len(set)
	} else {
		m.Hosts = "-"
	}
	return m
}

func s(v interface{}) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

// ---------------------------------------------------------------- Markdown

// RenderMarkdown 生成 Markdown 报告
func RenderMarkdown(res *Result, evidenceDir string) string {
	fs := res.Findings
	cov := res.Coverage
	m := buildMeta(res)
	c := cnt(fs)
	var L []string

	L = append(L, "# Litmus 内网渗透测试报告\n")
	L = append(L, fmt.Sprintf("- 运行编号：`%d`", m.RunID))
	L = append(L, fmt.Sprintf("- 生成时间：%s", m.Time))
	L = append(L, fmt.Sprintf("- 强度档位：`%s`（端口 %s / 并发 %s）",
		s(m.Intensity), s(m.Ports), s(m.Threads)))
	L = append(L, "- 耗时："+pyFloat(m.Elapsed)+"s")
	L = append(L, fmt.Sprintf("- 发现总数：**%d**\n", len(fs)))

	L = append(L, "## 一、结论摘要\n")
	L = append(L, "| 等级 | 数量 |")
	L = append(L, "|---|---|")
	for _, sv := range model.Severities {
		L = append(L, fmt.Sprintf("| %s（%s） | %d |", model.SevCN[sv], sv, c[sv]))
	}
	L = append(L, "")
	if len(fs) == 0 {
		L = append(L, "> 本轮未发现可确认的问题。**注意**：未发现 ≠ 没有问题，"+
			"请对照第三节「覆盖情况」确认哪些面根本没测。\n")
	}

	// 覆盖情况
	L = append(L, "## 二、覆盖情况（三态）\n")
	st := map[string]int{"ok": 0, "skip": 0, "na": 0}
	for _, v := range cov {
		st[v.State]++
	}
	L = append(L, fmt.Sprintf("- 已测（ok）：%d 项", st["ok"]))
	L = append(L, fmt.Sprintf("- 未测（skip）：%d 项", st["skip"]))
	L = append(L, fmt.Sprintf("- 不适用（na）：%d 项\n", st["na"]))
	var skips []*model.Coverage
	for _, v := range cov {
		if v.State == "skip" {
			skips = append(skips, v)
		}
	}
	if len(skips) > 0 {
		L = append(L, "**未测项及原因：**\n")
		L = append(L, "| 目标 | 类别 | 项目 | 原因 |")
		L = append(L, "|---|---|---|---|")
		for _, v := range skips {
			L = append(L, fmt.Sprintf("| %s | %s | %s | %s |",
				v.Target, v.Category, v.Item, v.Reason))
		}
		L = append(L, "")
	}
	// 逐项清单：ok 也要列。
	//
	// 只列 skip 的话，客户无法核对「你说测了的那几项」到底跑没跑 ——
	// 覆盖表的意义就是可核对，不是报个漂亮数字。
	if len(cov) > 0 {
		L = append(L, "**逐项清单（含已测）：**\n")
		L = append(L, "| 目标 | 类别 | 检查项 | 状态 | 命中 | 说明 |")
		L = append(L, "|---|---|---|---|---|---|")
		for _, v := range cov {
			note := v.Reason
			if note == "" {
				note = "—"
			}
			L = append(L, fmt.Sprintf("| %s | %s | %s | %s | %d | %s |",
				v.Target, v.Category, v.Item, v.State, v.Count, note))
		}
		L = append(L, "")
	}

	// 漏洞明细
	L = append(L, "## 三、漏洞明细（按等级分类）\n")
	if len(fs) == 0 {
		L = append(L, "（无）\n")
	}
	for _, sv := range model.Severities {
		var group []*model.Finding
		for _, f := range fs {
			if f.Severity == sv {
				group = append(group, f)
			}
		}
		if len(group) == 0 {
			continue
		}
		L = append(L, fmt.Sprintf("### %s（%s）— %d 条\n", model.SevCN[sv], sv, len(group)))
		for _, f := range group {
			L = append(L, fmt.Sprintf("#### %s %s\n", f.ID, f.Name))
			L = append(L, fmt.Sprintf("- **等级**：%s（%s） / 取证等级 **%s**",
				f.SevCNOf(), f.Severity, f.Level))
			L = append(L, fmt.Sprintf("- **目标**：`%s`", f.Target))
			L = append(L, fmt.Sprintf("- **置信度**：%s", f.Confidence))
			L = append(L, fmt.Sprintf("- **时间**：%s", f.Time))
			L = append(L, "")
			L = append(L, "**证据**\n")
			L = append(L, "```")
			if t := strings.TrimSpace(f.Evidence); t != "" {
				L = append(L, t)
			} else {
				L = append(L, "(无)")
			}
			L = append(L, "```\n")
			if rs := sharesOf(f); len(rs) > 0 {
				L = append(L, "**匿名可枚举的共享**\n")
				L = append(L, "| # | 共享名 | 类型 | 备注 |")
				L = append(L, "|---|---|---|---|")
				for i, sh := range rs {
					L = append(L, fmt.Sprintf("| %d | `%s` | %s | %s |",
						i+1, sh["name"], sh["type"],
						strings.ReplaceAll(sh["remark"], "|", `\|`)))
				}
				L = append(L, "")
			}
			L = append(L, "**复现**\n")
			L = append(L, "```")
			if t := strings.TrimSpace(f.Repro); t != "" {
				// {ID} 是生成 finding 时还拿不到的编号（编号在收敛阶段才定），
				// 渲染这一刻才知道，所以替换放这里。
				L = append(L, strings.ReplaceAll(t, "{ID}", f.ID))
			} else {
				L = append(L, "(未提供)")
			}
			L = append(L, "```\n")
			if f.PoC != "" {
				L = append(L, fmt.Sprintf("- **PoC**：`%s`（直接复验）", f.PoC))
			}
			if f.RawRef != "" {
				L = append(L, fmt.Sprintf("- **原始证据**：`%s`", f.RawRef))
			}
			if len(f.Creds) > 0 {
				var parts []string
				for _, cc := range f.Creds {
					parts = append(parts, fmt.Sprintf("`%s %s:%d %s/%s`",
						cc.Proto, cc.Host, cc.Port, cc.User, model.MaskSecret(cc.Secret, 4)))
				}
				L = append(L, "- **取得凭据**："+strings.Join(parts, "，"))
			}
			L = append(L, fmt.Sprintf("\n**影响**：%s", f.Impact))
			L = append(L, fmt.Sprintf("\n**修复建议**：%s\n", f.Fix))
		}
	}

	// 附录
	L = append(L, "## 四、方法与边界\n")
	L = append(L, "- 扫描方式：TCP connect 全端口探测（按强度档位取端口表），不做 SYN 半开。")
	L = append(L, "- 服务判定：连接成功才算 open；服务指纹必须给出原始响应证据，识别不出记 `unknown`。")
	L = append(L, "- 漏洞判定：走完协议拿到「只有漏洞成立才出现」的字节才计为确认；"+
		"仅端口开放、仅 banner 命中不计。")
	L = append(L, "- 口令策略：只做少量默认口令验证，**不做字典爆破**（避免撞锁与账号锁定）。")
	L = append(L, "- 数据读取：数据库只取库表名与行数，**不抽样明文**；凭据在报告中一律打码。")
	L = append(L, "- L1 只代表「看得见」，L2 表示拿到真实数据/凭据，L3 表示拿到内部权限。\n")

	if res.Diff != nil {
		d := res.Diff
		L = append(L, "## 五、与上一轮的差异\n")
		L = append(L, fmt.Sprintf("- 新增：%d 条", len(d.New)))
		L = append(L, fmt.Sprintf("- 仍在：%d 条", len(d.Still)))
		L = append(L, fmt.Sprintf("- 已修复：%d 条\n", len(d.Fixed)))
		for _, f := range d.New {
			L = append(L, fmt.Sprintf("- 🆕 `%s` %s @ %s", s(f["id"]), s(f["name"]), s(f["target"])))
		}
		for _, f := range d.Fixed {
			L = append(L, fmt.Sprintf("- ✅ 已修复 `%s` %s @ %s", s(f["id"]), s(f["name"]), s(f["target"])))
		}
		L = append(L, "")
	}

	return strings.Join(L, "\n") + "\n"
}

// sharesOf 从 extra.rpc_shares 取出共享表
func sharesOf(f *model.Finding) []map[string]string {
	if f.Extra == nil {
		return nil
	}
	raw, ok := f.Extra["rpc_shares"]
	if !ok || raw == nil {
		return nil
	}
	list, ok := raw.([]interface{})
	if !ok {
		// 也接受 []map[string]interface{}（Go 内部直接塞的）
		if m, ok2 := raw.([]map[string]interface{}); ok2 {
			out := make([]map[string]string, 0, len(m))
			for _, it := range m {
				out = append(out, map[string]string{
					"name": s(it["name"]), "type": s(it["type"]), "remark": s(it["remark"]),
				})
			}
			return out
		}
		return nil
	}
	out := make([]map[string]string, 0, len(list))
	for _, it := range list {
		m, ok := it.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, map[string]string{
			"name": s(m["name"]), "type": s(m["type"]), "remark": s(m["remark"]),
		})
	}
	return out
}

// ---------------------------------------------------------------- HTML

const htmlHead = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Litmus 渗透测试报告 · run __RUN_ID__</title>
<style>
:root{--bg:#0f1115;--card:#171a21;--line:#2a2f3a;--fg:#e6e8ee;--dim:#9aa3b2;
--critical:#ff5d52;--high:#ff9f45;--medium:#ffd166;--low:#6ea8fe;--info:#9aa3b2;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.7 -apple-system,"PingFang SC","Microsoft YaHei",system-ui,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:32px 20px 80px}
h1{font-size:26px;margin:0 0 6px}
h2{font-size:20px;margin:38px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--line)}
h3{font-size:17px;margin:26px 0 10px}
h4{font-size:15px;margin:22px 0 8px}
.meta{color:var(--dim);font-size:13px}
.meta code{color:#cbd5e1}
table{border-collapse:collapse;width:100%;margin:12px 0;font-size:14px}
th,td{border:1px solid var(--line);padding:8px 10px;text-align:left;vertical-align:top}
th{background:#1d222b;font-weight:600}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:16px 18px;margin:14px 0}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;
font-weight:700;color:#111}
.critical{background:var(--critical)}.high{background:var(--high)}
.medium{background:var(--medium)}.low{background:var(--low)}.info{background:var(--info)}
pre{background:#0b0d11;border:1px solid var(--line);border-radius:8px;padding:12px;
overflow:auto;font:12.5px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;
white-space:pre-wrap;word-break:break-word;color:#cfd6e4}
.kv{color:var(--dim);font-size:13px;margin:2px 0}
.kv b{color:var(--fg);font-weight:600}
.muted{color:var(--dim)}
.tag{font-size:12px;color:var(--dim);border:1px solid var(--line);
border-radius:6px;padding:1px 6px;margin-left:6px}
footer{margin-top:50px;color:var(--dim);font-size:12.5px;border-top:1px solid var(--line);padding-top:16px}
@media print{body{background:#fff;color:#111}.card{background:#fff;border-color:#ddd}
pre{background:#f6f7f9;color:#111}th{background:#eee}}
</style></head><body><div class="wrap">
`

const htmlTail = `<footer>
本报告由 Litmus 自动生成。判定纪律：只写已复现事实，推演内容标注【推演】；
未测项在「覆盖情况」中单列原因。报告中凭据一律打码，完整值见 evidence/ 原始文件。
</footer></div></body></html>
`

// esc 对齐 Python html.escape：& < > " ' → &amp; &lt; &gt; &quot; &#x27;
// Go 的 html.EscapeString 用的是 &#34;/&#39; 数字实体，逐字 diff 会对不上，
// 所以这里自己实现。
var escReplacer = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	`"`, "&quot;",
	"'", "&#x27;",
)

func esc(v string) string { return escReplacer.Replace(v) }

// RenderHTML 生成自包含 HTML 报告
func RenderHTML(res *Result) string {
	fs := res.Findings
	cov := res.Coverage
	m := buildMeta(res)
	c := cnt(fs)
	var out []string

	out = append(out, strings.ReplaceAll(htmlHead, "__RUN_ID__", fmt.Sprint(m.RunID)))
	out = append(out, "<h1>Litmus 内网渗透测试报告</h1>")
	out = append(out, fmt.Sprintf(
		`<div class="meta">运行编号 <code>%d</code> · 生成时间 %s · 强度 <code>%s</code> （端口 %s / 并发 %s） · 耗时 %ss</div>`,
		m.RunID, esc(m.Time), esc(s(m.Intensity)), esc(s(m.Ports)), esc(s(m.Threads)), pyFloat(m.Elapsed)))

	out = append(out, "<h2>一、结论摘要</h2>")
	out = append(out, `<div class="card"><table><tr><th>等级</th><th>数量</th></tr>`)
	for _, sv := range model.Severities {
		out = append(out, fmt.Sprintf(`<tr><td><span class="badge %s">%s</span></td><td>%d</td></tr>`,
			sv, model.SevCN[sv], c[sv]))
	}
	out = append(out, fmt.Sprintf(`<tr><td><b>合计</b></td><td><b>%d</b></td></tr></table></div>`, len(fs)))
	if len(fs) == 0 {
		out = append(out, `<div class="card muted">本轮未发现可确认的问题。`+
			`<b>未发现 ≠ 没有问题</b> —— 请对照「覆盖情况」确认哪些面根本没测。</div>`)
	}

	out = append(out, "<h2>二、覆盖情况（三态）</h2>")
	st := map[string]int{"ok": 0, "skip": 0, "na": 0}
	for _, v := range cov {
		st[v.State]++
	}
	out = append(out, fmt.Sprintf(`<div class="card">已测 <b>%d</b> 项 · 未测 <b>%d</b> 项 · 不适用 <b>%d</b> 项</div>`,
		st["ok"], st["skip"], st["na"]))
	var skips []*model.Coverage
	for _, v := range cov {
		if v.State == "skip" {
			skips = append(skips, v)
		}
	}
	if len(skips) > 0 {
		out = append(out, "<h3>未测项及原因</h3><table><tr><th>目标</th><th>类别</th><th>项目</th><th>原因</th></tr>")
		for _, v := range skips {
			out = append(out, fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
				esc(v.Target), esc(v.Category), esc(v.Item), esc(v.Reason)))
		}
		out = append(out, "</table>")
	}
	if len(cov) > 0 {
		out = append(out, "<h3>逐项清单（含已测）</h3><table><tr><th>目标</th><th>类别</th><th>检查项</th><th>状态</th><th>命中</th><th>说明</th></tr>")
		for _, v := range cov {
			note := v.Reason
			if note == "" {
				note = "—"
			}
			out = append(out, fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td></tr>",
				esc(v.Target), esc(v.Category), esc(v.Item), esc(v.State), v.Count, esc(note)))
		}
		out = append(out, "</table>")
	}

	out = append(out, "<h2>三、漏洞明细（按等级分类）</h2>")
	if len(fs) == 0 {
		out = append(out, `<div class="card muted">（无）</div>`)
	}
	for _, sv := range model.Severities {
		var group []*model.Finding
		for _, f := range fs {
			if f.Severity == sv {
				group = append(group, f)
			}
		}
		if len(group) == 0 {
			continue
		}
		out = append(out, fmt.Sprintf(`<h3><span class='badge %s'>%s</span> %d 条</h3>`,
			sv, model.SevCN[sv], len(group)))
		for _, f := range group {
			out = append(out, `<div class="card">`)
			out = append(out, fmt.Sprintf(`<h4>%s %s<span class="tag">%s</span><span class="tag">%s</span></h4>`,
				esc(f.ID), esc(f.Name), esc(f.Level), esc(f.Confidence)))
			out = append(out, fmt.Sprintf(`<div class="kv">目标 <b>%s</b></div>`, esc(f.Target)))
			out = append(out, fmt.Sprintf(`<div class="kv">时间 %s</div>`, esc(f.Time)))
			out = append(out, "<div class='kv'><b>证据</b></div>")
			ev := strings.TrimSpace(f.Evidence)
			if ev == "" {
				ev = "(无)"
			}
			out = append(out, "<pre>"+esc(ev)+"</pre>")
			if rs := sharesOf(f); len(rs) > 0 {
				out = append(out, "<div class='kv'><b>匿名可枚举的共享</b></div>")
				out = append(out, "<table><tr><th>#</th><th>共享名</th><th>类型</th><th>备注</th></tr>")
				for i, sh := range rs {
					out = append(out, fmt.Sprintf("<tr><td>%d</td><td><code>%s</code></td><td>%s</td><td>%s</td></tr>",
						i+1, esc(sh["name"]), esc(sh["type"]), esc(sh["remark"])))
				}
				out = append(out, "</table>")
			}
			out = append(out, "<div class='kv'><b>复现</b></div>")
			rp := strings.TrimSpace(f.Repro)
			if rp == "" {
				rp = "(未提供)"
			}
			rp = strings.ReplaceAll(rp, "{ID}", f.ID)
			out = append(out, "<pre>"+esc(rp)+"</pre>")
			if f.PoC != "" {
				out = append(out, fmt.Sprintf(`<div class="kv">PoC <code>%s</code>（直接复验）</div>`,
					esc(f.PoC)))
			}
			if f.RawRef != "" {
				out = append(out, fmt.Sprintf(`<div class="kv">原始证据 <code>%s</code></div>`, esc(f.RawRef)))
			}
			if len(f.Creds) > 0 {
				var parts []string
				for _, cc := range f.Creds {
					parts = append(parts, fmt.Sprintf("<code>%s %s:%d %s/%s</code>",
						esc(cc.Proto), esc(cc.Host), cc.Port, esc(cc.User),
						esc(model.MaskSecret(cc.Secret, 4))))
				}
				out = append(out, `<div class="kv">取得凭据：`+strings.Join(parts, "，")+`</div>`)
			}
			out = append(out, fmt.Sprintf(`<div class="kv"><b>影响</b>：%s</div>`, esc(f.Impact)))
			out = append(out, fmt.Sprintf(`<div class="kv"><b>修复建议</b>：%s</div>`, esc(f.Fix)))
			out = append(out, "</div>")
		}
	}

	out = append(out, "<h2>四、方法与边界</h2><div class='card'><ul>"+
		"<li>扫描方式：TCP connect 全端口探测（按强度档位取端口表），不做 SYN 半开。</li>"+
		"<li>服务判定：连接成功才算 open；指纹必须给出原始响应证据，识别不出记 unknown。</li>"+
		"<li>漏洞判定：走完协议拿到「只有漏洞成立才出现」的字节才计为确认。</li>"+
		"<li>口令策略：只做少量默认口令验证，<b>不做字典爆破</b>。</li>"+
		"<li>数据读取：数据库只取库表名与行数，不抽样明文；凭据在报告中一律打码。</li>"+
		"<li>L1 看得见 / L2 拿到真实数据或凭据 / L3 拿到内部权限。</li>"+
		"</ul></div>")

	if res.Diff != nil {
		d := res.Diff
		out = append(out, "<h2>五、与上一轮的差异</h2><div class='card'>")
		out = append(out, fmt.Sprintf(`<div class='kv'>新增 <b>%d</b> · 仍在 <b>%d</b> · 已修复 <b>%d</b></div>`,
			len(d.New), len(d.Still), len(d.Fixed)))
		for _, f := range d.New {
			out = append(out, fmt.Sprintf(`<div class='kv'>🆕 %s %s @ %s</div>`,
				esc(s(f["id"])), esc(s(f["name"])), esc(s(f["target"]))))
		}
		for _, f := range d.Fixed {
			out = append(out, fmt.Sprintf(`<div class='kv'>✅ 已修复 %s %s @ %s</div>`,
				esc(s(f["id"])), esc(s(f["name"])), esc(s(f["target"]))))
		}
		out = append(out, "</div>")
	}

	out = append(out, htmlTail)
	return strings.Join(out, "")
}

// Paths 三个产物路径
type Paths struct {
	Markdown string
	HTML     string
	JSON     string
}

// WriteReports 落盘三份产物：report.md / report.html / findings.json
func WriteReports(res *Result, outDir string) (Paths, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return Paths{}, err
	}
	p := Paths{
		Markdown: filepath.Join(outDir, "report.md"),
		HTML:     filepath.Join(outDir, "report.html"),
		JSON:     filepath.Join(outDir, "findings.json"),
	}
	if err := os.WriteFile(p.Markdown, []byte(RenderMarkdown(res, "evidence")), 0o644); err != nil {
		return p, err
	}
	if err := os.WriteFile(p.HTML, []byte(RenderHTML(res)), 0o644); err != nil {
		return p, err
	}
	// 机器可读：findings.json 的字段顺序由 struct 决定，
	// 与 Python 的 dict 顺序可能不同，但 JSON 语义等价。
	for _, f := range res.Findings {
		f.SyncCredsJSON()
	}
	payload := map[string]interface{}{
		"run_id":   res.RunID,
		"opts":     res.Opts,
		"elapsed":  res.Elapsed,
		"findings": res.Findings,
		"coverage": res.Coverage,
		"diff":     res.Diff,
	}
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return p, err
	}
	if err := os.WriteFile(p.JSON, b, 0o644); err != nil {
		return p, err
	}
	return p, nil
}
