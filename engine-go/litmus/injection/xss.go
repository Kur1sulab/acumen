package injection

import (
	"fmt"
	"strings"

	"github.com/Kur1sulab/kara/engine-go/litmus/scan"
)

// ================================================================ 反射型 XSS

// xssPayloads 只做「反射」验证：不执行 JS、不带事件处理器。
// 唯一标记串保证响应里出现的 <marker> 一定是本次请求带进去的，
// 而不是页面原本就有的标签。
func xssPayloads(mk string) []struct{ label, text string } {
	return []struct{ label, text string }{
		{"裸标签", "<" + mk + ">"},
		{"双引号属性逃逸", "\"><" + mk + ">"},
		{"单引号属性逃逸", "'><" + mk + ">"},
		{"闭合再开标签", "</title><" + mk + ">"},
	}
}

// isHTML 响应是不是 HTML 上下文。JSON/纯文本里出现未编码的尖括号不是 XSS，
// 这条判断专治「拿 API 响应报 XSS」的误报。
func isHTML(s *snap) bool {
	ct := strings.ToLower(s.resp.Header("content-type"))
	if ct == "" {
		return true // 未声明：按 HTML 处理（老站常见），但仍要求未编码的完整标签
	}
	return strings.Contains(ct, "html") || strings.Contains(ct, "xhtml")
}

// reflectedInLocation 看 Location 里有没有原样带出去的标记（重定向参数反射）。
func reflectedInLocation(s *snap, needle string) (string, bool) {
	check := func(r *snap) (string, bool) {
		if r == nil || r.resp == nil {
			return "", false
		}
		loc := r.resp.Header("location")
		if loc == "" {
			return "", false
		}
		if strings.Contains(loc, needle) || strings.Contains(strings.ToLower(loc), strings.ToLower(needle)) {
			return loc, true
		}
		return "", false
	}
	if loc, ok := check(s); ok {
		return loc, true
	}
	if s != nil && s.resp != nil {
		for _, h := range s.resp.History {
			if loc, ok := check(newSnap(request{}, h)); ok {
				return loc, true
			}
		}
	}
	return "", false
}

func runXSS(c *scan.Ctx) scan.Result {
	p, na := prepare(c)
	if na != nil {
		return *na
	}
	pts, total := pointsOf(c, 14, nil)
	if len(pts) == 0 {
		return scan.Skip(noPointReason(c))
	}
	o := &outcome{points: len(pts)}
	o.noteTruncated(total, len(pts))
	mk := marker("xss")

	for _, pt := range pts {
		if p.blockedMsg != "" {
			break
		}
		b := p.fetch(get(pt.rawURL))
		if !b.ok() {
			o.fail("基线不可达 " + pt.endpoint() + "：" + b.errText())
			continue
		}
		o.okPoints++
		// 基线不可能含随机标记；这条是防御性对照，防止 marker 生成退化。
		if strings.Contains(b.text, mk) {
			o.note("基线响应已含标记 " + mk + "，跳过该点")
			continue
		}
		found := false
		encoded := false
		for _, pl := range xssPayloads(mk) {
			u := pt.withValueAppend(pl.text)
			r := p.fetch(get(u))
			if !r.ok() {
				o.fail("payload 请求失败：" + r.errText())
				continue
			}
			want := "<" + mk + ">"
			if strings.Contains(r.text, want) {
				if !isHTML(r) {
					o.note("参数 " + pt.name + " 有未编码反射，但上下文是 " +
						strings.ToLower(r.resp.Header("content-type")) + "（非 HTML，不构成 XSS）")
					continue
				}
				o.add(newFinding(c, metaXSS, findingOpts{
					sev:   "medium",
					level: "L1",
					conf:  "confirmed",
					evidence: fmt.Sprintf("参数: %s = %s\npayload: %s\n请求: GET %s\n响应: HTTP %d / %dB / Content-Type: %s\n反射片段: %s\n基线是否含同一标记: 否",
						pt.name, pt.value, pl.text, u, r.status(), r.length(),
						orDash(r.resp.Header("content-type")), snippetCI(r.text, want, 90)),
					repro:  curlGet(u),
					impact: "攻击者可构造带脚本的链接，在受害者浏览器里以目标站身份执行任意 JS（窃取会话、改写页面、发起 CSRF）。",
					fix:    "输出到 HTML 上下文时做上下文相关编码（HTML/属性/JS/URL 分别转义）；配合 CSP 作为纵深防御。",
					extra: map[string]interface{}{
						"path": pathOf(u), "param": pt.name, "payload": pl.text,
						"marker": mk, "context": "html",
					},
				}))
				found = true
				break
			}
			if strings.Contains(r.text, "&lt;"+mk+"&gt;") || strings.Contains(r.text, "&lt;"+mk) {
				encoded = true
			}
		}
		if found {
			continue
		}
		// 重定向参数：Location 里原样带着未编码的标签，同样属于反射注入面。
		if loc, ok := reflectedInLocation(p.fetch(get(pt.withValueAppend("<"+mk+">"))), "<"+mk+">"); ok {
			u := pt.withValueAppend("<" + mk + ">")
			o.add(newFinding(c, metaXSS, findingOpts{
				sev:   "low",
				level: "L1",
				conf:  "likely",
				evidence: fmt.Sprintf("参数: %s = %s\n请求: GET %s\nLocation: %s\n说明: 标记原样进入 Location 头（未编码），不是 HTML 体内的 XSS，但同属未过滤反射",
					pt.name, pt.value, u, loc),
				repro:  curlGet(u),
				impact: "反射进 Location 时浏览器不一定执行脚本，但说明该参数未做输出编码，同一参数换到 HTML 上下文即可被利用。",
				fix:    "对跳转参数做白名单校验与 URL 编码，不要直接拼接用户输入。",
				extra: map[string]interface{}{
					"path": pathOf(u), "param": pt.name, "location": loc, "context": "location",
				},
			}))
			continue
		}
		if encoded {
			o.note("参数 " + pt.name + " 出现 HTML 编码形态（&lt;" + mk + "&gt;），判定为已编码")
		}
	}
	return o.result(p)
}

func orDash(s string) string {
	if s == "" {
		return "(未声明)"
	}
	return s
}
