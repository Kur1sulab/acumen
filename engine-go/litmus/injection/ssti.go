package injection

import (
	"fmt"
	"strings"

	"github.com/Kur1sulab/kara/engine-go/litmus/scan"
)

// ================================================================ 模板注入

// sstiCase 一个模板语法用例：首次 payload、确认 payload（换一组操作数）。
//
// 为什么用随机四位数乘 7：`{{7*7}}` 回显的 49 太容易在页面里撞上（"1499"、"4900"）。
// 乘积是五位数、且基线里必须没有它，才轮到「换一组操作数再算一次」这一关 ——
// 两次数值都对上，才可能是真的在求值，而不是巧合或回显。
type sstiCase struct {
	label, tpl, product        string
	confirmTpl, confirmProduct string
}

func sstiCases() []sstiCase {
	a1 := randInRange(1000, 9999)
	a2 := a1 + 1
	b := 7
	p1 := itoa(a1 * b)
	p2 := itoa(a2 * b)
	n1 := itoa(a1)
	m1 := itoa(b)
	n2 := itoa(a2)
	syn := []struct{ label, pre, post string }{
		{"Jinja2/Twig {{}}", "{{", "}}"},
		{"EL/JSP ${}", "${", "}"},
		{"Thymeleaf/Ruby #{}", "#{", "}"},
		{"ERB/ASP <%= %>", "<%= ", " %>"},
	}
	out := make([]sstiCase, 0, len(syn)+1)
	for _, s := range syn {
		out = append(out, sstiCase{
			label:          s.label,
			tpl:            s.pre + n1 + "*" + m1 + s.post,
			product:        p1,
			confirmTpl:     s.pre + n2 + "*" + m1 + s.post,
			confirmProduct: p2,
		})
	}
	// 契约点名的经典形态：{{7*7}} → 49。只有基线里没有 49 时才有意义，
	// 否则「基线本来就有 49」会把这次判定变成误报（调用方负责过滤）。
	out = append(out, sstiCase{
		label: "经典 {{7*7}}", tpl: "{{7*7}}", product: "49",
		confirmTpl: "{{8*7}}", confirmProduct: "56",
	})
	return out
}

func runSSTI(c *scan.Ctx) scan.Result {
	p, na := prepare(c)
	if na != nil {
		return *na
	}
	pts, total := pointsOf(c, 12, nil)
	if len(pts) == 0 {
		return scan.Skip(noPointReason(c))
	}
	o := &outcome{points: len(pts)}
	o.noteTruncated(total, len(pts))

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
		found := false
		for _, cs := range sstiCases() {
			// 对照：基线里本来就有这个数 → 这个用例作废，绝不拿它判定
			if strings.Contains(b.text, cs.product) {
				if cs.product == "49" {
					o.note("基线含 49，经典 {{7*7}} 按对照规则不采用")
				} else {
					o.note("基线含 " + cs.product + "，该用例作废")
				}
				continue
			}
			u := pt.withValueAppend(cs.tpl)
			r := p.fetch(get(u))
			if !r.ok() {
				o.fail("payload 请求失败：" + r.errText())
				continue
			}
			if !strings.Contains(r.text, cs.product) {
				continue
			}
			// 确认：换一组操作数，乘积必须同样出现，且基线里没有
			if strings.Contains(b.text, cs.confirmProduct) {
				continue
			}
			cu := pt.withValueAppend(cs.confirmTpl)
			r2 := p.fetch(get(cu))
			if !r2.ok() || !strings.Contains(r2.text, cs.confirmProduct) {
				continue
			}
			o.add(newFinding(c, metaSSTI, findingOpts{
				sev:   "high",
				level: "L2",
				conf:  "confirmed",
				evidence: fmt.Sprintf("参数: %s = %s\n模板语法: %s\npayload: %s\n请求: GET %s\n响应: HTTP %d / %dB，出现求值结果 %s（基线不含）\n确认 payload: %s → 出现 %s\n判定: 两次不同操作数都被服务端求值 = 模板注入，不是回显",
					pt.name, pt.value, cs.label, cs.tpl, u, r.status(), r.length(),
					cs.product, cs.confirmTpl, cs.confirmProduct),
				repro:  curlGet(u),
				impact: "多数模板引擎在求值时可访问对象属性与内置函数，可进一步读到配置/环境变量，部分引擎可升级为远程代码执行。",
				fix:    "不要把用户输入当模板渲染；改用静态模板 + 变量传参，或对输入做严格白名单。",
				extra: map[string]interface{}{
					"path": pathOf(u), "param": pt.name, "payload": cs.tpl,
					"product": cs.product, "confirm_product": cs.confirmProduct,
				},
			}))
			found = true
			break
		}
		if found {
			continue
		}
	}
	return o.result(p)
}
