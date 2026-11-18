package injection

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Kur1sulab/kara/engine-go/litmus/scan"
)

// ================================================================ 开放重定向

// redirectPayloads 外部域名一律用 evil.com（保留域名举例，不会真的被访问：
// 我们只看 Location 头，不跟随跳转）。
var redirectPayloads = []struct{ label, value string }{
	{"协议相对", "//evil.com"},
	{"绝对 URL", "https://evil.com"},
	{"反斜杠绕过", `/\evil.com`},
	{"混用斜杠", "https:/evil.com"},
}

// locHost 取 Location 的主机名（相对跳转返回空串）
func locHost(loc string) string {
	u, err := url.Parse(strings.TrimSpace(loc))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func isEvilHost(h string) bool {
	return h == "evil.com" || strings.HasSuffix(h, ".evil.com")
}

func runOpenRedirect(c *scan.Ctx) scan.Result {
	p, na := prepare(c)
	if na != nil {
		return *na
	}
	all := collectPoints(c, 0)
	pts, total := pointsOf(c, 12, redirectParam)
	if len(pts) == 0 {
		return scan.Skip(fmt.Sprintf("检查了 %d 个参数，没有跳转类参数名（redirect/next/return/url/callback 等），开放重定向无注入入口", len(all)))
	}
	o := &outcome{points: len(pts)}
	o.noteTruncated(total, len(pts))

	for _, pt := range pts {
		if p.blockedMsg != "" {
			break
		}
		// 基线：原值必须不跳外域，否则「本来就跳」不能归因于 payload
		b := p.fetch(get(pt.rawURL).noRedirect())
		if !b.ok() {
			o.fail("基线不可达 " + pt.endpoint() + "：" + b.errText())
			continue
		}
		o.okPoints++
		if bh := locHost(b.resp.Header("location")); isEvilHost(bh) {
			o.note("基线 Location 已指向外域 " + bh + "，该点不做结论")
			continue
		}
		found := false
		for _, pl := range redirectPayloads {
			u := pt.withValueOnly(pl.value)
			r := p.fetch(get(u).noRedirect())
			if !r.ok() {
				o.fail("payload 请求失败：" + r.errText())
				continue
			}
			loc := r.resp.Header("location")
			h := locHost(loc)
			if r.status() < 300 || r.status() >= 400 || loc == "" || !isEvilHost(h) {
				continue
			}
			if h == strings.ToLower(p.host) {
				continue
			}
			// 复现一次
			r2 := p.fetch(get(u).noRedirect())
			if !r2.ok() || !isEvilHost(locHost(r2.resp.Header("location"))) {
				continue
			}
			o.add(newFinding(c, metaOpenRedirect, findingOpts{
				sev:   "medium",
				level: "L1",
				conf:  "confirmed",
				evidence: fmt.Sprintf("参数: %s = %s\npayload（%s）: %s\n请求: GET %s（不跟随跳转）\n基线: HTTP %d / Location: %s\npayload 响应: HTTP %d / Location: %s\n判定: Location 指向外部域 %s，且与目标域 %s 不同",
					pt.name, pt.value, pl.label, pl.value, u,
					b.status(), orDash(b.resp.Header("location")),
					r.status(), loc, h, p.host),
				repro:  curlGet(u),
				impact: "攻击者可借目标域名的可信链接把用户导向钓鱼站，也是 OAuth token 窃取链里的常见一环。",
				fix:    "跳转目标改用服务端白名单映射（如 ?next=home → /home），或校验目标为同域相对路径，禁止 // 与绝对 URL。",
				extra: map[string]interface{}{
					"path": pathOf(u), "param": pt.name, "payload": pl.value, "location": loc,
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

// ================================================================ CRLF 响应头注入

// crlfPayloads 已经是 wire 形态：%0d%0a 必须原样到达服务端，再编码一次就变成
// 字面量 "%0d0d%0a"，注入不成立。最后一条是 Unicode 分隔符（U+560A U+560D），
// 某些容器/网关把它当 CRLF 处理。
func crlfPayloads(mk string) []struct{ label, raw string } {
	return []struct{ label, raw string }{
		{"CRLF", "%0d%0aX-Injected:litmus" + mk},
		{"LF", "%0aX-Injected:litmus" + mk},
		{"Unicode CRLF", "%E5%98%8A%E5%98%8DX-Injected:litmus" + mk},
	}
}

func runCRLF(c *scan.Ctx) scan.Result {
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
	mk := marker("crlf")

	for _, pt := range pts {
		if p.blockedMsg != "" {
			break
		}
		b := p.fetch(get(pt.rawURL).noRedirect())
		if !b.ok() {
			o.fail("基线不可达 " + pt.endpoint() + "：" + b.errText())
			continue
		}
		o.okPoints++
		if _, ok := b.resp.HeaderOK("x-injected"); ok {
			o.note("基线响应已有 X-Injected 头（非本次注入），该点不做结论")
			continue
		}
		found := false
		for _, pl := range crlfPayloads(mk) {
			u := pt.withValueAppendEncoded(pl.raw)
			r := p.fetch(get(u).noRedirect())
			if !r.ok() {
				o.fail("payload 请求失败：" + r.errText())
				continue
			}
			v, ok := r.resp.HeaderOK("x-injected")
			if !ok || !strings.Contains(v, mk) {
				// 标记出现在别的头里也是注入面，但归因较弱，记一条 note 供人工看
				for _, h := range r.resp.Headers {
					if strings.Contains(h.Value, mk) {
						o.note("标记出现在响应头 " + h.Name + " 中（非 X-Injected，归因较弱）")
						break
					}
				}
				continue
			}
			// 复现一次
			r2 := p.fetch(get(u).noRedirect())
			v2, ok2 := r2.resp.HeaderOK("x-injected")
			if !r2.ok() || !ok2 || !strings.Contains(v2, mk) {
				continue
			}
			o.add(newFinding(c, metaCRLF, findingOpts{
				sev:   "medium",
				level: "L2",
				conf:  "confirmed",
				evidence: fmt.Sprintf("参数: %s = %s\npayload（%s）: %s\n请求: GET %s\n基线响应头: 无 X-Injected\npayload 响应: HTTP %d，新增响应头 X-Injected: %s\n二次请求复现: 是",
					pt.name, pt.value, pl.label, pl.raw, u, r.status(), v),
				repro:  curlGet(u),
				impact: "可向响应注入任意头与响应体（HTTP 响应拆分），进而种 Cookie、关闭 CSP、缓存投毒，配合代理时甚至能污染其他用户的响应。",
				fix:    "在框架层对写入响应头的值做 CR/LF 过滤，拒绝用户输入进入 Location/Set-Cookie 的值。",
				extra: map[string]interface{}{
					"path": pathOf(u), "param": pt.name, "payload": pl.raw, "header": "X-Injected:" + v,
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
