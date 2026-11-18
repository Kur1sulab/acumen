package injection

import (
	"net/url"
	"strings"

	"github.com/Kur1sulab/kara/engine-go/litmus/httpc"
	"github.com/Kur1sulab/kara/engine-go/litmus/scan"
)

// point 一个可注入的参数点。
//
// 用「原 URL + 参数名在原文里的字节区间」表示，而不是 url.Values：
// url.Values.Encode() 会重排参数、重编码百分号，而有些服务端是按原始查询串
// 解析的（WAF、老 CGI）；重编码会把 %0d%0a 变成 %250d%250a，CRLF 检查直接失效。
// 保留区间就能做到「只换这一个值，其余字节原样发出去」。
type point struct {
	rawURL string // 原 URL（含查询串）
	name   string // 参数名（已解码）
	value  string // 参数值（已解码）
	keyAt  [2]int // name 在 rawURL 里的字节区间
	valAt  [2]int // value 在 rawURL 里的字节区间（无 "=" 时是空区间）
}

// endpoint 去掉查询串的端点，用于去重与「同一参数只测一次」
func (p point) endpoint() string {
	if i := strings.IndexByte(p.rawURL, '?'); i >= 0 {
		return p.rawURL[:i]
	}
	return p.rawURL
}

// withValueRaw 用已编码好的值替换参数值，其余字节原样保留
func (p point) withValueRaw(enc string) string {
	return p.rawURL[:p.valAt[0]] + enc + p.rawURL[p.valAt[1]:]
}

// withValueAppend 在**原值后面**追加 payload（最贴近真实注入：id=7' 而不是 id='）
func (p point) withValueAppend(payload string) string {
	return p.withValueRaw(url.QueryEscape(p.value + payload))
}

// withValueOnly 用 payload 整体替换原值（SSRF/路径穿越/开放重定向要的是完整替换）
func (p point) withValueOnly(payload string) string {
	return p.withValueRaw(url.QueryEscape(payload))
}

// withValueEncoded 直接塞一段已在 wire 上编码好的串（CRLF 的 %0d%0a 必须原样到服务端，
// 再编码一次服务端只会收到字面量 "%0d%0a"，注入不成立）
func (p point) withValueEncoded(raw string) string { return p.withValueRaw(raw) }

// withValueAppendEncoded 保留原值，再把原始 wire 片段接在后面：
// next=/home 变成 next=%2Fhome%0d%0aX-Injected:…，比整段替换更贴近真实利用
// （整段替换常把请求打到 404，测不出注入面）。
func (p point) withValueAppendEncoded(raw string) string {
	return p.withValueRaw(url.QueryEscape(p.value) + raw)
}

// withName 换参数名并设值（NoSQL 的 user[$ne]=x 要改的是名字不是值）
func (p point) withName(name, rawValue string) string {
	encName := url.QueryEscape(name)
	s := p.rawURL[:p.keyAt[0]] + encName + p.rawURL[p.keyAt[1]:]
	shift := len(encName) - (p.keyAt[1] - p.keyAt[0])
	return s[:p.valAt[0]+shift] + rawValue + s[p.valAt[1]+shift:]
}

// ---------------------------------------------------------------- 解析

// noiseParam 明显不是业务参数的键：统计/广告点击 ID。测它们只会浪费预算。
func noiseParam(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "", "_", "_ga", "_gl", "_hsenc", "gclid", "fbclid", "msclkid",
		"yclid", "dclid", "cachebust", "cachebuster", "mc_cid", "mc_eid":
		return true
	}
	return strings.HasPrefix(n, "utm_") || strings.HasPrefix(n, "__")
}

// parsePoints 从一条 URL 里抽出全部参数点（保序）。
func parsePoints(rawURL string) []point {
	q := strings.IndexByte(rawURL, '?')
	if q < 0 {
		return nil
	}
	end := len(rawURL)
	if h := strings.IndexByte(rawURL[q:], '#'); h >= 0 {
		end = q + h
	}
	var out []point
	for i := q + 1; i < end; {
		j := strings.IndexByte(rawURL[i:end], '&')
		segEnd := end
		if j >= 0 {
			segEnd = i + j
		}
		if segEnd > i {
			seg := rawURL[i:segEnd]
			eq := strings.IndexByte(seg, '=')
			nameRaw, valRaw := seg, ""
			keyAt := [2]int{i, segEnd}
			valAt := [2]int{segEnd, segEnd}
			if eq < 0 {
				// 只有名字没有值（?debug）：没有可注入的值，跳过
				i = segEnd + 1
				continue
			}
			nameRaw = seg[:eq]
			valRaw = seg[eq+1:]
			keyAt = [2]int{i, i + eq}
			valAt = [2]int{i + eq + 1, segEnd}
			name := unescapeOr(nameRaw, nameRaw)
			val := unescapeOr(valRaw, "")
			if !noiseParam(name) {
				out = append(out, point{rawURL: rawURL, name: name, value: val,
					keyAt: keyAt, valAt: valAt})
			}
		}
		i = segEnd + 1
	}
	return out
}

func unescapeOr(s, def string) string {
	if s == "" {
		return def
	}
	v, err := url.QueryUnescape(s)
	if err != nil {
		return s // 畸形百分号编码：按原文用，别丢参数
	}
	return v
}

// ---------------------------------------------------------------- 收集

// collectPoints 汇总根地址 + 爬虫落点里的参数点，按「端点+参数名」去重。
// limit<=0 表示不截断（pointOf 需要先拿到总数才能如实报告「有几个点没测」）。
func collectPoints(c *scan.Ctx, limit int) []point {
	var urls []string
	if b := strings.TrimSpace(c.Base); b != "" {
		urls = append(urls, b)
	}
	urls = append(urls, c.URLs...)

	seen := map[string]bool{}
	var out []point
	for _, raw := range urls {
		u := strings.TrimSpace(raw)
		if u == "" {
			continue
		}
		if !strings.Contains(u, "://") {
			u = httpc.BuildURLJoin(c.Base, u)
		}
		for _, pt := range parsePoints(u) {
			key := pt.endpoint() + "\x00" + pt.name
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, pt)
			if limit > 0 && len(out) >= limit {
				return out
			}
		}
	}
	return out
}

// pointsOf 收集并按参数名过滤（SSRF 只关心 URL 类参数，开放重定向只关心跳转类参数）。
// 第二个返回值是过滤后的**总数**（未截断），调用方用它报告「还有几个点没测」。
func pointsOf(c *scan.Ctx, limit int, keep func(string) bool) ([]point, int) {
	all := collectPoints(c, 0)
	if keep != nil {
		var matched []point
		for _, p := range all {
			if keep(p.name) {
				matched = append(matched, p)
			}
		}
		all = matched
	}
	total := len(all)
	if limit > 0 && total > limit {
		all = all[:limit]
	}
	return all, total
}

// endpoints 去重后的端点（不含查询串），XXE 找 XML 端点用。
func endpoints(c *scan.Ctx, limit int) []string {
	var out []string
	seen := map[string]bool{}
	add := func(raw string) {
		if len(out) >= limit {
			return
		}
		u := strings.TrimSpace(raw)
		if u == "" {
			return
		}
		if !strings.Contains(u, "://") {
			u = httpc.BuildURLJoin(c.Base, u)
		}
		if i := strings.IndexByte(u, '?'); i >= 0 {
			u = u[:i]
		}
		if i := strings.IndexByte(u, '#'); i >= 0 {
			u = u[:i]
		}
		if u == "" || seen[u] {
			return
		}
		seen[u] = true
		out = append(out, u)
	}
	add(c.Base)
	for _, u := range c.URLs {
		add(u)
	}
	return out
}

// noPointReason 没有注入点时的 skip 理由。必须写清「查了多少、缺什么」，
// 否则报告读者会把它当成「没问题」。
func noPointReason(c *scan.Ctx) string {
	n := 0
	if strings.TrimSpace(c.Base) != "" {
		n++
	}
	n += len(c.URLs)
	return "可用落点 " + itoa(n) + " 个（根地址 + 爬虫 URL）中没有带查询参数的端点，" +
		"未发现可注入参数；表单字段不在 scan.Ctx 里（crawl 只给 action 不给字段名），未覆盖"
}

// ---------------------------------------------------------------- 参数名分类

// urlLikeParam 服务端要去抓取的参数名（SSRF）
func urlLikeParam(name string) bool {
	n := strings.ToLower(name)
	for _, k := range []string{"url", "uri", "link", "href", "src", "dest",
		"target", "host", "domain", "site", "redirect", "return", "next",
		"callback", "webhook", "feed", "proxy", "image", "img", "avatar",
		"remote", "resource", "fetch", "endpoint", "service", "api"} {
		if strings.Contains(n, k) {
			return true
		}
	}
	return false
}

// redirectParam 会把参数值写进 Location 的参数名（开放重定向）
func redirectParam(name string) bool {
	n := strings.ToLower(name)
	for _, k := range []string{"redirect", "return", "next", "url", "uri",
		"continue", "dest", "target", "goto", "forward", "callback", "out",
		"link", "to", "ref", "back", "r", "u"} {
		if n == k || strings.HasPrefix(n, k+"_") || strings.HasSuffix(n, "_"+k) ||
			strings.Contains(n, "redirect") || strings.Contains(n, "returnurl") ||
			strings.Contains(n, "return_url") || strings.Contains(n, "callback") {
			return true
		}
	}
	return false
}

// itoa 小工具（避免为了一处 fmt 再引包）
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
