package authz

// cookie.go —— 会话 Cookie 缺少 HttpOnly / Secure / SameSite。
//
// 只判会话类 Cookie（名字里带 session / jsessionid / phpsessid / token / auth / sid），
// 因为只有它们被盗走才等于会话被接管；给一个 theme=dark 报「缺 Secure」是噪声。
//
// 证据里绝不出现 Cookie 值 —— Set-Cookie 的 value 就是会话凭据本身，
// 写进报告等于把会话贴到交付物上。

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Kur1sulab/kara/engine-go/litmus/model"
	"github.com/Kur1sulab/kara/engine-go/litmus/scan"
)

func init() {
	scan.Register(scan.Check{
		Meta: mk("session-cookie-flags", "会话 Cookie 缺少安全属性", "low", "CWE-1004"),
		Run:  runSessionCookieFlags,
	})
}

// cookieInfo Set-Cookie 里我们关心的属性（不保存 value）。
type cookieInfo struct {
	Name     string
	HttpOnly bool
	Secure   bool
	SameSite string
}

func parseCookie(raw string) *cookieInfo {
	parts := strings.Split(raw, ";")
	first := strings.TrimSpace(parts[0])
	i := strings.IndexByte(first, '=')
	if i <= 0 {
		return nil
	}
	c := &cookieInfo{Name: first[:i]}
	for _, p := range parts[1:] {
		kv := strings.TrimSpace(p)
		low := strings.ToLower(kv)
		switch {
		case low == "httponly":
			c.HttpOnly = true
		case low == "secure":
			c.Secure = true
		case strings.HasPrefix(low, "samesite="):
			c.SameSite = strings.TrimSpace(kv[len("samesite="):])
		}
	}
	return c
}

// sessionCookieWords 会话类 Cookie 的名字特征。
var sessionCookieWords = []string{
	"session", "jsessionid", "phpsessid", "asp.net_sessionid", "token", "auth", "sid",
}

func isSessionCookie(name string) bool {
	low := strings.ToLower(name)
	for _, w := range sessionCookieWords {
		if strings.Contains(low, w) {
			return true
		}
	}
	return false
}

func runSessionCookieFlags(ctx *scan.Ctx) scan.Result {
	if ctx.Base == "" {
		return scan.Skip("无 Web 探测目标")
	}
	p := newProber(ctx)
	urls := probeURLs(ctx, 4)

	// 同名 Cookie 可能出现多次（匿名页 / 登录页各一次）。只按**首次观察**判定：
	// 那次响应确实漏了属性，就是真的漏了；不拿后一次的合规去洗掉前一次的问题。
	seen := map[string]*cookieInfo{}
	from := map[string]string{}
	reached := 0
	for _, u := range urls {
		if !p.left() {
			break
		}
		v := viewOf(p.do("GET", u, nil, nil))
		if v.Err != nil {
			continue
		}
		reached++
		for _, sc := range v.SetCookies {
			c := parseCookie(sc)
			if c == nil || !isSessionCookie(c.Name) {
				continue
			}
			if _, ok := seen[c.Name]; !ok {
				seen[c.Name] = c
				from[c.Name] = u
			}
		}
	}
	if len(seen) == 0 {
		if reached == 0 {
			return scan.Skip("目标不可达，未观察到会话 Cookie")
		}
		return scan.Skip("未观察到会话 Cookie")
	}

	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)

	var fs []*model.Finding
	for _, name := range names {
		c := seen[name]
		var missing []string
		if !c.HttpOnly {
			missing = append(missing, "HttpOnly")
		}
		if !c.Secure {
			missing = append(missing, "Secure")
		}
		if c.SameSite == "" || strings.EqualFold(c.SameSite, "none") {
			missing = append(missing, "SameSite")
		}
		if len(missing) == 0 {
			continue
		}
		channel := "（当前通道 " + ctx.Scheme + "，Secure 在明文通道下本来也不会被回传）"
		if strings.EqualFold(ctx.Scheme, "https") {
			channel = "（通道已是 https，Secure 缺失没有理由）"
		}
		fs = append(fs, model.NewFinding("authz/session-cookie-flags",
			"会话 Cookie 缺少安全属性", "low", ctx.Base, model.FindingOpts{
				Host: ctx.Host, Port: ctx.Port, Scheme: ctx.Scheme, Category: "web",
				Level: "L1", Confidence: "confirmed",
				Evidence: fmt.Sprintf(
					"GET %s 的响应下发会话 Cookie %s=***：缺少 %s %s。"+
						"HttpOnly 缺失 → XSS 可直接读走会话；Secure 缺失 → 明文通道下会话可被旁路截获；"+
						"SameSite 缺失 → 跨站请求默认携带该 Cookie。",
					from[name], name, strings.Join(missing, "、"), channel),
				Repro:  fmt.Sprintf("curl -sS -i '%s' | grep -i '^set-cookie: %s'", from[name], name),
				Impact: "会话 Cookie 可被脚本读取或在明文通道上泄露，攻击者拿到后可直接冒用会话（无需口令）。",
				Fix: "统一加 HttpOnly; Secure; SameSite=Lax（确需跨站携带时才用 None + Secure）；" +
					"在框架/网关层统一收口，避免各接口各写一套。",
				CVSS:    "3.1",
				TitleEN: "Session Cookie Missing Security Attributes",
				Extra: map[string]interface{}{
					"path":     pathOf(from[name]),
					"endpoint": from[name],
					"cookie":   name,
					"missing":  missing,
					"httponly": c.HttpOnly,
					"secure":   c.Secure,
					"samesite": c.SameSite,
					"scheme":   ctx.Scheme,
				},
			}))
	}
	return scan.OK(p.used(), fs...)
}
