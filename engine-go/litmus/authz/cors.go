package authz

// cors.go —— CORS 允许任意源 + 携带凭据。
//
// 判据只有两条，缺一不可：
//   Access-Control-Allow-Origin: <我们发的那个 Origin>   （回显，不是 *）
//   Access-Control-Allow-Credentials: true
//
// 为什么 * 不算：浏览器的 CORS 规则里 "*" 与 credentials 互斥，带凭据的请求
// 拿到 "*" 会被浏览器直接拒掉，报出来是噪声。真正可利用的是「回显任意 Origin」。
//
// 只发一次 GET（带 Origin），不发预检：预检只会多一轮请求，结论一样，
// 而 README 级的目标不值得多打两次。

import (
	"fmt"
	"strings"

	"github.com/Kur1sulab/kara/engine-go/litmus/httpc"
	"github.com/Kur1sulab/kara/engine-go/litmus/model"
	"github.com/Kur1sulab/kara/engine-go/litmus/scan"
)

func init() {
	scan.Register(scan.Check{
		Meta: mk("cors-credential", "CORS 允许任意源携带凭据", "medium", "CWE-942"),
		Run:  runCORSCredential,
	})
}

// corsProbeURLs CORS 探测地址表：入口页打头，其余按「API 优先」排序。
//
// 为什么排序而不是直接截断：CORS 的风险全在数据接口上，官网首页回什么
// 都不重要。ctx.URLs 里前面几条往往是首页/静态页，直接截 5 条会把真正的
// /api/xxx 挤出去 —— 结果就是「扫了但什么都没测到」。
func corsProbeURLs(ctx *scan.Ctx, max int) []string {
	var out []string
	if ctx.Base != "" {
		out = append(out, httpc.NormURL(ctx.Base))
	}
	var apis, rest []string
	for _, u := range ctx.URLs {
		if !sameOrigin(ctx, u) {
			continue
		}
		n := httpc.NormURL(u)
		if len(out) > 0 && n == out[0] {
			continue
		}
		if containsAny(pathOf(n), "/api/", "/v1/", "/v2/", "/v3/", "graphql") {
			apis = append(apis, n)
			continue
		}
		rest = append(rest, n)
	}
	out = append(out, apis...)
	out = append(out, rest...)
	out = dedupeStrings(out)
	if len(out) > max {
		out = out[:max]
	}
	return out
}

func runCORSCredential(ctx *scan.Ctx) scan.Result {
	if ctx.Base == "" {
		return scan.Skip("无 Web 探测目标")
	}
	p := newProber(ctx)
	urls := corsProbeURLs(ctx, 6)
	var (
		fs       []*model.Finding
		reached  int
		seenPath = map[string]bool{}
	)
	for _, u := range urls {
		if !p.left() {
			break
		}
		v := viewOf(p.do("GET", u, []httpc.Header{{Name: "Origin", Value: EvilOrigin}}, nil))
		if v.Err != nil {
			continue
		}
		reached++
		acao := strings.TrimSpace(v.header("access-control-allow-origin"))
		acac := strings.ToLower(strings.TrimSpace(v.header("access-control-allow-credentials")))
		if acao == "" || acac != "true" {
			continue
		}
		// 必须回显我们发的源；"*" 与 credentials 互斥，浏览器根本不会带凭据。
		if !strings.EqualFold(acao, EvilOrigin) {
			continue
		}
		path := pathOf(u)
		if seenPath[path] {
			continue
		}
		seenPath[path] = true

		fs = append(fs, model.NewFinding("authz/cors-credential",
			"CORS 允许任意源携带凭据", "medium", ctx.Base, model.FindingOpts{
				Host: ctx.Host, Port: ctx.Port, Scheme: ctx.Scheme, Category: "web",
				Level: "L1", Confidence: "confirmed",
				Evidence: fmt.Sprintf(
					"GET %s 携带 Origin: %s → 响应 Access-Control-Allow-Origin: %s 且 "+
						"Access-Control-Allow-Credentials: true。任意站点都可带受害者 Cookie 读取该接口响应。",
					u, EvilOrigin, acao),
				Repro: fmt.Sprintf("curl -sS -i -H 'Origin: %s' '%s' | grep -i 'access-control'", EvilOrigin, u),
				Impact: "攻击者控制的网页可在受害者已登录的情况下，跨站读取该接口返回的数据" +
					"（用户信息、CSRF token 等），把 CSRF 从「盲打」升级成「可读」。",
				Fix: "按白名单回显 Origin（只允许业务自有域名），并对 Vary: Origin 做缓存隔离；" +
					"确需跨站时不要同时开 Credentials；用 SameSite=Lax/Strict 降低会话被跨站携带的可能。",
				CVSS:    "5.3",
				TitleEN: "CORS Allows Any Origin With Credentials",
				Extra: map[string]interface{}{
					"path":              path,
					"endpoint":          u,
					"allow_origin":      acao,
					"allow_credentials": true,
					"probe_origin":      EvilOrigin,
				},
			}))
	}
	if reached == 0 {
		return scan.Skip("目标不可达，未完成 CORS 探测")
	}
	return scan.OK(p.used(), fs...)
}
