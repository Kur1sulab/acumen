package framework

// B 组：无害的已知风险点存在性判定。
//
// 本组和 A 组的区别只有一个：结论落点不同。
//   - A 组问「这是什么组件」，B 组问「这个已知风险点在不在这里」。
//   - B 组命中时 severity=high、confidence=confirmed，但 Evidence 必须是真实响应原文，
//     且在正文里写清「确认了什么、没确认什么」。凡是没验证的（可利用性、口令是否有效、
//     密钥是否可破）一律写进 evidence / impact，不写进结论。
//
// 本组全部只读：GET 为主；shiro-rememberme-key 只多发一个 Cookie 头，
// 值固定为 bGl0bXVzMi1wcm9iZQ==（base64 的 "litmus2-probe"），不是序列化流、
// 不含 gadget。没有任何写操作、没有登录尝试、没有口令爆破。

import (
	"fmt"
	"strings"

	"github.com/Kur1sulab/kara/engine-go/litmus/httpc"
	"github.com/Kur1sulab/kara/engine-go/litmus/model"
	"github.com/Kur1sulab/kara/engine-go/litmus/scan"
)

func init() {
	scan.Register(
		shiroRememberMeKey,
		actuatorGateway,
		druidWeak,
		nacosWeak,
	)
}

// ---------------------------------------------------------------- B1 Shiro rememberMe

// rememberMeProbe base64("litmus2-probe")。刻意选一个「不是 Java 序列化流」的固定串：
// 目的只是看 Shiro 会不会对它做解密/反序列化并清 cookie，不构造任何 gadget。
const rememberMeProbe = "bGl0bXVzMi1wcm9iZQ=="

var shiroRememberMeKey = scan.Check{
	Meta: scan.Meta{
		Name: "framework/shiro-rememberme-key", Family: Family,
		Title:    "Shiro rememberMe 功能启用（反序列化记忆点存在，未验证可利用）",
		Severity: "high", Owasp: "A08:2021", CWE: "CWE-502",
	},
	Run: runShiroRememberMeKey,
}

func runShiroRememberMeKey(c *scan.Ctx) scan.Result {
	p := newProbe(c)
	if p.base == "" {
		return scan.Skip("无 Web 根（Base 为空），未做 rememberMe 功能判定")
	}
	lines := []string{p.controlLine()}

	plain := p.get("/")
	withCookie := p.getH("/", httpc.H("Cookie", "rememberMe="+rememberMeProbe))
	plainCookie := strings.Join(setCookieNamed(plain, "rememberMe"), " | ")
	probeCookie := strings.Join(setCookieNamed(withCookie, "rememberMe"), " | ")

	lines = append(lines, p.line("GET", "/（对照：不带 rememberMe）", plain))
	lines = append(lines, p.line("GET", "/（Cookie: rememberMe="+rememberMeProbe+"）", withCookie))
	if probeCookie != "" {
		lines = append(lines, "  响应 Set-Cookie: "+clip(probeCookie, 200))
	}
	if s := p.snippet(withCookie, 240); s != "" {
		lines = append(lines, "  探针响应正文："+s)
	}

	// 结构类：Shiro 收到无法反序列化的 rememberMe 后会把它清掉（回写同名 cookie）。
	// 注意：单凭「cookie 被清掉」不够 —— 任何 remember-me 实现都会这么干。
	// 本项按判据要求，必须看到「反序列化失败」的证据（错误特征串，或 5xx），
	// 正常 200 只算弱信号，不进 high 结论。
	cleared := probeCookie != "" && plainCookie == ""
	if cleared {
		lines = append(lines, "  观察：带固定 rememberMe 的请求被回写同名 cookie（服务端清除了这个无效 cookie）")
	}

	// 文本类：反序列化异常特征。允许出现在响应里，但必须不在对照与基线里。
	errMarkers := []string{
		"StreamCorruptedException", "InvalidClassException", "InvalidObjectException",
		"ObjectInputStream", "org.apache.shiro", "Deserialization",
	}
	var errHits []string
	for _, m := range errMarkers {
		if whereMarker(withCookie, m) == "" {
			continue
		}
		if whereMarker(plain, m) != "" || !p.admit(m) {
			continue
		}
		errHits = append(errHits, m)
		lines = append(lines, fmt.Sprintf("  反序列化相关特征 %q 出现在探针响应里（对照与基线都不含）", m))
	}

	// 5xx + cookie 被清除，是「反序列化失败走到异常分支」的旁证；
	// 状态码对照拿的是同路径不带 cookie 的响应。
	errorStatus := cleared && withCookie != nil && withCookie.Err == nil && withCookie.Status >= 500 &&
		(plain == nil || plain.Err != nil || plain.Status < 500)
	if errorStatus {
		lines = append(lines, "  观察：探针请求返回 5xx，而对照请求不是 5xx —— 反序列化失败路径被触发")
	}

	if !errorStatus && len(errHits) == 0 {
		if cleared {
			lines = append(lines, "  未命中：只看到 cookie 被清除，响应仍是正常状态，"+
				"没有反序列化错误特征 —— 按本项判据不足以判定 rememberMe 反序列化功能启用"+
				"（可能是其它框架的 remember-me 实现）")
		} else {
			lines = append(lines, "  未命中：带固定 rememberMe 的请求没有被回写 cookie，响应里也没有反序列化异常特征")
		}
		return p.result(nil)
	}

	lines = append(lines,
		"说明：payload 为 base64(\"litmus2-probe\")，不是 Java 序列化流，不含任何 gadget；",
		"      本项仅判断 rememberMe 功能启用，未验证可利用；未破解密钥，未发送 CommonsBeanutils 等利用链。")

	markers := []string{"Set-Cookie: rememberMe"}
	if len(errHits) > 0 {
		markers = append(markers, errHits...)
	}
	return p.result([]*model.Finding{p.finding(findingSpec{
		check: "framework/shiro-rememberme-key", name: "Shiro rememberMe 功能启用（反序列化记忆点存在，未验证可利用）",
		severity: "high", confidence: "confirmed",
		titleEN:  "Shiro rememberMe deserialization point present (exploitability not verified)",
		evidence: strings.Join(lines, "\n"),
		repro:    "curl -si -H 'Cookie: rememberMe=" + rememberMeProbe + "' " + p.url("/"),
		impact: "rememberMe 启用意味着 Shiro 会对客户端可控的 rememberMe cookie 做解密 + Java 反序列化。" +
			"历史版本存在 Shiro-550（硬编码密钥）与 Shiro-721（Padding Oracle）这类反序列化记忆点，理论上可导致未授权 RCE；" +
			"本项未验证密钥、未验证 gadget 链，不下可利用结论。",
		fix: "升级 Apache Shiro 到 >=1.7.1；轮换并随机化 rememberMe 加密密钥；不需要 rememberMe 就关闭；" +
			"WAF 拦截异常 rememberMe 值。",
		cvss:    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
		path:    "/",
		markers: markers,
		extra: map[string]interface{}{
			"product":                       "Apache Shiro",
			"payload":                       rememberMeProbe,
			"payload_decoded":               "litmus2-probe",
			"payload_note":                  "固定串；非 Java 序列化流；不含 gadget",
			"rememberme_enabled":            true,
			"deserialization_error_markers": errHits,
		},
	})})
}

// ---------------------------------------------------------------- B2 Gateway actuator

var actuatorGateway = scan.Check{
	Meta: scan.Meta{
		Name: "framework/actuator-gateway", Family: Family,
		Title:    "Spring Cloud Gateway actuator 路由未授权可读",
		Severity: "high", Owasp: "A01:2021", CWE: "CWE-306",
	},
	Run: runActuatorGateway,
}

func runActuatorGateway(c *scan.Ctx) scan.Result {
	p := newProbe(c)
	if p.base == "" {
		return scan.Skip("无 Web 根（Base 为空），未做 Gateway actuator 判定")
	}
	lines := []string{p.controlLine()}

	const path = "/actuator/gateway/routes"
	r := p.get(path)
	lines = append(lines, p.line("GET", path, r))

	if r != nil && r.Err == nil {
		body := bodyOf(r)
		hasRoutes := containsFold(body, `"routes"`) || containsFold(body, "route_id")
		// 判定：非 401/403、2xx、JSON、与随机路径不同、含 routes 字段。
		// 302 到登录页不算命中（那正说明有鉴权）。
		hit := r.Status >= 200 && r.Status < 300 && looksJSON(r) && p.distinct(r) && hasRoutes &&
			(p.admit(`"routes"`) || p.admit("route_id"))
		if hit {
			lines = append(lines, "  判定：2xx + JSON + 含 routes/route_id，且响应与随机路径基线不同（非 401/403，未要求认证）")
			if s := p.snippet(r, 320); s != "" {
				lines = append(lines, "  响应正文："+s)
			}
			lines = append(lines, "说明：本项只读取路由清单，未调用 refresh / 新增路由等写接口，未修改任何网关配置。")
			return p.result([]*model.Finding{p.finding(findingSpec{
				check: "framework/actuator-gateway", name: "Spring Cloud Gateway actuator 路由未授权可读",
				severity: "high", confidence: "confirmed",
				titleEN:  "Spring Cloud Gateway actuator routes exposed without auth",
				evidence: strings.Join(lines, "\n"),
				repro:    "curl -si " + p.url(path),
				impact: "未授权者可读取网关路由与后端 URI，直接暴露内网拓扑（数据库、注册中心、管理端地址）；" +
					"若同时开放 POST /actuator/gateway/routes 等写端点，可进一步注入 filter。本项只验证读，未验证写。",
				fix: "收敛 management.endpoints.web.exposure.include，移除 gateway 端点或加认证；" +
					"网关 actuator 只监听管理网段。",
				cvss:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
				path:    path,
				markers: []string{"routes", "route_id"},
				extra:   map[string]interface{}{"product": "Spring Cloud Gateway", "read_only": true},
			})})
		}
		lines = append(lines, fmt.Sprintf("  未命中：状态 %d / JSON=%v / 含 routes=%v / 与基线不同=%v",
			r.Status, looksJSON(r), hasRoutes, p.distinct(r)))
	} else {
		lines = append(lines, "  未命中：请求失败")
	}
	return p.result(nil)
}

// ---------------------------------------------------------------- B3 Druid

var druidWeak = scan.Check{
	Meta: scan.Meta{
		Name: "framework/druid-weak", Family: Family,
		Title:    "Druid 监控台未授权访问",
		Severity: "high", Owasp: "A01:2021", CWE: "CWE-306",
	},
	Run: runDruidWeak,
}

func runDruidWeak(c *scan.Ctx) scan.Result {
	p := newProbe(c)
	if p.base == "" {
		return scan.Skip("无 Web 根（Base 为空），未做 Druid 监控台判定")
	}
	lines := []string{p.controlLine()}

	const path = "/druid/index.html"
	r := p.get(path)
	lines = append(lines, p.line("GET", path, r))

	if r != nil && r.Err == nil && r.Status == 200 && p.distinct(r) && p.admit("Druid Stat Index") &&
		containsFold(bodyOf(r), "Druid Stat Index") {
		lines = append(lines, "  判定：200 且页面标题为 Druid Stat Index，响应与随机路径基线不同，未跳转登录页")
		if s := p.snippet(r, 240); s != "" {
			lines = append(lines, "  响应正文："+s)
		}
		lines = append(lines, "说明：本项只访问监控台首页，未请求 websession.json / sql.json 等数据接口，未做任何修改。")
		return p.result([]*model.Finding{p.finding(findingSpec{
			check: "framework/druid-weak", name: "Druid 监控台未授权访问",
			severity: "high", confidence: "confirmed",
			titleEN:  "Druid monitoring console accessible without auth",
			evidence: strings.Join(lines, "\n"),
			repro:    "curl -si " + p.url(path),
			impact: "未授权者可打开 Druid 监控台，进而读取数据源、SQL 执行统计与会话信息（本项未继续拉取数据）；" +
				"Druid 历史版本亦有已知漏洞。",
			fix:     "为 /druid/* 配置登录与来源 IP 白名单；生产环境关闭 StatViewServlet 或移除监控台。",
			cvss:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			path:    path,
			markers: []string{"Druid Stat Index"},
			extra:   map[string]interface{}{"product": "Alibaba Druid", "read_only": true},
		})})
	}
	lines = append(lines, "  未命中：/druid/index.html 不是可匿名访问的 Druid 监控台（404/跳转登录/内容与基线相同）")
	return p.result(nil)
}

// ---------------------------------------------------------------- B4 Nacos

var nacosWeak = scan.Check{
	Meta: scan.Meta{
		Name: "framework/nacos-weak", Family: Family,
		Title:    "Nacos 用户列表未授权可读 / 控制台暴露（默认口令风险点）",
		Severity: "high", Owasp: "A01:2021", CWE: "CWE-306",
	},
	Run: runNacosWeak,
}

func runNacosWeak(c *scan.Ctx) scan.Result {
	p := newProbe(c)
	if p.base == "" {
		return scan.Skip("无 Web 根（Base 为空），未做 Nacos 判定")
	}
	lines := []string{p.controlLine()}

	const usersPath = "/nacos/v1/auth/users"
	users := p.get(usersPath)
	index := p.get("/nacos/")
	lines = append(lines, p.line("GET", usersPath, users))
	lines = append(lines, p.line("GET", "/nacos/", index))
	if s := p.snippet(users, 260); s != "" {
		lines = append(lines, "  用户接口响应正文（敏感字段已打码）："+s)
	}

	// 情形 1（真正的高危）：认证关闭，用户列表直接可读。
	unauthUsers := users != nil && users.Err == nil && users.Status == 200 && looksJSON(users) &&
		(containsFold(bodyOf(users), "pageItems") || containsFold(bodyOf(users), "username")) &&
		(p.admit("pageItems") || p.admit("username"))
	if unauthUsers {
		lines = append(lines, "  判定：/nacos/v1/auth/users 未要求认证即返回用户列表（200 + pageItems/username）")
		if s := p.snippet(users, 320); s != "" {
			lines = append(lines, "  响应正文（敏感字段已打码）："+s)
		}
		lines = append(lines, "说明：本项只读取一次用户列表，未尝试登录、未修改任何用户或配置。")
		return p.result([]*model.Finding{p.finding(findingSpec{
			check: "framework/nacos-weak", name: "Nacos 用户列表未授权可读（认证未开启）",
			severity: "high", confidence: "confirmed",
			titleEN:  "Nacos user list readable without authentication",
			evidence: strings.Join(lines, "\n"),
			repro:    "curl -si " + p.url(usersPath),
			impact: "未授权者可枚举 Nacos 用户名与口令哈希（本项未尝试破解）；" +
				"结合控制台默认口令风险，可能导致配置中心被接管、进而篡改业务配置。",
			fix:     "开启 nacos.core.auth.enabled 并配置 token 密钥；/nacos/* 限制在管理网段；升级到修复版本。",
			cvss:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			path:    usersPath,
			markers: []string{"pageItems", "username"},
			extra:   map[string]interface{}{"product": "Nacos", "auth_enabled": false},
		})})
	}

	// 情形 2（风险点）：控制台可达。此时认证可能开启，但 Nacos 默认口令 nacos/nacos
	// 是公开的已知风险点；本项不尝试登录（登录会创建 token），只记「暴露 + 需人工核验」。
	console := index != nil && index.Err == nil && index.Status == 200 && p.distinct(index) &&
		containsFold(bodyOf(index), "nacos") && p.admit("nacos")
	if !console {
		lines = append(lines, "  未命中：用户列表不可匿名读，/nacos/ 控制台也不可达")
		return p.result(nil)
	}

	authState := "未判定"
	if users != nil && users.Err == nil {
		switch {
		case users.Status == 403:
			authState = fmt.Sprintf("认证端点返回 %d（鉴权已开启）", users.Status)
		case users.Status == 404:
			authState = "认证端点 404（版本或路径不同）"
		default:
			authState = fmt.Sprintf("认证端点返回 %d", users.Status)
		}
	}
	lines = append(lines, "  判定：/nacos/ 控制台可匿名打开，"+authState)
	if s := p.snippet(index, 200); s != "" {
		lines = append(lines, "  控制台正文："+s)
	}
	lines = append(lines, "说明：本项只确认控制台暴露，未尝试 nacos/nacos 默认口令登录（登录会创建 token，属写操作），"+
		"未验证默认口令是否仍然有效，需人工核验。")
	return p.result([]*model.Finding{p.finding(findingSpec{
		check: "framework/nacos-weak", name: "Nacos 控制台暴露（默认口令 nacos 风险点，未验证登录）",
		severity: "high", confidence: "confirmed",
		titleEN:  "Nacos console exposed (default credential risk, login not attempted)",
		evidence: strings.Join(lines, "\n"),
		repro:    "curl -si " + p.url("/nacos/"),
		impact: "Nacos 控制台对外可达。Nacos 历史上默认口令为 nacos/nacos 且默认未开启鉴权，" +
			"若未改口令可导致配置中心被接管；本项未验证默认口令是否有效，不宣称已接管。",
		fix:     "控制台限制到管理网段；修改默认口令并开启鉴权；升级到最新稳定版。",
		cvss:    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
		path:    "/nacos/",
		markers: []string{"nacos console"},
		extra: map[string]interface{}{
			"product": "Nacos", "auth_state": authState,
			"default_cred_verified": false,
		},
	})})
}
