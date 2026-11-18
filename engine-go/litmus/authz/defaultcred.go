package authz

// defaultcred.go —— 默认口令探测（对照组是这套逻辑的全部价值）。
//
// 为什么必须有对照组：登录接口对「口令错」和「口令对」的响应经常长得差不多，
// 而失败页会回显账号名 —— 只要响应体不是逐字节相同，天真的实现就会把每一次
// 尝试都判成成功。这里的判据是「相对一次必然失败的尝试，出现了新的会话证据」：
// 新会话 Cookie / 跳到非登录页 / JSON success|token。四者都没有就是没命中。
//
// 三条硬约束（写在这里，改代码前先读）：
//  1. 字典故意小：每产品 2-3 对 + 通用 4 对，截到每账号 5 次。
//  2. 命中锁定/验证码特征立刻停手，不猜、不绕。
//  3. 口令进报告前一律 model.MaskSecret(pass, 4)；Extra 里也只放打码值。

import (
	"fmt"

	"github.com/Kur1sulab/kara/engine-go/litmus/model"
	"github.com/Kur1sulab/kara/engine-go/litmus/scan"
)

func init() {
	scan.Register(scan.Check{
		Meta: mk("default-cred", "默认口令可登录", "high", "CWE-1392"),
		Run:  runDefaultCred,
	})
}

func runDefaultCred(ctx *scan.Ctx) scan.Result {
	if ctx.Base == "" {
		return scan.Skip("无 Web 探测目标")
	}
	p := newProber(ctx)
	eps := discoverLogin(ctx, p, 2)
	if len(eps) == 0 {
		return scan.Skip("未发现登录入口")
	}

	var (
		fs      []*model.Finding
		tried   int
		blocked int
	)
	for _, ep := range eps {
		if !p.left() {
			break
		}
		// 登录页本身就要求验证码：连对照组都不发（发了也是败仗，还会污染失败基线）。
		if ep.Captcha {
			blocked++
			continue
		}
		// 对照组：一个必然不存在的账号 + 必然错误的口令。
		base := p.loginAttempt(ep, ProbeUser, ProbePass)
		if base.Err != nil {
			continue
		}
		if base.Lock != "" {
			// 响应里出现人机验证/锁定：不尝试任何口令。
			blocked++
			continue
		}

		perUser := map[string]int{}
		stop := false
		for _, c := range dictFor(ep.Product) {
			if stop || !p.left() {
				break
			}
			if perUser[c.user] >= maxAttemptsPerAccount {
				continue
			}
			perUser[c.user]++
			tried++
			cand := p.loginAttempt(ep, c.user, c.pass)
			if cand.Err != nil {
				continue
			}
			if cand.Lock != "" {
				// 出现锁定/验证码：本次探测到此为止（继续打就是真爆破了）。
				stop = true
				break
			}
			if hit, why := credVerdict(base, cand); hit {
				fs = append(fs, defaultCredFinding(ctx, ep, c, why, perUser[c.user], base, cand))
				stop = true
				break
			}
		}
	}

	switch {
	case len(fs) > 0:
		return scan.OK(p.used(), fs...)
	case tried == 0 && blocked > 0:
		return scan.Skip("登录入口带验证码/锁定保护，未做口令尝试")
	case tried == 0:
		return scan.Skip("无法建立失败基线（登录接口不可达或响应异常），未做口令尝试")
	}
	return scan.OK(p.used())
}

func defaultCredFinding(ctx *scan.Ctx, ep loginEndpoint, c credPair, why string,
	attempts int, base, cand *loginAttempt) *model.Finding {

	// 打码后的口令：前 4 位可见，够现场核对是哪一个默认值，又不足以直接复用。
	masked := model.MaskSecret(c.pass, 4)

	extra := map[string]interface{}{
		"path":           pathOf(ep.URL),
		"endpoint":       ep.URL,
		"kind":           ep.Kind,
		"user":           c.user,
		"attempts":       attempts,
		"control_status": base.Status,
		"control_len":    base.Len,
		"control_marker": base.Sig,
		"hit_status":     cand.Status,
		"signal":         why,
		"secret_masked":  masked,
	}
	if ep.Product != "" {
		extra["product"] = ep.Product
	}

	f := model.NewFinding("authz/default-cred", "默认口令可登录", "high", ctx.Base, model.FindingOpts{
		Host: ctx.Host, Port: ctx.Port, Scheme: ctx.Scheme, Category: "web",
		Level: "L2", Confidence: "confirmed",
		Evidence: fmt.Sprintf(
			"登录入口 %s：对照组（账号 %s + 必然错误口令）→ HTTP %d，无会话证据；"+
				"候选默认口令（账号 %s）→ HTTP %d，%s。口令已打码，仅保留前 4 位。",
			ep.URL, ProbeUser, base.Status, c.user, cand.Status, why),
		Repro: fmt.Sprintf(
			"curl -sS -i -c /tmp/litmus.jar -d '%s=%s&%s=<报告记录的前 4 位对应的默认值>' '%s'；"+
				"预期与对照组不同：出现会话 Cookie / 跳转 / JSON token。",
			ep.UserField, c.user, ep.PassField, ep.URL),
		Impact: "攻击者可用出厂默认口令直接登录，拿到与正常用户相同的会话；" +
			"若该账号是管理账号，等于把后台交给了攻击者（本工具只验证到登录成功，未做任何管理操作）。",
		Fix: "立即修改/禁用默认账号；首次部署强制改密并要求复杂度；" +
			"对默认口令清单做一次全量自检；管理入口加访问控制与登录告警。",
		CVSS:    "9.8",
		TitleEN: "Default Credentials Accepted",
		Extra:   extra,
		Creds: []model.Cred{*model.NewCred("http", ctx.Host, ctx.Port, c.user,
			masked, "password", "authz/default-cred", "口令仅保留前 4 位，明文不落报告")},
	})
	f.SyncCredsJSON()
	return f
}
