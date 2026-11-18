package injection

import (
	"fmt"
	"strings"
	"time"

	"github.com/Kur1sulab/kara/engine-go/litmus/scan"
)

// ================================================================ SSRF

// ssrfPayloads 全部指向「只有服务端自己能到」的地址：
// 本机 SSH（有 banner 或立即拒绝）、云元数据（内容可辨识）、必然关闭的端口。
var ssrfPayloads = []struct{ label, value string }{
	{"本机 SSH", "http://127.0.0.1:22/"},
	{"云元数据", "http://169.254.169.254/latest/meta-data/"},
	{"本机关闭端口", "http://127.0.0.1:1/"},
}

// ssrfStrong 只有真的取回了目标内容才会出现的特征
var ssrfStrong = []struct{ label, needle string }{
	{"SSH banner", "ssh-2.0-"},
	{"云元数据 ami-id", "ami-id"},
	{"云元数据 instance-id", "instance-id"},
	{"云元数据 security-credentials", "security-credentials"},
	{"云元数据 iam", "meta-data/iam"},
	{"云元数据 user-data", "user-data"},
}

// ssrfWeak 错误文本：说明服务端尝试过连接，但也可能是普通参数校验报错，
// 所以只给 likely，且要求响应与基线明显不同。
var ssrfWeak = []string{
	"connection refused", "econnrefused", "connectex", "dial tcp",
	"no route to host", "getaddrinfo", "connection timed out",
	"failed to connect", "couldn't connect", "could not connect",
	"name or service not known",
}

func runSSRF(c *scan.Ctx) scan.Result {
	p, na := prepare(c)
	if na != nil {
		return *na
	}
	all := collectPoints(c, 0)
	pts, total := pointsOf(c, 8, urlLikeParam)
	if len(pts) == 0 {
		return scan.Skip(fmt.Sprintf("检查了 %d 个参数，没有 URL 类参数名（url/uri/redirect/callback/host/image 等），SSRF 无注入入口", len(all)))
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
		for _, pl := range ssrfPayloads {
			u := pt.withValueOnly(pl.value)
			// 不跟随跳转：目标把 payload 原样写进 Location 时，跟随等于扫描器
			// 自己去连 127.0.0.1:22 / 云元数据 —— 越界且会把 SSRF 判成「客户端跳转」。
			r := p.fetch(get(u).noRedirect().withTimeout(max(p.timeout, 12*time.Second)))
			if !r.ok() {
				o.fail("SSRF payload 请求失败：" + r.errText())
				continue
			}
			conf := ""
			detail := ""
			for _, s := range ssrfStrong {
				if !strings.Contains(r.sigText(), s.needle) {
					continue
				}
				if strings.Contains(b.sigText(), s.needle) {
					continue // 基线本来就有，不能算
				}
				conf = "confirmed"
				detail = fmt.Sprintf("响应出现 %s 特征（%q）：%s", s.label, s.needle, snippetCI(r.rawText(), s.needle, 60))
				break
			}
			if conf == "" {
				for _, w := range ssrfWeak {
					if !strings.Contains(r.sigText(), w) || strings.Contains(b.sigText(), w) {
						continue
					}
					if !r.differs(b) {
						continue
					}
					conf = "likely"
					detail = fmt.Sprintf("响应出现连接错误文本 %q：%s", w, snippetCI(r.rawText(), w, 60))
					break
				}
			}
			if conf == "" {
				continue
			}
			// 计时差异只作为辅助证据：元数据请求可能很快，SSH 可能悬挂，
			// 单靠耗时无法定性，写进证据供人工复核。
			delta := r.elapsed() - b.elapsed()
			timing := fmt.Sprintf("基线 %.2fs / payload %.2fs", b.elapsed().Seconds(), r.elapsed().Seconds())
			if delta > 2*time.Second {
				timing += fmt.Sprintf("（慢 %.1fs，指向服务端真的去连了）", delta.Seconds())
			}
			o.add(newFinding(c, metaSSRF, findingOpts{
				sev:   "high",
				level: "L2",
				conf:  conf,
				evidence: fmt.Sprintf("参数: %s = %s（%s）\n请求: GET %s\n基线: HTTP %d / %dB\npayload 响应: HTTP %d / %dB\n判定: %s\n耗时: %s",
					pt.name, pt.value, pl.label, u, b.status(), b.length(),
					r.status(), r.length(), detail, timing),
				repro:  curlGet(u),
				impact: "服务端会代攻击者访问内网或云元数据服务，可读取实例凭据（进而接管云账号）、探测内网拓扑、访问仅监听在 127.0.0.1 的管理接口。",
				fix:    "对目标 URL 做协议/域名白名单，解析后校验 IP 不在内网与链路本地段，禁止跟随重定向到内网，云主机启用 IMDSv2。",
				extra: map[string]interface{}{
					"path": pathOf(u), "param": pt.name, "payload": pl.value,
					"seconds": r.elapsed().Seconds(), "baseline_seconds": b.elapsed().Seconds(),
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
