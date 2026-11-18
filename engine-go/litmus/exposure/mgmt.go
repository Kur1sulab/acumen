// 管理面未授权：Spring Actuator 堆转储、Jolokia、Consul。
//
// 三项都要求「返回的是这个产品的真实结构」，不是随便 200：
// jolokia 的 JSON 必须真有 op/attr 字段，consul 必须真有 Config/DebugConfig 结构。
//
// heapdump 是本包唯一会碰到大文件的检查，因此用了最保守的读法：
// 先 HEAD 拿元信息，再发一个 Range: bytes=0-1023 的 GET，读到 1KB 立刻断连接
// （rawSniff）。即使服务端忽略 Range，也不会把几百 MB 的堆转储拉下来。
package exposure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/Kur1sulab/kara/engine-go/litmus/httpc"
	"github.com/Kur1sulab/kara/engine-go/litmus/scan"
)

func init() {
	scan.Register(
		scan.Check{
			Meta: scan.Meta{
				Name: "exposure/actuator-heapdump", Family: "exposure",
				Title:    "Spring Actuator heapdump 可下载",
				Severity: "critical",
				Owasp:    "A05:2021 安全配置错误",
				CWE:      "CWE-200",
			},
			Run: guard("exposure/actuator-heapdump", ChkActuatorHeapdump),
		},
		scan.Check{
			Meta: scan.Meta{
				Name: "exposure/jolokia-list", Family: "exposure",
				Title:    "Jolokia 未授权可列举 MBean",
				Severity: "high",
				Owasp:    "A01:2021 访问控制失效",
				CWE:      "CWE-306",
			},
			Run: guard("exposure/jolokia-list", ChkJolokiaList),
		},
		scan.Check{
			Meta: scan.Meta{
				Name: "exposure/consul-unauth", Family: "exposure",
				Title:    "Consul agent API 未授权",
				Severity: "high",
				Owasp:    "A01:2021 访问控制失效",
				CWE:      "CWE-306",
			},
			Run: guard("exposure/consul-unauth", ChkConsulUnauth),
		},
	)
}

// ---------------------------------------------------------------- heapdump

// contentLength 解析 Content-Length（解析不出来返回 -1，绝不猜）
func contentLength(r *httpc.Response) int64 {
	v := strings.TrimSpace(r.Header("content-length"))
	if v == "" {
		return -1
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return -1
	}
	return n
}

var contentRangeRe = regexp.MustCompile(`(?i)bytes\s+\d+-\d+/(\d+)`)

// totalSize 从 Content-Range 或 Content-Length 得总大小
func totalSize(headers map[string]string, head *httpc.Response) int64 {
	if m := contentRangeRe.FindStringSubmatch(headers["content-range"]); m != nil {
		if n, err := strconv.ParseInt(m[1], 10, 64); err == nil {
			return n
		}
	}
	if v := strings.TrimSpace(headers["content-length"]); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	if head != nil {
		return contentLength(head)
	}
	return -1
}

// isHPROF 堆转储魔数（JDK 的 hprof 文件头）
func isHPROF(b []byte) bool {
	return len(b) >= 12 && string(b[:12]) == "JAVA PROFILE"
}

// ChkActuatorHeapdump Spring Actuator heapdump 可下载。
//
// 判据（两级）：
//  1. 正文前 12 字节是 "JAVA PROFILE" → 直接确认（confidence=confirmed）
//  2. 头部二元信号：Content-Length/Content-Range ≥1MB 且
//     Content-Type 为二进制或 Content-Disposition 指向 heapdump
//     → 判为可下载（confidence=likely），因为小文件可能是空转储
//
// 绝不全量下载：HEAD + Range 1KB，然后立即断连接。
func ChkActuatorHeapdump(c *scan.Ctx) scan.Result {
	const p = "/actuator/heapdump"
	u := urlFor(c, p)
	b := newBudget(c)

	head := probe(c, "HEAD", u, nil)
	tested := 1
	if head == nil || head.Err != nil {
		if head == nil {
			return scan.Skip("目标无响应（连接未建立）")
		}
		return scan.Skip("目标不可达: " + head.ErrText())
	}
	headCT := strings.ToLower(head.Header("content-type"))
	headCL := contentLength(head)
	headDisp := strings.ToLower(head.Header("content-disposition"))

	var notes []string
	// 只在这两种状态下继续：200（可下载）或 405/501（不支持 HEAD，改用受限 GET）。
	// 403/404 再去 GET 一遍只是自找风控。
	needSniff := head.Status == http.StatusOK || head.Status == http.StatusMethodNotAllowed ||
		head.Status == http.StatusNotImplemented
	if !needSniff {
		return okN(tested, fmt.Sprintf("HEAD %s → HTTP %d（端点不可下载）", p, head.Status))
	}

	if !b.take() {
		return scan.Skip("探测预算不足，未做受限读取")
	}
	sniff := rawSniff(u, []httpc.Header{{Name: "Range", Value: "bytes=0-1023"}},
		maxBodySniff, timeoutOf(c))
	tested++

	confident := sniff.Err == nil && isHPROF(sniff.Body)
	size := totalSize(sniff.Headers, head)
	if size < 0 {
		size = headCL
	}
	binary := strings.Contains(sniff.Headers["content-type"], "octet-stream") ||
		strings.Contains(headCT, "octet-stream") ||
		strings.Contains(sniff.Headers["content-disposition"], "heapdump") ||
		strings.Contains(headDisp, "heapdump")
	const (
		big    = 1 << 20
		medium = 64 << 10
	)
	dispHeapdump := strings.Contains(sniff.Headers["content-disposition"], "heapdump") ||
		strings.Contains(headDisp, "heapdump")
	// 两种头部信号：够大且是二进制；或者明确以附件形式声明为 heapdump 且不是空文件
	confirmedByHeader := sniff.Err == nil &&
		((size >= big && binary) || (size >= medium && dispHeapdump))

	if !confident && !confirmedByHeader {
		notes = append(notes, fmt.Sprintf("HEAD → HTTP %d | Content-Length=%d | Content-Type=%s",
			head.Status, headCL, orDefault(head.Header("content-type"), "(无)")))
		if sniff.Err != nil {
			notes = append(notes, "受限读取失败: "+sniff.Err.Error())
		} else {
			notes = append(notes, fmt.Sprintf("Range 读取 → HTTP %d，头 12 字节非 JAVA PROFILE", sniff.Status))
		}
		return okN(tested, "heapdump 端点未提供可下载的堆转储："+strings.Join(notes, "；"))
	}

	conf := "confirmed"
	if !confident {
		conf = "likely" // 只有响应头证据：目标可能返回的是空/占位文件
	}
	ev := fmt.Sprintf("HEAD %s → HTTP %d | Content-Type: %s | Content-Length: %d | Content-Disposition: %s\n"+
		"GET %s（Range: bytes=0-1023）→ HTTP %d | Content-Range: %s\n"+
		"头 16 字节(hex): %s%s\n"+
		"说明: 只读前 1KB 即断连接，未下载完整堆转储。",
		p, head.Status, orDefault(head.Header("content-type"), "(无)"), headCL,
		orDefault(head.Header("content-disposition"), "(无)"),
		p, sniff.Status, orDefault(sniff.Headers["content-range"], "(无)"),
		hexPrefix(sniff.Body, 16),
		map[bool]string{true: "（\"JAVA PROFILE\" 魔数命中）", false: ""}[confident])
	f := newFinding(c, findingSpec{
		Check: "exposure/actuator-heapdump", Name: "Spring Actuator heapdump 可下载",
		Severity: "critical", Level: "L3", Category: "web", Target: u,
		Confidence: conf, Evidence: ev,
		Repro: "curl -s -r 0-1023 -o /tmp/heapdump.head '" + u +
			"' && xxd -l 16 /tmp/heapdump.head",
		Impact: "堆转储含运行期全部明文：数据库口令、Redis/消息队列凭据、会话 token、" +
			"内存中的业务数据与私钥。拿到它基本等于拿下该应用及其后端全部依赖。",
		Fix: "关闭 heapdump 端点（management.endpoints.web.exposure.include 白名单），" +
			"管理端口只监听 127.0.0.1 并由跳板机访问；已暴露过的实例需整体轮换凭据。",
		Extra: map[string]interface{}{
			"path":         p,
			"content_type": orDefault(head.Header("content-type"), ""),
			"content_size": size,
			"hprof_magic":  confident,
			"range_only":   true,
		},
	})
	return okN(tested, "heapdump 可下载（仅读取 1KB 头部确认）", f)
}

// ---------------------------------------------------------------- Jolokia

// jolokiaShape 判定 jolokia/list 的结构：一层 MBean 名 → {op:…, attr:…}
func jolokiaShape(v interface{}) (int, []string) {
	m, ok := v.(map[string]interface{})
	if !ok {
		return 0, nil
	}
	count := 0
	var names []string
	for k, raw := range m {
		sub, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		_, hasOp := sub["op"]
		_, hasAttr := sub["attr"]
		if !hasOp && !hasAttr {
			continue
		}
		count++
		if len(names) < 5 {
			names = append(names, k)
		}
	}
	return count, names
}

// ChkJolokiaList Jolokia 未授权（能列出 MBean → 可直接 exec）。
func ChkJolokiaList(c *scan.Ctx) scan.Result {
	const p = "/jolokia/list"
	r := probe(c, "GET", urlFor(c, p), nil)
	if r == nil || r.Err != nil {
		if r == nil {
			return scan.Skip("目标无响应（连接未建立）")
		}
		return scan.Skip("目标不可达: " + r.ErrText())
	}
	if r.Status != 200 {
		return okN(1, fmt.Sprintf("GET /jolokia/list → HTTP %d", r.Status))
	}
	v, err := r.JSON()
	if err != nil {
		return okN(1, "GET /jolokia/list → 200 但正文不是 JSON")
	}
	n, names := jolokiaShape(v)
	if n == 0 {
		return okN(1, "GET /jolokia/list → JSON 中无 op/attr 字段，不是 Jolokia 列表")
	}
	ev := fmt.Sprintf("GET /jolokia/list → HTTP 200 | 长度 %dB\n"+
		"判据: JSON 顶层为 MBean 名映射，且含 op/attr 字段（共 %d 个 MBean）\n"+
		"样本: %s",
		len(r.Body), n, orDefault(strings.Join(names, ", "), "(无)"))
	return okN(1, "", newFinding(c, findingSpec{
		Check: "exposure/jolokia-list", Name: "Jolokia 未授权可列举 MBean",
		Severity: "high", Level: "L2", Category: "web",
		Target: urlFor(c, p), Evidence: ev,
		Repro: "curl -s '" + urlFor(c, p) + "' | head -c 400",
		Impact: "可读全部 MBean 并调用其操作（含 javax.management.loading:type=MLet 的 exec），" +
			"通常一步到命令执行；即使不能 exec，也能读到数据源 URL 与运行时配置。",
		Fix: "Jolokia 加认证（jolokia.user/jolokia.password）或限制来源 IP，" +
			"生产环境直接不暴露 jolokia servlet。",
		Extra: map[string]interface{}{"path": p, "mbeans": n, "samples": names},
	}))
}

// ---------------------------------------------------------------- Consul

// ChkConsulUnauth Consul agent API 未授权。
func ChkConsulUnauth(c *scan.Ctx) scan.Result {
	const p = "/v1/agent/self"
	r := probe(c, "GET", urlFor(c, p), nil)
	if r == nil || r.Err != nil {
		if r == nil {
			return scan.Skip("目标无响应（连接未建立）")
		}
		return scan.Skip("目标不可达: " + r.ErrText())
	}
	if r.Status != 200 {
		return okN(1, fmt.Sprintf("GET /v1/agent/self → HTTP %d", r.Status))
	}
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(bodyOf(r)), &obj); err != nil {
		return okN(1, "GET /v1/agent/self → 200 但正文不是 JSON 对象")
	}
	cfg, hasCfg := obj["Config"].(map[string]interface{})
	_, hasDbg := obj["DebugConfig"]
	_, hasMember := obj["Member"]
	if !hasCfg || (!hasDbg && !hasMember) {
		return okN(1, "GET /v1/agent/self → JSON 缺 Config/DebugConfig 结构，不是 Consul agent")
	}
	// 只取几个非敏感的元信息字段，绝不整段回显（Config 里可能有 ACL token）
	dc := asString(cfg["Datacenter"])
	node := asString(cfg["NodeName"])
	ver := asString(cfg["Version"])
	server := fmt.Sprint(cfg["Server"])
	ev := fmt.Sprintf("GET /v1/agent/self → HTTP 200 | 长度 %dB\n"+
		"判据: JSON 含 Config 与 DebugConfig，是 Consul agent 自述信息\n"+
		"字段: Datacenter=%s NodeName=%s Version=%s Server=%s\n"+
		"说明: 仅提取非敏感元信息，未回显 Config 全文（可能含 ACL token）。",
		len(r.Body), orDefault(dc, "(空)"), orDefault(node, "(空)"),
		orDefault(ver, "(空)"), server)
	return okN(1, "", newFinding(c, findingSpec{
		Check: "exposure/consul-unauth", Name: "Consul agent API 未授权",
		Severity: "high", Level: "L2", Category: "web",
		Target: urlFor(c, p), Evidence: ev,
		Repro: "curl -s '" + urlFor(c, p) + "' | head -c 400",
		Impact: "可读写 KV、注册/注销服务、查询所有节点与健康检查，进而篡改服务发现把流量" +
			"劫持到攻击者节点；DebugConfig 还会泄露运维参数与目录结构。",
		Fix: "开启 ACL（acl.enabled=true）并下发最小权限 token；HTTP API 只监听 127.0.0.1，" +
			"跨机访问走 mTLS 的 server 端口。",
		Extra: map[string]interface{}{
			"path": p, "datacenter": dc, "node": node, "version": ver,
		},
	}))
}

func asString(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}
