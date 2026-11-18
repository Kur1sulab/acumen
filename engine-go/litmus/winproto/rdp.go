package winproto

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/Kur1sulab/kara/engine-go/litmus/model"
)

// ================================================================ RDP
//
// 与 Python 版 _parse_rdp_neg / probe_rdp 一一对应。

var rdpProtoNames = map[uint32]string{
	0x00000000: "PROTOCOL_RDP（传统 RDP 安全层，无 TLS、无 NLA）",
	0x00000001: "PROTOCOL_SSL（TLS，但无 NLA）",
	0x00000002: "PROTOCOL_HYBRID（CredSSP / NLA）",
	0x00000004: "PROTOCOL_RDSTLS",
	0x00000008: "PROTOCOL_HYBRID_EX（NLA + 早期用户认证）",
}

var rdpFailNames = map[uint32]string{
	1: "SSL_REQUIRED_BY_SERVER",
	2: "SSL_NOT_ALLOWED_BY_SERVER",
	3: "SSL_CERT_NOT_ON_SERVER",
	4: "INCONSISTENT_FLAGS",
	5: "HYBRID_REQUIRED_BY_SERVER",
	6: "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER",
}

// rdpCR 是 X.224 Connection Request，requestedProtocols = TLS | CredSSP (0x03)。
var rdpCR = []byte{
	0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00,
}

// rdpNeg 是协商应答的解析结果。
//
// typ 取 "rsp" / "failure" / "none"，对应 Python 版 dict 的 type 字段。
type rdpNeg struct {
	typ   string
	value uint32
	off   int
}

// parseRDPNeg 解析 X.224 Connection Confirm 里的 RDP Negotiation Response。
//
// LI 字段各家实现不一致（有的把 neg data 算进 LI，有的不算），
// 所以先按标准位置读，读不到再扫特征串，两种都失败才算 none。
func parseRDPNeg(resp []byte) rdpNeg {
	if len(resp) < 11 || resp[0] != 0x03 {
		return rdpNeg{typ: "none"}
	}
	li := int(resp[4])
	for _, off := range []int{4 + 1 + li, 4 + 1 + 6} {
		if off+8 <= len(resp) && (resp[off] == 0x02 || resp[off] == 0x03) {
			typ := resp[off]
			length := int(binary.LittleEndian.Uint16(resp[off+2 : off+4]))
			if length != 8 {
				continue
			}
			val := binary.LittleEndian.Uint32(resp[off+4 : off+8])
			kind := "failure"
			if typ == 0x02 {
				kind = "rsp"
			}
			return rdpNeg{typ: kind, value: val, off: off}
		}
	}
	// fallback：直接扫 RDP_NEG_RSP / RDP_NEG_FAILURE 特征
	for _, pat := range []struct {
		sig  []byte
		kind string
	}{
		{[]byte{0x02, 0x00, 0x08, 0x00}, "rsp"},
		{[]byte{0x03, 0x00, 0x08, 0x00}, "failure"},
	} {
		for i := 11; i+len(pat.sig) <= len(resp); i++ {
			if resp[i] != pat.sig[0] {
				continue
			}
			match := true
			for k, b := range pat.sig {
				if resp[i+k] != b {
					match = false
					break
				}
			}
			if match && i+8 <= len(resp) {
				return rdpNeg{typ: pat.kind, value: binary.LittleEndian.Uint32(resp[i+4 : i+8]), off: i}
			}
		}
	}
	return rdpNeg{typ: "none"}
}

// ProbeRDP 只做 X.224 协商，读 selectedProtocol 判定是否强制 NLA。
func ProbeRDP(host string, port int, timeout time.Duration) *model.Finding {
	if port <= 0 {
		port = DefaultRDPPort
	}
	if timeout <= 0 {
		timeout = DefaultRDPTimeout
	}
	t := target{host: host, port: port}
	ev := []string{}

	c, err := dial(host, port, timeout, false)
	if err != nil {
		return nil
	}
	defer func() { _ = c.Close() }() // 关闭失败无处理价值

	if err := writeAll(c, rdpCR, timeout); err != nil {
		return nil
	}
	resp := []byte{}
	deadline := time.Now().Add(timeout)
	tmp := make([]byte, 512)
	for time.Now().Before(deadline) && len(resp) < 512 {
		if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			break
		}
		n, err := c.Read(tmp)
		if n > 0 {
			resp = append(resp, tmp[:n]...)
		}
		if err != nil || n == 0 {
			break
		}
		if len(resp) >= 11 {
			break
		}
	}
	if len(resp) == 0 {
		ev = append(ev, "X.224 Connection Request 无应答")
		return nil
	}
	neg := parseRDPNeg(resp)
	ev = append(ev, fmt.Sprintf("X.224 CR → %dB 应答: %s", len(resp), hexPreview(resp, 32)))

	if neg.typ == "failure" {
		code := neg.value
		name, ok := rdpFailNames[code]
		if !ok {
			name = "未知"
		}
		ev = append(ev, fmt.Sprintf("RDP Negotiation Failure → %s（%d）", name, code))
		if code == 5 {
			ev = append(ev, "结论：服务端要求 NLA（CredSSP），预认证已启用")
		}
		return nil
	}
	if neg.typ == "none" {
		ev = append(ev, "应答中无 RDP Negotiation Response —— 服务端不支持"+
			"RDP 协商扩展（Windows 2008 之前的实现）")
		return t.finding(result{
			check:    "rdp.no_negotiation",
			name:     "RDP 不支持协商扩展（老版本协议栈）",
			severity: "medium",
			level:    "L1",
			evidence: joinLines(ev),
			repro:    reproReplay + fmt.Sprintf("\n# 对照（装了 nmap 的话）：nmap -p %d --script rdp-ntlm-info %s", port, host),
			impact: "不支持协商扩展意味着不提供 CredSSP/NLA 预认证，" +
				"历史版本协议栈存在 MS12-020、CVE-2019-0708（BlueKeep）" +
				"一类预认证漏洞面。" +
				"【推演】是否真可被 BlueKeep 利用需专门检测脚本确认，" +
				"本条只证明「协商扩展缺失」。",
			fix: "升级到受支持的 Windows 版本并启用 NLA；" +
				"RDP 不直接暴露在不可信网络，前置跳板机或 VPN。",
			extra: map[string]interface{}{"negotiation": "none"},
		})
	}

	selected := neg.value
	pname, ok := rdpProtoNames[selected]
	if !ok {
		pname = fmt.Sprintf("未知（0x%X）", selected)
	}
	ev = append(ev, fmt.Sprintf("RDP Negotiation Response → selectedProtocol=0x%X = %s", selected, pname))
	extra := map[string]interface{}{
		"negotiation":       "rsp",
		"selected_protocol": selected,
		"selected_name":     pname,
	}
	if selected == 0x00000000 {
		return t.finding(result{
			check:    "rdp.no_nla",
			name:     "RDP 未强制 NLA（允许传统 RDP 安全层）",
			severity: "medium",
			level:    "L1",
			evidence: joinLines(ev),
			repro:    reproReplay + fmt.Sprintf("\n# 对照（装了 nmap 的话）：nmap -p %d --script rdp-enum-encryption %s", port, host),
			impact: "服务端接受传统 RDP 安全层（无 TLS、无 CredSSP 预认证）。" +
				"这条路径上的认证发生在图形会话建立之后，因此暴露了" +
				"预认证阶段的攻击面，且会话加密强度取决于客户端选择。" +
				"【推演】结合弱口令可被直接撞库登录，但本条不证明口令强度。",
			fix: "组策略：计算机配置 → 管理模板 → Windows 组件 → 远程桌面服务 → " +
				"远程桌面会话主机 → 安全 → 「要求使用网络级别的身份验证对远程" +
				"连接的用户进行身份验证」设为「已启用」；同时把安全层设为 SSL/TLS。",
			extra: extra,
		})
	}
	if selected == 0x00000001 {
		return t.finding(result{
			check:    "rdp.no_nla_tls",
			name:     "RDP 启用 TLS 但未启用 NLA",
			severity: "low",
			level:    "L1",
			evidence: joinLines(ev),
			repro:    reproReplay + fmt.Sprintf("\n# 对照（装了 nmap 的话）：nmap -p %d --script rdp-enum-encryption %s", port, host),
			impact: "传输层已加密，但预认证未启用 —— 未通过身份验证的客户端" +
				"即可推进到会话协商阶段。",
			fix:   "启用 NLA（同上组策略项）。",
			extra: extra,
		})
	}
	ev = append(ev, "结论：已强制 NLA，配置合规")
	return nil
}
