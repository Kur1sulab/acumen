package winproto

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Kur1sulab/kara/engine-go/litmus/model"
)

// ================================================================ LDAP
//
// 与 Python 版 _ldap_bind_msg / _ldap_search_msg / _ldap_read /
// _ldap_has_done / _ldap_msgs / _ldap_result / _ldap_entry / probe_ldap 一一对应。

// ldapPortHint 保留 Python 版 LDAP_PORT_HINT 的端口 → 协议提示表
// （Python 版当前没用到，逐函数移植故保留）。
var ldapPortHint = map[int]string{389: "ldap", 636: "ldaps", 3268: "ldap", 3269: "ldaps"}

// ldapBindMsg 组 simple BindRequest。
//
// protocolOp 是 CHOICE 的 APPLICATION tag：BindRequest = [APPLICATION 0] = 0x60。
// 不是 context [0]（0xA0）—— 只有内层 authentication 的 simple 才是 [0] = 0x80。
func ldapBindMsg(mid int, dn, pw string) []byte {
	inner := append(derInt(3, 0x02), derOctets([]byte(dn))...)
	inner = append(inner, der(0x80, []byte(pw))...)
	return der(0x30, append(derInt(mid, 0x02), der(0x60, inner)...))
}

// ldapSearchMsg 组 SearchRequest。
//
// attrs / filt 为 nil 时用 Python 版同样的默认值：
// filt 是 (objectClass=*) 的 [7] present 形式，attrs 是 rootDSE 常用属性表。
func ldapSearchMsg(mid int, base string, filt []byte, attrs []string, size, scope int) []byte {
	if attrs == nil {
		attrs = []string{"namingContexts", "defaultNamingContext", "dnsHostName",
			"supportedLDAPVersion", "supportedControl"}
	}
	if filt == nil {
		filt = der(0x87, []byte("objectClass")) // [7] present
	}
	body := derOctets([]byte(base))
	body = append(body, derEnum(scope)...)     // 0=baseObject 1=singleLevel 2=wholeSubtree
	body = append(body, derEnum(0)...)         // derefAliases=never
	body = append(body, derInt(size, 0x02)...) // sizeLimit
	body = append(body, derInt(10, 0x02)...)   // timeLimit
	body = append(body, derBool(false)...)     // typesOnly
	body = append(body, filt...)
	var list []byte
	for _, a := range attrs {
		list = append(list, derOctets([]byte(a))...)
	}
	body = append(body, der(0x30, list)...)
	// SearchRequest = [APPLICATION 3] = 0x63
	return der(0x30, append(derInt(mid, 0x02), der(0x63, body)...))
}

// ldapRead 读到 SearchResultDone（0x65）或超时为止。
func ldapRead(c net.Conn, timeout time.Duration, deadline time.Time) []byte {
	if deadline.IsZero() {
		deadline = time.Now().Add(timeout)
	}
	per := 2 * time.Second
	if timeout < per {
		per = timeout
	}
	buf := []byte{}
	tmp := make([]byte, 8192)
	for time.Now().Before(deadline) {
		if err := c.SetReadDeadline(time.Now().Add(per)); err != nil {
			break
		}
		n, err := c.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil || n == 0 {
			// Python: 超时 break、连接错误 break、EOF break
			break
		}
		if ldapHasDone(buf) {
			break
		}
	}
	return buf
}

func ldapHasDone(buf []byte) bool {
	for _, m := range ldapMsgs(buf) {
		if m.opTag == 0x65 {
			return true
		}
	}
	return false
}

// ldapMsg 是一条 LDAPMessage 的三元组（msgid, protocolOp tag, content）。
type ldapMsg struct {
	mid   int
	opTag byte
	op    []byte
}

// ldapMsgs 把 TCP 缓冲切成若干条 LDAPMessage；遇到不完整的尾部就停。
func ldapMsgs(buf []byte) []ldapMsg {
	out := []ldapMsg{}
	i := 0
	for i < len(buf) {
		tag, content, nxt, err := tlv(buf, i)
		if err != nil || tag != 0x30 {
			break
		}
		_, midB, j, err := tlv(content, 0)
		if err != nil {
			break
		}
		mid := 0
		for _, b := range midB {
			mid = mid<<8 | int(b)
		}
		opTag, op, _, err := tlv(content, j)
		if err != nil {
			break
		}
		out = append(out, ldapMsg{mid: mid, opTag: opTag, op: op})
		i = nxt
	}
	return out
}

// ldapResult 解析 BindResponse / SearchResultDone 的公共头：
// resultCode, matchedDN, diagnostic。
//
// Python 版遇到截断的 op 会抛 ValueError；Go 版返回 err，调用方按
// 「这条报文不认」处理（契约 §4.3）。
func ldapResult(op []byte) (rc int, matched, diag string, err error) {
	_, codeB, i, err := tlv(op, 0)
	if err != nil {
		return 0, "", "", err
	}
	if len(codeB) == 0 {
		rc = -1
	} else {
		rc = int(int8(codeB[0]))
		for _, b := range codeB[1:] {
			rc = rc<<8 | int(b)
		}
	}
	_, matchedB, i, err := tlv(op, i)
	if err != nil {
		return rc, "", "", nil
	}
	_, diagB, _, err := tlv(op, i)
	if err != nil {
		return rc, "", "", nil
	}
	return rc, utf8Replace(matchedB), utf8Replace(diagB), nil
}

// ldapEntry 解析 SearchResultEntry → (dn, {attr: [vals]})。
func ldapEntry(op []byte) (string, map[string][]string, error) {
	_, dnB, i, err := tlv(op, 0)
	if err != nil {
		return "", nil, err
	}
	_, attrs, _, err := tlv(op, i)
	if err != nil {
		return "", nil, err
	}
	out := map[string][]string{}
	j := 0
	for j < len(attrs) {
		_, pa, next, err := tlv(attrs, j)
		if err != nil {
			return "", nil, err
		}
		j = next
		_, nameB, k, err := tlv(pa, 0)
		if err != nil {
			return "", nil, err
		}
		_, vals, _, err := tlv(pa, k)
		if err != nil {
			return "", nil, err
		}
		vlist := []string{}
		m := 0
		for m < len(vals) {
			_, v, next2, err := tlv(vals, m)
			if err != nil {
				return "", nil, err
			}
			vlist = append(vlist, utf8Replace(v))
			m = next2
		}
		out[string(nameB)] = vlist
	}
	return utf8Replace(dnB), out, nil
}

// ProbeLDAP 做匿名 bind + rootDSE +（可选）匿名读目录条目。
//
// useTLS 会被端口强制覆盖：636 / 3269 一律走 TLS，与 Python 版一致。
func ProbeLDAP(host string, port int, timeout time.Duration, useTLS bool) *model.Finding {
	if port <= 0 {
		port = DefaultLDAPPort
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if port == 636 || port == 3269 {
		useTLS = true
	}
	t := target{host: host, port: port}
	ev := []string{}

	c, err := dial(host, port, timeout, useTLS)
	if err != nil {
		return nil
	}
	defer func() { _ = c.Close() }() // 关闭失败无处理价值

	// ---- 1) 匿名 simple bind ----
	if err := writeAll(c, ldapBindMsg(1, "", ""), timeout); err != nil {
		return nil
	}
	buf := ldapRead(c, timeout, time.Time{})
	bindRC := -1
	diag := ""
	found := false
	for _, m := range ldapMsgs(buf) {
		if m.opTag != 0x61 {
			continue
		}
		rc, _, d, err := ldapResult(m.op)
		if err != nil {
			continue // 畸形 BindResponse：当没读到（Python 会抛异常，见包注释）
		}
		bindRC, diag, found = rc, d, true
		break
	}
	if !found {
		ev = append(ev, fmt.Sprintf("bind 无 BindResponse（%dB 原始）: %s", len(buf), hexPreview(buf, 40)))
		return nil
	}
	diagTxt := ""
	if diag != "" {
		diagTxt = "（" + diag + "）"
	}
	ev = append(ev, fmt.Sprintf("anonymous simple bind → resultCode=%d%s", bindRC, diagTxt))
	if bindRC != 0 {
		// 49 = invalidCredentials，53 = unwillingToPerform，都是正常加固
		ev = append(ev, "结论：匿名 bind 被拒，该目录要求认证")
		return nil
	}

	// ---- 2) rootDSE ----
	if err := writeAll(c, ldapSearchMsg(2, "", nil, []string{
		"namingContexts", "defaultNamingContext", "dnsHostName",
		"supportedLDAPVersion", "supportedControl", "supportedCapabilities",
	}, 5, 0), timeout); err != nil {
		return nil
	}
	buf2 := ldapRead(c, timeout, time.Time{})
	ctxs := []string{}
	dnsName := ""
	for _, m := range ldapMsgs(buf2) {
		if m.opTag != 0x64 {
			continue
		}
		if _, attrs, err := ldapEntry(m.op); err == nil {
			if v := attrs["namingContexts"]; len(v) > 0 {
				ctxs = v
			} else if v := attrs["defaultNamingContext"]; len(v) > 0 {
				ctxs = v
			}
			if v := attrs["dnsHostName"]; len(v) > 0 {
				dnsName = v[0]
			}
		}
		break // Python 版拿到第一条 entry 就 break
	}
	if len(ctxs) > 0 {
		extra := ""
		if dnsName != "" {
			extra = "，dnsHostName=" + dnsName
		}
		ev = append(ev, fmt.Sprintf("rootDSE 匿名可读 → namingContexts=%s%s",
			strings.Join(ctxs[:minInt(4, len(ctxs))], ", "), extra))
	} else {
		ev = append(ev, fmt.Sprintf("rootDSE 匿名查询无 namingContexts（%dB）", len(buf2)))
	}

	// ---- 3) 有命名上下文就试一次匿名读条目（只读、sizeLimit=5）----
	type entry struct {
		dn    string
		attrs map[string][]string
	}
	entries := []entry{}
	if len(ctxs) > 0 {
		base := ctxs[0]
		// (objectClass=*) 是最小假设：不猜属性名，不猜 OU 结构
		if err := writeAll(c, ldapSearchMsg(3, base, der(0x87, []byte("objectClass")),
			[]string{"distinguishedName", "sAMAccountName", "objectClass", "cn"}, 5, 2), timeout); err != nil {
			return nil
		}
		buf3 := ldapRead(c, timeout, time.Time{})
		for _, m := range ldapMsgs(buf3) {
			if m.opTag != 0x64 {
				continue
			}
			dn, attrs, err := ldapEntry(m.op)
			if err != nil {
				continue // 畸形条目：跳过，不 panic
			}
			entries = append(entries, entry{dn: dn, attrs: attrs})
		}
		ev = append(ev, fmt.Sprintf("匿名 subtree search base=%s sizeLimit=5 → 返回 %d 条", base, len(entries)))
		for _, e := range entries[:minInt(3, len(entries))] {
			// 属性名必须如实标注 —— OpenLDAP 用 cn/uid，AD 才有 sAMAccountName，
			// 不能把 cn 的值挂到 sAMAccountName 标签下（会误导读者以为目录结构是 AD）
			nm := ""
			for _, key := range []string{"sAMAccountName", "uid", "cn"} {
				if v := e.attrs[key]; len(v) > 0 {
					nm = fmt.Sprintf("  (%s=%s)", key, v[0])
					break
				}
			}
			ev = append(ev, fmt.Sprintf("  · %s%s", e.dn, nm))
		}
	}

	ctxForRepro := ""
	if len(ctxs) > 0 {
		ctxForRepro = ctxs[0]
	}
	if len(entries) > 0 {
		return t.finding(result{
			check:    "ldap.anon_read",
			name:     "LDAP 匿名可读目录条目（域信息泄露）",
			severity: "high",
			level:    "L2",
			evidence: joinLines(ev),
			repro: reproReplay + fmt.Sprintf("\n# 对照（装了 ldap-utils 的话）：ldapsearch -x -H ldap://%s:%d -b \"%s\" -s sub \"(objectClass=*)\"",
				host, port, ctxForRepro),
			impact: "匿名即可枚举目录对象（用户/组/计算机的 DN 与账号标识），" +
				"为后续密码喷洒与 Kerberoasting 提供完整账号清单。" +
				"AD 里账号标识是 sAMAccountName，OpenLDAP 通常是 uid/cn —— " +
				"本次实际读到的属性见上方证据。" +
				"【推演】账号清单本身不等于可登录，但把爆破面从「猜」变成「点名」。",
			fix: "1) AD：dsheuristic 关闭匿名绑定 —— 组策略「网络访问: 不允许匿名 " +
				"SID/名称转换」+ 注册表 RestrictAnonymous=1；\n" +
				"2) 在域控上启用 LDAP signing 与 channel binding（LdapEnforceChannelBinding=2）；\n" +
				"3) 仅对必要的服务账号开放读权限，删除 Authenticated Users 的泛读 ACE。",
			extra: map[string]interface{}{
				"naming_contexts": ctxs,
				"anon_entries":    len(entries),
				"dns_host_name":   dnsName,
			},
		})
	}
	if len(ctxs) > 0 {
		ctxTxt := strings.Join(ctxs[:minInt(2, len(ctxs))], ", ")
		if ctxTxt == "" { // 对齐 Python 的 `", ".join(...) or "未知"`
			ctxTxt = "未知"
		}
		return t.finding(result{
			check:    "ldap.anon_bind",
			name:     "LDAP 允许匿名绑定并泄露命名上下文",
			severity: "medium",
			level:    "L2",
			evidence: joinLines(ev),
			repro: reproReplay + fmt.Sprintf("\n# 对照（装了 ldap-utils 的话）：ldapsearch -x -H ldap://%s:%d -b \"\" -s base \"(objectClass=*)\"",
				host, port),
			impact: fmt.Sprintf("匿名可读 rootDSE，泄露域名 DN（%s）与目录服务标识。"+
				"这本身不直接泄露数据，但把「猜域名」变成「已知域名」，"+
				"是后续 LDAP 查询与 Kerberos 攻击的前置信息。", ctxTxt),
			fix: "关闭匿名绑定，或至少限制 rootDSE 的可读属性；" +
				"域控上启用 LDAP signing。",
			extra: map[string]interface{}{
				"naming_contexts": ctxs,
				"anon_entries":    0,
				"dns_host_name":   dnsName,
			},
		})
	}
	return nil
}
