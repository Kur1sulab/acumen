package winproto

import "time"

// ================================================================ 协议指纹
//
// 为什么需要：这三个协议都是「客户端先说话」，netprobe 的 banner 抓取
// 对它们完全失效（端口开着但 identify 返回 unknown）。不识别出协议，
// 服务级探针就不会被调度，整类问题被静默漏掉。

// Identify 对未知端口做一次轻量协议指纹，返回 "smb" / "ldap" / "rdp" 或 ""。
//
// 标准端口直接按端口判定（零网络开销）；非标准端口才发一个最小探测包。
// 顺序按出现频率：SMB 最多，LDAP 次之，RDP 最后。
func Identify(host string, port int, timeout time.Duration) string {
	if timeout <= 0 {
		timeout = IdentifyTimeout
	}
	switch port {
	case 445, 139:
		return "smb"
	case 389, 636, 3268, 3269:
		return "ldap"
	case 3389:
		return "rdp"
	}
	if sniffSMB(host, port, timeout) {
		return "smb"
	}
	if sniffLDAP(host, port, timeout) {
		return "ldap"
	}
	if sniffRDP(host, port, timeout) {
		return "rdp"
	}
	return ""
}

func sniffSMB(host string, port int, timeout time.Duration) bool {
	c, err := dial(host, port, timeout, false)
	if err != nil {
		return false
	}
	defer func() { _ = c.Close() }() // 关闭失败无处理价值
	if err := nbSend(c, negReqRandom(0), timeout); err != nil {
		return false
	}
	r, err := nbRecv(c, timeout)
	if err != nil {
		return false
	}
	return len(r) >= 64 && len(r) >= 4 &&
		r[0] == smb2Magic[0] && r[1] == smb2Magic[1] && r[2] == smb2Magic[2] && r[3] == smb2Magic[3]
}

func sniffLDAP(host string, port int, timeout time.Duration) bool {
	useTLS := port == 636 || port == 3269
	c, err := dial(host, port, timeout, useTLS)
	if err != nil {
		return false
	}
	defer func() { _ = c.Close() }() // 关闭失败无处理价值
	if err := writeAll(c, ldapBindMsg(1, "", ""), timeout); err != nil {
		return false
	}
	buf := ldapRead(c, timeout, time.Time{})
	for _, m := range ldapMsgs(buf) {
		if m.opTag == 0x61 { // BindResponse
			return true
		}
	}
	return false
}

func sniffRDP(host string, port int, timeout time.Duration) bool {
	c, err := dial(host, port, timeout, false)
	if err != nil {
		return false
	}
	defer func() { _ = c.Close() }() // 关闭失败无处理价值
	if err := writeAll(c, rdpCR, timeout); err != nil {
		return false
	}
	if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return false
	}
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if err != nil || n < 11 {
		return false
	}
	r := buf[:n]
	return r[0] == 0x03 && r[1] == 0x00 && r[5] == 0xd0
}
