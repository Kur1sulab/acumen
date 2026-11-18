package authprobe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Kur1sulab/kara/engine-go/litmus/model"
)

// ================================================================ FTP
//
// 判据：USER anonymous → 331，PASS → 230。只发 PWD，不列目录不下载。

// ProbeFTP 对应 authprobe.probe_ftp。
func ProbeFTP(host string, port int, timeout time.Duration) *model.Finding {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	c, err := dial(host, port, timeout, false)
	if err != nil {
		return nil
	}
	defer func() { _ = c.Close() }() // 探针收尾

	banner := recvUntil(c, []byte("\n"), 65536, timeout)
	if !bytes.HasPrefix(banner, []byte("220")) {
		return nil
	}
	_, _ = c.Write([]byte("USER anonymous\r\n"))
	r1 := recvUntil(c, []byte("\n"), 65536, timeout)
	_, _ = c.Write([]byte("PASS anonymous@example.com\r\n"))
	r2 := recvUntil(c, []byte("\n"), 65536, timeout)
	if !(bytes.HasPrefix(r1, []byte("331")) && bytes.HasPrefix(r2, []byte("230"))) {
		return nil
	}
	_, _ = c.Write([]byte("PWD\r\n"))
	r3 := recvUntil(c, []byte("\n"), 65536, timeout)

	ev := "banner: " + txt(banner, 200) + "\nUSER anonymous → " + txt(r1, 120)
	ev += "\nPASS anonymous@example.com → " + txt(r2, 120)
	ev += "\nPWD → " + txt(r3, 200)

	return result{
		check:    "ftp-anonymous",
		name:     "FTP 匿名登录",
		severity: "high",
		level:    "L2",
		evidence: ev,
		repro:    "ftp " + host + " " + strconv.Itoa(port) + "   # 用户名 anonymous，口令任意",
		impact:   "匿名用户可读取共享目录（常见备份、配置文件、源码），可写入时可植入后门。",
		fix:      "关闭匿名访问 + 改用 SFTP + 限制目录权限。",
		extra:    map[string]interface{}{"product": "ftp", "banner": txt(banner, 120)},
		creds: []model.Cred{*model.NewCred("ftp", host, port, "anonymous",
			"anonymous@example.com", "password", "", "")},
	}.finding(host, port)
}

// ================================================================ VNC
//
// 判据：security types 里出现 None(1)，且选中后 SecurityResult == 0。
// 只做版本握手与安全类型选择，不进图形会话。

// ProbeVNC 对应 authprobe.probe_vnc。
func ProbeVNC(host string, port int, timeout time.Duration) *model.Finding {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	c, err := dial(host, port, timeout, false)
	if err != nil {
		return nil
	}
	defer func() { _ = c.Close() }() // 探针收尾

	ver := recv(c, 12, timeout)
	if !bytes.HasPrefix(ver, []byte("RFB ")) {
		return nil
	}
	_, _ = c.Write([]byte("RFB 003.008\n"))
	ntypes := recv(c, 1, timeout)
	if len(ntypes) == 0 {
		return nil
	}
	n := int(ntypes[0])
	types := recv(c, n, timeout)
	if !bytes.Contains(types, []byte{1}) { // 1 = None（无认证）
		return nil
	}
	_, _ = c.Write([]byte{0x01})
	res := recv(c, 4, timeout)
	if len(res) < 4 || binary.BigEndian.Uint32(res) != 0 {
		return nil
	}
	val := binary.BigEndian.Uint32(res)

	nums := make([]string, 0, len(types))
	for _, t := range types {
		nums = append(nums, strconv.Itoa(int(t)))
	}
	// Python: f"...security types: {list(types)}" → "[1, 2]"
	ev := "banner: " + txt(ver, 40) + "\nsecurity types: [" +
		strings.Join(nums, ", ") + "]\n"
	ev += fmt.Sprintf("选择 None(1) → SecurityResult = %d（0 = 认证通过）", val)

	return result{
		check:    "vnc-nopasswd",
		name:     "VNC 无认证访问",
		severity: "critical",
		level:    "L2",
		evidence: ev,
		repro:    "vncviewer " + host + "::" + strconv.Itoa(port) + "   # 直接进入桌面，不提示口令",
		impact:   "攻击者直接接管远程桌面，等同获得交互式主机控制权。",
		fix:      "设置 VNC 口令 + 仅监听 127.0.0.1 走 SSH 隧道 + 防火墙限制。",
		extra:    map[string]interface{}{"product": "vnc", "rfb": txt(ver, 20)},
	}.finding(host, port)
}

// ================================================================ rsync
//
// 判据：#list 真返回模块名。只列模块，不跑 --list-only 逐模块枚举文件。

// ProbeRsync 对应 authprobe.probe_rsync。
func ProbeRsync(host string, port int, timeout time.Duration) *model.Finding {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	c, err := dial(host, port, timeout, false)
	if err != nil {
		return nil
	}
	defer func() { _ = c.Close() }() // 探针收尾

	_, _ = c.Write([]byte("@RSYNCD: 31.0\n"))
	hello := recvUntil(c, []byte("\n"), 65536, timeout)
	if !bytes.HasPrefix(hello, []byte("@RSYNCD:")) {
		return nil
	}
	_, _ = c.Write([]byte("#list\n"))
	var buf []byte
	for i := 0; i < 8; i++ {
		chunk := recv(c, 4096, 1500*time.Millisecond)
		if len(chunk) == 0 {
			break
		}
		buf = append(buf, chunk...)
		if bytes.Contains(buf, []byte("@RSYNCD: EXIT")) {
			break
		}
	}
	mods := []string{}
	for _, line := range splitLines(decodeRepl(buf)) {
		if strings.HasPrefix(line, "@RSYNCD") {
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		mods = append(mods, strings.TrimSpace(strings.SplitN(line, "\t", 2)[0]))
	}
	if len(mods) == 0 {
		return nil
	}
	shown := mods
	if len(shown) > 20 {
		shown = shown[:20]
	}

	return result{
		check:    "rsync-list",
		name:     "rsync 未授权模块列表",
		severity: "high",
		level:    "L2",
		evidence: "@RSYNCD: 31.0 → " + txt(hello, 60) + "\n#list →\n" + txt(buf, 600),
		repro: "rsync rsync://" + host + ":" + strconv.Itoa(port) + "/   # 列出模块\n" +
			"rsync -av rsync://" + host + ":" + strconv.Itoa(port) + "/<模块>/ ./",
		impact: "未授权可同步整个模块内容（常见备份、网站根目录），可读可写时可直接投毒。",
		fix:    "模块加 auth users + secrets file，或仅允许内网。",
		extra:  map[string]interface{}{"product": "rsync", "modules": shown},
	}.finding(host, port)
}
