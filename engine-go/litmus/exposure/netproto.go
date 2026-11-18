// 网络协议面：ZooKeeper 四字命令、SMTP 开放中继。
//
// 这两项是「裸 TCP 说话」，不是 HTTP。三条纪律：
//   - 只发只读命令：ZK 的 srvr/stat 都是纯查询；SMTP 只到 RCPT，绝不发 DATA
//     （发了就等于替客户往外投递邮件，性质完全变了）。
//   - 端口要对得上：不会拿 8080 去发 EHLO。端口不像该协议的就不测，报 skip。
//   - 连不上就是 skip 带原因，不是 ok —— 「没测」和「没问题」必须在报告里分开。
package exposure

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Kur1sulab/kara/engine-go/litmus/model"
	"github.com/Kur1sulab/kara/engine-go/litmus/scan"
)

func init() {
	scan.Register(
		scan.Check{
			Meta: scan.Meta{
				Name: "exposure/zookeeper-unauth", Family: "exposure",
				Title:    "ZooKeeper 四字命令未授权",
				Severity: "high",
				Owasp:    "A01:2021 访问控制失效",
				CWE:      "CWE-306",
			},
			Run: guard("exposure/zookeeper-unauth", ChkZooKeeper),
		},
		scan.Check{
			Meta: scan.Meta{
				Name: "exposure/smtp-open-relay", Family: "exposure",
				Title:    "SMTP 开放中继探测",
				Severity: "medium",
				Owasp:    "A05:2021 安全配置错误",
				CWE:      "CWE-441",
			},
			Run: guard("exposure/smtp-open-relay", ChkSMTPOpenRelay),
		},
	)
}

// ---------------------------------------------------------------- ZooKeeper

// zkPorts 该目标上值得发四字命令的端口（客户端的 2181 与两个常用备端口）
func zkPorts(c *scan.Ctx) []int {
	if c == nil || c.Port == 0 {
		return []int{2181}
	}
	switch c.Port {
	case 2181, 2182, 2183:
		return []int{c.Port}
	}
	return nil
}

// fourLetter 发一个四字命令并收响应。
//
// 首包用完整超时（远端要查内存），后续用短空闲超时收尾 ——
// ZK 的四字命令没有长度前缀，只能靠「不再有数据」判断结束。
func fourLetter(host string, port int, cmd string, timeout time.Duration) (string, error) {
	conn, err := dialHook("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(cmd)); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	tmp := make([]byte, 2048)
	first := true
	for buf.Len() < 8192 {
		if first {
			_ = conn.SetReadDeadline(time.Now().Add(timeout))
			first = false
		} else {
			_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		}
		n, err := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			break
		}
	}
	return buf.String(), nil
}

// looksZooKeeper 四字命令响应特征（srvr 与 stat 都以 "Zookeeper version:" 开头）
func looksZooKeeper(s string) bool {
	return strings.Contains(s, "Zookeeper version") || strings.Contains(s, "Zxid")
}

// ChkZooKeeper ZooKeeper 四字命令未授权。
func ChkZooKeeper(c *scan.Ctx) scan.Result {
	ports := zkPorts(c)
	if len(ports) == 0 {
		return scan.Skip(fmt.Sprintf(
			"端口 %d 非 ZooKeeper 客户端端口（2181/2182/2183），未发送四字命令", c.Port))
	}
	t := timeoutOf(c)
	tested := 0
	var notes []string
	dialFailures := 0
	var srvr, stat string
	hitPort := 0
	for _, p := range ports {
		tested++
		out, err := fourLetter(c.Host, p, "srvr", t)
		if err != nil {
			dialFailures++
			notes = append(notes, fmt.Sprintf("%d: %v", p, err))
			continue
		}
		if !looksZooKeeper(out) {
			notes = append(notes, fmt.Sprintf("%d: 响应无 ZooKeeper 特征（%q）", p, clip(firstLine(out), 60)))
			continue
		}
		srvr, hitPort = out, p
		if tested < 64 {
			tested++
			if out2, err2 := fourLetter(c.Host, p, "stat", t); err2 == nil {
				stat = out2
			}
		}
		break
	}
	if hitPort == 0 {
		if dialFailures == len(ports) {
			return scan.Skip("ZooKeeper 端口不可达：" + strings.Join(notes, "；"))
		}
		return okN(tested, "四字命令无 ZooKeeper 响应："+strings.Join(notes, "；"))
	}

	all := srvr + "\n" + stat
	var markers []string
	if strings.Contains(all, "Zookeeper version") {
		markers = append(markers, "Zookeeper version")
	}
	if strings.Contains(all, "Zxid") {
		markers = append(markers, "Zxid")
	}
	ev := fmt.Sprintf("TCP %s:%d\n%s\n"+
		"判据: 未认证的四字命令（srvr/stat）返回版本与事务 ID（命中: %s）\n"+
		"说明: 只发送只读查询命令，未执行任何写操作（mkntr/删除等一律未发）。",
		c.Host, hitPort, clip(all, 400), strings.Join(markers, ", "))
	return okN(tested, "", newFinding(c, findingSpec{
		Check: "exposure/zookeeper-unauth", Name: "ZooKeeper 四字命令未授权",
		Severity: "high", Level: "L1", Category: "host",
		Target:   net.JoinHostPort(c.Host, strconv.Itoa(hitPort)),
		Evidence: ev,
		Repro: fmt.Sprintf("printf 'srvr' | nc -w 2 %s %d",
			c.Host, hitPort),
		Impact: "四字命令开放意味着 2181 端口没有任何访问控制，且往往伴随 conf/cons 等命令可用：" +
			"可读取全部节点路径与元数据，配合 ACL 缺失可用客户端直连读写配置中心（dubbo/kafka 配置）。",
		Fix: "开启 ACL 与 SASL 认证；把 2181 限制为仅应用网段可访问；" +
			"关闭不需要的四字命令（4lw.commands.whitelist=srvr,ruok 按需最小化），或启用 4lw 认证。",
		Extra: map[string]interface{}{
			"port":    hitPort,
			"markers": markers,
		},
	}))
}

// ---------------------------------------------------------------- SMTP

// smtpPorts 该目标上值得谈 SMTP 的端口
func smtpPorts(c *scan.Ctx) []int {
	if c == nil || c.Port == 0 {
		return []int{25, 465, 587}
	}
	switch c.Port {
	case 25, 465, 587:
		return []int{c.Port}
	}
	return nil
}

// smtpResult 一次 SMTP 对话的要点
type smtpResult struct {
	Banner string
	Ehlo   string
	Auth   bool
	Mail   string
	Rcpt   string
}

// sendSMTP 发一条命令并读完整回复（支持 250- 多行）
func sendSMTP(conn net.Conn, br *bufio.Reader, cmd string, timeout time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(cmd + "\r\n")); err != nil {
		return ""
	}
	return readReply(conn, br, timeout)
}

// readReply 读到「第 4 个字符是空格」的最后一行为止（RFC 5321 多行回复）
func readReply(conn net.Conn, br *bufio.Reader, timeout time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	var b strings.Builder
	for i := 0; i < 64; i++ {
		line, err := br.ReadString('\n')
		if line != "" {
			b.WriteString(line)
		}
		if err != nil {
			break
		}
		l := strings.TrimRight(line, "\r\n")
		if len(l) < 4 || l[3] != '-' {
			break
		}
	}
	return b.String()
}

// smtpProbe 一次完整对话：EHLO → (MAIL/RCPT)。
//
// 绝不发 DATA：本函数的意义只是判断「服务端是否愿意接受外域收件人」，
// 真投递一封邮件会把渗透测试变成真实的垃圾邮件源，性质完全不同。
func smtpProbe(host string, port int, useTLS bool, timeout time.Duration) (smtpResult, error) {
	var res smtpResult
	conn, err := dialHook("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return res, err
	}
	defer func() { _ = conn.Close() }()
	if useTLS {
		tc := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
			MinVersion:         tls.VersionTLS10,
		})
		_ = tc.SetDeadline(time.Now().Add(timeout))
		if err := tc.Handshake(); err != nil {
			return res, err
		}
		conn = tc
	}
	br := bufio.NewReader(conn)
	res.Banner = readReply(conn, br, timeout)
	if !strings.HasPrefix(res.Banner, "220") {
		return res, fmt.Errorf("非 SMTP 服务（首包: %q）", clip(firstLine(res.Banner), 60))
	}
	res.Ehlo = sendSMTP(conn, br, "EHLO litmus.local", timeout)
	if !strings.HasPrefix(res.Ehlo, "250") {
		return res, fmt.Errorf("EHLO 未被接受（%q）", clip(firstLine(res.Ehlo), 60))
	}
	res.Auth = strings.Contains(strings.ToUpper(res.Ehlo), "AUTH")
	if !res.Auth {
		res.Mail = sendSMTP(conn, br, "MAIL FROM:<litmus@example.com>", timeout)
		if strings.HasPrefix(res.Mail, "250") {
			res.Rcpt = sendSMTP(conn, br, "RCPT TO:<litmus-probe@example.net>", timeout)
		}
	}
	// 收尾必须干净：发 QUIT，不把连接晾在那儿等对端超时。
	// 返回值刻意忽略 —— 会话已结束，QUIT 的应答不影响任何结论。
	_ = sendSMTP(conn, br, "QUIT", timeout)
	return res, nil
}

// ChkSMTPOpenRelay SMTP 开放中继探测（只判不利用）。
func ChkSMTPOpenRelay(c *scan.Ctx) scan.Result {
	ports := smtpPorts(c)
	if len(ports) == 0 {
		return scan.Skip(fmt.Sprintf(
			"端口 %d 非 SMTP 端口（25/465/587），未发送协议探测", c.Port))
	}
	t := timeoutOf(c)
	tested := 0
	var fs []*model.Finding
	var notes []string
	got := false
	for _, p := range ports {
		tested++
		res, err := smtpProbe(c.Host, p, p == 465, t)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%d: %v", p, err))
			continue
		}
		got = true
		target := net.JoinHostPort(c.Host, strconv.Itoa(p))
		switch {
		case res.Auth:
			ev := fmt.Sprintf("TCP %s | EHLO → 250 且通告 AUTH\n%s\n"+
				"说明: 服务要求认证，中继风险取决于认证账号的可控性（本项未做口令猜测）。",
				target, clip(res.Ehlo, 300))
			fs = append(fs, newFinding(c, findingSpec{
				Check: "exposure/smtp-open-relay", Name: "SMTP 服务开放且要求认证",
				Severity: "info", Level: "L1", Category: "host", Target: target,
				Evidence: ev,
				Repro:    fmt.Sprintf("printf 'EHLO litmus.local\\r\\nQUIT\\r\\n' | nc -w 3 %s %d", c.Host, p),
				Impact: "邮件服务对外可达，暴露在口令猜测与已知 MTA 漏洞的攻击面内；" +
					"若存在弱口令账号，账号被接管后可用于钓鱼与横向。",
				Fix: "限制 25/465/587 的访问来源到已知业务网段；强制 TLS 与强口令/多因素；" +
					"关闭开放中继（默认即可，但要显式核对 mynetworks 与 smtpd_relay_restrictions）。",
				Extra: map[string]interface{}{"port": p, "auth": true},
			}))
		case res.Rcpt != "" && (strings.HasPrefix(res.Rcpt, "250") || strings.HasPrefix(res.Rcpt, "251")):
			ev := fmt.Sprintf("TCP %s\n%s\n%s\n%s\n"+
				"判据: EHLO 无 AUTH 通告，且对外部域 RCPT TO 返回 %s（接受收件人）\n"+
				"说明: 只发到 RCPT，未发 DATA —— 是否为真正可投递的开放中继需人工确认（本项不投递任何邮件）。",
				target, clip(res.Banner, 120), clip(res.Ehlo, 200),
				clip(res.Rcpt, 120), firstLine(res.Rcpt))
			fs = append(fs, newFinding(c, findingSpec{
				Check: "exposure/smtp-open-relay", Name: "SMTP 疑似开放中继（接受外域收件人）",
				Severity: "medium", Level: "L1", Category: "host",
				Confidence: "likely", Target: target, Evidence: ev,
				Repro: fmt.Sprintf("printf 'EHLO litmus.local\\r\\nMAIL FROM:<litmus@example.com>\\r\\n"+
					"RCPT TO:<litmus-probe@example.net>\\r\\nQUIT\\r\\n' | nc -w 3 %s %d", c.Host, p),
				Impact: "无认证即可提交外域收件人，很可能可被用作垃圾邮件/钓鱼跳板，" +
					"导致客户 IP 与域名进入黑名单，并成为攻击者隐藏来源的通道。",
				Fix: "关闭匿名中继：smtpd_relay_restrictions 只允许 authenticated 与本地域；" +
					"对外部域 RCPT 直接 554；开启 SPF/DKIM/DMARC 并监控异常发信量。",
				Extra: map[string]interface{}{"port": p, "auth": false,
					"rcpt": firstLine(res.Rcpt)},
			}))
		default:
			notes = append(notes, fmt.Sprintf("%d: EHLO 200 但 %s", p,
				rcptVerdict(res)))
		}
		// 一个端口谈成即可，不在同一台主机上反复骚扰
		break
	}
	if !got {
		return scan.Skip("SMTP 端口均无响应或非 SMTP 服务：" + strings.Join(notes, "；"))
	}
	if len(fs) == 0 {
		return okN(tested, "SMTP 可达但未发现开放中继特征"+suffixNotes(notes))
	}
	return okN(tested, "SMTP 探测有结论"+suffixNotes(notes), fs...)
}

// rcptVerdict 把 RCPT 阶段的结果写成一句话
func rcptVerdict(res smtpResult) string {
	switch {
	case res.Mail != "" && !strings.HasPrefix(res.Mail, "250"):
		return "MAIL FROM 被拒（" + firstLine(res.Mail) + "）"
	case res.Rcpt == "":
		return "未进入 RCPT 阶段"
	default:
		return "外域收件人被拒（" + firstLine(res.Rcpt) + "）"
	}
}

func suffixNotes(notes []string) string {
	if len(notes) == 0 {
		return ""
	}
	return "：" + strings.Join(notes, "；")
}
