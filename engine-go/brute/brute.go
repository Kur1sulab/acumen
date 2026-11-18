// Package brute：内网服务弱口令验证（FTP / MySQL / PostgreSQL / Redis / Telnet / HTTP-Basic）。
//
// 为什么自己写协议而不是调 hydra：断网现场没有外部二进制可用（也常常不允许落盘），
// 所以每条协议的最小握手里都自己实现，只用标准库。代价是支持的协议有边界——
// SSH 需要完整传输层（x/crypto），不在零依赖范围内，脚本里明确报 skip 而不是假装跑过。
//
// 三条纪律（写在代码里，不靠自觉）：
//  1. **有额度**：MaxAttempts 默认 20，命中即停；不做无限字典轰炸。
//  2. **识别锁定**：服务返回「尝试过多/账号锁定」类信号立即停止该目标，不把账号打爆。
//  3. **只报可复现的证据**：命中记下协议回包摘要（如 Redis +OK、MySQL OK 包），
//     报告里凭它一条命令就能复现。
package brute

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// 服务名（与 --service 取值、产物里的 service 字段一致）。
const (
	SVCFTP    = "ftp"
	SVCMYSQL  = "mysql"
	SVCPG     = "postgres"
	SVCRedis  = "redis"
	SVCTelnet = "telnet"
	SVCHTTP   = "http-basic"
)

// Cred 一组凭据。
type Cred struct {
	User string
	Pass string
}

// Options 爆破参数。
type Options struct {
	Service     string        // 空 = 按端口/banner 自动识别
	Users       []string      // 空 = 内置用户名表
	Passes      []string      // 空 = 内置口令表
	Timeout     time.Duration // 单次握手超时，默认 4s
	MaxAttempts int           // 默认 20
	Log         func(format string, a ...any)
}

// Hit 一条命中。
type Hit struct {
	Service string `json:"service"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	User    string `json:"user"`
	Pass    string `json:"pass"`
	Note    string `json:"note"` // 协议回包摘要，用于复现
}

// Result 一轮结果。
type Result struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Service string `json:"service"`
	Tried   int    `json:"tried"`
	Found   []Hit  `json:"found"`
	Skipped string `json:"skipped,omitempty"` // 不支持/被锁/无响应时写原因，绝不装成「没弱口令」
	Elapsed float64 `json:"elapsed"`
}

// ErrLocked 服务明确表示「尝试过多 / 账号锁定」。
var ErrLocked = errors.New("服务提示尝试次数过多或账号已锁定，已停止")

// DefaultUsers 内置用户名（内网运维最常见的那些）。
var DefaultUsers = []string{"root", "admin", "administrator", "test", "guest", "user", "mysql", "postgres", "redis"}

// DefaultPasses 内置口令（弱口令高频项，刻意保持很短）。
var DefaultPasses = []string{
	"", "root", "admin", "123456", "password", "12345678", "admin123", "root123",
	"P@ssw0rd", "test", "guest", "888888", "qwerty", "1qaz2wsx", "Passw0rd",
}

// Detect 按端口与 banner 猜协议；识别不出返回空串。
func Detect(host string, port int, timeout time.Duration) string {
	switch port {
	case 21:
		return SVCFTP
	case 23:
		return SVCTelnet
	case 3306:
		return SVCMYSQL
	case 5432:
		return SVCPG
	case 6379:
		return SVCRedis
	case 80, 81, 443, 8000, 8080, 8081, 8443, 8888, 9000:
		return SVCHTTP
	}
	conn, err := dial(host, port, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	buf := make([]byte, 64)
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	n, _ := conn.Read(buf)
	b := strings.ToLower(string(buf[:n]))
	switch {
	case strings.HasPrefix(b, "220") && strings.Contains(b, "ftp"):
		return SVCFTP
	case strings.Contains(b, "mysql"):
		return SVCMYSQL
	case strings.HasPrefix(b, "-err") || strings.HasPrefix(b, "+"):
		return SVCRedis
	}
	return ""
}

// Run 跑一轮：按 Options.Service（空则自动识别）选协议，命中即停。
func Run(ctx context.Context, host string, port int, opt Options) Result {
	if ctx == nil {
		ctx = context.Background()
	}
	res := Result{Host: host, Port: port}
	t0 := time.Now()
	defer func() { res.Elapsed = time.Since(t0).Seconds() }()

	timeout := opt.Timeout
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	svc := opt.Service
	if svc == "" {
		svc = Detect(host, port, timeout)
	}
	res.Service = svc
	if svc == "" {
		res.Skipped = "无法识别服务类型（可显式 --service）"
		return res
	}

	users := opt.Users
	if len(users) == 0 {
		users = DefaultUsers
	}
	passes := opt.Passes
	if len(passes) == 0 {
		passes = DefaultPasses
	}
	max := opt.MaxAttempts
	if max <= 0 {
		max = 20
	}
	logf := opt.Log
	if logf == nil {
		logf = func(string, ...any) {}
	}

	tried := 0
	for _, u := range users {
		for _, p := range passes {
			if tried >= max {
				res.Tried = tried
				return res
			}
			if err := ctx.Err(); err != nil {
				res.Tried = tried
				res.Skipped = "已取消"
				return res
			}
			tried++
			ok, note, err := attempt(ctx, svc, host, port, u, p, timeout)
			if err != nil {
				if errors.Is(err, ErrLocked) {
					res.Tried = tried
					res.Skipped = "服务提示尝试过多/账号锁定，已停止"
					return res
				}
				res.Tried = tried
				res.Skipped = fmt.Sprintf("协议错误：%v", err)
				return res
			}
			logf("[brute] %s://%s:%d %q/%q -> %v", svc, host, port, u, p, ok)
			if ok {
				res.Tried = tried
				res.Found = append(res.Found, Hit{Service: svc, Host: host, Port: port,
					User: u, Pass: p, Note: note})
				return res // 命中即停：再试下去只是徒增告警
			}
		}
	}
	res.Tried = tried
	return res
}

func attempt(ctx context.Context, svc, host string, port int, user, pass string, timeout time.Duration) (bool, string, error) {
	switch svc {
	case SVCFTP:
		return tryFTP(ctx, host, port, user, pass, timeout)
	case SVCMYSQL:
		return tryMySQL(ctx, host, port, user, pass, timeout)
	case SVCPG:
		return tryPostgres(ctx, host, port, user, pass, timeout)
	case SVCRedis:
		return tryRedis(ctx, host, port, user, pass, timeout)
	case SVCTelnet:
		return tryTelnet(ctx, host, port, user, pass, timeout)
	case SVCHTTP:
		return tryHTTPBasic(ctx, host, port, user, pass, timeout)
	}
	return false, "", fmt.Errorf("不支持的服务类型 %q", svc)
}

// ---------------------------------------------------------------- 协议实现

func dial(host string, port int, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
}

func readLine(r *bufio.Reader, timeout time.Duration) (string, error) {
	return r.ReadString('\n')
}

// tryFTP：220 → USER → 331 → PASS → 230。
func tryFTP(ctx context.Context, host string, port int, user, pass string, timeout time.Duration) (bool, string, error) {
	conn, err := dial(host, port, timeout)
	if err != nil {
		return false, "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout * 3))
	r := bufio.NewReader(conn)
	if line, err := readLine(r, timeout); err != nil {
		return false, "", err
	} else if !strings.HasPrefix(line, "220") {
		return false, "", fmt.Errorf("非 FTP 欢迎语: %s", strings.TrimSpace(line))
	}
	fmt.Fprintf(conn, "USER %s\r\n", user)
	line, err := readLine(r, timeout)
	if err != nil {
		return false, "", err
	}
	code := strings.TrimSpace(line)
	if strings.HasPrefix(code, "230") {
		return true, "USER 直接通过（匿名/免密）: " + code, nil
	}
	if !strings.HasPrefix(code, "331") {
		if isLockSignal(code) {
			return false, "", ErrLocked
		}
		return false, "", nil
	}
	fmt.Fprintf(conn, "PASS %s\r\n", pass)
	line, err = readLine(r, timeout)
	if err != nil {
		return false, "", err
	}
	resp := strings.TrimSpace(line)
	if strings.HasPrefix(resp, "230") {
		return true, "登录成功: " + resp, nil
	}
	if isLockSignal(resp) {
		return false, "", ErrLocked
	}
	return false, "", nil
}

// tryMySQL：读 handshake → 按插件算 auth 响应 → 看 OK/ERR。
func tryMySQL(ctx context.Context, host string, port int, user, pass string, timeout time.Duration) (bool, string, error) {
	conn, err := dial(host, port, timeout)
	if err != nil {
		return false, "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout * 2))
	hdr := make([]byte, 4)
	if _, err := ioReadFull(conn, hdr); err != nil {
		return false, "", err
	}
	n := int(uint32(hdr[0]) | uint32(hdr[1])<<8 | uint32(hdr[2])<<16)
	body := make([]byte, n)
	if _, err := ioReadFull(conn, body); err != nil {
		return false, "", err
	}
	if len(body) < 4 || body[0] != 0x0a {
		return false, "", fmt.Errorf("非 MySQL 握手包")
	}
	plugin, scramble, err := parseMySQLHandshake(body)
	if err != nil {
		return false, "", err
	}
	auth := mysqlAuth(plugin, pass, scramble)
	// 客户端能力标志：协议41 + 安全连接 + 插件认证
	caps := uint32(0x0000aa05 | 0x00008000)
	pkt := make([]byte, 4, 64)
	binary.LittleEndian.PutUint32(pkt, caps)
	pkt = append(pkt, 0, 0, 0, 0) // max packet 4B
	pkt = append(pkt, 33)         // charset utf8
	pkt = append(pkt, make([]byte, 23)...)
	pkt = append(pkt, []byte(user)...)
	pkt = append(pkt, 0)
	if len(auth) > 0 {
		pkt = append(pkt, byte(len(auth)))
		pkt = append(pkt, auth...)
	} else {
		pkt = append(pkt, 0)
	}
	if strings.HasPrefix(plugin, "caching_sha2_password") {
		pkt = append(pkt, []byte(plugin)...)
		pkt = append(pkt, 0)
	}
	if _, err := conn.Write(mysqlPacket(pkt)); err != nil {
		return false, "", err
	}
	resp, err := readMySQLPacket(conn)
	if err != nil {
		return false, "", err
	}
	if len(resp) == 0 {
		return false, "", nil
	}
	switch resp[0] {
	case 0x00:
		return true, "MySQL 登录成功（OK 包）", nil
	case 0xff:
		msg := string(resp[3:])
		if isLockSignal(msg) {
			return false, "", ErrLocked
		}
		return false, "", nil
	case 0xfe: // auth switch：换插件重算一次
		if len(resp) > 1 {
			return false, "", nil
		}
	}
	return false, "", nil
}

func parseMySQLHandshake(body []byte) (plugin string, scramble []byte, err error) {
	// 跳过服务器版本串
	i := 1
	for i < len(body) && body[i] != 0 {
		i++
	}
	i++ // NUL
	i += 4 // connection id
	scramble = append(scramble, body[i:i+8]...)
	i += 8
	i++    // filler
	i += 2 // capability lower
	if i >= len(body) {
		return "mysql_native_password", scramble, nil
	}
	i++    // charset
	i += 2 // status
	i += 2 // capability upper
	authLen := 0
	if i < len(body) {
		authLen = int(body[i])
	}
	i++
	i += 10 // reserved
	if i+12 <= len(body) {
		scramble = append(scramble, body[i+1:i+13]...)
	}
	plugin = "mysql_native_password"
	if i+13 < len(body) {
		if end := strings.IndexByte(string(body[i+13:]), 0); end >= 0 {
			plugin = string(body[i+13 : i+13+end])
		}
	}
	_ = authLen
	return plugin, scramble, nil
}

func mysqlAuth(plugin, pass string, scramble []byte) []byte {
	if pass == "" {
		return nil
	}
	switch {
	case strings.HasPrefix(plugin, "caching_sha2_password"):
		// XOR(SHA256(pass), SHA256(SHA256(SHA256(pass)) + scramble))
		h1 := sha256.Sum256([]byte(pass))
		h2 := sha256.Sum256(h1[:])
		h := sha256.New()
		h.Write(h2[:])
		h.Write(scramble)
		h3 := h.Sum(nil)
		out := make([]byte, len(h1))
		for i := range h1 {
			out[i] = h1[i] ^ h3[i]
		}
		return out
	default: // mysql_native_password
		h1 := sha1.Sum([]byte(pass))
		h2 := sha1.Sum(h1[:])
		h := sha1.New()
		h.Write(scramble)
		h.Write(h2[:])
		h3 := h.Sum(nil)
		out := make([]byte, len(h1))
		for i := range h1 {
			out[i] = h1[i] ^ h3[i]
		}
		return out
	}
}

func mysqlPacket(payload []byte) []byte {
	n := len(payload)
	out := make([]byte, 4+n)
	out[0] = byte(n)
	out[1] = byte(n >> 8)
	out[2] = byte(n >> 16)
	out[3] = 0
	copy(out[4:], payload)
	return out
}

func readMySQLPacket(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := ioReadFull(conn, hdr); err != nil {
		return nil, err
	}
	n := int(uint32(hdr[0]) | uint32(hdr[1])<<8 | uint32(hdr[2])<<16)
	body := make([]byte, n)
	if _, err := ioReadFull(conn, body); err != nil {
		return nil, err
	}
	return body, nil
}

// tryPostgres：StartupMessage → AuthenticationMD5 / SASL → 认证结果。
func tryPostgres(ctx context.Context, host string, port int, user, pass string, timeout time.Duration) (bool, string, error) {
	conn, err := dial(host, port, timeout)
	if err != nil {
		return false, "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout * 3))

	payload := make([]byte, 4, 64)
	binary.BigEndian.PutUint32(payload, 196608) // 协议 3.0
	payload = append(payload, []byte("user\x00")...)
	payload = append(payload, []byte(user)...)
	payload = append(payload, 0)
	payload = append(payload, []byte("database\x00")...)
	payload = append(payload, []byte(user)...)
	payload = append(payload, 0, 0)
	pkt := make([]byte, 4, 4+len(payload))
	binary.BigEndian.PutUint32(pkt, uint32(4+len(payload)))
	pkt = append(pkt, payload...)
	if _, err := conn.Write(pkt); err != nil {
		return false, "", err
	}

	for i := 0; i < 6; i++ {
		hdr := make([]byte, 5)
		if _, err := ioReadFull(conn, hdr); err != nil {
			return false, "", err
		}
		typ := hdr[0]
		n := int(binary.BigEndian.Uint32(hdr[1:]))
		body := make([]byte, n-4)
		if n > 4 {
			if _, err := ioReadFull(conn, body); err != nil {
				return false, "", err
			}
		}
		switch typ {
		case 'R': // Authentication*
			if len(body) < 4 {
				return false, "", fmt.Errorf("认证包异常")
			}
			method := binary.BigEndian.Uint32(body[:4])
			switch method {
			case 0: // OK
				return true, "PostgreSQL 免密通过", nil
			case 5: // MD5
				inner := md5.Sum([]byte(pass + user))
				outer := md5.Sum(append([]byte(hex.EncodeToString(inner[:])), body[4:8]...))
				msg := append([]byte("md5"+hex.EncodeToString(outer[:])), 0)
				if _, err := conn.Write(pgPasswordMsg(msg)); err != nil {
					return false, "", err
				}
			case 3: // cleartext
				if _, err := conn.Write(pgPasswordMsg(append([]byte(pass), 0))); err != nil {
					return false, "", err
				}
			case 10: // SASL SCRAM-SHA-256
				ok, err := pgScram(conn, body[4:], user, pass)
				if err != nil || !ok {
					return false, "", err
				}
				return true, "PostgreSQL SCRAM 登录成功", nil
			default:
				return false, "", fmt.Errorf("不支持的认证方式 %d", method)
			}
		case 'E':
			msg := string(body)
			if isLockSignal(msg) {
				return false, "", ErrLocked
			}
			return false, "", nil
		case 'Z':
			return false, "", nil
		}
	}
	return false, "", nil
}

func pgPasswordMsg(pass []byte) []byte {
	body := append(append([]byte("p"), 0, 0, 0, 0), pass...)
	binary.BigEndian.PutUint32(body[1:5], uint32(4+len(pass)))
	return body
}

func pgScram(conn net.Conn, mech []byte, user, pass string) (bool, error) {
	// 取服务端 nonce
	parts := strings.SplitN(string(mech), "\x00", 2)
	first := parts[0]
	nonce := ""
	for _, kv := range strings.Split(first, ",") {
		if strings.HasPrefix(kv, "r=") {
			nonce = kv[2:]
		}
	}
	raw := make([]byte, 18)
	_, _ = rand.Read(raw)
	clientNonce := base64.RawStdEncoding.EncodeToString(raw)
	clientFirstBare := "n=" + user + ",r=" + nonce + clientNonce
	clientFirst := "n,," + clientFirstBare
	msg := append([]byte("p"), 0, 0, 0, 0)
	binary.BigEndian.PutUint32(msg[1:5], uint32(4+len(clientFirst)))
	msg = append(msg, []byte(clientFirst)...)
	if _, err := conn.Write(msg); err != nil {
		return false, err
	}
	// 读 server-first
	hdr := make([]byte, 5)
	if _, err := ioReadFull(conn, hdr); err != nil {
		return false, err
	}
	if hdr[0] != 'R' {
		return false, nil
	}
	n := int(binary.BigEndian.Uint32(hdr[1:]))
	body := make([]byte, n-4)
	if _, err := ioReadFull(conn, body); err != nil {
		return false, err
	}
	serverFirst := string(body[4:])
	var salt string
	iter := 4096
	for _, kv := range strings.Split(serverFirst, ",") {
		if strings.HasPrefix(kv, "s=") {
			salt = kv[2:]
		}
		if strings.HasPrefix(kv, "i=") {
			iter, _ = strconv.Atoi(kv[2:])
		}
	}
	saltBin, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return false, err
	}
	salted := pbkdf2SHA256([]byte(pass), saltBin, iter, 32)
	clientKey := hmacSHA256(salted, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)
	clientFinalNoProof := "c=biws,r=" + nonce + clientNonce
	authMessage := clientFirstBare + "," + serverFirst + "," + clientFinalNoProof
	sig := hmacSHA256(storedKey[:], []byte(authMessage))
	proof := make([]byte, len(clientKey))
	for i := range clientKey {
		proof[i] = clientKey[i] ^ sig[i]
	}
	final := clientFinalNoProof + ",p=" + base64.StdEncoding.EncodeToString(proof)
	out := append([]byte("p"), 0, 0, 0, 0)
	binary.BigEndian.PutUint32(out[1:5], uint32(4+len(final)))
	out = append(out, []byte(final)...)
	if _, err := conn.Write(out); err != nil {
		return false, err
	}
	// 读最终结果
	hdr2 := make([]byte, 5)
	if _, err := ioReadFull(conn, hdr2); err != nil {
		return false, err
	}
	n2 := int(binary.BigEndian.Uint32(hdr2[1:]))
	body2 := make([]byte, n2-4)
	if _, err := ioReadFull(conn, body2); err != nil {
		return false, err
	}
	return hdr2[0] == 'R', nil
}

// tryRedis：AUTH（带/不带用户名两种写法）→ +OK 即命中。
func tryRedis(ctx context.Context, host string, port int, user, pass string, timeout time.Duration) (bool, string, error) {
	conn, err := dial(host, port, timeout)
	if err != nil {
		return false, "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout * 2))
	r := bufio.NewReader(conn)
	cmd := redisCmd("PING")
	if pass == "" {
		if _, err := conn.Write(cmd); err != nil {
			return false, "", err
		}
	} else {
		if _, err := conn.Write(redisCmd("AUTH", user, pass)); err != nil {
			return false, "", err
		}
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return false, "", err
	}
	line = strings.TrimSpace(line)
	switch {
	case strings.HasPrefix(line, "+OK"), strings.HasPrefix(line, "+PONG"):
		if pass == "" {
			return true, "Redis 未设口令（PING 直接可用）", nil
		}
		return true, "Redis AUTH 通过: " + line, nil
	case strings.Contains(strings.ToLower(line), "too many"), strings.Contains(strings.ToLower(line), "locked"):
		return false, "", ErrLocked
	}
	return false, "", nil
}

func redisCmd(args ...string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	return []byte(b.String())
}

// tryTelnet：等 login: / Password: 提示后提交；只有看到 shell 提示符才算命中。
func tryTelnet(ctx context.Context, host string, port int, user, pass string, timeout time.Duration) (bool, string, error) {
	conn, err := dial(host, port, timeout)
	if err != nil {
		return false, "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout * 4))
	buf := make([]byte, 512)

	readFor := func(marks ...string) string {
		deadline := time.Now().Add(timeout * 2)
		var sb strings.Builder
		for time.Now().Before(deadline) {
			n, err := conn.Read(buf)
			if n > 0 {
				sb.Write(buf[:n])
				low := strings.ToLower(sb.String())
				for _, m := range marks {
					if strings.Contains(low, m) {
						return low
					}
				}
			}
			if err != nil {
				return strings.ToLower(sb.String())
			}
		}
		return strings.ToLower(sb.String())
	}

	prompt := readFor("login:", "username:", "password:", "ogin")
	if strings.Contains(prompt, "password:") && !strings.Contains(prompt, "login") {
		fmt.Fprintf(conn, "%s\r\n", pass)
	} else {
		fmt.Fprintf(conn, "%s\r\n", user)
		fmt.Fprintf(conn, "%s\r\n", pass)
	}
	after := readFor("$", "#", ">", "incorrect", "failed", "denied")
	switch {
	case strings.Contains(after, "incorrect"), strings.Contains(after, "failed"), strings.Contains(after, "denied"):
		return false, "", nil
	case strings.Contains(after, "$"), strings.Contains(after, "#"):
		return true, "Telnet 登录后出现 shell 提示符", nil
	}
	return false, "", nil
}

// tryHTTPBasic：401 → 带凭据再请求，200/3xx 即命中。
func tryHTTPBasic(ctx context.Context, host string, port int, user, pass string, timeout time.Duration) (bool, string, error) {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(host, strconv.Itoa(port)))
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: insecureTLS()}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, "", err
	}
	req.SetBasicAuth(user, pass)
	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return false, "", nil
	case resp.StatusCode < 400:
		return true, fmt.Sprintf("HTTP Basic 通过（%d）", resp.StatusCode), nil
	}
	return false, "", nil
}

func isLockSignal(msg string) bool {
	m := strings.ToLower(msg)
	for _, s := range []string{"too many", "locked", "lockout", "try again later", "denied", "blocked"} {
		if strings.Contains(m, s) {
			return true
		}
	}
	return false
}
