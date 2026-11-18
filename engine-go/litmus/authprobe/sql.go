package authprobe

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Kur1sulab/kara/engine-go/litmus/model"
)

// ================================================================ MySQL
//
// 判据：走完 handshake + mysql_native_password，服务端回 OK 包才算登进去。
// 只做 SHOW DATABASES 与 information_schema 计数，SELECT 业务表的事不做。

// MySQLDefaults 与 Python 版 MYSQL_DEFAULTS 逐项一致。
var MySQLDefaults = [][2]string{{"root", ""}, {"root", "root"}, {"root", "123456"}}

// mysqlPacket 对应 _mysql_pkt：3 字节小端长度 + 1 字节序号 + payload。
func mysqlPacket(payload []byte, seq byte) []byte {
	n := len(payload)
	out := make([]byte, 4+n)
	out[0] = byte(n)
	out[1] = byte(n >> 8)
	out[2] = byte(n >> 16)
	out[3] = seq
	copy(out[4:], payload)
	return out
}

// readFull 从连接上读满 n 字节。对端正常关闭（EOF）按 Python 的 recv→b"" 处理：
// 返回已经读到的部分、err=nil；读超时/复位则返回错误，由调用方决定是否放弃探针。
func readFull(c net.Conn, n int, timeout time.Duration) ([]byte, error) {
	buf := make([]byte, 0, n)
	for len(buf) < n {
		_ = c.SetReadDeadline(time.Now().Add(timeout))
		chunk := make([]byte, n-len(buf))
		k, err := c.Read(chunk)
		if k > 0 {
			buf = append(buf, chunk[:k]...)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return buf, nil
			}
			return buf, err
		}
		if k == 0 {
			return buf, nil
		}
	}
	return buf, nil
}

// mysqlRead 对应 _mysql_read：返回 (body, seq, err)。
// body=nil 且 err=nil 表示「对端没给完整包头」（Python 的 (None, None)）。
func mysqlRead(c net.Conn, timeout time.Duration) ([]byte, byte, error) {
	head, err := readFull(c, 4, timeout)
	if err != nil {
		return nil, 0, err
	}
	if len(head) < 4 {
		return nil, 0, nil
	}
	ln := int(head[0]) | int(head[1])<<8 | int(head[2])<<16
	seq := head[3]
	body, err := readFull(c, ln, timeout)
	if err != nil {
		return nil, 0, err
	}
	return body, seq, nil
}

// mysqlHandshake 是服务端握手包里探针要用的三个字段。
type mysqlHandshake struct {
	version      string
	salt         []byte
	capabilities uint32
}

// parseMySQLHandshake 对应 _mysql_login 里的握手解析段。
// 任何越界都返回错误（Python 那里是一整段 try/except → "握手包解析失败"）。
func parseMySQLHandshake(body []byte) (mysqlHandshake, error) {
	var h mysqlHandshake
	fail := errors.New("握手包解析失败")
	if len(body) < 1 {
		return h, fail
	}
	i := 1
	j := bytes.IndexByte(body[i:], 0)
	if j < 0 {
		return h, fail
	}
	j += i
	h.version = decodeRepl(body[i:j])
	i = j + 1 + 4 // 跳过 thread id
	if i+8 > len(body) {
		return h, fail
	}
	salt := append([]byte(nil), body[i:i+8]...)
	i += 8 + 1 // +filler
	if i+2 > len(body) {
		return h, fail
	}
	capLo := binary.LittleEndian.Uint16(body[i:])
	i += 2 + 1 + 2 // caps + charset + status
	if i+2 > len(body) {
		return h, fail
	}
	capHi := binary.LittleEndian.Uint16(body[i:])
	i += 2
	if i+1 > len(body) {
		return h, fail
	}
	authLen := int(body[i])
	i += 1 + 10 // auth_len + reserved
	h.capabilities = uint32(capLo) | uint32(capHi)<<16

	rest := []byte(nil)
	if i < len(body) {
		rest = body[i:]
	}
	add := authLen - 8
	if add < 0 {
		add = 0
	}
	if add > len(rest) {
		add = len(rest)
	}
	tail := bytes.TrimRight(rest[:add], "\x00")
	if len(tail) > 12 {
		tail = tail[:12]
	}
	salt = append(salt, tail...)
	h.salt = salt
	return h, nil
}

// mysqlNativePassword 对应 _mysql_native：SHA1(pw) XOR SHA1(salt + SHA1(SHA1(pw))).
func mysqlNativePassword(pw string, salt []byte) []byte {
	if pw == "" {
		return nil
	}
	s1 := sha1.Sum([]byte(pw))
	s2 := sha1.Sum(s1[:])
	h := sha1.New()
	_, _ = h.Write(salt)
	_, _ = h.Write(s2[:])
	s3 := h.Sum(nil)
	out := make([]byte, len(s1))
	for i := range s1 {
		out[i] = s1[i] ^ s3[i]
	}
	return out
}

// mysqlHandshakeResponse 对应 _mysql_login 里拼 payload 的那几行。
// 常量与 Python 版相同：CLIENT_41 | CLIENT_SECURE | CLIENT_PLUGIN | (cap & 1)。
func mysqlHandshakeResponse(capabilities uint32, user, pw string, salt []byte) []byte {
	const (
		client41     = 0x00000200
		clientSecure = 0x00008000
		clientPlugin = 0x00080000
	)
	caps := uint32(client41 | clientSecure | clientPlugin)
	caps |= capabilities & 0x00000001

	auth := mysqlNativePassword(pw, salt)
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, caps)
	_ = binary.Write(&b, binary.LittleEndian, uint32(16777216))
	b.WriteByte(33)
	b.Write(make([]byte, 23))
	b.WriteString(user)
	b.WriteByte(0)
	b.WriteByte(byte(len(auth)))
	b.Write(auth)
	b.WriteString("mysql_native_password")
	b.WriteByte(0)
	return b.Bytes()
}

// mysqlLogin 对应 _mysql_login。返回 (conn, ok, msg, version, err)。
// err != nil 表示「连不上 / 握手读取超时」这类致命错误 —— Python 版会抛异常，
// 让整个 probe_mysql 放弃（而不是换下一个口令重试）。
func mysqlLogin(host string, port int, user, pw string, timeout time.Duration) (net.Conn, bool, string, string, error) {
	c, err := dial(host, port, timeout, false)
	if err != nil {
		return nil, false, "", "", err
	}
	body, _, err := mysqlRead(c, timeout)
	if err != nil {
		_ = c.Close()
		return nil, false, "", "", err
	}
	if body == nil {
		_ = c.Close()
		return nil, false, "无握手包", "", nil
	}
	hs, perr := parseMySQLHandshake(body)
	if perr != nil {
		_ = c.Close()
		return nil, false, perr.Error(), "", nil
	}
	payload := mysqlHandshakeResponse(hs.capabilities, user, pw, hs.salt)
	if _, err := c.Write(mysqlPacket(payload, 1)); err != nil {
		_ = c.Close()
		return nil, false, "认证无响应", hs.version, nil
	}
	resp, _, err := mysqlRead(c, timeout)
	if err != nil {
		_ = c.Close()
		return nil, false, "", hs.version, err
	}
	if resp == nil {
		_ = c.Close()
		return nil, false, "认证无响应", hs.version, nil
	}
	if len(resp) > 0 && resp[0] == 0x00 {
		label := pw
		if label == "" {
			label = "空口令"
		}
		return c, true, "认证成功（" + user + "/" + label + "）", hs.version, nil
	}
	errText := ""
	if len(resp) > 0 && resp[0] == 0xff {
		errText = decodeRepl(resp[3:])
	}
	_ = c.Close()
	if errText == "" {
		errText = "认证失败"
	}
	return nil, false, errText, hs.version, nil
}

// mysqlQuery 对应 _mysql_query。只处理结果集的第一列解析（与 Python 版相同）。
func mysqlQuery(c net.Conn, sql string, timeout time.Duration) ([][]interface{}, error) {
	payload := append([]byte{0x03}, []byte(sql)...)
	if _, err := c.Write(mysqlPacket(payload, 0)); err != nil {
		return nil, err
	}
	rows := [][]interface{}{}
	body, _, err := mysqlRead(c, timeout)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return rows, nil
	}
	if body[0] == 0xff || body[0] == 0x00 {
		return rows, nil
	}
	ncol := int(body[0])
	for i := 0; i < ncol; i++ {
		if _, _, err := mysqlRead(c, timeout); err != nil { // 列定义
			return nil, err
		}
	}
	if _, _, err := mysqlRead(c, timeout); err != nil { // EOF
		return nil, err
	}
	for {
		body, _, err := mysqlRead(c, timeout)
		if err != nil {
			return nil, err
		}
		if len(body) == 0 {
			break
		}
		if body[0] == 0xfe || body[0] == 0xff {
			break
		}
		i := 0
		vals := []interface{}{}
		for i < len(body) {
			ln := int(body[i])
			i++
			if ln == 0xFB {
				vals = append(vals, nil)
				continue
			}
			end := i + ln
			if end > len(body) {
				end = len(body)
			}
			vals = append(vals, decodeRepl(body[i:end]))
			i = end
		}
		rows = append(rows, vals)
	}
	return rows, nil
}

// mysqlCount 复刻 int(rows[0][0] or 0)：None/空串 → 0，非数字 → 不算数。
func mysqlCount(v interface{}) (int, bool) {
	switch x := v.(type) {
	case nil:
		return 0, true
	case string:
		if x == "" {
			return 0, true
		}
		n, err := strconv.Atoi(x)
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}

// ProbeMySQL 对应 authprobe.probe_mysql。
func ProbeMySQL(host string, port int, timeout time.Duration) *model.Finding {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	var (
		ev      []string
		conn    net.Conn
		used    [2]string
		version string
	)
	for _, cred := range MySQLDefaults {
		c, ok, msg, ver, err := mysqlLogin(host, port, cred[0], cred[1], timeout)
		if version == "" {
			version = ver
		}
		label := cred[1]
		if label == "" {
			label = "<空>"
		}
		ev = append(ev, "LOGIN "+cred[0]+"/"+label+" → "+msg)
		if err != nil {
			// Python 版这里会抛异常，probe_service 统一吞成 None。
			return nil
		}
		if ok {
			conn, used = c, cred
			break
		}
	}
	if conn == nil {
		return nil
	}
	defer func() { _ = conn.Close() }() // 探针收尾

	dbs, err := mysqlQuery(conn, "SHOW DATABASES", timeout)
	if err != nil {
		return nil
	}
	names := []string{}
	for _, r := range dbs {
		if len(r) == 0 || r[0] == nil {
			continue
		}
		if s, ok := r[0].(string); ok && s != "" {
			names = append(names, s)
		}
	}
	ev = append(ev, "SHOW DATABASES → "+txt([]byte(strings.Join(names, ", ")), 400))

	counts := map[string]int{}
	order := []string{}
	limited := names
	if len(limited) > 12 {
		limited = limited[:12]
	}
	for _, db := range limited {
		q := "SELECT COUNT(*) FROM information_schema.tables " +
			"WHERE table_schema='" + db + "'"
		rows, err := mysqlQuery(conn, q, timeout)
		if err != nil {
			continue // Python: except Exception: pass
		}
		if len(rows) == 0 || len(rows[0]) == 0 {
			continue
		}
		n, ok := mysqlCount(rows[0][0])
		if !ok {
			continue
		}
		counts[db] = n
		order = append(order, db)
	}
	if len(counts) > 0 {
		ev = append(ev, "表数量 → "+txt([]byte(pyReprIntMap(order, counts)), 400))
	}

	repro := "mysql -h " + host + " -P " + strconv.Itoa(port) + " -u " + used[0] + " "
	if used[1] != "" {
		repro += "-p'" + used[1] + "'"
	}
	repro += " -e 'SHOW DATABASES'"

	return result{
		check:    "mysql-default-cred",
		name:     "MySQL 默认/空口令登录成功",
		severity: "critical",
		level:    "L3",
		evidence: strings.Join(ev, "\n"),
		repro:    repro,
		impact:   "攻击者以数据库账户登录，可读取业务库全部数据、写入 UDF 提权。",
		fix:      "设置强口令、删除匿名账户、限制 host 来源、禁止 root 远程。",
		extra: map[string]interface{}{
			"product":      "mysql",
			"version":      version,
			"databases":    names,
			"table_counts": counts,
		},
		creds: []model.Cred{*model.NewCred("mysql", host, port, used[0], used[1],
			"password", "", "")},
	}.finding(host, port)
}

// ================================================================ PostgreSQL
//
// 判据：收到 AuthenticationOk（R 消息 code=0）才算 trust/免密。

// maxPGMessage 是单条 PostgreSQL 报文的上限（16MB）。
// 原版 recv(ln-4) 遇到恶意长度会直接申请几个 GB 内存；这里超限直接放弃，
// 属于安全加固，正常服务端不会触发。
const maxPGMessage = 16 << 20

// PGDefaults 与 Python 版 PG_DEFAULTS 逐项一致。
var PGDefaults = [][2]string{{"postgres", ""}, {"postgres", "postgres"}, {"postgres", "123456"}}

// pgStartupPacket 对应 _pg_startup 的启动包。
func pgStartupPacket(user string) []byte {
	params := "user\x00" + user + "\x00database\x00" + user +
		"\x00application_name\x00litmus\x00\x00"
	body := append(be32(196608), []byte(params)...)
	return append(be32(uint32(len(body)+4)), body...)
}

// pgPasswordMessage 是 cleartext 口令消息（'p' + len + pw + NUL）。
func pgPasswordMessage(pw string) []byte {
	tok := append([]byte(pw), 0)
	msg := append([]byte("p"), be32(uint32(4+len(tok)))...)
	return append(msg, tok...)
}

// pgMD5Message 是 md5 口令消息：md5(md5(pw+user)hex + salt)hex 前缀 "md5"。
func pgMD5Message(pw, user string, salt []byte) []byte {
	inner := md5.Sum([]byte(pw + user))
	innerHex := hex.EncodeToString(inner[:])
	outer := md5.Sum([]byte(innerHex + string(salt)))
	tok := append([]byte("md5"+hex.EncodeToString(outer[:])), 0)
	msg := append([]byte("p"), be32(uint32(4+len(tok)))...)
	return append(msg, tok...)
}

// pgStartup 对应 _pg_startup。fatal=true 表示报文畸形（Python 版会抛异常，
// probe_postgres 不接 → probe_service 返回 None），调用方应当直接放弃。
func pgStartup(c net.Conn, user, pw string, hasPw bool) (state string, raw []byte, fatal bool) {
	if _, err := c.Write(pgStartupPacket(user)); err != nil {
		return "no-response", nil, false
	}
	// 【修正原版缺陷】Python 的 _pg_startup 收到 AuthenticationOk 就 return，
	// 把后面的 ParameterStatus / BackendKeyData / ReadyForQuery 留在缓冲区里。
	// 结果 _pg_query 第一次就把残留的 ReadyForQuery 当成当前查询的结束，
	// SELECT version() 永远返回空，而「表数量」拿到的是 version 的行。
	// 这里认证成功后继续读到 ReadyForQuery 再返回（协议上本来也该这样），
	// 否则证据是错位的假数据。oracle 脚本对 Python 侧做了同样的补丁。
	authenticated := false
	for {
		head := recv(c, 5, 4*time.Second) // Python 这里恒用 4.0 秒，与 timeout 参数无关
		if len(head) < 5 {
			if authenticated {
				return "ok", raw, false
			}
			return "no-response", nil, false
		}
		ln := binary.BigEndian.Uint32(head[1:5])
		if ln < 4 || int64(ln)-4 > maxPGMessage {
			return "no-response", head, true
		}
		want := int(ln) - 4
		body := recv(c, want, 4*time.Second)
		for len(body) < want {
			more := recv(c, want-len(body), 4*time.Second)
			if len(more) == 0 {
				break
			}
			body = append(body, more...)
		}
		msg := append(append([]byte(nil), head...), body...)
		switch head[0] {
		case 'R':
			if len(body) < 4 {
				return "invalid-auth-message", msg, true
			}
			code := binary.BigEndian.Uint32(body[:4])
			switch code {
			case 0:
				authenticated = true
				raw = msg
				continue
			case 3: // cleartext
				if !hasPw {
					return "need-pw", msg, false
				}
				_, _ = c.Write(pgPasswordMessage(pw))
			case 5: // md5
				if !hasPw {
					return "need-pw", msg, false
				}
				if len(body) < 8 {
					return "invalid-auth-message", msg, true
				}
				_, _ = c.Write(pgMD5Message(pw, user, body[4:8]))
			case 2, 7, 9, 10:
				return "unsupported-auth", msg, false
			default:
				return "auth-" + strconv.FormatUint(uint64(code), 10), msg, false
			}
		case 'E':
			return "error", msg, false
		case 'Z':
			if authenticated {
				return "ok", msg, false
			}
			// 没认证就收到 ReadyForQuery：按「没话说」处理，继续等认证结果
		default:
			// ParameterStatus / BackendKeyData / NoticeResponse 继续读
		}
	}
}

// pgQuery 对应 _pg_query，只解析 DataRow（'D'），遇到 ReadyForQuery（'Z'）
// 或 ErrorResponse（'E'）就停。
func pgQuery(c net.Conn, sql string) [][]interface{} {
	q := append([]byte(sql), 0)
	msg := append([]byte("Q"), be32(uint32(4+len(q)))...)
	if _, err := c.Write(append(msg, q...)); err != nil {
		return nil
	}
	rows := [][]interface{}{}
	for {
		head := recv(c, 5, 4*time.Second)
		if len(head) < 5 {
			break
		}
		ln := binary.BigEndian.Uint32(head[1:5])
		if ln < 4 || int64(ln)-4 > maxPGMessage {
			break
		}
		want := int(ln) - 4
		body := recv(c, want, 4*time.Second)
		for len(body) < want {
			more := recv(c, want-len(body), 4*time.Second)
			if len(more) == 0 {
				break
			}
			body = append(body, more...)
		}
		switch head[0] {
		case 'D':
			if len(body) < 2 {
				return rows
			}
			n := int(binary.BigEndian.Uint16(body[:2]))
			i := 2
			vals := []interface{}{}
			for k := 0; k < n; k++ {
				if i+4 > len(body) {
					break
				}
				l := int(int32(binary.BigEndian.Uint32(body[i : i+4])))
				i += 4
				if l < 0 {
					vals = append(vals, nil)
					continue
				}
				end := i + l
				if end > len(body) {
					end = len(body)
				}
				vals = append(vals, decodeRepl(body[i:end]))
				i = end
			}
			rows = append(rows, vals)
		case 'Z', 'E':
			return rows
		}
	}
	return rows
}

// ProbePostgres 对应 authprobe.probe_postgres。
func ProbePostgres(host string, port int, timeout time.Duration) *model.Finding {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	var (
		ev   []string
		conn net.Conn
		used [2]string
	)
	for _, cred := range PGDefaults {
		c, err := dial(host, port, timeout, false)
		if err != nil {
			return nil
		}
		state, _, fatal := pgStartup(c, cred[0], cred[1], cred[1] != "")
		label := cred[1]
		if label == "" {
			label = "<空>"
		}
		ev = append(ev, "STARTUP user="+cred[0]+" pw="+label+" → "+state)
		if fatal {
			_ = c.Close()
			return nil
		}
		if state == "ok" {
			conn, used = c, cred
			break
		}
		_ = c.Close()
	}
	if conn == nil {
		return nil
	}
	defer func() { _ = conn.Close() }() // 探针收尾

	rows := pgQuery(conn, "SELECT version(), current_user, current_database()")
	var ver []interface{}
	if len(rows) > 0 {
		ver = rows[0]
	}
	ev = append(ev, "SELECT version() → "+txt([]byte(pyReprList(ver)), 400))

	cnt := pgQuery(conn, "SELECT count(*) FROM information_schema.tables "+
		"WHERE table_schema NOT IN ('pg_catalog','information_schema')")
	var ntables interface{} = "?"
	if len(cnt) > 0 && len(cnt[0]) > 0 {
		ntables = cnt[0][0]
	}
	ev = append(ev, "用户表数量 → "+pyReprAny(ntables))

	version := ""
	if len(ver) > 0 && ver[0] != nil {
		version = pyReprAny(ver[0])
	}

	repro := "psql 'host=" + host + " port=" + strconv.Itoa(port) +
		" user=" + used[0] + " "
	if used[1] == "" {
		repro += "password="
	}
	repro += "' -c '\\l'"

	return result{
		check:    "postgres-trust",
		name:     "PostgreSQL 免密/默认口令登录成功",
		severity: "critical",
		level:    "L3",
		evidence: strings.Join(ev, "\n"),
		repro:    repro,
		impact:   "攻击者可访问全部数据库，读取业务数据，可能通过 COPY TO PROGRAM 执行命令。",
		fix:      "pg_hba.conf 收紧为 scram-sha-256 + 强口令 + 限制 listen_addresses。",
		extra: map[string]interface{}{
			"product": "postgres",
			"version": version,
			"tables":  ntables,
		},
		creds: []model.Cred{*model.NewCred("postgres", host, port, used[0], used[1],
			"password", "", "")},
	}.finding(host, port)
}
