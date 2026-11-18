package authprobe

import (
	"bytes"
	"strconv"
	"strings"
	"time"

	"github.com/Kur1sulab/kara/engine-go/litmus/model"
)

// ================================================================ Redis
//
// 判据：PING 收到 +PONG 才算无认证。NOAUTH 只说明「有认证」，不是漏洞。

// ProbeRedis 对应 authprobe.probe_redis。
//
// Python 签名是 probe_redis(host, port, timeout=4.0, **kw) —— tls 被 **kw
// 吞掉，探针始终走明文（真实 Redis 的 TLS 是 6.0 的 tls-port，独立端口）。
func ProbeRedis(host string, port int, timeout time.Duration) *model.Finding {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	c, err := dial(host, port, timeout, false)
	if err != nil {
		return nil
	}
	defer func() { _ = c.Close() }() // 探针收尾，关闭失败无处理价值

	_, _ = c.Write([]byte("PING\r\n"))
	r := recv(c, 512, timeout)
	if !bytes.HasPrefix(r, []byte("+PONG")) {
		// NOAUTH = 有认证，不是漏洞；其余（含空响应）同样不出结论。
		return nil
	}
	ev := []string{"PING → " + txt(r, MaxEvid)}

	info := map[string]string{}
	_, _ = c.Write([]byte("INFO server\r\n"))
	buf := recvUntil(c, []byte("\r\n"), 8192, timeout)
	// INFO 是 bulk reply，多读几次凑够
	for i := 0; i < 6; i++ {
		more := recv(c, 4096, 1*time.Second)
		if len(more) == 0 {
			break
		}
		buf = append(buf, more...)
	}
	for _, line := range splitLines(decodeRepl(buf)) {
		if !strings.Contains(line, ":") ||
			strings.HasPrefix(line, "*") || strings.HasPrefix(line, "$") {
			continue
		}
		k, v, _ := strings.Cut(line, ":")
		switch k {
		case "redis_version", "os", "tcp_port", "run_id":
			info[k] = strings.TrimSpace(v)
		}
	}
	ev = append(ev, "INFO server → "+txt(buf, 400))

	var keys interface{}
	_, _ = c.Write([]byte("DBSIZE\r\n"))
	r3 := recv(c, 128, timeout)
	ev = append(ev, "DBSIZE → "+txt(r3, MaxEvid))
	if bytes.HasPrefix(r3, []byte(":")) {
		body := strings.TrimSpace(string(r3[1:]))
		if body == "" {
			// Python: int(b"" or 0) == 0
			keys = 0
		} else if n, err := strconv.Atoi(body); err == nil {
			keys = n
		}
	}

	level := "L2"
	if n, ok := keys.(int); ok && n != 0 {
		level = "L3"
	}

	extra := map[string]interface{}{"product": "redis", "keys": keys}
	for k, v := range info {
		extra[k] = v
	}

	return result{
		check:    "redis-unauth",
		name:     "Redis 未授权访问",
		severity: "high",
		level:    level,
		evidence: strings.Join(ev, "\n"),
		repro:    "redis-cli -h " + host + " -p " + strconv.Itoa(port) + " ping   # 直接返回 PONG，无 AUTH 提示",
		impact:   "攻击者可直接读写全部键值、写计划任务或 SSH 公钥实现主机接管。",
		fix:      "bind 内网地址 + 设置 requirepass + 禁用危险命令（rename-command）。",
		extra:    extra,
	}.finding(host, port)
}

// ================================================================ Memcached
//
// 判据：stats 有 STAT 返回才算暴露；curr_items 非 0 才升到 L3。

// ProbeMemcached 对应 authprobe.probe_memcached。
func ProbeMemcached(host string, port int, timeout time.Duration) *model.Finding {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	c, err := dial(host, port, timeout, false)
	if err != nil {
		return nil
	}
	defer func() { _ = c.Close() }() // 探针收尾

	_, _ = c.Write([]byte("stats\r\n"))
	var buf []byte
	for i := 0; i < 8; i++ {
		chunk := recv(c, 4096, 1500*time.Millisecond)
		if len(chunk) == 0 {
			break
		}
		buf = append(buf, chunk...)
		if bytes.Contains(buf, []byte("END\r\n")) {
			break
		}
	}
	if !bytes.Contains(buf, []byte("STAT ")) {
		return nil
	}

	info := map[string]string{}
	for _, line := range splitLines(decodeRepl(buf)) {
		if !strings.HasPrefix(line, "STAT ") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			info[parts[1]] = parts[2]
		}
	}
	items := "0"
	if v, ok := info["curr_items"]; ok {
		items = v
	}

	level := "L2"
	if items != "0" {
		level = "L3"
	}

	extra := map[string]interface{}{"product": "memcached", "items": items}
	for k, v := range info {
		extra[k] = v
	}

	return result{
		check:    "memcached-unauth",
		name:     "Memcached 未授权访问",
		severity: "high",
		level:    level,
		evidence: "stats →\n" + txt(buf, 600),
		repro:    "printf 'stats\\r\\n' | nc " + host + " " + strconv.Itoa(port),
		impact:   "可读取缓存数据（当前 " + items + " 条），常含会话令牌与业务明文。",
		fix:      "仅监听内网 + SASL 认证 + 防火墙限制来源。",
		extra:    extra,
	}.finding(host, port)
}
