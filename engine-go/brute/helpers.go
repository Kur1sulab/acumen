// helpers.go —— 协议实现要用到的几个小工具（标准库拼装）。
package brute

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"io"
	"net"
)

// ioReadFull 读满整个 buf（net.Conn + 定长包解析高频使用）。
func ioReadFull(conn net.Conn, buf []byte) (int, error) {
	return io.ReadFull(conn, buf)
}

// hmacSHA256 RFC 2104 的 SHA-256 版本（SCRAM 用）。
func hmacSHA256(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

// pbkdf2SHA256 PBKDF2-HMAC-SHA256（RFC 8018）。Go 标准库没有 pbkdf2，
// 但 SCRAM-SHA-256 必须要它——这里按规范实现，仅用于认证计算。
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	if iter <= 0 {
		iter = 1
	}
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	blocks := (keyLen + hashLen - 1) / hashLen
	out := make([]byte, 0, blocks*hashLen)
	buf := make([]byte, 4)

	for block := 1; block <= blocks; block++ {
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf)
		u := prf.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iter; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

// insecureTLS 内网自签证书是常态：爆破只看口令对不对，不做证书校验。
func insecureTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} // #nosec G402 —— 授权内网目标
}
