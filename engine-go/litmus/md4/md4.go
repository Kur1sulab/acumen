// Package md4 是 RFC 1320 的 MD4 实现。
//
// 为什么要自己写：NTLM 的响应计算必须用 MD4（NT 哈希 = MD4(UTF-16LE(口令))），
// 而 Go 标准库**没有** crypto/md4（它在 golang.org/x/crypto/md4，属于外部模块）。
// 引外部模块就破了「零第三方依赖 + CGO_ENABLED=0 静态单文件」这条线，
// 所以这 100 行必须自己写。
//
// MD4 本身早已不适合做通用摘要（碰撞容易），这里只用于 NTLM 兼容 ——
// 目标协议要求什么就用什么，与「推荐用什么」是两件事。
package md4

import (
	"encoding/binary"
	"math/bits"
)

// Size MD4 摘要长度（字节）
const Size = 16

// BlockSize MD4 分组长度（字节）
const BlockSize = 64

// digest 保存中间状态
type digest struct {
	s   [4]uint32
	x   [BlockSize]byte
	nx  int
	len uint64
}

// New 返回一个空的 MD4 状态
func New() *digest {
	d := &digest{}
	d.Reset()
	return d
}

// Reset 复位到初始向量（RFC 1320 §3.3）
func (d *digest) Reset() {
	d.s[0] = 0x67452301
	d.s[1] = 0xefcdab89
	d.s[2] = 0x98badcfe
	d.s[3] = 0x10325476
	d.nx = 0
	d.len = 0
}

// Write 追加数据（io.Writer 兼容）
func (d *digest) Write(p []byte) (int, error) {
	n := len(p)
	d.len += uint64(n)
	if d.nx > 0 {
		k := copy(d.x[d.nx:], p)
		d.nx += k
		if d.nx == BlockSize {
			d.block(d.x[:])
			d.nx = 0
		}
		p = p[k:]
	}
	for len(p) >= BlockSize {
		d.block(p[:BlockSize])
		p = p[BlockSize:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return n, nil
}

// Sum 收尾并返回摘要
func (d *digest) Sum() [Size]byte {
	// 保存当前状态，填充后计算，再把状态还原 —— 允许继续 Write
	d0 := *d
	length := d0.len
	var pad [72]byte
	pad[0] = 0x80
	padLen := 56 - int(length%BlockSize)
	if padLen <= 0 {
		padLen += BlockSize
	}
	var lenBytes [8]byte
	binary.LittleEndian.PutUint64(lenBytes[:], length<<3)
	d0.Write(pad[:padLen])
	d0.Write(lenBytes[:])

	var out [Size]byte
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(out[i*4:], d0.s[i])
	}
	return out
}

// block 处理一个 64 字节分组
func (d *digest) block(p []byte) {
	var x [16]uint32
	for i := 0; i < 16; i++ {
		x[i] = binary.LittleEndian.Uint32(p[i*4:])
	}
	a, b, c, dd := d.s[0], d.s[1], d.s[2], d.s[3]

	// Round 1: F(x,y,z) = (x & y) | (^x & z)，K = 0
	for i := 0; i < 16; i += 4 {
		a = bits.RotateLeft32(a+f(b, c, dd)+x[i+0], 3)
		dd = bits.RotateLeft32(dd+f(a, b, c)+x[i+1], 7)
		c = bits.RotateLeft32(c+f(dd, a, b)+x[i+2], 11)
		b = bits.RotateLeft32(b+f(c, dd, a)+x[i+3], 19)
	}

	// Round 2: G(x,y,z) = (x & y) | (x & z) | (y & z)，K = 0x5a827999
	for i := 0; i < 4; i++ {
		a = bits.RotateLeft32(a+g(b, c, dd)+x[i+0]+0x5a827999, 3)
		dd = bits.RotateLeft32(dd+g(a, b, c)+x[i+4]+0x5a827999, 5)
		c = bits.RotateLeft32(c+g(dd, a, b)+x[i+8]+0x5a827999, 9)
		b = bits.RotateLeft32(b+g(c, dd, a)+x[i+12]+0x5a827999, 13)
	}

	// Round 3: H(x,y,z) = x ^ y ^ z，K = 0x6ed9eba1
	order := [16]int{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}
	for i := 0; i < 16; i += 4 {
		a = bits.RotateLeft32(a+h(b, c, dd)+x[order[i+0]]+0x6ed9eba1, 3)
		dd = bits.RotateLeft32(dd+h(a, b, c)+x[order[i+1]]+0x6ed9eba1, 9)
		c = bits.RotateLeft32(c+h(dd, a, b)+x[order[i+2]]+0x6ed9eba1, 11)
		b = bits.RotateLeft32(b+h(c, dd, a)+x[order[i+3]]+0x6ed9eba1, 15)
	}

	d.s[0] += a
	d.s[1] += b
	d.s[2] += c
	d.s[3] += dd
}

func f(x, y, z uint32) uint32 { return (x & y) | (^x & z) }
func g(x, y, z uint32) uint32 { return (x & y) | (x & z) | (y & z) }
func h(x, y, z uint32) uint32 { return x ^ y ^ z }

// Sum 便捷函数：一次算完
func Sum(data []byte) [Size]byte {
	d := New()
	d.Write(data)
	return d.Sum()
}

// NTLM 计算 NT 哈希 = MD4(UTF-16LE(口令))
//
// 注意：UTF-16LE 编码而不是 UTF-8。中文/非 ASCII 口令必须按 UTF-16LE 转，
// 否则哈希与 Windows 算出来的不一致，登录会一直 0xc000006d。
func NTLM(password string) [Size]byte {
	u := UTF16LE(password)
	return Sum(u)
}

// UTF16LE 把字符串编成 UTF-16LE 字节（含 surrogate pair 处理）
func UTF16LE(s string) []byte {
	rs := []rune(s)
	out := make([]byte, 0, len(rs)*2)
	for _, r := range rs {
		if r <= 0xFFFF {
			out = append(out, byte(r), byte(r>>8))
			continue
		}
		// 辅助平面：拆成 surrogate pair
		r -= 0x10000
		hi := 0xD800 + (r >> 10)
		lo := 0xDC00 + (r & 0x3FF)
		out = append(out, byte(hi), byte(hi>>8), byte(lo), byte(lo>>8))
	}
	return out
}
