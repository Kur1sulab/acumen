package winproto

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

// ================================================================ DER / BER
//
// LDAP 的线上编码是 ASN.1 BER。只用到最基础的五种 tag，
// 不引第三方库（pyasn1 在内网机器上装不了），手写够用。
//
// 与 Python 版 _der_len / _der / _der_int / _der_enum / _der_octets /
// _der_bool / _tlv 一一对应。

var (
	errTLVShort    = errors.New("tlv: 越界")
	errTLVLenField = errors.New("tlv: 长度域非法")
	errTLVContent  = errors.New("tlv: 内容越界")
)

// derLen 编码长度域：<0x80 用单字节，否则 0x80|字节数 + 大端字节。
func derLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], uint64(n))
	i := 0
	for i < len(raw) && raw[i] == 0 {
		i++
	}
	out := make([]byte, 0, 1+len(raw)-i)
	out = append(out, byte(0x80|(len(raw)-i)))
	return append(out, raw[i:]...)
}

// der 组一个 TLV。
func der(tag byte, content []byte) []byte {
	out := make([]byte, 0, 1+len(content)+2)
	out = append(out, tag)
	out = append(out, derLen(len(content))...)
	return append(out, content...)
}

// derInt 编码 INTEGER（默认 tag=0x02）。负数按二进制补码。
func derInt(n int, tag byte) []byte {
	return der(tag, derIntContent(n))
}

// derIntContent 对齐 Python 的 n.to_bytes((n.bit_length() + 8) // 8,
// "big", signed=True)：正数永远留一个符号位，所以 0x80 要写成 00 80。
func derIntContent(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	a := n
	if a < 0 {
		a = -a
	}
	nb := (bits.Len(uint(a)) + 8) / 8
	b := make([]byte, nb)
	v := n
	for i := nb - 1; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
	return b
}

// derEnum 编码 ENUMERATED（tag=0x0a）。
func derEnum(n int) []byte {
	return derInt(n, 0x0a)
}

// derOctets 编码 OCTET STRING（tag=0x04）。
func derOctets(b []byte) []byte {
	return der(0x04, b)
}

// derBool 编码 BOOLEAN（tag=0x01，真值 0xff）。
func derBool(v bool) []byte {
	if v {
		return der(0x01, []byte{0xff})
	}
	return der(0x01, []byte{0x00})
}

// tlv 读一个 TLV，返回 (tag, content, nextIndex)。畸形数据返回 error。
func tlv(data []byte, i int) (tag byte, content []byte, next int, err error) {
	if i < 0 || i+2 > len(data) {
		return 0, nil, i, errTLVShort
	}
	tag = data[i]
	i++
	ln := int(data[i])
	i++
	if ln&0x80 != 0 {
		n := ln & 0x7F
		if n == 0 || i+n > len(data) {
			return 0, nil, i, errTLVLenField
		}
		ln = 0
		for _, b := range data[i : i+n] {
			ln = ln<<8 | int(b)
		}
		i += n
	}
	if i+ln > len(data) {
		return 0, nil, i, errTLVContent
	}
	return tag, data[i : i+ln], i + ln, nil
}
