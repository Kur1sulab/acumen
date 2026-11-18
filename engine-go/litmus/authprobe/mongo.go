package authprobe

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"time"

	"github.com/Kur1sulab/kara/engine-go/litmus/model"
)

// ================================================================ MongoDB
//
// 判据：OP_QUERY admin.$cmd {isMaster:1} 收到有效 BSON 回复（ok / ismaster），
// 说明服务端没要求认证。只发这一条命令，不枚举库、不读集合。

// mongoQueryPacket 构造 OP_QUERY admin.$cmd {isMaster:1}。
//
// 字节布局与 Python 版逐字节一致（golden 测试拿 Python 真跑出来的 hex 比对）：
//
//	header: messageLength=16+len(payload), requestID=1, responseTo=0, opCode=2004
//	body:   flags=0, fullCollectionName="admin.$cmd\0", numberToSkip=0,
//	        numberToReturn=-1, BSON doc
func mongoQueryPacket() []byte {
	// BSON: {"isMaster": 1}
	doc := []byte{0x13, 0x00, 0x00, 0x00}        // 文档长度 19
	doc = append(doc, 0x10)                      // int32 类型
	doc = append(doc, []byte("isMaster\x00")...) // 字段名
	doc = append(doc, 0x01, 0x00, 0x00, 0x00)    // 值 1
	doc = append(doc, 0x00)                      // 文档结束

	payload := le32(0) // flags
	payload = append(payload, []byte("admin.$cmd\x00")...)
	payload = append(payload, le32(0)...)          // numberToSkip
	payload = append(payload, le32(0xFFFFFFFF)...) // numberToReturn = -1
	payload = append(payload, doc...)

	msg := le32(uint32(16 + len(payload)))
	msg = append(msg, le32(1)...)    // requestID
	msg = append(msg, le32(0)...)    // responseTo
	msg = append(msg, le32(2004)...) // OP_QUERY
	return append(msg, payload...)
}

// ProbeMongo 对应 authprobe.probe_mongo。
func ProbeMongo(host string, port int, timeout time.Duration) *model.Finding {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	c, err := dial(host, port, timeout, false)
	if err != nil {
		return nil
	}
	defer func() { _ = c.Close() }() // 探针收尾

	if _, err := c.Write(mongoQueryPacket()); err != nil {
		return nil
	}
	head := recv(c, 16, timeout)
	if len(head) < 16 {
		return nil
	}
	ln := int(int32(binary.LittleEndian.Uint32(head[:4])))
	// 恶意长度（负数/超大）直接放弃：原版会按 ln-16 去 recv，几个 GB 的
	// 请求足以把进程 OOM。正常 OP_REPLY 不会超过 16MB。
	if ln < 16 || ln > 16+(16<<20) {
		return nil
	}
	body := []byte{}
	for len(body) < ln-16 {
		chunk := recv(c, ln-16-len(body), timeout)
		if len(chunk) == 0 {
			break
		}
		body = append(body, chunk...)
	}
	lower := lowerASCII(body)
	if !bytes.Contains(body, []byte("ok\x00")) && !bytes.Contains(lower, []byte("ismaster")) {
		return nil
	}

	var wireVersion interface{}
	if i := bytes.Index(lower, []byte("maxwireversion\x00")); i != -1 && i+19 <= len(body) {
		wireVersion = int(int32(binary.LittleEndian.Uint32(body[i+15 : i+19])))
	}

	ev := "OP_QUERY admin.$cmd {isMaster:1} → 收到有效回复（未要求认证）\n"
	ev += txt(body, 500)

	return result{
		check:    "mongo-unauth",
		name:     "MongoDB 未授权访问",
		severity: "high",
		level:    "L2",
		evidence: ev,
		repro: "mongosh 'mongodb://" + host + ":" + strconv.Itoa(port) +
			"/' --eval 'db.adminCommand({listDatabases:1})'",
		impact: "未开启鉴权时可直接读写全部集合，历史漏洞常导致整库拖走。",
		fix:    "开启 authorization + 创建管理员账户 + 仅监听内网。",
		extra: map[string]interface{}{
			"product":      "mongodb",
			"wire_version": wireVersion,
			"note":         "仅验证命令可达；集合枚举未实现，报告不臆测数据量",
		},
	}.finding(host, port)
}
