package winproto

import (
	"fmt"
	"strings"
	"time"

	"github.com/Kur1sulab/kara/engine-go/litmus/model"
)

// probe_smb 的 Go 移植。逐段对应 Python 版 probe_smb / _signing_finding /
// _smb1_only。

// ProbeSMB 探测 SMB2 匿名/guest 会话 + 签名策略。
//
// 只连 IPC$（命名管道命名空间），不碰任何磁盘共享。
// 没有结论时返回 nil —— 绝不用「端口开着」冒充结论。
func ProbeSMB(host string, port int, timeout time.Duration) *model.Finding {
	if port <= 0 {
		port = DefaultSMBPort
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	t := target{host: host, port: port}
	ev := []string{}

	c, err := dial(host, port, timeout, false)
	if err != nil {
		return nil
	}
	defer func() { _ = c.Close() }() // 关闭失败无处理价值

	// ---- 1) NEGOTIATE：拿签名策略与方言 ----
	if err := nbSend(c, negReqRandom(0), timeout); err != nil {
		return nil
	}
	r, err := nbRecv(c, timeout)
	if err != nil {
		return nil
	}
	h := parseHdr(r)
	if h == nil {
		ev = append(ev, "NEGOTIATE 无 SMB2 应答（可能仅支持 SMB1 或被设备拦截）")
		ev = append(ev, "原始: "+hexPreview(r, 64))
		return smb1Only(t, ev)
	}
	neg := parseNeg(r)
	if h.status != 0 || neg == nil {
		ev = append(ev, "NEGOTIATE → "+stName(h.status))
		return nil
	}

	sec := neg.securityMode
	signingEnabled := sec&0x0001 != 0
	signingRequired := sec&0x0002 != 0
	dname := dialectName(neg.dialect)
	signWord := "disabled"
	if signingEnabled {
		signWord = "enabled"
	}
	reqWord := "可选"
	if signingRequired {
		reqWord = "REQUIRED"
	}
	ev = append(ev, fmt.Sprintf("NEGOTIATE → SecurityMode=0x%04X（signing %s / %s），方言 %s",
		sec, signWord, reqWord, dname))

	// ---- 2) SESSION_SETUP：匿名 ----
	if err := nbSend(c, ssReq(spnegoInit(ntlmType1()), 1, 0), timeout); err != nil {
		return nil
	}
	r1, err := nbRecv(c, timeout)
	if err != nil {
		return nil
	}
	h1 := parseHdr(r1)
	if h1 == nil {
		ev = append(ev, "SESSION_SETUP 无应答")
		if !signingRequired {
			return signingFinding(t, ev, sec, dname)
		}
		return nil
	}

	st1 := h1.status
	sess := h1.session
	anonOK := false
	switch st1 {
	case 0x00000000:
		// 服务端一次就接受（部分设备直接放行空 token）
		anonOK = true
		ev = append(ev, fmt.Sprintf("SESSION_SETUP(匿名) → STATUS_SUCCESS，SessionId=0x%X", sess))
	case 0xC0000016:
		// 正常两步：拿到 challenge，回空凭据
		challenge := findNTLMSSP(r1)
		flags := ntlm2Flags(challenge)
		hasType2 := ""
		if len(challenge) > 0 {
			hasType2 = "（含 NTLMSSP Type2）"
		}
		ev = append(ev, fmt.Sprintf("SESSION_SETUP(1) → MORE_PROCESSING_REQUIRED，challenge %dB%s，NegotiateFlags=0x%08X",
			len(challenge), hasType2, flags))
		if err := nbSend(c, ssReq(spnegoResp(ntlmType3(flags)), 2, h1.session), timeout); err != nil {
			return nil
		}
		r2, err := nbRecv(c, timeout)
		if err != nil {
			return nil
		}
		if h2 := parseHdr(r2); h2 != nil {
			sess = h2.session
			if sess == 0 {
				sess = h1.session
			}
			st2 := h2.status
			ev = append(ev, fmt.Sprintf("SESSION_SETUP(匿名凭据) → %s，SessionId=0x%X", stName(st2), sess))
			anonOK = st2 == 0x00000000
		} else {
			ev = append(ev, "SESSION_SETUP(匿名凭据) 无应答")
		}
	default:
		ev = append(ev, "SESSION_SETUP(匿名) → "+stName(st1))
	}

	if !anonOK {
		ev = append(ev, "结论：匿名会话被拒（该主机不允许空凭据会话）")
		return signingFinding(t, ev, sec, dname)
	}

	// ---- 3) TREE_CONNECT IPC$：匿名会话到底能干什么 ----
	var tree uint32
	treeErr := func() error {
		if err := nbSend(c, tcReq(host, "IPC$", 3, sess), timeout); err != nil {
			return err
		}
		r3, err := nbRecv(c, timeout)
		if err != nil {
			return err
		}
		h3 := parseHdr(r3)
		if h3 != nil && h3.status == 0 {
			tree = h3.tree
			ev = append(ev, fmt.Sprintf("TREE_CONNECT \\\\%s\\IPC$ → STATUS_SUCCESS，TreeId=%d", host, tree))
		} else if h3 != nil {
			ev = append(ev, fmt.Sprintf("TREE_CONNECT \\\\%s\\IPC$ → %s", host, stName(h3.status)))
		}
		return nil
	}()
	if treeErr != nil {
		ev = append(ev, "TREE_CONNECT 失败: "+treeErr.Error())
	}

	// ---- 4) CREATE srvsvc：IPC$ 通不等于命名管道可达 ----
	// 实测（Samba guest ok=no）：IPC$ 树照样能连，但 share 被拒。
	// 所以「能连 IPC$」本身只值 medium，必须真打开一个 RPC 管道
	// 才能证明横向移动入口存在。只 FILE_OPEN，不建不写。
	pipeOK := false
	pipeName := ""
	var pipeFID []byte
	var pipeMid uint64
	var shares []share
	if tree != 0 {
		// MessageId 必须严格连续递增（接在 TREE_CONNECT 的 mid=3 之后）。
		// 实测 Samba：mid 跳号（如 10）会被静默丢弃 —— 不回错误也不回
		// 成功，客户端只看到超时。这是最容易踩的坑之一。
		for idx, pname := range []string{"srvsvc", "samr", "lsarpc", "winreg"} {
			var h4 *smbHeader
			var r4 []byte
			err := func() error {
				if err := nbSend(c, createReq(pname, 4+uint64(idx), sess, tree, createAccessReadPipe), timeout); err != nil {
					return err
				}
				var err error
				r4, err = nbRecv(c, timeout)
				if err != nil {
					return err
				}
				h4 = parseHdr(r4)
				return nil
			}()
			if err != nil {
				ev = append(ev, fmt.Sprintf("CREATE %s 异常: %s", pname, err.Error()))
				break
			}
			if h4 != nil && h4.status == 0 {
				pipeOK = true
				pipeName = pname
				pipeFID = sliceFrom(r4, 128, 16) // SMB2 CREATE 响应里的 FileId
				pipeMid = 5 + uint64(idx)
				ev = append(ev, fmt.Sprintf("CREATE \\\\%s\\IPC$\\%s → STATUS_SUCCESS（匿名可打开命名管道）", host, pname))
				break
			}
			if h4 != nil {
				ev = append(ev, fmt.Sprintf("CREATE %s → %s", pname, stName(h4.status)))
			} else {
				ev = append(ev, fmt.Sprintf("CREATE %s → 无应答", pname))
			}
		}
		if !pipeOK {
			ev = append(ev, "结论：匿名会话成立，但所有常见 RPC 管道都打不开 —— 只能确认「会话存在」，不能确认「可枚举数据」")
		}
	}

	// ---- 5) srvsvc 上真发一次 NetrShareEnum：把「管道可达」升格成
	//         「匿名读到了什么」。这一步才是 L2 证据，管道可达只是入口。
	if pipeOK && pipeName == "srvsvc" && len(pipeFID) > 0 {
		sh, rpcEv, err := rpcShareEnum(c, pipeFID, tree, sess, host, pipeMid, timeout)
		ev = append(ev, rpcEv...)
		if err != nil {
			ev = append(ev, "NetrShareEnum 异常: "+err.Error())
		}
		shares = sh
	}

	rpcSharesExtra := make([]map[string]interface{}, 0, len(shares))
	for _, s := range shares {
		rpcSharesExtra = append(rpcSharesExtra, map[string]interface{}{
			"name": s.name, "type": shareTypeName(s.typ), "remark": s.remark,
		})
	}
	var pipeOpened interface{} = false
	if pipeName != "" {
		pipeOpened = pipeName
	}
	extra := map[string]interface{}{
		"dialect":          dname,
		"security_mode":    fmt.Sprintf("0x%04X", sec),
		"signing_required": signingRequired,
		"signing_enabled":  signingEnabled,
		"anon_session":     true,
		"ipc_tree":         tree != 0,
		"pipe_opened":      pipeOpened,
		"rpc_shares":       rpcSharesExtra,
	}

	// 分级：只 IPC$/特殊共享 ≠ 数据外泄，必须和「枚举到磁盘共享」分开
	realShares := make([]share, 0, len(shares))
	for _, s := range shares {
		if base := s.typ & 0x0000FFFF; base == 0 || base == 1 || base == 2 {
			realShares = append(realShares, s)
		}
	}

	var severity, level, impact string
	switch {
	case len(realShares) > 0:
		severity, level = "high", "L2"
		impact = fmt.Sprintf(
			"匿名 SMB 会话不仅可建立，还通过 \\\\%s\\IPC$\\srvsvc 的 "+
				"NetrShareEnum 实际枚举到 %d 个共享（%s）。这是真实数据外泄，"+
				"不是「理论上可达」：共享名与备注往往直接暴露业务用途"+
				"（备份盘、财务、HR、源码），拿到清单后即可针对性尝试匿名/弱口令"+
				"挂载，或按备注筛选高价值目标。",
			host, len(shares), joinShareNames(shares))
		if !signingRequired {
			impact += "\n【推演】SMB 签名未声明为必需，结合匿名会话可尝试" +
				"Responder + ntlmrelayx 中继；Samba 的 " +
				"server signing=mandatory 不一定在 SecurityMode 置位，" +
				"需在目标上二次确认。"
		}
	case len(shares) > 0:
		// 只枚举到 IPC$/特殊共享：管道可达是实锤，但没拿到业务数据
		severity, level = "medium", "L1"
		impact = fmt.Sprintf(
			"匿名会话可建立，并且 NetrShareEnum 调用成功，但只返回 %d 个"+
				"特殊共享（%s），磁盘/打印共享对匿名不可见。这条不算数据外泄，"+
				"它证明的是「匿名可以在这台机器的 srvsvc 上执行 RPC」——"+
				"同一通道上 samr/lsarpc/winreg 往往同样开放，可继续枚举"+
				"域账号、LSA 策略与注册表。",
			len(shares), joinShareNames(shares))
	case pipeOK:
		severity, level = "high", "L2"
		impact = fmt.Sprintf(
			"匿名 SMB 会话可建立，并且能打开 \\\\%s\\IPC$\\%s 命名管道。"+
				"命名管道可达是横向移动的直接入口：srvsvc 可远程枚举共享与"+
				"会话、samr 可枚举域账号、lsarpc 可读 LSA 策略、winreg 可读"+
				"注册表。攻击者不需要任何凭据就能拿到这些信息，"+
				"再配合密码喷洒或中继扩大战果。",
			host, pipeName)
	default:
		severity, level = "medium", "L1"
		impact = fmt.Sprintf(
			"匿名 SMB 会话可建立（\\\\%s\\IPC$ 树连接成功），但常见的"+
				"RPC 命名管道（srvsvc/samr/lsarpc/winreg）都无法打开。"+
				"这条本身不足以直接读数据，价值在于确认「该主机接受空凭据"+
				"会话」——配合 NTLM 中继或后续的 RPC 面扩展可继续推进。"+
				"【推演】是否还能通过其他管道（如 netlogon、eventlog）"+
				"进一步利用，需针对该主机单独枚举管道清单。",
			host)
	}
	if !signingRequired {
		impact += fmt.Sprintf(
			"\n【推演】同时 SMB 签名未在 NEGOTIATE 中声明为必需"+
				"（SecurityMode=0x%04X），若确实未强制，可用 Responder "+
				"+ ntlmrelayx 把该主机认证中继到同网段其他主机。"+
				"注意：Samba 的 server signing=mandatory 不一定在 "+
				"SecurityMode 里置 REQUIRED 位，此项需在目标上二次确认。",
			sec)
	}
	// 注意：Python 版在 real_shares / shares 分支里各自赋过一次 fix，
	// 但紧接着被下面这段无条件覆盖 —— 可观测的只有这一段，故只保留它。
	fix := "1) 关闭匿名访问：组策略「网络访问: 不允许匿名 SID/名称转换」+" +
		"「网络访问: 限制对命名管道的匿名访问」设 Enabled；\n" +
		"2) 注册表 RestrictAnonymous=1、RestrictAnonymousSAM=1；\n" +
		"3) 若确有匿名共享需求，改用专用低权账号并在防火墙限制来源网段；\n" +
		"4) 强制 SMB 签名（见同主机 SMB 签名条目）。"

	// 标题跟着「实际拿到了什么」走：枚举到共享就别只说「能开管道」
	var title string
	switch {
	case len(realShares) > 0:
		title = fmt.Sprintf("SMB 匿名会话可枚举共享（%d 个业务共享，含 %s）",
			len(realShares), joinShareNames(realShares[:minInt(3, len(realShares))]))
	case len(shares) > 0:
		title = "SMB 匿名会话可执行 RPC 枚举（仅 IPC$，管道可达）"
	case pipeOK:
		title = fmt.Sprintf("SMB 匿名会话建立成功（可打开 %s 命名管道）", pipeName)
	default:
		title = "SMB 匿名会话建立成功（IPC$ 可达，管道受限）"
	}

	return t.finding(result{
		check:    "smb.anon_session",
		name:     title,
		severity: severity,
		level:    level,
		evidence: joinLines(ev),
		// 复验主路径必须是 litmus 自己：交付物是静态单文件，目标机上没有 Python，
		// 写「python3 poc/xxx.py」等于给客户一条跑不通的路。smbclient 那条留给
		// 手上有 samba 工具链的团队做交叉对照。
		repro: reproReplay +
			"\n# 对照（装了 samba 客户端的话）：smbclient -N -L //" + host + "/",
		impact: impact,
		fix:    fix,
		extra:  extra,
	})
}

// signingFinding 是 Python 的 _signing_finding()：匿名没成，但签名未强制
// 仍是独立的中危问题（中继面）。
func signingFinding(t target, ev []string, sec uint16, dname string) *model.Finding {
	if sec&0x0002 != 0 {
		return nil
	}
	ev = append(append([]string{}, ev...),
		fmt.Sprintf("签名策略：SecurityMode=0x%04X，REQUIRED 位未置位 → 服务端不强制 SMB 签名", sec))
	return t.finding(result{
		check:    "smb.signing_not_required",
		name:     "SMB 签名未强制（NTLM 中继风险）",
		severity: "medium",
		level:    "L1",
		evidence: joinLines(ev),
		repro:    reproReplay + fmt.Sprintf("\n# 对照（装了 nmap 的话）：nmap -p %d --script smb2-security-mode %s", t.port, t.host),
		impact: "未强制签名时，攻击者可用 Responder 抓取该主机的 NTLM 认证并" +
			"中继到同网段其他未强制签名的主机，直接获得对方权限。" +
			"【推演】是否能成功取决于目标网段是否存在第二台未强制签名的主机。",
		fix: "组策略：计算机配置 → Windows 设置 → 安全设置 → 本地策略 → " +
			"安全选项 → 「Microsoft 网络服务器: 对通信进行数字签名(始终)」" +
			"设为「已启用」；域内用 GPO 统一下发并强制生效。",
		extra: map[string]interface{}{
			"dialect":          dname,
			"security_mode":    fmt.Sprintf("0x%04X", sec),
			"signing_required": false,
			"signing_enabled":  sec&0x0001 != 0,
			"anon_session":     false,
		},
	})
}

// smb1Only 是 Python 的 _smb1_only()：只回 SMB1 的老系统，
// MS17-010 面 + 该协议早已被弃用。
func smb1Only(t target, ev []string) *model.Finding {
	ev = append(append([]string{}, ev...),
		"服务端未响应 SMB2 NEGOTIATE —— 该主机可能只启用 SMB1"+
			"（Windows 2003/XP 时代，或组策略未禁用 SMB1）")
	return t.finding(result{
		check:    "smb.smb1_only",
		name:     "SMB 服务仅支持 SMB1（老协议）",
		severity: "medium",
		level:    "L1",
		evidence: joinLines(ev),
		repro:    reproReplay + fmt.Sprintf("\n# 对照（装了 nmap 的话）：nmap -p %d --script smb-protocols,smb-vuln-ms17-010 %s", t.port, t.host),
		impact: "SMB1 存在多个可远程利用的历史漏洞（MS17-010 永恒之蓝即走 SMB1），" +
			"且不提供现代加密与签名保证。" +
			"【推演】是否真的可被 MS17-010 利用需进一步用 smb-vuln-ms17-010 验证，" +
			"本条只证明「SMB2 协商失败、仅 SMB1 可用」。",
		fix: "禁用 SMB1：Set-SmbServerConfiguration -EnableSMB1Protocol $false；" +
			"客户端侧同步关闭 mrxsmb10 驱动。若业务确需 SMB1，隔离到独立网段。",
		extra: map[string]interface{}{"smb2": false},
	})
}

func joinShareNames(shares []share) string {
	names := make([]string, 0, len(shares))
	for _, s := range shares {
		names = append(names, s.name)
	}
	return strings.Join(names, ", ")
}

func joinLines(lines []string) string {
	return strings.Join(lines, "\n")
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
