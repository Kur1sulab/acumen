# litmus2 Go 版 · 移植契约

本文件是 Go 版与 Python 版的**对齐契约**。任何模块移植前必读。

## 一、项目定位（不许改）

`litmus2` 是内网授权渗透验证框架。三条不可让步的设计线：

1. **零第三方依赖** —— 只用 Go 标准库。`go.mod` 里除 `module`/`go` 两行外**不许出现任何 require**。
   - 不许引 `golang.org/x/...`、`github.com/...`
   - 不许 cgo（`import "C"`），构建必须 `CGO_ENABLED=0` 通过
   - 缺能力就手写（MD4 就是这么来的，见 `internal/md4`）
2. **三态覆盖** —— 任何检查面必须显式产出 `ok` / `skip`（带原因）/ `na`。
   没测的东西绝不能伪装成"通过"或"没漏洞"。
3. **分级看证据** —— `L1` 只到可达/存在，`L2` 要真实数据（共享名、版本、凭据），
   `L3` 要内部权限。不许把 L1 写成 L2。

## 二、目录与包职责

```
cmd/litmus/          CLI 门面（子命令分发）
internal/model/      Finding / Coverage / Cred / Target + 工具函数【已完成，不许改】
internal/store/      JSONL 状态库（替代 SQLite）【已完成，不许改】
internal/scope/      目标解析 + 范围守卫【已完成，不许改】
internal/md4/        RFC 1320 MD4 + NTLM 哈希【已完成，测试全绿，不许改】
internal/netprobe/   端口扫描 + 服务识别
internal/winproto/   SMB2 / LDAP / RDP 协议探针
internal/httpc/      HTTP 客户端（含 TLS、重定向、超时、原始报文捕获）
internal/authprobe/  服务级真登验证（凭据复用）
internal/yamlite/    YAML 子集解析（nuclei 模板用）
internal/tpl/        nuclei 模板引擎
internal/webcheck/   Web 侧检查（敏感路径、指纹、配置泄露）
internal/engine/     调度核心
internal/report/     报告渲染（md + json）
internal/pocgen/     PoC 生成
```

## 三、已完成包的 API（直接调用，不要重写）

### model

```go
model.NowISO() string                       // "2006-01-02T15:04:05-0700"
model.MaskSecret(v string, keep int) string // 只留前 keep 位
model.Slug(s string, maxlen int) string
model.DedupeKey(check, target, extra string) string

type Finding struct {
    ID, Check, Name, Severity, Target, Host string
    Port int
    Scheme, Category, Level, Confidence, Time string
    Evidence, Repro, Impact, Fix, CVSS, PoC string
    RawRef string
    Extra, Triage map[string]interface{}
    TitleEN string
    Creds []Cred        // json:"-"，序列化走 CredsJSON
    CredsJSON []CredJSON
}
func model.NewFinding(check, name, severity, target string, o model.FindingOpts) *Finding
func (f *Finding) Key() string        // 去重键
func (f *Finding) SyncCredsJSON()     // 序列化前必须调
func (f *Finding) SevRankOf() int

type FindingOpts struct {
    Host, Scheme, Category, Level, Confidence string
    Port int
    Evidence, Repro, Impact, Fix, CVSS, TitleEN string
    Extra, Triage map[string]interface{}
    Creds []Cred
}

type Coverage struct { Target, Category, Item, State, Reason string; Count int; Time string }
func model.NewCoverage(target, category, item, state, reason string, count int) *Coverage

type Cred struct { Proto, Host string; Port int; User, Secret, Kind, Source, Note string }
func model.NewCred(proto, host string, port int, user, secret, kind, source, note string) *Cred
```

**JSON 字段名必须与 Python 版 `to_dict()` 逐字一致** —— 这是 oracle 差分的唯一依据。
Python 的 `Finding.to_dict()` 字段：`id, check, name, severity, target, host, port,
scheme, category, level, confidence, time, evidence, repro, impact, fix, cvss, poc,
raw_ref, extra, triage, title_en, creds`。

### store

```go
s, err := store.Open(dir)                          // dir 一般是 <out>/state
runID, err := s.NewRun(args, targetsHash)
err = s.FinishRun(runID)
done := s.DoneHosts(runID)                         // map[string]bool
err = s.MarkHost(runID, host, "done", ports)
err = s.SaveFindings(runID, findings)
prev := s.LastRun(exclude, onlyWithFindings)       // 0 = 没有
done := s.DoneHostsForHash(targetsHash)
fs, err := s.FindingsOf(runID)
err = s.Close()
```

### scope

```go
raws, err := scope.ParseTargets(items, files []string) []string
res := scope.ScopeOK(host string, allowPublic bool)   // {OK, Reason, IPs}
parsed, err := scope.Expand(raws []string, maxHosts int) []scope.Parsed
type Parsed struct { Host string; Port int; Scheme, Raw string }
```

## 四、移植纪律

### 4.1 Python 源码就是规格

Python 版在 `~/tools/litmus2/`。**逐函数对照移植**，不要"顺便优化"。
行为差异必须能解释清楚（例如 Go 没有 `socket.setdefaulttimeout` 的等价物，
那就显式传 timeout，而不是换个语义）。

### 4.2 三态不许塌缩

Python 版里每个 `cover(..., state="skip", reason="...")` 都要在 Go 版有对应。
漏一个 skip 就是漏一个"未测"声明，报告会撒谎。

### 4.3 错误处理

- 网络错误一律**不是** `panic`，是 `skip` + 原因
- 解析失败要保留原始字节的 hex 前缀（前 64 字节）到 `evidence`，便于现场排查
- 超时必须显式设置（Go 的 `net.Dial` 默认无超时，忘了就是永久挂住）

### 4.4 并发

- 端口级并发用 `sync.WaitGroup` + 信号量（`chan struct{}`）控并发数
- **不许**无限制 `go func()`（几千端口会把 fd 打爆）
- 每个 goroutine 必须有自己的超时；结果通过 channel 汇总，不许直接写共享 map

### 4.5 测试

每个包必须有 `*_test.go`，至少覆盖：
- 字节构造：与 Python 版同输入 → 同 hex（把 Python 算出的 hex 硬编码进测试）
- 解析：喂已知响应字节 → 断言解析出的字段
- 边界：空输入、超长输入、畸形响应不 panic

## 五、验证命令

```bash
cd ~/tools/litmus2-go
go vet ./...                                    # 必须干净
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o litmus ./cmd/litmus
go test ./...                                   # 必须全绿
```

## 六、与 Python 版的关系

- Python 版**保留**，作为 oracle（正确性基准）与作战机上的 REPL 调试环境
- Go 版是**交付载体**（静态单文件、无解释器依赖）
- 两边共用同一个 `findings.json` schema，报告层可互换

## 七、禁止事项

- 禁止 `import "C"`、禁止任何外部 module
- 禁止把 `sqlite` 引进来（存储已改 JSONL）
- 禁止在日志/报告/JSON 里输出完整口令（一律走 `model.MaskSecret`）
- 禁止 `panic` 用于正常的网络失败路径
- 禁止吞掉错误（`_ = err` 只允许出现在"坏行跳过"这类明确容错处，且必须注释原因）

---

## 六、端到端验收：`dev/parity.py`（2026-11-18 建）

单测只能证明「函数对」，证明不了「两个实现行为等价」。`dev/parity.py` 做的事是：
同一目标、同一参数，Python 原版与 Go 版各跑一遍，把 `findings.json` 逐字段、
`report.md` / `report.html` 逐字节对掉。

```
env -u PYTHONPATH python3 dev/parity.py -t 127.0.0.1 -p 22,80,88
```

**只归一化三样**（见下节「已知偏离」）：生成时间与每条发现的时间、耗时、PoC 命令。

当前基线（本机 127.0.0.1:22,80,88）：发现 2 条 / 21 个字段全等 / `report.md` 与
`report.html` 逐字节一致。任何改动后跑一次 parity，红了就是真回归。

覆盖表的比对**含 reason**（不只比 ok/skip/na）。理由很直接：三态原则要求「没测
必须写清为什么」，原因变了就是行为变了。唯一例外是「模块未装配（xx 未移植）」
被归一化成 `<UNPORTED>` —— 这是移植进度造成的临时差异，模块到位后归一化自动失效。

## 七、已知识偏离 Python 版的地方（全部是有意的）

移植不是逐字翻译。下面每一处都是对着 Python 原版确认过行为之后**主动改的**，
理由与证据都在代码注释里。

### 1. `--no-web` / `--no-auth-probe` 时补记 skip（engine.doHost）

Python 原版在这两个开关打开时，对受影响的端口**既不测也不记**，于是覆盖表上
直接消失。这正是三态原则要防的事：没测的项目伪装成「本轮没问题」。
Go 版补一条 `skip` 并写明「本轮跳过」，覆盖表如实呈现。

证据：`run -p 1-100 --no-web` 在 Python 版报告里 80/88 完全不出现；Go 版有
两行 `web@80` / `web@88` 的 skip。

### 2. RPC FAULT 码偏移 24 → 16（winproto.rpc）

Python 版读 `d[24:28]`，但 fault PDU 只有 16 字节头（object UUID 那 8 字节
仅存在于 request/bind），body 从偏移 16 起。按 24 读等于跳过 fault code 本身，
对真实 Windows 服务端必读错。Go 版按 DCE/RPC 标准布局取 `d[16:20]`。

Python 侧保留原样作 oracle —— 它自带的假服务端也按 24 造，所以 Python 测试
自洽、掩盖了这个偏差。

### 3. PoC 不是 `.py` 脚本，而是 `litmus replay` 子命令（cmd/litmus/replay.go）

Python 版 `pocgen.py`（869 行）生成 `poc/LS-001-xxx.py`，报告里写
`python3 poc/xxx.py` 复验。但 Go 版存在的全部理由是「目标机没有 Python」——
生成 .py 等于把交付物钉死在一个不存在的解释器上。

所以 Go 版把复验做进二进制：

```
litmus replay -f findings.json --list
litmus replay -f findings.json --id LS-001
```

按 check 名分发到 winproto / webcheck 重跑一遍，把「原证据」与「本次证据」并排
打印，并给出「复现成功 / 已消失 / 结论变了」三态判定。退出码 0 = 复现成功。

代价：报告里的 PoC 行文案与 Python 版不同（前者 `python3 ...`，后者 `litmus replay ...`）。
`report_test` 因此把 PoC 行纳入归一化 —— 归一的只是命令文本，「PoC 行存在且位置
正确」仍然被守住。

### 4. 状态库 JSONL 而非 state.db

Go 标准库无 SQLite。用 `mattn/go-sqlite3` 要 cgo（废掉静态交叉编译），用
`modernc.org/sqlite` 拖几十个依赖（废掉零依赖）。改 JSONL，代价是**与 Python 版
state.db 不互通，跨版本 `--resume` 不支持**（同版本续跑可以）。收益：人类可读、
可 grep、可 diff —— 证据链正好需要这个。

### 5. `IP.IsPrivate()` 需要补网段表（scope.extraPrivate4）

Go 的 `net.IP.IsPrivate()` 只认 RFC1918 + `fc00::/7`，Python 的 `is_private`
还包含 TEST-NET、保留段、`198.18.0.0/15` 等。不补齐会把 `192.0.2.1` 这类靶场
黑洞判成公网拒绝掉。`scope_test.go` 里 21 条实测表就是从 `python3 3.12.16` 跑
出来的并集。

## 六、覆盖表粒度（2026-11-18 增补 · 硬约束）

**一条铁律：覆盖表的每一行，必须对应客户能问出口的一个问题。**

客户会问「你测 SQL 注入了吗」「你测 Nacos 未授权了吗」，
他不会问「你跑 webcheck 了吗」。所以：

- 一个检查项 = 覆盖表一行，`item` 写 `族/检查项名`，如 `injection/sqli-error`
- **禁止**用模块名概括内部多个检查项。曾经这里是 `webcheck@18099 ok` 一行盖住 11 项，
  等于把「某项没测」藏进「模块跑过了」里面 —— 这是三态诚实原则的直接破口。
- 检查项异常（panic / 超时）必须记 `skip` 并写原因，不许记 `ok`。
  「跑崩了」和「跑完没命中」在报告里必须是两种长相。
- 报告 `report.md` / `report.html` 必须列出**全量逐项清单**（含已测项），
  不能只列 skip —— 只列 skip 客户就没法核对「你说测了的那几项到底测了没有」。

## 七、检查项注册与记账收口 `internal/scan`

各族检查分文件写在 `internal/injection`、`internal/framework`、
`internal/authz`、`internal/exposure`，但**注册与记账统一走 `internal/scan`**。

理由：如果每个族自己往覆盖表塞行，迟早出现「A 族记了 ok、B 族忘了记」，
覆盖表开始撒谎。收口到一个注册表，`engine` 只遍历一遍，谁都不会漏。

写一个检查项的最小样板：

```go
package injection

import (
    "litmus2/internal/scan"
    "litmus2/internal/model"
)

func init() {
    scan.Register(scan.Check{
        Meta: scan.Meta{
            Name:     "injection/sqli-error",
            Family:   "injection",
            Title:    "报错注入",
            Severity: "high",
            Owasp:    "A03",
            CWE:      "CWE-89",
        },
        Run: runSQLiError,
    })
}

func runSQLiError(c *scan.Ctx) scan.Result {
    if c.Base == "" {
        return scan.NA("目标不是 Web 服务")
    }
    // ... 探测 ...
    if len(c.URLs) == 0 {
        return scan.Skip("爬虫未取到带参数的 URL，无法测试注入")
    }
    return scan.OK(n, findings...)
}
```

三条注册纪律：

1. `Name` **全局唯一**。重名 `panic` —— 两个同名项会让覆盖表互相覆盖。
2. `Family` 必填，用于覆盖表分组与 `scan.Families()`。
3. `Run` 必须返回三态之一。返回空 `State` 会被 engine 强制降级为 `skip` 并标注
   「检查项未上报状态（实现缺陷）」—— 宁可承认实现有缺陷，也不让覆盖表撒谎。

`engine` 不需要为每个新检查包改代码：新包在 `internal/allcheck` 里 import 一下，
`init()` 自动注册，覆盖表自动多出对应行。
