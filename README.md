# 空境 · Kara

**小而精的本地漏扫。** 一条命令：填目标 → 扫 → 命中入账 → 复验 → 导出。
**单一 CLI 界面**（没有网页、没有服务、不开端口），库只留在本机 `~/.kara/vuln.db`。

## 三个动词，没有第四层

```bash
kara                                   # 状态：引擎、库、存量
kara scan -t <目标> [-m 模式]           # 扫
kara list [-i 序号] [-​-assets]          # 看（--csv / --md 导出）
kara verify [--ids …] [--deep]         # 复验
```

```bash
kara scan -t 127.0.0.1:8080 -m api          # 单模式，快
kara scan -t example.com,10.0.0.5 -m all --parallel 3
kara list --sev high                        # 看高危；--q 关键词 / --status 待验证
kara list -i 12                             # 单条详情：判据、证据、复现命令
kara list --assets                          # 资产：主机 / 端口 / 指纹
kara list --md report.md                    # 导出（CSV 带 BOM，Excel 不乱码）
kara verify --ids 12,15                     # 复验：同一模式同一入口重跑
kara verify --deep --sev high               # 深度验证：用内建内核真打一轮
```

`kara` 是仓库根目录的薄壳（`~/.local/bin/kara` 软链过去），等价 `python3 -m vc.cli`。
不给子命令就打印状态——不占端口、不起浏览器、没有第二套入口。

## 九种模式

| 模式 | 干什么 |
|---|---|
| `all` | 全流程（子域→验活→资产→备案→指纹→路径→API→JS→端口→报告）|
| `portscan` | 96 个常用端口 + banner 服务识别 |
| `fingerprint` | 28 条规则 / 26 种技术（headers + body 双通道）|
| `api` | 28 个候选端点：Swagger / Actuator / Druid / GraphQL / Nacos / pprof / heapdump…（软 404 基线 + 存活复验 + 取证）|
| `jsintel` | 外链 JS 抽接口与密钥线索（值打码，只 GET）|
| `paths` | 19 条敏感路径（`.git` `.env` 备份包…）|
| `subdomain` | 证书日志枚举子域（crt.sh → certspotter）|
| `baseline` | 域名暴露面 8 项基线（安全头 / webfiles / mailsec / archives / ssl / dns / whois / geoasn）|
| `strike` | **深度验证**：内建内核真打（真登 / 未授权 / 注入 / 敏感路径），判定到 L1/L2 |

前八种只读（全引擎零写原语，`POST/PUT/DELETE` = 0）；`strike` 会真的发请求。

## 深度验证（`-m strike`）

只读模式给的是「可疑面」；要回答「这是不是真漏洞、拿到了什么」，用内建验证内核
（源码 `engine-go/litmus/`，移植自 litmus2，零第三方依赖）：

```bash
kara scan -t https://x -m strike --ports top100 --intensity normal
kara verify --deep --sev high          # 对库里已有命中真打一轮
kara verify --deep --dry-run           # 只列目标，不发请求
```

- 级别：`L1` 只到「看得见」，`L2` 是「拿到了真实数据/凭据」——**交付线看 L2**。
- 产物：`out/<target>/strike/{report.md, findings.json, evidence/}`，随扫描产物一起入账。
- 三态覆盖：跳过的检查一定带原因（`coverage`），**没测的不会伪装成「没漏洞」**。

## 凭什么算命中

- **去重合并**：键 `sha1(资产|标题|端点|参数)`。同一漏洞被多份产物报到不新增条目，次数 +1、来源取并集、严重度取最高、首次发现取最早。
- **分级判据**：路径可达 ≠ 高危（凭据 / 源码 / 配置 / 备份 / 运维端点才 high）；JS 敏感串二次判定，压缩 JS 的 `sk`/`ak` 变量名不当密钥。
- **复验**：按当初发现它的同一个模式重跑，结论分「仍存在 / 已消失 / 无法判定 / 不可复验」——**连不上目标不算已消失**。
- **吃别家产物**：nuclei / xray / nmap / nessus / yakit / CSV / MD 表格 / 原始 HTTP 报文丢进收件箱，自动归一化进同一张表。

## 安装与引擎

引擎按 `engine/sweep` → `PATH` 上的 `sweep` → `~/.local/bin/sweep` 顺序找；
`--engine /path/to/sweep` 指定后只认它，指错会明确报错。

```bash
cd engine-go
go build -ldflags "-X github.com/Kur1sulab/kara/engine-go/cli.Version=v1.1.0" -o ../engine/sweep ./cmd/sweep
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o ../build/sweep-win64.exe ./cmd/sweep   # 绿色版
```

Windows：下 Releases 的 `kara-*-win64.zip`，解压双击 `kara.bat`（命令行，参数直接接在后面）。

## 边界

- 无服务、无端口、无鉴权面：只有一个进程在跑命令。
- 引擎用列表参数启动、不拼 shell；目标先过字符白名单；并发上限 4；停止走进程组 `TERM → KILL`。
- 数据在 `~/.kara/vuln.db`（SQLite），删了就是清空重来，不动原始产物。

## 文件

```
kara                 入口薄壳（等价 python3 -m vc.cli）
engine-go/           引擎源码（Go）：cli/ 命令层，litmus/ 深度验证内核，其余为各模式
engine/sweep         引擎构建产物（gitignore，用上面的命令重建）
vc/cli.py            CLI：状态 / scan / list / verify
vc/paths.py          库路径与收件箱默认值（单一来源）
vc/scans.py          引擎发现、目标校验、任务池、进度解析
vc/parsers.py        第三方格式解析 + 资产/漏洞形状判别
vc/parsers_sweep.py  引擎原生产物解析（8 种形状）+ 分级与误报过滤
vc/store.py          SQLite：去重合并 / 筛选 / 状态 / 复验结论 / 导出
vc/ingest.py         收件箱遍历、内容指纹增量
vc/verify.py         复验：按原模式重跑、三态判定（连不上 ≠ 已消失）
tests/               123 个单测 + 引擎真产物 fixtures
```

```bash
python3 -m unittest discover -s tests -v
```
