# 鉴微 · Acumen

**小而精的本地漏扫。** 填目标 → 开扫 → 看命中 → 导报告，四步闭环，
全程只跑在 `127.0.0.1`，不发一个外部请求。

界面用 Python 标准库的 `http.server` + 原生 HTML/CSS/JS 写，没有 pip、没有 npm、
没有前端构建;扫描引擎是一个本地 Go 单文件二进制（`sweep`），绿色版直接把它塞在包里。
整个产品的重量是:一个解压即用的目录 + 一个 7MB 的引擎 + 一个 200KB 的界面。

```
┌─ 浏览器 127.0.0.1:7788 ─────────────────────────────────────────────┐
│ 扫描   一行一个目标  [10.71.32.204 / example.com / https://…]        │
│        模式  ○全流程 ○端口 ○指纹 ○API ○JS ○路径 ○子域 ○基线         │
│        [开始扫描]                              引擎: engine/sweep   │
│ ─────────────────────────────────────────────────────────────────── │
│ 进度   全流程  10/10 步  端口扫描 → 指纹识别 → API 未授权 → …        │
│ 结果   条目/命中   CRITICAL 5  HIGH 30  MEDIUM 45  LOW 11  资产 47   │
└─────────────────────────────────────────────────────────────────────┘
```

## 为什么叫「小而精」

| 常见漏扫平台 | 鉴微 |
|---|---|
| 装 Docker、起数据库、配账号 | 解压双击（绿色版）或 `./run.sh` |
| 要联网拉镜像、拉模板、上报云端 | 零出站，不联网也能跑完 |
| 结果在别人的服务上 | 数据就在本机 `~/.acumen/vuln.db` |
| 前端要 node 构建 | 一个 HTML + 一个 JS，改完刷新就生效 |

战场设定是离线内网和只进不出的 VDI:那里升级一次依赖都要走审批，能带进去的东西越少越好。

## 跑起来

**绿色版（Windows，什么都不用装）**

```
解压 acumen-x.y.z-win64.zip
双击 acumen.bat
```

自带 Python 3.12 运行时和 `engine\sweep.exe`，不需要 Python、不需要 Go、不需要联网。

**源码目录（macOS / Linux）**

```bash
cd ~/tools/acumen
./run.sh                 # 默认 127.0.0.1:7788，自动开浏览器
./run.sh --port 7799     # 换端口
```

引擎按这个顺序找:包内 `engine/sweep` → `PATH` 里的 `sweep` → `~/.local/bin/sweep`。
想指定就用 `--engine /path/to/sweep`（指错了会明确报错，不会偷偷换成别的二进制）。

**只想扫、不开页面**

```bash
python3 -m vc.server --scan                    # 扫一遍收件箱，打印 JSON 统计后退出
python3 -m vc.server --scan --force            # 忽略 mtime 缓存全部重解析
```

## 八种扫描模式

引擎是 Go 写的单文件内核，子命令与界面上的模式一一对应:

| 模式 | 干什么 | 输入 |
|---|---|---|
| 全流程 | 子域→验活→资产→备案→指纹→路径→API→JS→端口→报告，10 步 | IP / 域名 |
| 端口扫描 | TCP connect 常用端口表 + 旗帜抓取识别服务 | IP / 域名 |
| 指纹识别 | headers + body 双通道指纹规则 | URL |
| API 未授权 | 27 个候选端点，软 404 基线过滤 + 命中取证 | URL |
| JS 情报 | 外链 JS 抽接口 / 密钥线索（只 GET，并发 ≤6） | URL |
| 敏感路径 | `.git` / `.env` / swagger / actuator / druid 等 | URL |
| 子域枚举 | 证书日志枚举子域（crt.sh → certspotter 兜底） | 域名 |
| 域名基线 | 域名暴露面 8 项基线检查 | 域名 |

安全边界写在代码里，不靠自觉:

- 引擎用 `subprocess` **列表参数**启动，绝不拼 shell；目标先过字符白名单，空格 / 引号 / 分号 / 换行这类注入形状直接拒
- 并发上限 4、单目标超时、停止走进程组 `TERM → KILL`
- 产物只落在 `<收件箱>/scan-<时间>-<id>/out/<target>/`，由摄入器入账，扫描器不直接写数据表
- 进度来自引擎自己的 `--progress-file` JSONL 契约，不猜 stdout

## 结果怎么用

打开页面就自动整理，`POST /api/rescan` 按 `mtime + size + 内容指纹` 增量，
未变文件 0 成本跳过；后台还有 5 秒轮询的 watcher，扫出来的东西几秒后自己长出来。

**去重合并** — 去重键 = `sha1(资产 | 标题 | 端点 | 参数)`。同一漏洞被两份产物报过 →
不新增条目，而是 `命中次数 +1`、`来源` 取并集、`严重度` 取最高、`首次发现` 取最早。
所以「96 条目 / 116 命中」= 96 个不同漏洞，被报过 116 次。

**状态流转** — `待验证 / 已确认 / 误报 / 已修复 / 已忽略`，页面上直接改，落 SQLite，表头勾选框可批量改。

**导出** — 右上角 `导出 CSV` / `导出 MD`，导出的就是当前看到的:严重度 / 状态 / 搜索词
三个筛选条件都跟着走。CSV 带 BOM（Excel 直接开不乱码），MD 按严重度分组带汇总表头。

## 引擎产物怎么进表

`engine/sweep` 每个模式都写一份结构化 JSON，摄入器直接按模式解析，不用二次转换:

| 引擎产物 | 变成什么 |
|---|---|
| `paths.json` | 漏洞：敏感路径可访问（`.env` / `.git/config` 这类给高危，`/actuator` 这类给中危）+ 资产 |
| `ports.json` | 资产：开放端口 + 服务 + banner（二进制协议的 banner 会净化，MySQL 握手包不会把界面弄成乱码） |
| `api_unauth.json` | 漏洞：只认 `hit:true` 的端点，分级沿用引擎的「高/中/低」 |
| `jsintel.json` | 漏洞：JS 里的硬编码凭据（**带二次判定**，压缩 JS 的 `sk`/`ak` 变量名不会变成高危）；接口数写进备注 |
| `fingerprint.json` | 资产：指纹标签（Nginx / Spring Boot…） |
| `secheaders.json` / `webfiles.json` 等基线 | 漏洞：基线风险项，`warn` 一律低危（缺安全头是真问题，但不是高危） |
| `evidence/**/meta.json` | 漏洞：引擎取证过的命中点，带复现材料 |

三条判据值得单独说，因为都是被真实产物教出来的:

- **路径可达 ≠ 高危**。分级只看「拿到它能不能继续往下走」:凭据/配置/源码/备份/运维端点给高危，
  普通管理页给中危，其它只记低危。
- **敏感串要二次判定**。引擎按 key 名粗匹配，在压缩过的第三方 JS 上 8 条命中里 8 条是
  `var sk={}` 这种变量名。现在要求「像凭据的值」:带厂商前缀（AKIA/sk-/ghp_/eyJ…），
  或者长度 ≥16 且字母数字混排。丢掉的条数会写在收件箱备注里，不偷偷吞掉。
- **同一份事实不重复计数**。基线结果引擎会在 `out/<host>/` 和 `out/<host>/evidence/baseline/`
  各写一份，`<name>.json` 和 `<name>.txt` 也是同一批事实的两种排版 —— 只解析一份。

解析器代次（`PARSER_GEN`）参与文件指纹:解析逻辑升级后旧产物自动重解析一次，
不用手动点「全量重解析」。

## 收到的产物也能一起吃

这是附加能力，不是主线:手上要是有别的工具的历史产物，一起丢进收件箱就能并进同一张表。

默认扫这三个目录（不存在会自动建第一个）:

```
~/pentest-inbox      ← 建议：新产物往这丢，最干净
~/pentest
~/pentest-assets
```

自定义:`./run.sh --inbox ~/scans/target-a/live --inbox ~/scans/target-b`

| 格式 | 长什么样 | 产出 |
|---|---|---|
| `nuclei_jsonl` | nuclei `-jsonl` 输出 | 漏洞 |
| `nuclei_text` | `[CVE-xxx] [http] [critical] url` | 漏洞（自动跳过 `[info] [4/28]` 这类进度行） |
| `xray` | xray jsonl / `{"data":{"detail":[…]}}` | 漏洞 |
| `nmap_xml` | `nmap -oX` | 资产（只收 open 端口）+ 脚本里带 CVSS 的漏洞 |
| `nessus` | `.nessus` 导出 XML | 漏洞（severity 0-4 映射） |
| `yakit_port` | `[Result] {"host":…,"port":…}` | 资产（`isOpen:true` 才收） |
| `host_inventory` | 存活/指纹清单 JSON（host + status/server/title…） | **资产，不是漏洞** |
| `csv_table` | 含 漏洞名/风险等级/URL 列的 CSV/TSV（中英文表头都认） | 漏洞 |
| `md_table` | 报告里的 Markdown 表格 | 漏洞（无漏洞列的表格自动判掉） |
| `http_packet` | 报告里的「原始请求+响应」JSON:`{title, level, req:[…], resp:[…]}` | 漏洞（从 `Host:` 取资产与端口、请求行取端点、`level` 取分级，响应体取证据） |

判别是「先看形状再解析」:有 host 键 + ≥2 个探测字段 + 没有 severity/vuln 标记 → 判成资产清单，
不会再把指纹表刷成 14 条 info 漏洞。

扩展名白名单 `.json/.jsonl/.txt/.csv/.tsv/.xml/.nessus/.md`，单文件 >20MB 跳过，
`smali/ res/ assets/ apktool-i/ node_modules/ .git/` 之类目录直接不进去。
单次上限 4000 文件。

## 数据在哪

```
~/.acumen/vuln.db        # SQLite:findings / assets / files / log
```

删了就是清空重来（不会动原始产物文件）。

## 开关与排查

- **收件箱状态** 页:每个文件被认成什么格式、出了几条、备注为什么跳过；「只看有产出」过滤噪音。
- **日志** 页:默认只看汇总事件；要看逐文件明细点「含逐文件明细」。
- **扫描页底部**:引擎就绪会显示二进制路径；显示「没找到扫描引擎」说明包不完整或 PATH 上那个不在了。
- 只绑 `127.0.0.1`，无鉴权，**仅本机单人用**；要给别人看得自己套反代加认证。
- 只读不联网:全程不发任何外部请求（`tools/check_offline.py` 在 CI 里守这条）。

## 文件

```
run.sh                启动（端口占用则复用已有实例）
vc/parsers.py         10 类第三方格式解析 + 资产/漏洞形状判别
vc/parsers_sweep.py   引擎原生产物解析（7 种形状）+ 分级与误报过滤
vc/store.py           SQLite:去重合并 / 筛选 / 状态 / 导出
vc/ingest.py          收件箱遍历、mtime+指纹增量（带解析器代次）
vc/scans.py           扫描控制:引擎发现、目标校验、任务池、进度解析
vc/server.py          stdlib HTTP + JSON API + watcher
vc/ui/                单页前端（无框架、无构建）
engine/sweep          扫描引擎（绿色版内置；源码目录按 PATH 找）
docs/shots/           真跑出来的界面截图（扫描页 / 漏洞页 / 资产页）
tools/                构建与门禁:绿色版打包 / 零依赖 / 离网自检
tests/                84 个单测 + 引擎真产物 fixtures
                    （含「指纹清单不能被当漏洞」「CVE 只收规范编号」
                      「压缩 JS 变量名不能当密钥」「自带引擎优先于系统同名二进制」回归）
```

测试:`python3 -m unittest discover -s tests -v`

绿色版构建（需要一次 Go 交叉编译）:

```bash
cd ~/tools/sweep/engine-go && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go build -trimpath -ldflags "-s -w" -o ~/tools/acumen/build/sweep-win64.exe ./cmd/atlas
cd ~/tools/acumen && python3 tools/build_win_bundle.py \
  --python-zip /path/to/python-3.12.8-embed-amd64.zip
```
