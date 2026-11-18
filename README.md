# 漏扫控制台 · Vuln Console

把散在各处的漏扫产物（nuclei / xray / nmap / nessus / yakit / 报告 Markdown / CSV）自动收进一个本地看板：
**打开页面就自动整理**——扫描收件箱、归一化、去重合并、按严重度与资产聚合，可筛选、改状态、导 CSV / MD。

零依赖：只用 Python 标准库（`http.server` + `sqlite3`），不需要 pip、不需要前端构建。

```
┌─ 浏览器 127.0.0.1:7788 ─────────────────────────────────────────────┐
│ 条目/命中   CRITICAL 5  HIGH 30  MEDIUM 45  LOW 11  INFO 5  资产 47 │
│ 严重度: 全部 严重 高危 中危 低危 信息        搜索 [         ] 重扫  │
│ ┌──────┬──────────────────┬────────────┬────────┬────┬────┬──────┐ │
│ │严重度│漏洞              │资产        │端点    │命中│状态│发现  │ │
│ └──────┴──────────────────┴────────────┴────────┴────┴────┴──────┘ │
└────────────────────────────────────────────────────────────────────┘
```

界面默认**白色浅色版**，右上角「☾ 暗色 / ☀︎ 白色」一键切换，选择记在 localStorage。

## 跑起来

```bash
cd ~/tools/vuln-console
./run.sh                 # 默认 127.0.0.1:7788，自动开浏览器
./run.sh --port 7799     # 换端口
```

`run.sh` 会先探端口：已经在跑就直接打开已有实例，不会起第二个。

不想开页面、只想把收件箱整理进库：

```bash
python3 -m vc.server --scan            # 扫一遍，打印 JSON 统计，退出
python3 -m vc.server --scan --force    # 忽略 mtime 缓存，全部重解析
```

## 收件箱放哪

默认扫这三个目录（不存在会自动建第一个）：

```
~/pentest-inbox      ← 建议：新产物往这丢，最干净
~/pentest
~/pentest-assets
```

自定义：

```bash
./run.sh --inbox ~/pentest/lzxf-1111/live-1116 --inbox ~/pentest-assets
```

**页面打开即整理**：前端一进来就 `POST /api/rescan`（按 mtime+size+内容指纹增量，未变文件 0 成本跳过），
后台还有一个 5 秒轮询的 watcher——扫描器把结果写进收件箱，页面几秒后自己长出来，不用点。

## 认得的格式

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
| `http_packet` | 报告里的「原始请求+响应」JSON：`{title, level, req:[…], resp:[…]}` | 漏洞（从 `Host:` 取资产与端口、请求行取端点、`level` 取分级，响应体取证据） |

判别是「先看形状再解析」：有 host 键 + ≥2 个探测字段 + 没有 severity/vuln 标记 → 判成资产清单，
不会再把指纹表刷成 14 条 info 漏洞。

扩展名白名单 `.json/.jsonl/.txt/.csv/.tsv/.xml/.nessus/.md`，单文件 >20MB 跳过，
`smali/ res/ assets/ apktool-i/ node_modules/ .git/` 之类目录直接不进去（APK 反编译产物里全是应用资源，不是扫描结果）。
单次上限 4000 文件。

## 去重与合并

去重键 = `sha1(资产 | 标题 | 端点 | 参数)`。同一漏洞被两份产物报过 → 不新增条目，
而是 `命中次数 +1`、`来源` 取并集、`严重度` 取最高、`首次发现` 取最早。
所以「96 条目 / 116 命中」= 96 个不同漏洞，被报过 116 次。

状态：`待验证 / 已确认 / 误报 / 已修复 / 已忽略`，页面上直接改，落 SQLite，刷新不丢。
表头勾选框可批量改。

## 导出

右上角 **导出 CSV** / **导出 MD**：**导出的就是你当前看到的**——会带上严重度 / 状态 / 搜索词三个筛选条件，
CSV 带 BOM（Excel 直接开不乱码），MD 按严重度分组带汇总表头。

## 数据在哪

```
~/.vuln-console/vuln.db        # SQLite：findings / assets / files / log
```

删了就是清空重来（不会动原始产物文件）。

## 开关与排查

- **收件箱状态** 页：每个文件被认成什么格式、出了几条、备注为什么跳过；「只看有产出」过滤噪音。
- **日志** 页：默认只看汇总事件；要看逐文件明细点「含逐文件明细」。
- 只绑 `127.0.0.1`，无鉴权，**仅本机单人用**；要给别人看得自己套反代加认证。
- 只读不联网：全程不发任何外部请求。

## 文件

```
run.sh              启动（端口占用则复用已有实例）
vc/parsers.py       10 类格式解析 + 资产/漏洞形状判别
vc/store.py         SQLite：去重合并 / 筛选 / 状态 / 导出
vc/ingest.py        收件箱遍历、mtime+指纹增量
vc/server.py        stdlib HTTP + JSON API + watcher
vc/ui/              单页前端（无框架、无构建）
tests/              18 个单测（含「指纹清单不能被当漏洞」回归）
```

测试：`python3 -m unittest discover -s tests -v`
