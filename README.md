# 空境 · Kara

**小而精的本地漏扫。** 填目标 → 开扫 → 命中入账 → 复验 → 导报告。有网页版，也有纯终端版；
扫的是外面的目标，数据与库只留在本机 `~/.kara/vuln.db`。

## 能力

- **八种模式**：全流程 / 端口扫描 / 指纹识别 / API 未授权 / JS 情报 / 敏感路径 / 子域枚举 / 域名基线
- **去重合并**：去重键 `sha1(资产|标题|端点|参数)`。同一漏洞被多份产物报过不新增条目，命中次数 +1、来源取并集、严重度取最高、首次发现取最早
- **复验**：按当初发现它的同一个模式、同一个入口重跑，结论分「仍存在 / 已消失 / 无法判定 / 不可复验」——**连不上目标不算已消失**
- **分级判据**：路径可达 ≠ 高危（凭据 / 源码 / 配置 / 备份 / 运维端点才 high）；JS 敏感串二次判定，压缩 JS 的 `sk` / `ak` 变量名不当密钥
- **凭什么算命中**：点开每条看端点、判据、证据和复现命令，命令一键复制
- **导出**：CSV（带 BOM，Excel 不乱码）/ MD，跟随当前严重度、状态、搜索筛选
- **吃别家产物**：nuclei / xray / nmap / nessus / yakit / CSV / MD 表格 / 原始 HTTP 报文丢进收件箱，自动归一化进同一张表

## 跑起来

**网页版（macOS / Linux）**

```bash
./run.sh                 # 127.0.0.1:7788，自动开浏览器
./run.sh --port 7799     # 换端口
```

**终端版**（不想开页面就用这个，同一个库）

```bash
kara scan -t 127.0.0.1:8080 -m api       # 扫：实时进度 + 本轮新增命中表
kara scan -t example.com,10.0.0.5 -m all --parallel 3
kara list --sev high                     # 看命中（--q 关键词 / --status 待验证）
kara show 12                             # 单条详情：判据、证据、复现命令
kara assets                              # 资产：主机 / 端口 / 指纹
kara verify --ids 12,15                  # 复验：同一模式同一入口重跑
kara export --format md -o report.md     # 导出 CSV / MD
kara summary                             # 库总览
kara engine                              # 引擎与八种模式自检
```

`kara` 就是仓库根目录那个薄壳（`~/.local/bin/kara` 软链过去），等价于 `python3 -m vc.cli`。
终端版与网页版共用同一套 Store / ScanManager / Verifier，写的是同一份库，随时换着用。

`api` / `paths` / `fingerprint` / `jsintel` 这类吃 URL 的模式会先握手判协议：
`127.0.0.1:8080` 自动走 `http://`，公网站点仍走 `https://`；要自己定就加 `--scheme http|https|raw`。

**Windows**：下 Releases 里的 `kara-*-win64.zip`，解压双击 `kara.bat`，不需要装 Python 也不需要 Go。

引擎按 `engine/sweep` → `PATH` 上的 `sweep` → `~/.local/bin/sweep` 顺序找；`--engine /path/to/sweep` 指定后只认它，指错会明确报错。

### 引擎（Go，仓库内自带）

`engine-go/` 是 Kara 自己的扫描内核（Go 标准库 + `yaml.v3`，零外部依赖），Kara 不依赖机器上装没装过别的扫描器。

```bash
cd engine-go
go build -ldflags "-X github.com/Kur1sulab/kara/engine-go/cli.Version=v1.0.0" -o ../engine/sweep ./cmd/sweep
# Windows 绿色版用的交叉编译
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o ../build/sweep-win64.exe ./cmd/sweep
```

## 边界

- 只绑 `127.0.0.1`，无鉴权，仅本机单人用
- 零出站，`tools/check_offline.py` 在 CI 里守这条
- 引擎用列表参数启动不拼 shell，目标先过字符白名单，并发上限 4，停止走进程组 `TERM → KILL`
- 数据在 `~/.kara/vuln.db`（SQLite），删了就是清空重来，不动原始产物

## 文件

```
run.sh               网页版启动（端口占用则复用已有实例）
kara                 终端版入口（等价 python3 -m vc.cli）
engine-go/           扫描内核源码（Go，构建产物 → engine/sweep）
vc/cli.py            终端模式：scan / list / show / verify / export …
vc/parsers.py        第三方格式解析 + 资产/漏洞形状判别
vc/parsers_sweep.py  引擎原生产物解析（7 种形状）+ 分级与误报过滤
vc/store.py          SQLite：去重合并 / 筛选 / 状态 / 复验结论 / 导出
vc/ingest.py         收件箱遍历、mtime + 指纹增量
vc/scans.py          引擎发现、目标校验、任务池、进度解析
vc/verify.py         复验：按原模式重跑、三态判定（连不上 ≠ 已消失）
vc/server.py         stdlib HTTP + JSON API + watcher
vc/ui/               单页前端（无框架、无构建）
engine/sweep         扫描引擎（由 engine-go/ 构建）
tests/               104 个单测 + 引擎真产物 fixtures
```

```bash
python3 -m unittest discover -s tests -v
```
