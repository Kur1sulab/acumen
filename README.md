# 空境 · Kara

**小而精的本地漏扫。** 填目标 → 开扫 → 命中入账 → 复验 → 导报告，全程只跑在 `127.0.0.1`，不发一个外部请求。

## 能力

- **八种模式**：全流程 / 端口扫描 / 指纹识别 / API 未授权 / JS 情报 / 敏感路径 / 子域枚举 / 域名基线
- **去重合并**：去重键 `sha1(资产|标题|端点|参数)`。同一漏洞被多份产物报过不新增条目，命中次数 +1、来源取并集、严重度取最高、首次发现取最早
- **复验**：按当初发现它的同一个模式、同一个入口重跑，结论分「仍存在 / 已消失 / 无法判定 / 不可复验」——**连不上目标不算已消失**
- **分级判据**：路径可达 ≠ 高危（凭据 / 源码 / 配置 / 备份 / 运维端点才 high）；JS 敏感串二次判定，压缩 JS 的 `sk` / `ak` 变量名不当密钥
- **凭什么算命中**：点开每条看端点、判据、证据和复现命令，命令一键复制
- **导出**：CSV（带 BOM，Excel 不乱码）/ MD，跟随当前严重度、状态、搜索筛选
- **吃别家产物**：nuclei / xray / nmap / nessus / yakit / CSV / MD 表格 / 原始 HTTP 报文丢进收件箱，自动归一化进同一张表

## 跑起来

**源码（macOS / Linux）**

```bash
./run.sh                 # 127.0.0.1:7788，自动开浏览器
./run.sh --port 7799     # 换端口
```

**Windows**：下 Releases 里的 `kara-*-win64.zip`，解压双击 `kara.bat`，不需要装 Python 也不需要 Go。

引擎按 `engine/sweep` → `PATH` 上的 `sweep` → `~/.local/bin/sweep` 顺序找；`--engine /path/to/sweep` 指定后只认它，指错会明确报错。

只想扫、不开页面：

```bash
python3 -m vc.server --scan
```

## 边界

- 只绑 `127.0.0.1`，无鉴权，仅本机单人用
- 零出站，`tools/check_offline.py` 在 CI 里守这条
- 引擎用列表参数启动不拼 shell，目标先过字符白名单，并发上限 4，停止走进程组 `TERM → KILL`
- 数据在 `~/.kara/vuln.db`（SQLite），删了就是清空重来，不动原始产物

## 文件

```
run.sh               启动（端口占用则复用已有实例）
vc/parsers.py        第三方格式解析 + 资产/漏洞形状判别
vc/parsers_sweep.py  引擎原生产物解析（7 种形状）+ 分级与误报过滤
vc/store.py          SQLite：去重合并 / 筛选 / 状态 / 复验结论 / 导出
vc/ingest.py         收件箱遍历、mtime + 指纹增量
vc/scans.py          引擎发现、目标校验、任务池、进度解析
vc/verify.py         复验：按原模式重跑、三态判定（连不上 ≠ 已消失）
vc/server.py         stdlib HTTP + JSON API + watcher
vc/ui/               单页前端（无框架、无构建）
engine/sweep         扫描引擎
tests/               104 个单测 + 引擎真产物 fixtures
```

```bash
python3 -m unittest discover -s tests -v
```
