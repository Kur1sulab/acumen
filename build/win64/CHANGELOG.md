# 更新日志

版本号按 [语义化版本](https://semver.org/lang/zh-CN/)：修 bug 走 patch，加能力走 minor，
输出格式或数据库结构不兼容才走 major。

## 1.1.0 — 2026-11-18

### 新增

- **CVE 识别链路**。新增 `cve_of()`，从标题、证据、原始报文里识别编号，兼容
  `CVE-2021-44228` / `cve_2021_44228` / `CVE 2021 44228` 以及全角横线、短破折、
  长破折、减号等分隔符；多个编号排序去重后用逗号连接。
- **nuclei 从 `template-id` 取编号**（`CVE-2021-44228.yaml` 的 template-id 就是编号本身）。
- **nessus 从 `<cve>` 子元素取编号**，支持一条 item 多个 CVE。
- **界面 CVE 徽章**：标题前渲染等宽小标签，无编号不占位，多个折叠成 `+N`，
  点击复制。

### 修复

- **繁体表头报告整份丢弃**。`編號 / 發現 / 嚴重度 / 風險描述` 这些词不在识别表里，
  88 行的白盒审计报告一条不出。补齐繁体词后救回 15 条。
- **`cve` 字段被模板名污染**。nuclei 的 template-id 可能是 `exposed-panel` 这种名字，
  以前直接写进 `cve` 字段。现在只收规范编号，非编号文本一律丢弃。
- **端点协议被覆盖**。`rdp://10.0.0.5:3389` 以前被硬拼成 `https://...`，现在带协议的
  端点照原样展示。
- **端口拼两遍**。资产已是 `host:port` 形式时又追加了一次端口，显示成
  `10.0.0.5:3389:3389`。
- **`_port_of()` 从未被调用**，端点里的端口一直没回填到 `port` 字段。

### 工程

- 新增 `tools/check_zero_deps.py`：扫描全部 import，非标准库就失败；同时检查前端
  没有混进 `package.json` / `node_modules` 之类的构建链。核心承诺进 CI。
- 新增 GitHub Actions：单测 × (ubuntu, macos) × (3.9, 3.12, 3.13)，另加零依赖自检与
  JS 语法检查。
- 单测 44 → 58，新增 `tests/test_cve_chain.py` 与 `tests/fixtures/`
  （nuclei jsonl / nessus xml / 繁体 md 三份回归夹具）。

### 说明

全库 126 条 finding 的 CVE 命中数为 0，原因是存量数据本身是 App 白盒审计与内网渗透
报告，讲的是 TLS 校验关闭、TrustManager 空实现这类配置缺陷，本来就不挂 CVE 编号。
链路已就绪，nuclei / nessus 产物进来会自动带编号。

## 1.0.0 — 2026-11-18

首个版本。

- 9 类产物解析：nuclei jsonl / nuclei text / xray / nmap xml / nessus / yakit /
  存活清单 / CSV / Markdown 表格，另加「原始请求响应包」。
- 形状判别：有 host 键且无 severity 标记的判为资产清单，不会把指纹表刷成 info 漏洞。
- 去重键 `sha1(资产|标题|端点|参数)`，命中次数累加、来源取并集、严重度取最高、
  首次发现取最早。
- 5 种状态流转，落 SQLite，支持批量改。
- 导出 CSV（带 BOM，Excel 不乱码）/ Markdown，跟随当前筛选。
- 深浅双主题，过 WCAG AA。
- 零依赖：Python 标准库 + 原生 HTML/CSS/JS，无 pip、无 npm、无构建。
