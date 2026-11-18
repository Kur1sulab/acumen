// litmus2 —— 内网授权渗透验证框架（Go 版）
//
// 设计目标（与 Python 版一致，但换了载体）：
//   - 零第三方依赖：只用 Go 标准库，CGO_ENABLED=0 静态单文件
//   - 拷进去就能跑：目标机不需要 Python / pip / 联网 / 管理员
//   - 三态覆盖：ok / skip（带原因）/ na，没测的东西绝不伪装成「通过」
//   - 分级看证据：L1 可达、L2 真实数据/凭据、L3 内部权限
//
// 交付形态决定了代码形态：这个二进制是泡在客户内网 VDI 里跑的，
// 不是从外面打进目标。所以 Windows 控制台代码页、只读盘写盘失败、
// 断网环境、无管理员权限，都得当成常态而不是异常。
package main

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strings"
)

// Version 版本号
const Version = "2.0.0-go"

func usage() {
	fmt.Fprintf(os.Stderr, `litmus2 %s —— 内网授权渗透验证框架（零依赖 Go 单文件）

用法:
  litmus doctor                            陌生环境自检（VDI / 跳板机先跑这个）
  litmus run      -t <目标...> [选项]      跑一轮
  litmus selftest                          自检（协议构造 + 解析 + 判定）
  litmus report   <run目录>                重新渲染报告
  litmus diff     <A> <B>                  对比两轮结果
  litmus resume   <run目录>                续跑
  litmus replay   -f <findings> --id <ID>  重放单条发现，验证是否仍可复现

目标:
  -t, --target        目标：IP / host:port / CIDR / URL，可重复
  -T, --target-file   目标文件（每行一个，# 注释），可重复

扫描:
  -p, --ports         端口：top100 / top1000 / full / 80,443,1-1024
      --intensity     强度档位：low / normal / high（默认 normal）
      --threads       并发数
      --timeout       超时秒数
      --allow-public  允许公网目标（默认只放行私网/回环）
      --max-hosts     CIDR 展开上限（默认 256）
      --creds         口令尝试次数上限（0=不做口令尝试）
      --no-auth-probe 跳过服务级真登验证
      --no-web        跳过 Web 侧检查
      --templates     nuclei 模板目录（可选）

输出:
      --out           输出目录（默认 runs/<时间戳>；不可写时自动退到临时目录）
      --state-db      状态库目录（默认 <out>/state）
      --resume        续跑：跳过已完成主机
      --diff          与上一轮对比（新增/仍在/已修复）
      --json          末尾打印 JSON 摘要
  -q, --quiet         安静模式

构建:
  # 本机
  CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o litmus ./cmd/litmus
  # Windows VDI（静态单文件，约 5.5MB）
  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o litmus.exe ./cmd/litmus
`, Version)
}

func main() {
	// 必须在任何输出之前：Windows 控制台默认 GBK，不切 UTF-8 中文全乱码。
	initConsole()

	args := os.Args[1:]
	if len(args) == 0 {
		// 双击 exe（无参数 + 连着终端）直接进问答 —— 客户 VDI 上没人敲参数。
		// 重定向/管道场景没终端，打用法而不是弹一个读不到输入的问答。
		if isTerminal() {
			rc := interactiveWizard()
			// 双击启动时，main 一返回控制台窗口就消失，报告路径根本来不及看。
			// 这里停一下等人按键 —— 只在真是终端时停，管道/脚本不受影响。
			fmt.Print("\n 按回车键退出…")
			_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
			os.Exit(rc)
		}
		usage()
		os.Exit(2)
	}
	// 不带子命令直接给参数时，默认按 run 处理（与 Python 版 cmd 默认值一致）
	if strings.HasPrefix(args[0], "-") {
		os.Exit(cmdRun(args))
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "version", "-V", "--version":
		fmt.Printf("litmus2 %s (%s/%s, %s)\n", Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
	case "help", "-h", "--help":
		usage()
	case "doctor":
		os.Exit(cmdDoctor(rest))
	case "run":
		os.Exit(cmdRun(rest))
	case "selftest":
		os.Exit(cmdSelftest(rest))
	case "report":
		os.Exit(cmdReport(rest))
	case "diff":
		os.Exit(cmdDiff(rest))
	case "resume":
		os.Exit(cmdResume(rest))
	case "replay":
		os.Exit(cmdReplay(rest))
	default:
		fmt.Fprintf(os.Stderr, "未知子命令: %s\n\n", cmd)
		usage()
		os.Exit(2)
	}
}
