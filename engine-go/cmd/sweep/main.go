// sweep —— 空境 Kara 的扫描内核入口（engine-go/cmd/sweep）。
//
// 全部 CLI 逻辑在 cli 包，此处仅做薄壳：go build ./cmd/sweep。
// 与八咫（yata）分家后：Kara 只做终端扫描，内核不再挂 `serve` 子命令，
// 也不带 Web 控制台——界面那层归 Kara 自己的 vc/cli.py（终端）或 vc/server.py（网页）。
package main

import (
	"os"

	"github.com/Kur1sulab/kara/engine-go/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
