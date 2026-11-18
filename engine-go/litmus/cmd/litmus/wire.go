package main

import (
	"time"

	"github.com/Kur1sulab/kara/engine-go/litmus/engine"
	// 空白导入：injection 的 init() 把 12 个注入检查项注册进 scan 全局覆盖表。
	// 少了这一行，覆盖表里整族注入项会静默消失（编译仍然是绿的）。
	"github.com/Kur1sulab/kara/engine-go/litmus/authprobe"
	_ "github.com/Kur1sulab/kara/engine-go/litmus/injection"
	// 空白导入：authz 的 init() 把 9 个认证/授权检查项注册进 scan 全局覆盖表。
	_ "github.com/Kur1sulab/kara/engine-go/litmus/authz"
	// 空白导入：exposure 的 init() 把 14 个云与文件面检查项注册进 scan 全局覆盖表
	// （桶列举 / 元数据端点 / 前端密钥 / source map / SVN / .DS_Store / .idea /
	// 日志 / heapdump / Jolokia / Consul / ZooKeeper / SMTP 中继 / 上传点）。
	// engine.runScanFamilies 只跑 scan.All()，少这一行整族会静默消失。
	_ "github.com/Kur1sulab/kara/engine-go/litmus/exposure"
	// 空白导入：framework 的 init() 把 14 个框架指纹 + 已知风险点检查项
	// 注册进 scan 全局覆盖表。engine.runScanFamilies 只跑 scan.All()，
	// 少这一行整族会静默消失。
	_ "github.com/Kur1sulab/kara/engine-go/litmus/framework"
)

// init 把服务级真登探针装配进 engine。
//
// engine 用可注入 hook（engine.KeyFor / engine.ProbeAuth）而不是硬 import，
// 是为了在模块尚未移植时也能如实记 na；现在 authprobe 到位了，这里接上。
// 不接的后果：每个非 Web 端口都会落一条「无对应探针」的 na，覆盖表上
// 整类未授权访问静默消失 —— 这正是三态原则要防的。
func init() {
	engine.KeyFor = authprobe.KeyFor
	engine.ProbeAuth = func(host string, port int, service, product string,
		tls bool, timeout time.Duration) map[string]interface{} {
		return authprobe.ProbeDict(host, port, authprobe.Options{
			Service: service,
			Product: product,
			TLS:     tls,
			Timeout: timeout,
		})
	}
}
