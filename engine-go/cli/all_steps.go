package cli

// all_steps.go —— `all` 流水线里 jsintel 步骤的接线层。
//
// 对应 Python：yata.py:154（IP 分支）/ :172（域名分支）的 run_jsintel(base, out)：
// 默认参数 = workers=6 / max_files=60 / 单文件超时 10s（jsintel.Default*）。
// 端口扫描步骤的接线在 cli/port_cmd.go（runPortStep）。

import (
	"fmt"

	"github.com/Kur1sulab/kara/engine-go/baseline"
	"github.com/Kur1sulab/kara/engine-go/cve"
	"github.com/Kur1sulab/kara/engine-go/jsintel"
)

// runJSStep：JS 情报（非致命步骤，失败只记警告不中断流水线）。
func runJSStep(base, out string) error {
	_, err := jsintel.RunJSIntel(base, out,
		jsintel.DefaultWorkers, jsintel.DefaultMaxFiles, jsintel.DefaultTimeout)
	return err
}

// runBaselineStep：all 流水线里的暴露面基线（只跑 secheaders / webfiles / sslchain）。
// 这三项都是「对着目标自己发请求」，不需要任何外部服务。
func runBaselineStep(base, domain, out string) error {
	if base == "" {
		return fmt.Errorf("没有可用的 base URL")
	}
	return baseline.Run(baseline.Options{
		Domain: domain, URL: base, Out: out,
		AllowPrivate: true,
		Emit:         emit,
		Logf:         func(f string, a ...any) { fmt.Printf(f, a...) },
	})
}

// runCVEStep：离线 CVE 匹配（只请求目标自己，不查任何外部库）。
func runCVEStep(base, out string) error {
	if base == "" {
		return fmt.Errorf("没有可用的 base URL")
	}
	res, err := cve.Run(base)
	if err != nil {
		return err
	}
	if _, err := cve.Write(out, res); err != nil {
		return err
	}
	fmt.Printf("[*] CVE 匹配：识别产品 %d 个，版本区间命中 %d 条（L1）\n",
		len(res.Products), len(res.Matches))
	return nil
}
